//! Locations of controller-owned state, resolved from XDG variables.
//!
//! The state directory holds policy snapshots, audit records and session metadata. It is
//! created private (mode `0700` on Unix), must be owned by the current user, must not be
//! accessible to other users, and must not live inside the project being guarded.
//!
//! On Windows, where `HOME` is usually unset, the home directory is `USERPROFILE`.

use std::fs;
use std::path::{Path, PathBuf};

use agentguard_platform::access::{self, Owner};
use agentguard_platform::fs::UnixMode;
use serde::Serialize;

/// Problems with controller-owned paths.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PathsError {
    /// Neither `XDG_*` nor `HOME` is set, so no default location exists.
    #[error("cannot resolve a home directory: HOME is not set")]
    NoHome,

    /// The directory could not be created or inspected.
    #[error("{action} {}", path.display())]
    Io {
        /// What was attempted.
        action: &'static str,
        /// The path.
        path: PathBuf,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },

    /// The directory exists but other users can access it.
    #[error("{} is accessible by other users; restrict it to your account (Unix: chmod 700 {})", path.display(), path.display())]
    TooPermissive {
        /// The path.
        path: PathBuf,
        /// Observed permission bits (Unix only).
        mode: Option<u32>,
    },

    /// The directory is owned by a different user.
    #[error("{} is not owned by the current user", path.display())]
    WrongOwner {
        /// The path.
        path: PathBuf,
    },

    /// The directory is inside the guarded project, where an agent could reach it.
    #[error("{} is inside the project {}; state must live outside any guarded repository", state.display(), project.display())]
    InsideProject {
        /// The state directory.
        state: PathBuf,
        /// The project root.
        project: PathBuf,
    },

    /// The path exists but is not a directory.
    #[error("{} exists but is not a directory", path.display())]
    NotADirectory {
        /// The path.
        path: PathBuf,
    },
}

/// Resolved base directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppPaths {
    /// `$XDG_CONFIG_HOME/agentguard` (organisation policy, user preferences).
    pub config_dir: PathBuf,
    /// `$XDG_STATE_HOME/agentguard` (policy snapshots, audit, sessions).
    pub state_dir: PathBuf,
    /// `$XDG_RUNTIME_DIR/agentguard` (per-session sockets), if a runtime dir exists.
    pub runtime_dir: Option<PathBuf>,
}

impl AppPaths {
    /// Resolve from the process environment.
    pub fn from_env() -> Result<Self, PathsError> {
        Self::resolve(
            home_from_env(),
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        )
    }

    /// Resolve from explicit values (testable).
    pub fn resolve(
        home: Option<PathBuf>,
        xdg_config: Option<PathBuf>,
        xdg_state: Option<PathBuf>,
        xdg_runtime: Option<PathBuf>,
    ) -> Result<Self, PathsError> {
        let non_empty_abs = |p: Option<PathBuf>| p.filter(|p| p.is_absolute());
        let home = non_empty_abs(home);
        let config_base = match non_empty_abs(xdg_config) {
            Some(p) => p,
            None => home.clone().ok_or(PathsError::NoHome)?.join(".config"),
        };
        let state_base = match non_empty_abs(xdg_state) {
            Some(p) => p,
            None => home.ok_or(PathsError::NoHome)?.join(".local").join("state"),
        };
        Ok(Self {
            config_dir: config_base.join("agentguard"),
            state_dir: state_base.join("agentguard"),
            runtime_dir: non_empty_abs(xdg_runtime).map(|p| p.join("agentguard")),
        })
    }

    /// The sessions directory under the state directory.
    #[must_use]
    pub fn sessions_dir(&self) -> PathBuf {
        self.state_dir.join("sessions")
    }

    /// Create the state directory if needed and verify its safety properties.
    ///
    /// `project_root`, when given, must not contain the state directory.
    pub fn ensure_state_dir(&self, project_root: Option<&Path>) -> Result<PathBuf, PathsError> {
        if let Some(parent) = self.state_dir.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .unix_mode(0o700)
                .create(parent)
                .map_err(|source| PathsError::Io {
                    action: "creating",
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
        match fs::DirBuilder::new()
            .unix_mode(0o700)
            .create(&self.state_dir)
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(PathsError::Io {
                    action: "creating",
                    path: self.state_dir.clone(),
                    source,
                })
            }
        }
        check_private_dir(&self.state_dir)?;
        if let Some(project) = project_root {
            let state = fs::canonicalize(&self.state_dir).map_err(|source| PathsError::Io {
                action: "resolving",
                path: self.state_dir.clone(),
                source,
            })?;
            if let Ok(project) = fs::canonicalize(project) {
                if state.starts_with(&project) {
                    return Err(PathsError::InsideProject { state, project });
                }
            }
        }
        Ok(self.state_dir.clone())
    }
}

/// The home directory: `HOME`, or on Windows `USERPROFILE` when `HOME` is unset or empty.
pub fn home_from_env() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty());
    #[cfg(windows)]
    let home = home.or_else(|| std::env::var_os("USERPROFILE").filter(|h| !h.is_empty()));
    home.map(PathBuf::from)
}

/// Verify that `path` is a directory owned by the current user that no other user can access.
pub fn check_private_dir(path: &Path) -> Result<(), PathsError> {
    let meta = fs::metadata(path).map_err(|source| PathsError::Io {
        action: "inspecting",
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(PathsError::NotADirectory {
            path: path.to_path_buf(),
        });
    }
    let observed = access::of(path, &meta).map_err(|source| PathsError::Io {
        action: "inspecting the permissions of",
        path: path.to_path_buf(),
        source,
    })?;
    if observed.others_have_access {
        return Err(PathsError::TooPermissive {
            path: path.to_path_buf(),
            mode: agentguard_platform::fs::unix_mode(&meta).map(|m| m & 0o777),
        });
    }
    if observed.owner != Owner::CurrentUser {
        return Err(PathsError::WrongOwner {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_xdg_over_home() {
        let p = AppPaths::resolve(
            Some("/home/u".into()),
            Some("/cfg".into()),
            Some("/st".into()),
            Some("/run/user/1".into()),
        )
        .unwrap();
        assert_eq!(p.config_dir, PathBuf::from("/cfg/agentguard"));
        assert_eq!(p.state_dir, PathBuf::from("/st/agentguard"));
        assert_eq!(p.runtime_dir, Some(PathBuf::from("/run/user/1/agentguard")));
        assert_eq!(p.sessions_dir(), PathBuf::from("/st/agentguard/sessions"));
    }

    #[test]
    fn falls_back_to_home_and_requires_absolute() {
        let p =
            AppPaths::resolve(Some("/home/u".into()), None, Some("relative".into()), None).unwrap();
        assert_eq!(p.config_dir, PathBuf::from("/home/u/.config/agentguard"));
        assert_eq!(
            p.state_dir,
            PathBuf::from("/home/u/.local/state/agentguard")
        );
        assert!(p.runtime_dir.is_none());
        assert!(matches!(
            AppPaths::resolve(None, None, None, None),
            Err(PathsError::NoHome)
        ));
    }

    #[test]
    fn ensure_creates_private_dir_and_rejects_permissive() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths {
            config_dir: tmp.path().join("cfg"),
            state_dir: tmp.path().join("state").join("agentguard"),
            runtime_dir: None,
        };
        let created = paths.ensure_state_dir(None).unwrap();
        #[cfg(unix)]
        {
            let mode = agentguard_platform::fs::unix_mode(&fs::metadata(&created).unwrap());
            assert_eq!(mode, Some(0o700));
            agentguard_platform::fs::set_unix_mode(&created, 0o750).unwrap();
            assert!(matches!(
                paths.ensure_state_dir(None),
                Err(PathsError::TooPermissive {
                    mode: Some(0o750),
                    ..
                })
            ));
        }
    }

    #[test]
    fn ensure_rejects_state_inside_project() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("repo");
        fs::create_dir_all(&project).unwrap();
        let paths = AppPaths {
            config_dir: tmp.path().join("cfg"),
            state_dir: project.join(".agentguard-state"),
            runtime_dir: None,
        };
        assert!(matches!(
            paths.ensure_state_dir(Some(&project)),
            Err(PathsError::InsideProject { .. })
        ));
        let outside = AppPaths {
            state_dir: tmp.path().join("state"),
            ..paths
        };
        assert!(outside.ensure_state_dir(Some(&project)).is_ok());
    }

    #[test]
    fn check_private_dir_rejects_files() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            check_private_dir(&file),
            Err(PathsError::NotADirectory { .. })
        ));
    }
}
