//! Locating the policy file and the project root.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{ConfigError, POLICY_FILE_NAME};

/// What discovery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Discovered {
    /// The policy file.
    pub policy_path: PathBuf,
    /// The directory containing it; AgentGuard treats this as the project root.
    pub project_root: PathBuf,
    /// The nearest ancestor (including the project root) containing a `.git` entry, if any.
    /// Informational only; AgentGuard never reads inside it in Phase 1.
    pub git_root: Option<PathBuf>,
}

/// Walk from `start` upwards looking for the policy file.
pub fn discover(start: &Path) -> Result<Discovered, ConfigError> {
    let start_abs = if start.is_absolute() {
        start.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| start.to_path_buf(), |cwd| cwd.join(start))
    };
    for dir in start_abs.ancestors() {
        let candidate = dir.join(POLICY_FILE_NAME);
        if candidate.is_file() {
            return Ok(Discovered {
                policy_path: candidate,
                project_root: dir.to_path_buf(),
                git_root: find_git_root(dir),
            });
        }
    }
    Err(ConfigError::NotFound {
        searched_from: start_abs,
    })
}

/// Nearest ancestor containing a `.git` file or directory.
#[must_use]
pub fn find_git_root(from: &Path) -> Option<PathBuf> {
    from.ancestors()
        .find(|d| d.join(".git").exists())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_in_ancestor_and_reports_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let nested = root.join("src").join("deep");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir(root.join(".git")).unwrap();
        fs::write(root.join(POLICY_FILE_NAME), "version: 1\nmode: READ_ONLY\n").unwrap();

        let found = discover(&nested).unwrap();
        assert_eq!(found.project_root, root);
        assert_eq!(found.policy_path, root.join(POLICY_FILE_NAME));
        assert_eq!(found.git_root, Some(root.clone()));
    }

    #[test]
    fn not_found_reports_start() {
        let tmp = tempfile::tempdir().unwrap();
        let err = discover(tmp.path()).unwrap_err();
        match err {
            ConfigError::NotFound { searched_from } => assert_eq!(searched_from, tmp.path()),
            other => panic!("unexpected: {other}"),
        }
    }

    #[test]
    fn ignores_directory_named_like_policy() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(POLICY_FILE_NAME)).unwrap();
        assert!(discover(tmp.path()).is_err());
    }
}
