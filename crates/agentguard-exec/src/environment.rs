//! The environment a managed process starts with.
//!
//! Nothing is inherited by default. A profile names the variables that are passed through;
//! the trusted global policy may add names to the `development` profile. Whatever a profile
//! or policy says, names that look like credentials or that inject code
//! ([`agentguard_core::envvars`]) are withheld, with two exceptions that name an agent socket
//! rather than hold a secret (`SSH_AUTH_SOCK`, `GPG_AGENT_INFO`; the agent enforces its own
//! confirmation). `PATH` is rebuilt from trusted directories only, and a few variables are set
//! so that nothing waits for interactive input.
//!
//! Values are never logged. Records and audit events list the names passed and the number
//! withheld. The values of withheld credential-like variables are masked in captured output.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agentguard_core::envvars::{is_secret_name, may_pass};
use serde::Serialize;

/// Directories searched after the trusted entries of the caller's `PATH`.
pub const SYSTEM_PATH: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/opt/homebrew/bin",
];

const MINIMAL: &[&str] = &[
    "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ", "TMPDIR",
];

const DEVELOPMENT: &[&str] = &[
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "GOPATH",
    "GOROOT",
    "GOCACHE",
    "GOMODCACHE",
    "GOPROXY",
    "JAVA_HOME",
    "NVM_DIR",
    "NVM_BIN",
    "PNPM_HOME",
    "VOLTA_HOME",
    "BUN_INSTALL",
    "DENO_DIR",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "PYENV_ROOT",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "CI",
    "NO_COLOR",
    "FORCE_COLOR",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "NODE_ENV",
];

/// Agent sockets the `development` profile passes despite their names.
const AGENT_SOCKETS: &[&str] = &["SSH_AUTH_SOCK", "GPG_AGENT_INFO"];

/// Variables AgentGuard sets itself so nothing prompts or pages.
const FIXED: &[(&str, &str)] = &[
    ("TERM", "dumb"),
    ("PAGER", "cat"),
    ("GIT_PAGER", "cat"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_EDITOR", "true"),
    ("GIT_SEQUENCE_EDITOR", "true"),
    ("GCM_INTERACTIVE", "never"),
];

/// Shortest value of a withheld credential-like variable that is masked in output.
const MIN_MASKED_VALUE: usize = 8;

/// An environment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Identity, locale and temporary directory only.
    Minimal,
    /// Minimal plus toolchain, cache, certificate and proxy settings.
    Development,
}

impl Profile {
    /// Parse a profile name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "minimal" => Some(Profile::Minimal),
            "development" => Some(Profile::Development),
            _ => None,
        }
    }

    /// Name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Profile::Minimal => "minimal",
            Profile::Development => "development",
        }
    }
}

/// A built environment.
#[derive(Debug, Clone)]
pub struct BuiltEnvironment {
    /// The profile.
    pub profile: Profile,
    /// Every variable the process receives, sorted by name.
    pub vars: Vec<(String, String)>,
    /// Names passed from the caller's environment, sorted.
    pub passed: Vec<String>,
    /// How many of the caller's variables were withheld.
    pub withheld: usize,
    /// The trusted search path.
    pub path: Vec<PathBuf>,
    /// Values of withheld credential-like variables, masked in captured output.
    secret_values: Vec<String>,
}

impl BuiltEnvironment {
    /// Values to mask in output, longest first.
    #[must_use]
    pub fn secret_values(&self) -> &[String] {
        &self.secret_values
    }
}

fn current_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// Whether `dir` may be searched for executables: absolute, an existing directory owned by
/// root or the current user, not writable by group or others, and outside `project_root`
/// (a project can contain anything an agent wrote).
#[must_use]
pub fn is_trusted_dir(dir: &Path, project_root: &Path) -> bool {
    if !dir.is_absolute() {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(dir) else {
        return false;
    };
    if canonical.starts_with(project_root) {
        return false;
    }
    let Ok(meta) = std::fs::metadata(&canonical) else {
        return false;
    };
    meta.is_dir()
        && (meta.uid() == 0 || meta.uid() == current_uid())
        && meta.permissions().mode() & 0o022 == 0
}

/// The trusted search path: the caller's `PATH` entries that pass [`is_trusted_dir`], in
/// order, then the system directories not already present.
#[must_use]
pub fn trusted_path(caller_path: Option<&str>, project_root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let candidates = caller_path
        .unwrap_or_default()
        .split(':')
        .map(PathBuf::from)
        .chain(SYSTEM_PATH.iter().map(PathBuf::from));
    for dir in candidates {
        if !is_trusted_dir(&dir, project_root) {
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(&dir) else {
            continue;
        };
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    out
}

/// Build the environment for `profile` from the caller's variables.
#[must_use]
pub fn build(
    caller: &[(String, String)],
    profile: Profile,
    extra: &[String],
    project_root: &Path,
) -> BuiltEnvironment {
    let caller_path = caller
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str());
    let path = trusted_path(caller_path, project_root);
    let allowed = |name: &str| {
        if name.starts_with("LC_") && may_pass(name) {
            return true;
        }
        if MINIMAL.contains(&name) {
            return true;
        }
        if profile == Profile::Development {
            if AGENT_SOCKETS.contains(&name) {
                return true;
            }
            return (DEVELOPMENT.contains(&name) || extra.iter().any(|e| e == name))
                && may_pass(name);
        }
        false
    };
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut passed = Vec::new();
    let mut withheld = 0usize;
    let mut secret_values: Vec<String> = Vec::new();
    for (name, value) in caller {
        if name == "PATH" {
            continue;
        }
        if allowed(name) && !value.contains('\0') {
            vars.push((name.clone(), value.clone()));
            passed.push(name.clone());
        } else {
            withheld += 1;
            if is_secret_name(name) && value.len() >= MIN_MASKED_VALUE {
                secret_values.push(value.clone());
            }
        }
    }
    let path_value = path
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    vars.push(("PATH".to_owned(), path_value));
    for (k, v) in FIXED {
        vars.retain(|(name, _)| name != k);
        vars.push(((*k).to_owned(), (*v).to_owned()));
    }
    vars.sort();
    passed.sort();
    secret_values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    secret_values.dedup();
    BuiltEnvironment {
        profile,
        vars,
        passed,
        withheld,
        path,
        secret_values,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> Vec<(String, String)> {
        [
            ("PATH", "/usr/bin:.::relative/bin:/tmp"),
            ("HOME", "/home/u"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("CARGO_HOME", "/home/u/.cargo"),
            ("GITHUB_TOKEN", "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000"),
            ("AWS_SECRET_ACCESS_KEY", "FAKEfakeFAKEfakeFAKEfake"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("BASH_ENV", "/tmp/evil.sh"),
            ("NODE_OPTIONS", "--require /tmp/evil.js"),
            ("GIT_DIR", "/elsewhere/.git"),
            ("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent"),
            ("RANDOM_THING", "x"),
            ("TERM", "xterm-256color"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
    }

    #[test]
    fn credentials_and_injection_are_withheld() {
        let root = Path::new("/nonexistent-project");
        let dev = build(&caller(), Profile::Development, &[], root);
        let names: Vec<&str> = dev.vars.iter().map(|(k, _)| k.as_str()).collect();
        for absent in [
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "LD_PRELOAD",
            "BASH_ENV",
            "NODE_OPTIONS",
            "GIT_DIR",
            "RANDOM_THING",
        ] {
            assert!(!names.contains(&absent), "{absent}");
        }
        for present in [
            "HOME",
            "LANG",
            "LC_ALL",
            "CARGO_HOME",
            "SSH_AUTH_SOCK",
            "PATH",
        ] {
            assert!(names.contains(&present), "{present}");
        }
        assert!(dev.vars.contains(&("TERM".to_owned(), "dumb".to_owned())));
        assert!(dev
            .vars
            .contains(&("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned())));
        assert_eq!(dev.secret_values().len(), 2);
        let minimal = build(&caller(), Profile::Minimal, &[], root);
        assert!(!minimal
            .vars
            .iter()
            .any(|(k, _)| k == "CARGO_HOME" || k == "SSH_AUTH_SOCK"));
        // Policy additions cannot reintroduce credentials.
        let extra = build(
            &caller(),
            Profile::Development,
            &["RANDOM_THING".to_owned(), "GITHUB_TOKEN".to_owned()],
            root,
        );
        assert!(extra.vars.iter().any(|(k, _)| k == "RANDOM_THING"));
        assert!(!extra.vars.iter().any(|(k, _)| k == "GITHUB_TOKEN"));
    }

    #[test]
    fn path_keeps_only_trusted_directories() {
        let dir = tempfile::tempdir().unwrap();
        let project = std::fs::canonicalize(dir.path()).unwrap();
        let inside = project.join("node_modules/.bin");
        std::fs::create_dir_all(&inside).unwrap();
        let path = format!("{}:.::relative:/tmp:/usr/bin", inside.display());
        let trusted = trusted_path(Some(&path), &project);
        assert!(!trusted.iter().any(|p| p.starts_with(&project)));
        assert!(!trusted.iter().any(|p| p == Path::new("/tmp")));
        assert!(trusted.iter().any(|p| p.ends_with("bin")));
        assert!(trusted.iter().all(|p| p.is_absolute()));
    }
}
