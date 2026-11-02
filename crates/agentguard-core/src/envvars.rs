//! Rules for environment variable names, shared by trusted configuration (what a policy may
//! pass through) and the managed executor (what a process inherits).
//!
//! Two kinds of name are never passed to a managed process, whatever a profile or policy says:
//! names that look like they hold credentials, and names that make a program load or run code
//! the command line does not show (`LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, exported shell
//! functions, Git's command and repository overrides). Matching is by name only; values are
//! never inspected here.

/// Name fragments that suggest a credential, matched case-insensitively.
const SECRET_FRAGMENTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "PRIVATE",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "AUTH",
    "COOKIE",
    "SESSION",
    "_KEY",
    "SIGNING",
    "WEBHOOK",
    "DSN",
];

/// Exact names (case-insensitive) that change which code runs.
const INJECTION_NAMES: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "PS4",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "DOTNET_STARTUP_HOOKS",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "NPM_CONFIG_SCRIPT_SHELL",
    "NPM_CONFIG_NODE_OPTIONS",
];

/// Name prefixes (case-insensitive) that change which code runs or which repository and
/// configuration a tool uses.
const INJECTION_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "BASH_FUNC_",
    "GIT_",
    "GCONV_",
    "MALLOC_",
    "LOCPATH",
];

/// Whether `name` is a syntactically valid variable name (`[A-Za-z_][A-Za-z0-9_]*`, at most
/// 128 characters).
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `name` looks like it holds a credential.
#[must_use]
pub fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_FRAGMENTS.iter().any(|f| upper.contains(f))
}

/// Whether `name` changes which code a program runs or which repository it operates on.
#[must_use]
pub fn is_injection_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    INJECTION_NAMES.contains(&upper.as_str())
        || INJECTION_PREFIXES.iter().any(|p| upper.starts_with(p))
}

/// Whether `name` may ever reach a managed process.
#[must_use]
pub fn may_pass(name: &str) -> bool {
    is_valid_name(name) && !is_secret_name(name) && !is_injection_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_and_injection_are_never_passed() {
        for name in [
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "OPENAI_API_KEY",
            "NPM_TOKEN",
            "DATABASE_PASSWORD",
            "my_private_key",
            "SENTRY_DSN",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "BASH_FUNC_git%%",
            "NODE_OPTIONS",
            "GIT_SSH_COMMAND",
            "GIT_DIR",
            "git_config_global",
            "PYTHONPATH",
            "1BAD",
            "",
        ] {
            assert!(!may_pass(name), "{name}");
        }
        for name in ["PATH", "HOME", "LANG", "LC_ALL", "CARGO_HOME", "TERM", "CI"] {
            assert!(may_pass(name), "{name}");
        }
    }
}
