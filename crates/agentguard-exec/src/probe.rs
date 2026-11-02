//! Read-only probes of installed programs (provider versions for compatibility checks).
//!
//! The program is resolved through the trusted search path and run with `--version`, no
//! inherited environment beyond `PATH` and `HOME`, standard input closed, a 5-second limit and
//! 4 KiB of output.

use std::path::Path;
use std::time::Duration;

use crate::environment::trusted_path;
use crate::process::{run, Spawn, Termination};
use crate::validation::resolve;

/// The first line `program --version` prints, if the program is installed and answers.
#[must_use]
pub fn version(program: &str, caller_env: &[(String, String)]) -> Option<String> {
    let var = |n: &str| {
        caller_env
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
    };
    let path = trusted_path(var("PATH").as_deref(), Path::new("/nonexistent-project"));
    let exe = resolve(program, Path::new("/"), &path).ok()?;
    let mut env = vec![(
        "PATH".to_owned(),
        path.iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":"),
    )];
    if let Some(home) = var("HOME") {
        env.push(("HOME".to_owned(), home));
    }
    let args = vec!["--version".to_owned()];
    let r = run(&Spawn {
        program: &exe.path,
        arg0: program,
        args: &args,
        cwd: Path::new("/"),
        env: &env,
        timeout: Duration::from_secs(5),
        capture_limit: 4096,
        signals: None,
    });
    match r.termination {
        Termination::Exited { code: 0 } => String::from_utf8_lossy(&r.stdout.bytes)
            .lines()
            .next()
            .map(|l| l.trim().chars().take(128).collect()),
        _ => None,
    }
}

/// Parse `major.minor.patch` from the start of a version line (`2.1.300 (Claude Code)`).
#[must_use]
pub fn semver(line: &str) -> Option<(u64, u64, u64)> {
    let token = line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut parts = token.trim_start_matches('v').split('.').map(|p| {
        p.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u64>()
            .ok()
    });
    Some((
        parts.next()??,
        parts.next()??,
        parts.next().flatten().unwrap_or(0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(semver("2.1.300 (Claude Code)"), Some((2, 1, 300)));
        assert_eq!(semver("codex-cli 0.50.1"), Some((0, 50, 1)));
        assert_eq!(semver("nothing"), None);
        assert!(version("definitely-not-installed-xyz", &[]).is_none());
    }
}
