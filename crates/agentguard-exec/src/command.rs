//! Terminal operation categories for display, records and audit.
//!
//! The category describes a command to a human; it does not decide anything. Decisions come
//! from the policy engine, which reasons about the engine's [`CommandClass`], resources and
//! risk. The category is derived from that same analysis, so the two cannot disagree about
//! what a command is.

use agentguard_engine::{CommandAnalysis, CommandClass};
use serde::Serialize;

/// What kind of terminal operation a command is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalCategory {
    /// Reads or inspects, including Git inspection.
    ReadOnly,
    /// Compiles or bundles.
    Build,
    /// Runs tests.
    Test,
    /// Formats or lints.
    Formatting,
    /// Adds, removes, updates or publishes dependencies and packages.
    PackageManagement,
    /// Creates, changes or moves files, including local Git changes.
    FilesystemModification,
    /// Talks to another system, including Git remotes.
    Network,
    /// Starts, stops or signals processes and containers.
    ProcessManagement,
    /// Runs with elevated privileges.
    PrivilegeEscalation,
    /// Changes the operating system or infrastructure configuration.
    SystemConfiguration,
    /// Destroys data or history.
    Destructive,
    /// Touches credentials, security settings or AgentGuard's own controls.
    SecurityConfiguration,
    /// Not recognised.
    Unknown,
}

const TEST_WORDS: &[&str] = &[
    "test", "tests", "t", "jest", "vitest", "mocha", "ava", "pytest", "tox", "nox", "nextest",
    "rspec", "phpunit", "coverage", "bench",
];
const FORMAT_WORDS: &[&str] = &[
    "fmt",
    "format",
    "lint",
    "clippy",
    "prettier",
    "eslint",
    "black",
    "ruff",
    "flake8",
    "isort",
    "rustfmt",
    "gofmt",
    "goimports",
    "golangci-lint",
    "clang-format",
    "shellcheck",
    "shfmt",
    "stylelint",
    "rubocop",
    "ktlint",
    "swiftlint",
    "hadolint",
    "markdownlint",
    "yamllint",
    "biome",
    "oxlint",
    "vet",
    "mypy",
    "pylint",
    "typecheck",
    "type-check",
    "tsc",
    "check",
];

/// The category of an analysed command.
#[must_use]
pub fn categorize(analysis: &CommandAnalysis, argv: &[String]) -> TerminalCategory {
    use CommandClass as C;
    use TerminalCategory as T;
    let words: Vec<&str> = std::iter::once(analysis.executable.as_deref().unwrap_or_default())
        .chain(analysis.subcommand.as_deref())
        .chain(argv.iter().skip(1).take(3).map(String::as_str))
        .collect();
    let has = |list: &[&str]| words.iter().any(|w| list.contains(w));
    match analysis.class {
        C::ReadOnly | C::VcsRead | C::InfraRead => T::ReadOnly,
        C::DevTool if has(TEST_WORDS) => T::Test,
        C::DevTool if has(FORMAT_WORDS) => T::Formatting,
        C::DevTool => T::Build,
        C::VcsLocal | C::VcsWrite | C::FileWrite | C::PermissionChange => T::FilesystemModification,
        C::PackageChange | C::PackagePublish => T::PackageManagement,
        C::VcsRemote | C::Network => T::Network,
        C::Container => T::ProcessManagement,
        C::Privileged if analysis.privileged => T::PrivilegeEscalation,
        C::Privileged
            if matches!(
                analysis.executable.as_deref(),
                Some("kill" | "killall" | "pkill")
            ) =>
        {
            T::ProcessManagement
        }
        C::Privileged | C::InfraChange => T::SystemConfiguration,
        C::Destructive => T::Destructive,
        C::SecretAccess | C::Bypass => T::SecurityConfiguration,
        C::Interpreter | C::Unknown => T::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_engine::analyze_command;

    fn cat(cmd: &str) -> TerminalCategory {
        let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
        categorize(&analyze_command(cmd), &argv)
    }

    #[test]
    fn categories() {
        use TerminalCategory as T;
        for (cmd, want) in [
            ("npm test", T::Test),
            ("cargo test", T::Test),
            ("pnpm test", T::Test),
            ("npm run build", T::Build),
            ("cargo check", T::Formatting),
            ("cargo fmt", T::Formatting),
            ("npm run lint", T::Formatting),
            ("git status", T::ReadOnly),
            ("git commit -m x", T::FilesystemModification),
            ("git push origin main", T::Network),
            ("npm install left-pad", T::PackageManagement),
            ("rm -rf build", T::Destructive),
            ("pkill node", T::ProcessManagement),
            ("systemctl restart nginx", T::SystemConfiguration),
            ("sudo ls", T::PrivilegeEscalation),
            ("printenv", T::SecurityConfiguration),
            ("docker run x", T::ProcessManagement),
            ("frobnicate", T::Unknown),
        ] {
            assert_eq!(cat(cmd), want, "{cmd}");
        }
    }
}
