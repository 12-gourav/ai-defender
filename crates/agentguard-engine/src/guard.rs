//! Hard guards: rules evaluated before policy that no policy can override.
//!
//! - Unknown operations are denied.
//! - Changes to trusted authorization state are denied: AgentGuard's own state and
//!   configuration directories, the project policy file, and the agent hook settings that wire
//!   AgentGuard in. An agent able to edit any of these could switch the engine off or rewrite
//!   its rules.
//! - Agent-side attempts to run AgentGuard's privileged commands (approve, reject, approval
//!   management, policy changes, uninstall) or the engine binary itself are denied.
//!
//! The filesystem rules are exact for typed filesystem actions. For terminal commands they are a
//! best-effort text match that a determined agent can evade (`cp` via a variable, an interpreter
//! one-liner). That residual is why terminal commands are never allowed without a policy rule or
//! approval; see the known limitations.

use agentguard_audit::TamperKind;
use agentguard_core::action::{ConfigOp, FileOp};
use agentguard_core::{Action, NormalizedPath, SecurityContext};

/// Paths inside every project that hold trusted state. The hook-settings entries are the
/// initial list; each agent integration verifies and extends it for its vendor.
pub const PROJECT_PROTECTED_PATHS: &[&str] = &[
    ".agent-security.yml",
    ".agentguard",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".cursor/hooks.json",
];

/// Names of the command-line interface: `ai-defender`, and `agentguard` (the earlier name,
/// kept as an alias). Both are guarded identically.
pub const CLI_PROGRAMS: &[&str] = &["ai-defender", "agentguard"];

/// AgentGuard subcommands an agent must never run.
const PRIVILEGED_SUBCOMMANDS: &[&str] = &[
    "approve",
    "approvals",
    "reject",
    "grant",
    "policy",
    "allow",
    "disable",
    "uninstall",
    "trust",
    "register",
    "revoke",
    "keys",
    "rotate",
    "recover",
    "quarantine",
    "init",
    "project",
    "projects",
    "integrations",
];

/// A guard verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardViolation {
    /// The operation is not recognised.
    UnknownOperation,
    /// The action would change trusted state.
    TrustedState,
    /// The action would run a privileged AgentGuard command.
    SelfApproval,
}

impl GuardViolation {
    /// Stable rule identifier.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            GuardViolation::UnknownOperation => "guard.unknown-operation",
            GuardViolation::TrustedState => "guard.trusted-state",
            GuardViolation::SelfApproval => "guard.self-approval",
        }
    }

    /// User-facing reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            GuardViolation::UnknownOperation => {
                "the operation is not recognised; unknown operations are always denied"
            }
            GuardViolation::TrustedState => {
                "the action would modify AI Defender's trusted state (policy, approvals, audit or hook settings)"
            }
            GuardViolation::SelfApproval => {
                "agents cannot run AI Defender's approval or configuration commands"
            }
        }
    }

    /// The tamper kind to record, if this violation is tampering.
    #[must_use]
    pub const fn tamper_kind(self) -> Option<TamperKind> {
        match self {
            GuardViolation::UnknownOperation => None,
            GuardViolation::TrustedState => Some(TamperKind::TrustedStateModification),
            GuardViolation::SelfApproval => Some(TamperKind::SelfApprovalAttempt),
        }
    }
}

/// The trusted-state guard.
#[derive(Debug, Clone, Default)]
pub struct TrustedStateGuard {
    protected_roots: Vec<NormalizedPath>,
    home: Option<NormalizedPath>,
}

impl TrustedStateGuard {
    /// A guard protecting [`PROJECT_PROTECTED_PATHS`] in every project plus `protected_roots`
    /// (AgentGuard's state and configuration directories, user-level agent settings files).
    #[must_use]
    pub const fn new(protected_roots: Vec<NormalizedPath>) -> Self {
        Self {
            protected_roots,
            home: None,
        }
    }

    /// Also match protected paths under `home` when a terminal command writes them as `~/…`,
    /// `$HOME/…` or `${HOME}/…`.
    #[must_use]
    pub fn with_home(mut self, home: NormalizedPath) -> Self {
        self.home = Some(home);
        self
    }

    /// The protected roots beyond the per-project paths.
    #[must_use]
    pub fn protected_roots(&self) -> &[NormalizedPath] {
        &self.protected_roots
    }

    /// Every protected path for the context's project.
    fn protected(&self, ctx: &SecurityContext) -> Vec<NormalizedPath> {
        let root = ctx.project().root();
        PROJECT_PROTECTED_PATHS
            .iter()
            .filter_map(|rel| root.join(rel).ok())
            .chain(self.protected_roots.iter().cloned())
            .collect()
    }

    /// Check `action`. Returns the first violation found.
    #[must_use]
    pub fn check(&self, ctx: &SecurityContext, action: &Action) -> Option<GuardViolation> {
        if action.is_unknown_operation() {
            return Some(GuardViolation::UnknownOperation);
        }
        let protected = self.protected(ctx);
        match action {
            Action::Filesystem(a)
                if !matches!(a.op, FileOp::Read | FileOp::List | FileOp::Traverse) =>
            {
                action
                    .paths()
                    .into_iter()
                    .any(|p| protected.iter().any(|guarded| p.is_within(guarded)))
                    .then_some(GuardViolation::TrustedState)
            }
            Action::Configuration(c) if !matches!(c.op, ConfigOp::Read) => {
                (c.scope.is_trusted_state()
                    || action
                        .paths()
                        .into_iter()
                        .any(|p| protected.iter().any(|guarded| p.is_within(guarded))))
                .then_some(GuardViolation::TrustedState)
            }
            Action::Terminal(t) => {
                let command = t.command.as_str();
                if invokes_privileged_agentguard(command) {
                    return Some(GuardViolation::SelfApproval);
                }
                let command = comparable(command);
                let root = comparable(ctx.project().root().as_str());
                let home = self.home.as_ref().map(|h| comparable(h.as_str()));
                let mentions = |guarded: &NormalizedPath| {
                    let full = comparable(guarded.as_str());
                    let relative = full
                        .strip_prefix(root.as_str())
                        .map(|r| r.trim_start_matches('/'))
                        .filter(|r| !r.is_empty());
                    let under_home = home
                        .as_deref()
                        .and_then(|h| full.strip_prefix(h).filter(|r| r.starts_with('/')));
                    command.contains(&full)
                        || git_bash_form(&full).is_some_and(|f| command.contains(&f))
                        || relative.is_some_and(|r| command.contains(r))
                        || under_home.is_some_and(|r| {
                            HOME_PREFIXES
                                .iter()
                                .any(|prefix| command.contains(&format!("{prefix}{r}")))
                        })
                };
                protected
                    .iter()
                    .any(mentions)
                    .then_some(GuardViolation::TrustedState)
            }
            _ => None,
        }
    }
}

/// How a command can spell the home directory. On Windows, compared in lower case.
const HOME_PREFIXES: &[&str] = if cfg!(windows) {
    &[
        "~",
        "$home",
        "${home}",
        "%userprofile%",
        "$env:userprofile",
        "${env:userprofile}",
    ]
} else {
    &["~", "$HOME", "${HOME}"]
};

/// Text in the form paths are compared in: itself, or on Windows lower case with `/`
/// separators, since `C:\Dir`, `c:/dir` and `C:/DIR` all name the same directory.
fn comparable(text: &str) -> String {
    if cfg!(windows) {
        text.to_lowercase().replace('\\', "/")
    } else {
        text.to_owned()
    }
}

/// Git Bash's spelling of a Windows path: `c:/dir` is `/c/dir`.
fn git_bash_form(comparable_path: &str) -> Option<String> {
    if !cfg!(windows) {
        return None;
    }
    let mut chars = comparable_path.chars();
    match (chars.next(), chars.next()) {
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic() => {
            Some(format!("/{drive}{}", chars.as_str()))
        }
        _ => None,
    }
}

/// The program a command word names: its last path component; on Windows in lower case and
/// without an executable or script extension (`C:\x\AGENTGUARD-ENGINE.EXE`).
fn program_name(word: &str) -> String {
    let last = word
        .rsplit(|c| c == '/' || (cfg!(windows) && c == '\\'))
        .next()
        .unwrap_or(word);
    if !cfg!(windows) {
        return last.to_owned();
    }
    let lower = last.to_ascii_lowercase();
    [".exe", ".com", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|ext| lower.strip_suffix(ext))
        .unwrap_or(&lower)
        .to_owned()
}

fn invokes_privileged_agentguard(command: &str) -> bool {
    let words: Vec<&str> = command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '`'))
        .filter(|w| !w.is_empty())
        .collect();
    // The engine binary speaks the management protocol directly; an agent never needs it.
    words.iter().any(|w| program_name(w) == "agentguard-engine")
        || words.windows(2).any(|pair| match pair {
            [p, sub] => {
                CLI_PROGRAMS.contains(&program_name(p).as_str())
                    && PRIVILEGED_SUBCOMMANDS.contains(sub)
            }
            _ => false,
        })
}

// Unix paths throughout; the Windows path rules are tested in agentguard-core.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use agentguard_core::action::{FilesystemAction, TerminalAction};
    use agentguard_core::{AgentIdentity, AgentKind, BoundedText, PolicyVersion, ProjectIdentity};

    fn ctx() -> SecurityContext {
        SecurityContext::new(
            AgentIdentity::new(AgentKind::ClaudeCode),
            ProjectIdentity::new(NormalizedPath::new("/p").unwrap(), None),
            None,
            PolicyVersion::compute(b"x"),
            NormalizedPath::new("/p").unwrap(),
        )
        .unwrap()
    }

    fn guard() -> TrustedStateGuard {
        TrustedStateGuard::new(vec![
            NormalizedPath::new("/home/u/.local/state/agentguard").unwrap()
        ])
    }

    fn fs(op: &str, path: &str) -> Action {
        Action::Filesystem(FilesystemAction {
            op: FileOp::parse(op).unwrap(),
            path: NormalizedPath::new(path).unwrap(),
            destination: None,
            remote: None,
            content: None,
        })
    }

    fn term(c: &str) -> Action {
        Action::Terminal(TerminalAction {
            command: BoundedText::new(c).unwrap(),
        })
    }

    #[test]
    fn filesystem_writes_to_trusted_state_are_denied() {
        let g = guard();
        for path in [
            "/p/.agent-security.yml",
            "/p/.agentguard/approvals.db",
            "/p/.claude/settings.json",
            "/home/u/.local/state/agentguard/audit.jsonl",
        ] {
            assert_eq!(
                g.check(&ctx(), &fs("write", path)),
                Some(GuardViolation::TrustedState),
                "{path}"
            );
            assert_eq!(
                g.check(&ctx(), &fs("delete", path)),
                Some(GuardViolation::TrustedState),
                "{path}"
            );
            assert_eq!(g.check(&ctx(), &fs("read", path)), None, "{path}");
        }
        assert_eq!(g.check(&ctx(), &fs("write", "/p/src/main.rs")), None);
        assert_eq!(
            g.check(&ctx(), &fs("write", "/p/.claude/commands/x.md")),
            None
        );
    }

    #[test]
    fn rename_destination_is_checked() {
        let a = Action::Filesystem(FilesystemAction {
            op: FileOp::Rename,
            path: NormalizedPath::new("/p/evil.yml").unwrap(),
            destination: Some(NormalizedPath::new("/p/.agent-security.yml").unwrap()),
            remote: None,
            content: None,
        });
        assert_eq!(
            guard().check(&ctx(), &a),
            Some(GuardViolation::TrustedState)
        );
    }

    #[test]
    fn terminal_best_effort() {
        let g = guard();
        assert_eq!(
            g.check(&ctx(), &term("echo x > .agent-security.yml")),
            Some(GuardViolation::TrustedState)
        );
        assert_eq!(
            g.check(&ctx(), &term("rm -rf /home/u/.local/state/agentguard")),
            Some(GuardViolation::TrustedState)
        );
        assert_eq!(
            g.check(&ctx(), &term("agentguard approve 1234")),
            Some(GuardViolation::SelfApproval)
        );
        assert_eq!(
            g.check(
                &ctx(),
                &term("true && /usr/local/bin/agentguard policy set x")
            ),
            Some(GuardViolation::SelfApproval)
        );
        assert_eq!(
            g.check(&ctx(), &term("agentguard keys rotate")),
            Some(GuardViolation::SelfApproval)
        );
        assert_eq!(
            g.check(&ctx(), &term("agentguard init")),
            Some(GuardViolation::SelfApproval)
        );
        for command in [
            "agentguard project trust",
            "agentguard project revoke --yes",
            "agentguard approve 3f2a9c1e",
            "agentguard reject 3f2a9c1e",
            "agentguard approvals cancel 3f2a9c1e",
            "echo '{}' | ~/.npm/bin/agentguard-engine",
            "agentguard-engine --agent claude < req.json",
            "ai-defender approve 3f2a9c1e",
            "npx ai-defender project trust",
            "/usr/local/bin/ai-defender integrations x && true",
            "ai-defender policy set x",
        ] {
            assert_eq!(
                g.check(&ctx(), &term(command)),
                Some(GuardViolation::SelfApproval),
                "{command}"
            );
        }
        assert_eq!(g.check(&ctx(), &term("agentguard status")), None);
        let home =
            TrustedStateGuard::new(vec![
                NormalizedPath::new("/home/u/.claude/settings.json").unwrap()
            ])
            .with_home(NormalizedPath::new("/home/u").unwrap());
        for command in [
            "rm ~/.claude/settings.json",
            "echo '{}' > $HOME/.claude/settings.json",
            "cp x ${HOME}/.claude/settings.json",
        ] {
            assert_eq!(
                home.check(&ctx(), &term(command)),
                Some(GuardViolation::TrustedState),
                "{command}"
            );
        }
        assert_eq!(g.check(&ctx(), &term("cargo test")), None);
    }

    #[test]
    fn unknown_operation_is_a_violation() {
        assert_eq!(
            guard().check(&ctx(), &fs("shred", "/p/a")),
            Some(GuardViolation::UnknownOperation)
        );
    }
}
