//! Providers, the hook events AgentGuard registers for each, and what each event can do.
//!
//! Sources, retrieved 2026-10-31:
//! - Claude Code: <https://code.claude.com/docs/en/hooks> (hooks reference; `onFailure` needs
//!   Claude Code v2.1.295 or later).
//! - OpenAI Codex: <https://developers.openai.com/codex/hooks>, which redirects (308) to
//!   <https://learn.chatgpt.com/docs/hooks> (hooks reference, release behaviour).
//!
//! Only events documented there are used. An event's capability is what the provider's
//! documentation says it can do, not what AgentGuard would like it to do.

use agentguard_core::AgentKind;
use serde::Serialize;

/// Version of AgentGuard's adapters (bumped whenever payload parsing or responses change).
pub const ADAPTER_VERSION: &str = "agentguard.hooks.v1";

/// Date the provider documentation was last verified against these adapters.
pub const DOCS_VERIFIED: &str = "2026-10-31";

/// A supported provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Anthropic Claude Code.
    Claude,
    /// OpenAI Codex.
    Codex,
}

impl Provider {
    /// Every provider.
    pub const ALL: [Provider; 2] = [Provider::Claude, Provider::Codex];

    /// Parse the command-line name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "claude" => Some(Provider::Claude),
            "codex" => Some(Provider::Codex),
            _ => None,
        }
    }

    /// Command-line name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
        }
    }

    /// Display name.
    #[must_use]
    pub const fn display(self) -> &'static str {
        match self {
            Provider::Claude => "Claude Code",
            Provider::Codex => "OpenAI Codex",
        }
    }

    /// The agent identity hooks for this provider act for. It comes from the installed hook
    /// command line (`agentguard-engine hook <provider> <event>`), never from a payload.
    #[must_use]
    pub const fn agent(self) -> AgentKind {
        match self {
            Provider::Claude => AgentKind::ClaudeCode,
            Provider::Codex => AgentKind::Codex,
        }
    }

    /// Documentation the adapter was built against.
    #[must_use]
    pub const fn documentation(self) -> &'static str {
        match self {
            Provider::Claude => "https://code.claude.com/docs/en/hooks",
            Provider::Codex => {
                "https://developers.openai.com/codex/hooks (https://learn.chatgpt.com/docs/hooks)"
            }
        }
    }

    /// Events AgentGuard registers, with the tool matcher where the event takes one.
    #[must_use]
    pub fn events(self) -> &'static [EventSpec] {
        match self {
            Provider::Claude => CLAUDE_EVENTS,
            Provider::Codex => CODEX_EVENTS,
        }
    }

    /// The registered event named `name`.
    #[must_use]
    pub fn event(self, name: &str) -> Option<&'static EventSpec> {
        self.events().iter().find(|e| e.name == name)
    }
}

/// What an event can do, according to the provider's documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Runs before a tool call and can block it.
    PreExecutionEnforcement,
    /// Runs after a tool call; cannot undo it. Used for audit only.
    PostExecutionAudit,
    /// Lifecycle notification; cannot block anything.
    Informational,
}

/// A registered event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventSpec {
    /// Provider event name, exactly as documented.
    pub name: &'static str,
    /// Tool matcher (`None` for events without one).
    pub matcher: Option<&'static str>,
    /// What it can do.
    pub capability: Capability,
    /// Timeout written into the configuration, in seconds.
    pub timeout_seconds: u64,
}

/// Claude Code tools AgentGuard intercepts before execution. `MultiEdit` and `NotebookEdit`
/// are matched defensively for releases that provide them; their payloads are handled
/// conservatively. Anchored: Claude Code treats a matcher with regex characters as an unanchored
/// regex, so `Write` alone would also match `TodoWrite`.
pub const CLAUDE_PRE_TOOL_MATCHER: &str =
    "^(Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*)$";

/// Codex tools AgentGuard intercepts before execution (`Edit` and `Write` are documented
/// aliases of `apply_patch`; unified exec matches as `Bash`).
pub const CODEX_PRE_TOOL_MATCHER: &str = "^(Bash|apply_patch|mcp__.*)$";

const CLAUDE_EVENTS: &[EventSpec] = &[
    EventSpec {
        name: "PreToolUse",
        matcher: Some(CLAUDE_PRE_TOOL_MATCHER),
        capability: Capability::PreExecutionEnforcement,
        timeout_seconds: 60,
    },
    EventSpec {
        name: "PostToolUse",
        matcher: Some(CLAUDE_PRE_TOOL_MATCHER),
        capability: Capability::PostExecutionAudit,
        timeout_seconds: 10,
    },
    EventSpec {
        name: "PostToolUseFailure",
        matcher: Some(CLAUDE_PRE_TOOL_MATCHER),
        capability: Capability::PostExecutionAudit,
        timeout_seconds: 10,
    },
    EventSpec {
        name: "SessionStart",
        matcher: None,
        capability: Capability::Informational,
        timeout_seconds: 10,
    },
];

const CODEX_EVENTS: &[EventSpec] = &[
    EventSpec {
        name: "PreToolUse",
        matcher: Some(CODEX_PRE_TOOL_MATCHER),
        capability: Capability::PreExecutionEnforcement,
        timeout_seconds: 60,
    },
    EventSpec {
        name: "PostToolUse",
        matcher: Some(CODEX_PRE_TOOL_MATCHER),
        capability: Capability::PostExecutionAudit,
        timeout_seconds: 10,
    },
    EventSpec {
        name: "SessionStart",
        matcher: None,
        capability: Capability::Informational,
        timeout_seconds: 10,
    },
];
