//! Enforcement coverage: for each provider, which tools and paths are enforced before execution,
//! observed after it, not covered, or bypassable. The statements follow the providers'
//! documentation and AgentGuard's own matchers. No tool is listed as protected unless its
//! payload is parsed and every outcome of a failed evaluation is a block.

use serde::Serialize;

use crate::provider::Provider;

/// Coverage of one tool or path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Evaluated before execution; blocked on deny, approval required or failure.
    Protected,
    /// Seen after execution; recorded only.
    Observed,
    /// Not seen by AgentGuard.
    Unsupported,
    /// Seen in some cases, but a documented path avoids AgentGuard.
    Bypassable,
}

/// One coverage row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Row {
    /// Tool, event or path.
    pub subject: &'static str,
    /// Coverage.
    pub status: Status,
    /// Detail.
    pub detail: &'static str,
}

const fn row(subject: &'static str, status: Status, detail: &'static str) -> Row {
    Row {
        subject,
        status,
        detail,
    }
}

const CLAUDE: &[Row] = &[
    row("Bash, PowerShell", Status::Protected, "PreToolUse: the command text is classified and evaluated; a single Git command is bound to the repository state. Child processes the command starts are not seen individually."),
    row("Read", Status::Protected, "PreToolUse: sensitive-file and secret policy (Phase 6)."),
    row("Write, Edit", Status::Protected, "PreToolUse: target path policy and secret inspection of the written text; approvals are bound to the exact content."),
    row("MultiEdit, NotebookEdit", Status::Protected, "Matched for releases that provide them; handled as writes; an unexpected payload is blocked."),
    row("Glob, Grep", Status::Protected, "PreToolUse: evaluated as directory traversal of the searched path."),
    row("WebFetch", Status::Protected, "PreToolUse: evaluated as a network request to the URL's host."),
    row("WebSearch", Status::Protected, "PreToolUse: evaluated conservatively as a custom tool (approval by default); the query is not inspected."),
    row("MCP tools (mcp__*)", Status::Protected, "PreToolUse: evaluated conservatively as custom tools (approval by default); arguments are bound to approvals but not interpreted."),
    row("Agent (subagents)", Status::Unsupported, "Not matched; each subagent tool call fires PreToolUse itself and is evaluated."),
    row("Other built-in tools (TodoWrite, task and skill tools, ...)", Status::Unsupported, "Not matched: they do not run commands or touch files directly. A future tool is not covered until it is added."),
    row("PostToolUse, PostToolUseFailure", Status::Observed, "Audit only; the tool has already run."),
    row("SessionStart", Status::Observed, "Informational; adds context telling the agent how approvals work."),
    row("Hook failure (crash, timeout, missing engine)", Status::Bypassable, "Blocked when Claude Code honours `onFailure: \"block\"` (v2.1.295 or later); older releases continue the tool call."),
    row("Hooks held back", Status::Bypassable, "Claude Code holds back settings-file hooks in an interactive session until the workspace trust dialog is accepted."),
    row("Commands the developer runs directly", Status::Unsupported, "Not routed through Claude Code."),
];

const CODEX: &[Row] = &[
    row("Bash (shell and unified exec)", Status::Protected, "PreToolUse: the command text is classified and evaluated; a single Git command is bound to the repository state."),
    row("apply_patch (Edit, Write)", Status::Protected, "PreToolUse: the patch is parsed into per-file writes, moves and deletions; an unreadable patch is blocked."),
    row("MCP tools (mcp__*)", Status::Protected, "PreToolUse: evaluated conservatively as custom tools; arguments bound, not interpreted."),
    row("Other local function tools (update_plan, spawn_agent, ...)", Status::Unsupported, "Not matched."),
    row("Hosted tools (WebSearch)", Status::Unsupported, "Codex does not run PreToolUse or PostToolUse for hosted tools."),
    row("write_stdin", Status::Bypassable, "Input written to an already running process does not re-run PreToolUse."),
    row("Specialized tool paths", Status::Bypassable, "Codex documents that some tool paths can opt out of the default hook path."),
    row("PostToolUse", Status::Observed, "Audit only; cannot undo side effects."),
    row("SessionStart", Status::Observed, "Informational; adds context."),
    row("Hook failure", Status::Bypassable, "The command exits 2 (a block) when the engine cannot start or crashes; Codex does not document what a timed-out command hook does."),
    row("Hook trust", Status::Bypassable, "Codex skips new or changed hooks until they are reviewed and trusted with /hooks."),
    row("Commands the developer runs directly", Status::Unsupported, "Not routed through Codex."),
];

/// Coverage rows for `provider`.
#[must_use]
pub fn rows(provider: Provider) -> &'static [Row] {
    match provider {
        Provider::Claude => CLAUDE,
        Provider::Codex => CODEX,
    }
}

/// Statement attached to every coverage report.
pub const NOT_COMPLETE: &str = "Hook coverage is not complete AI-agent protection. Only the tools listed as protected are evaluated before they run, only in projects registered with AI Defender, and only while the provider runs the hooks. Codex itself describes its hooks as a guardrail, not a complete enforcement boundary.";
