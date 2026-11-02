# Agent integration research (2026-11-02)

Facts from vendor documentation, used to decide which agents AI Defender can govern and at what
coverage level. Re-verify before implementing an adapter: these products change monthly.

| Agent | Pre-execution blocking | Shell | File read | File write | On hook failure | Config | Planned coverage |
|---|---|---|---|---|---|---|---|
| Claude Code | yes | yes | yes | yes | open; closed with `onFailure: "block"` (2.1.295+) | `~/.claude/settings.json`, managed settings | existing adapter; FULL within its tool scope on 2.1.295+, PARTIAL before |
| Codex CLI | yes (deny only; `ask` unsupported) | yes | via shell only | yes (`apply_patch`) | open; no fail-closed setting | `~/.codex/hooks.json`, `requirements.toml` | existing adapter; PARTIAL |
| Cursor (IDE) | yes | `beforeShellExecution` | `beforeReadFile` | `preToolUse` on Write (unverified); `afterFileEdit` observes only | open; closed with `failClosed: true` | `~/.cursor/hooks.json`, `/etc/cursor/hooks.json` | adapter candidate; PARTIAL until write blocking is proven |
| Cursor CLI | inconsistent (forum reports: no hooks on Linux) | | | | | same files | UNSUPPORTED until verified |
| Google Antigravity (app, IDE, CLI) | yes (`decision: deny`) | `run_command` | `view_file` | `write_to_file`, `replace_file_content` | not documented | `~/.gemini/config/hooks.json`, `.agents/hooks.json` | adapter candidate; PARTIAL until failure behaviour is tested |
| Gemini CLI | yes | yes | yes | yes | open | `~/.gemini/settings.json` | superseded by Antigravity CLI for most users; not planned |
| Perplexity | no third-party interception API; not a coding agent | | | | | | UNSUPPORTED |
| GitHub Copilot CLI | yes | yes | yes | yes | closed on error, open on timeout | `~/.copilot/hooks/`, `.github/hooks/` | future adapter |
| Windsurf / Devin Desktop | yes | yes | likely | likely | open | `.devin/hooks.v1.json` (legacy `.windsurf/hooks.json`) | future; product identity unclear |

Consequences for every adapter:
- All of these fail open by default. An adapter must set the provider's fail-closed option where it
  exists and report PARTIAL where it does not.
- The engine must answer well inside each provider's timeout (Antigravity: 30 s; Copilot: 30 s).
- A hook `allow` never grants more than the provider's own deny rules; AI Defender only ever adds
  denials and approvals.

## Sources
- Claude Code hooks and settings: https://code.claude.com/docs/en/hooks, https://code.claude.com/docs/en/settings
- Codex hooks: https://learn.chatgpt.com/docs/hooks; approvals: https://developers.openai.com/codex/agent-approvals-security
- Cursor hooks: https://cursor.com/docs/agent/hooks; changelogs 1.7 and 2.1; CLI reports: https://forum.cursor.com/t/cursor-agent-cli-never-invokes-hooks-json-on-linux-2026-08-11-same-version-works-on-macos/168326
- Antigravity hooks and permissions: https://antigravity.google/docs/hooks, https://antigravity.google/docs/permissions
- Gemini CLI transition: https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/
- Perplexity Personal Computer and MCP: https://www.perplexity.ai/help-center/en/articles/14659663-what-is-personal-computer, https://www.perplexity.ai/help-center/en/articles/11502712-local-and-remote-mcps-for-perplexity
- Copilot CLI hooks: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference
- Devin/Windsurf hooks: https://docs.devin.ai/desktop/cascade/hooks
