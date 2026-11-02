# Agent hook integrations: Claude Code and OpenAI Codex

Status: Phase 8 (2026-10-31). Code:
- `crates/agentguard-hooks`: provider adapters, decisions, responses, installer, coverage.
- `crates/agentguard-engine-cli/src/integrations.rs`: the hook entry point and the
  `integrations.*` commands.
- `cli/src/commands/integrations.ts`: `ai-defender integrations`.

## 1. Sources

The adapters were built against the providers' official documentation, retrieved 2026-10-31.

| Provider | Documentation | Notes |
|---|---|---|
| Claude Code | <https://code.claude.com/docs/en/hooks> | `onFailure` needs v2.1.295+ |
| OpenAI Codex | <https://developers.openai.com/codex/hooks> | redirects (308) to <https://learn.chatgpt.com/docs/hooks>, the release-behaviour reference |

Every event, field, response shape and exit code AI Defender uses is documented there. Where the
documentation is silent (for example, what Codex does when a command hook times out), this
document says so instead of assuming.

Each adapter records its own compatibility data:
- adapter `agentguard.hooks.v1`;
- documentation verified 2026-10-31;
- the provider version, read from `<provider> --version` by `ai-defender integrations status`.

## 2. How a hook runs

```text
provider ─ runs `agentguard-engine hook <provider> <event>` with the native payload on stdin
  engine ─ validate payload ─ normalize the tool call into AI Defender protocol actions
         ─ verify trusted state ─ project from the trusted registry (from cwd, or from a target
           path inside a registered project) ─ identity: agent from the installed command line
         ─ per action: content and Git inspection ─ evaluate (existing policy engine)
           ─ digest (operation + exact tool input + Git state)
         ─ DENY → block; REQUIRE_APPROVAL → redeem an approved grant, or create a pending
           request and block; ALLOW → no decision
         ─ provider response ─ audit
```

- **One process per call.** The hook is the Rust engine binary itself. No daemon, no Node.js and
  no network are involved.
- **Adapters translate, never decide.** Decisions come from the same `evaluate` path,
  rules, mandatory baseline, guard and approval store as every other AI Defender decision.
- **Identity is never taken from the payload.** The agent identity comes from the installed
  command line (`hook claude` means Claude Code). The project comes from the registry, never from
  payload fields. `session_id` is recorded hashed and bound into the digest as a scope, but it is
  never treated as proof of anything. Payload fields such as `decision`, `approved` or
  `permissionDecision` are never read.

## 3. Events

| Provider | Event | Matcher | Capability | Timeout |
|---|---|---|---|---|
| Claude Code | `PreToolUse` | `^(Bash\|PowerShell\|Read\|Write\|Edit\|MultiEdit\|NotebookEdit\|Glob\|Grep\|WebFetch\|WebSearch\|mcp__.*)$` | **pre-execution enforcement** (`onFailure: "block"`) | 60 s |
| Claude Code | `PostToolUse`, `PostToolUseFailure` | same | post-execution audit (cannot block) | 10 s |
| Claude Code | `SessionStart` | — | informational (adds context) | 10 s |
| Codex | `PreToolUse` | `^(Bash\|apply_patch\|mcp__.*)$` | **pre-execution enforcement** (`\|\| exit 2`) | 60 s |
| Codex | `PostToolUse` | same | post-execution audit (cannot undo) | 10 s |
| Codex | `SessionStart` | — | informational | 10 s |

The Claude Code matcher is anchored. Claude Code treats a matcher containing regex characters as
an unanchored regex, so `Write` alone would also match `TodoWrite`.

Not used:
- **`PermissionRequest`.** `PreToolUse` already decides.
- **`UserPromptSubmit`.**
- **Claude Code `ConfigChange`.** It can block settings changes, but it was not adopted in this
  phase.
- **Claude Code `ask` and `defer`.** Approval must come from the trusted AI Defender CLI, not the
  agent's own UI, and `defer` works only in non-interactive mode.

## 4. Payload normalization

| Provider and tool | AI Defender action | Inspected and bound |
|---|---|---|
| Claude Code `Bash`, `PowerShell` | terminal command | command text; for a single `git` command, the Phase 7 repository facts and push/commit secret scans |
| Claude Code `Read` | filesystem read | Phase 6 sensitive-file policy |
| Claude Code `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | filesystem write | written text scanned for secrets; exact input bound |
| Claude Code `Glob`, `Grep` | filesystem traverse of `path` (default: `cwd`) | tree sensitivity |
| Claude Code `WebFetch` | network request to the URL's host | host |
| Claude Code `WebSearch`, `mcp__*` | custom tool (approval by default) | exact input bound; arguments not interpreted |
| Codex `Bash` (string, or `["bash","-lc",script]`) | terminal command | as above |
| Codex `apply_patch` | one filesystem action per file: add or update = write (added lines scanned), move = rename, delete = delete | patch parsed; an unreadable patch is blocked |
| Codex `mcp__*` | custom tool | exact input bound |

Relative paths are resolved against the session `cwd`, and symlinks to their targets.

Unknown payload fields are ignored, because providers add fields over time. A missing or
mistyped field AI Defender relies on is rejected as a possible schema change
(`hook.schema-changed`), and the call is blocked.

The digest binds:
- `hook.provider`;
- `hook.tool-input`, a SHA-256 over the canonical tool input. Claude Code's free-text
  `description` is excluded, because it does not change what runs;
- for single Git commands, the Phase 7 facts: HEAD, branch, staged tree, push source, range,
  remote URL identity, and named refs.

## 5. Decision mapping

| AI Defender | Claude Code response | Codex response |
|---|---|---|
| `ALLOW` | exit 0, no output: Claude Code's own permission rules still apply | exit 0, no output |
| `DENY` | exit 0, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"AI Defender blocked this operation: … (rule)."}}` | the same documented shape |
| `REQUIRE_APPROVAL` | the same deny shape, with the reason naming `ai-defender approve <id>` | same |
| Engine failure, invalid payload, unverified policy, unavailable audit or approval store | deny response | deny response |
| Deny response cannot be serialized | exit 2, reason on stderr (blocks `PreToolUse`) | exit 2 (blocks `PreToolUse`) |
| Outside every registered project (and not touching trusted state) | exit 0, no output (not governed) | same |

AI Defender never answers `allow`. It adds restrictions only, so neither provider's own
permission system is bypassed. Trusted state is guarded even outside registered projects:
- AI Defender's trust store;
- `.agentguard` and project hook settings;
- `~/.claude/settings.json` and `settings.local.json`;
- `~/.codex/hooks.json` and `config.toml`;
- the engine binary itself.

The guard also recognises `~/` and `$HOME/` spellings in terminal commands.

## 6. Approvals

Neither provider can pause an interactive tool call while a human approves somewhere else. So
`REQUIRE_APPROVAL` works like this:

1. **Blocked call.** The hook creates a Phase 5 pending request bound to the exact digest:
   agent, project, session, tool input and Git state. The claim token is kept in the trust store
   (`hooks/claims/`). The call is blocked with the approval command. A retry before the human
   decides reuses the same request.
2. **Human approval.** The human runs `ai-defender approve <id>` in their own terminal. It needs
   the interactive confirmation and the signing-key passphrase. An agent cannot do this: the
   guard denies `ai-defender approve` from agent tools, and an engine launched for an agent
   refuses approval.
3. **Retry.** The agent retries the identical call. The hook finds the approved grant for the
   recomputed digest and consumes it atomically, once. AI Defender then adds no objection. A
   changed call is a new operation and needs a new approval. Changes include:
   - another branch or file;
   - other content;
   - a moved HEAD or newly staged files;
   - another agent or session.

A grant is valid for 2 minutes after approval by default (configurable in global policy, at most
5). A consumed grant is never reused.

## 7. Failure behaviour

| Failure | Claude Code | Codex |
|---|---|---|
| Invalid or oversized payload (8 MiB), schema change | deny | deny |
| Trusted state missing or tampered | deny (`policy.integrity`) | deny |
| Audit log unavailable | deny | deny |
| Approval store or claim store unavailable, invalid grant | deny | deny |
| Engine binary missing or not executable | blocked by `onFailure: "block"` (v2.1.295+); **older versions continue the call** | `\|\| exit 2` blocks (tested with `sh`) |
| Engine crash | same as missing | `\|\| exit 2` blocks |
| Hook timeout (60 s) | blocked by `onFailure` (v2.1.295+); older versions continue | **undocumented**; treated as potentially bypassable |
| Informational or audit hook fails | never blocks (exit 0) | never blocks |

AI Defender does not block ordinary development when a notification hook fails. `SessionStart`
and `PostToolUse` failures are invisible to the agent.

## 8. Installation and removal

```text
ai-defender integrations                       list providers and events
ai-defender integrations install claude|codex  confirmation (or --yes)
ai-defender integrations status [claude|codex]
ai-defender integrations verify [claude|codex] exit 5 on any failed check
ai-defender integrations coverage [claude|codex]
ai-defender integrations uninstall claude|codex  confirmation + signing-key passphrase
```

- **Where.** User-level configuration only: `~/.claude/settings.json` (`hooks`) and
  `~/.codex/hooks.json`. If `CLAUDE_CONFIG_DIR` or `CODEX_HOME` is set, installation is refused,
  because the file would not be read.
- **Handlers.**
  - Claude Code uses exec form, with no shell: `command` = the engine's absolute path and
    `args` = `["hook","claude",<event>]`. `PreToolUse` also gets `onFailure: "block"`.
  - Codex uses `command` = `'<engine>' hook codex <event>`, with `|| exit 2` on `PreToolUse`.
  - Every handler carries `statusMessage: "AI Defender security check"`. That marker, together with
    the `hook` subcommand, identifies AI Defender's entries.
- **Safety.**
  - The existing file is backed up into the trust store (`integrations/backups/`, 0600) before
    any change.
  - The edit is idempotent: AI Defender replaces only its own handlers.
  - Unrelated keys, groups and hooks are preserved. That includes other security hooks, which
    are never disabled.
  - The write is atomic, and group and other write access is removed.
  - A file that is not a JSON object, or is a symlink, is never overwritten.
  - Uninstall removes only AI Defender's handlers, and only the groups and keys left empty by
    that removal. It needs the passphrase because it removes protection. Both commands are
    refused from an agent-launched engine.
- **Hook executable.** Installation records the engine binary's SHA-256 and refuses an engine
  that is:
  - not an absolute path;
  - not an executable file;
  - writable by group or others, or in a directory that is;
  - owned by another user.

  `status` and `verify` re-check every configured handler's engine path and hash.
- **Verify** checks:
  - trusted state;
  - that the configuration parses;
  - registered events;
  - fail-closed settings;
  - configuration permissions;
  - the executable and its identity.

  It then runs synthetic hook calls in-process: an invalid payload, an `ai-defender approve`
  attempt and a write to the provider's own hook file must all be blocked, and `SessionStart`
  must return the documented shape. The result is recorded as the last health check.
- **After installing.**
  - Claude Code holds back settings-file hooks in interactive sessions until the workspace trust
    dialog is accepted.
  - Codex skips new or changed hooks until they are trusted with `/hooks`. AI Defender cannot see
    either trust state.

## 9. Coverage

`ai-defender integrations coverage` prints the full table. In summary:

- **Protected (pre-execution):**
  - Claude Code: Bash, PowerShell, Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep,
    WebFetch, WebSearch, and MCP tools;
  - Codex: Bash, unified exec, `apply_patch`, and MCP tools.
- **Observed:** `PostToolUse`, `PostToolUseFailure` and `SessionStart`.
- **Unsupported:**
  - Claude Code `Agent` (each subagent's tool calls are hooked themselves);
  - other built-in tools that run no commands and touch no files;
  - Codex local function tools other than the above;
  - Codex hosted tools (WebSearch);
  - commands the developer runs directly;
  - other agents.
- **Bypassable:**
  - Claude Code hook failures before v2.1.295;
  - hooks held back before workspace trust;
  - Codex `write_stdin`;
  - Codex tool paths that opt out of hooks;
  - Codex timeouts (undocumented);
  - untrusted Codex hooks;
  - child processes of an allowed command;
  - anything outside a registered project.

**This is not complete AI-agent protection.** Codex itself calls its hooks "a useful guardrail,
not a complete enforcement boundary".

## 10. Audit

| Kind | When |
|---|---|
| `hook-invoked` | a hook starts (provider, event, tool, hashed session) |
| `hook-payload-rejected` | validation failed (reason code) |
| `hook-operation-normalized` | number of operations |
| `hook-decision` | per operation: decision, rule, policy version, project, agent |
| `approval-request-created`, `authorization-consumed`, … | Phase 5 events |
| `hook-response-generated` | the final outcome (`hook.not-governed`, `hook.grant-redeemed`, …) |
| `hook-failed` | internal failure (blocked) |
| `hook-unsupported-event` | an event or tool AI Defender does not support |
| `hook-tool-observed` | post-execution audit |

Each record has an enforcement status: `enforced-before-execution`, `observed-after-execution` or
`informational`. Tool arguments, file contents, claim tokens and raw session IDs are never
recorded.

## 11. Performance

Measured with the release engine on Linux: 30 calls each through the real `hook` subcommand in an
initialized sandbox. Each call includes process start, trust verification, policy, and four audit
writes.

| Call | p50 | p95 | Peak RSS |
|---|---|---|---|
| Allow (`Bash cargo test`) | 15.8 ms | 17.0 ms | 11.6 MiB |
| Allow (`Read package.json`) | 16.1 ms | 17.5 ms | 11.3 MiB |
| Deny (`rm -rf ../`) | 17.2 ms | 18.0 ms | 11.2 MiB |
| Deny (invalid payload) | 11.3 ms | 12.2 ms | 8.3 MiB |
| Approval (`git push`: Git inspection, push scan, request) | 120.7 ms | 167.4 ms | 11.3 MiB |
| Engine start alone (`version`) | 2 ms (mean) | | |

Policy evaluation itself takes roughly 5 ms: the allow figure minus the invalid-payload figure,
which validates and audits but does not evaluate. The human part of an approval is unbounded by
design.

For slow hooks, Claude Code logs `Hooks:` lines with durations (v2.1.296+). The engine's audit log
timestamps each stage.

## 12. Examples

Claude Code: an agent runs `git push origin main`.

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"AI Defender requires human approval for this exact operation (talking to a Git remote; profile:vcs-remote-commands). Ask the user to run `ai-defender approve 3f2a9c1e` in their own terminal; do not run it yourself. After approval, retry exactly the same call; any change needs a new approval."}}
```

Codex: `apply_patch` adding a file that contains a credential.

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"AI Defender blocked this operation: secret data may not be copied or written into an ordinary project file (mandatory:secret-into-ordinary-file)."}}
```

## 13. Troubleshooting

| Symptom | Check |
|---|---|
| Every tool call is blocked with "trusted state did not verify" | `ai-defender check`; restore trusted state, or uninstall the integration |
| Hooks never fire | Claude Code: accept workspace trust, restart the session. Codex: `/hooks`, trust the AI Defender hooks |
| `status` says degraded | `ai-defender integrations verify` names the failing check (engine moved, hash changed, events missing, fail-open) |
| Compatibility "degraded" for Claude Code | upgrade to 2.1.295+ so hook failures block |
| Approval keeps being requested | the retried call differs (content, branch, HEAD, session); approve the new request shown |
| The grant expired | approve again and retry within 2 minutes |
