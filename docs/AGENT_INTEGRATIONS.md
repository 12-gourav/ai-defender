# AI Provider Integration Feasibility Matrix

> **Implemented (Phase 8, 2026-10-31):** Claude Code and OpenAI Codex hook integrations, re-verified against the providers' current documentation. See [HOOKS.md](HOOKS.md) for what is implemented, the events and payloads used, and enforcement coverage. This document is the 2026-10-30 feasibility research; where it differs from HOOKS.md, HOOKS.md reflects the current documentation.

Researched 2026-10-30 against official documentation. Every "verified" cell cites the official page. Every integration remains **unproven** until Phase 10 tests exercise the real execution paths; this document establishes what the vendors document, not what AI Defender guarantees.

## 1. Integration strategy

AI Defender integrates by **running the agent's CLI inside the AI Defender container** ("contained tier"). This works regardless of the agent's hook quality, because enforcement is the container plus the host-side gateways. Hooks are configured additionally for early denial and clear messages.

Agents that only exist as desktop IDEs (Cursor IDE, Antigravity App/IDE) cannot be placed in the container by AI Defender. For those, only a **host-hooked tier** is possible, which is advisory and must be reported as such. The initial pilot will not claim enforcement for host-hooked agents.

## 2. Matrix

| Capability | Claude Code | OpenAI Codex CLI | Gemini CLI | Antigravity CLI | Cursor (cursor-agent / IDE) |
|---|---|---|---|---|---|
| Headless/terminal CLI exists | Yes | Yes (`codex`, `codex exec`) | Yes | Yes (separate from App/IDE) | `cursor-agent` CLI exists; agent-hook support in CLI **unconfirmed** |
| Pre-tool hook with deny | `PreToolUse` → `permissionDecision: deny` or exit 2 | `PreToolUse` → `permissionDecision: deny` or exit 2 | `BeforeTool` → `decision: deny` or exit 2 | `PreToolUse` → `decision: deny` | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` → `permission: deny` |
| Hook can return "ask" | Yes (`ask`, `defer`), but auto-approved under `bypassPermissions` per community report | **No** — `ask` is unsupported, hook marked failed and tool call proceeds | No (`allow`/`deny`/`block` only) | Yes (`ask`, `force_ask`) | Yes for shell/MCP; not enforced for `preToolUse` |
| Hook failure default | **Fail-open** | **Fail-open** (errors/timeouts don't block) | **Fail-open** (non-zero exit other than 2 is a warning) | Not documented | **Fail-open** |
| Fail-closed option | `onFailure: "block"` (v2.1.295+) | None documented | None documented | None documented | `failClosed: true` per hook |
| Admin-locked hooks | `allowManagedHooksOnly` in `/etc/claude-code/managed-settings.json`; lower levels cannot remove managed hooks | `requirements.toml` `[hooks]` + `allow_managed_hooks_only = true`; managed hooks trusted by policy | Not documented | Not documented | Enterprise `/etc/cursor/hooks.json` (MDM) and Team dashboard; override behaviour not documented |
| Hook can rewrite tool input | `updatedInput` | `updatedInput` (allow only) | `hookSpecificOutput.tool_input` | `overwrite` | Not used by AI Defender |
| Own OS sandbox on Linux | bubblewrap + socat proxy; off by default; fails open unless `failIfUnavailable`; built-in file tools exempt | bwrap + seccomp; `workspace-write` network off by default; `[features.network_proxy]` domains; MCP not filtered | Docker/Podman/runsc/lxc wrappers; mounts cwd at same absolute path | Kernel namespaces; unavailable if unprivileged userns blocked; no network by default | Not documented for Linux in reviewed material |
| Bypass flags that must be locked | `--dangerously-skip-permissions`, `permissions.defaultMode: bypassPermissions` → lock via `disableBypassPermissionsMode: "disable"` | `--dangerously-bypass-approvals-and-sandbox` / `--yolo`, `--dangerously-bypass-hook-trust` → `allowed_approval_policies` in requirements.toml; flags still exist | `--yolo` style auto-approve; no admin lock documented | `auto` permission preset; `unsandboxed(...)` rules | none documented beyond hook merge order (`deny` > `ask` > `allow`) |
| Non-interactive mode | `claude -p` | `codex exec` | `gemini -p` | documented CLI | `cursor-agent -p` (unverified) |
| Credential form | OAuth tokens in `~/.claude/.credentials.json` or `ANTHROPIC_API_KEY`; `apiKeyHelper` command supported | `~/.codex/auth.json` or `OPENAI_API_KEY` | OAuth in `~/.gemini/` or `GEMINI_API_KEY` | `~/.gemini/antigravity-cli/` | Cursor account login |
| Config paths the agent could write | `~/.claude/settings.json`, `.claude/settings*.json`, `~/.claude.json` | `~/.codex/config.toml`, `.codex/` | `~/.gemini/settings.json`, `.gemini/` | `~/.gemini/antigravity-cli/settings.json`, `.agents/hooks.json` | `~/.cursor/hooks.json`, `.cursor/hooks.json` |
| MCP servers (extra attack surface) | Yes; `allowedMcpServers`/`allowManagedMcpServersOnly` lockable | Yes; proxy does not filter MCP | Yes | Yes | Yes |
| Contained-tier feasibility | **High.** Managed settings in image lock hooks, bypass mode, permission rules; `onFailure: block` for fail-closed hooks | **High.** requirements.toml managed hooks; inner sandbox may need `danger-full-access` *inside our container* if bwrap cannot nest (R-11) | **Medium.** Hooks are fail-open with no lock; rely on container only; config dir made read-only | **Medium.** Hooks exist but failure semantics undocumented; rely on container | **Low/unknown.** CLI hook support unconfirmed; IDE cannot be contained |
| Host-hooked tier feasibility | Possible but **not recommended**: built-in tools bypass sandbox, hooks run as developer | Possible, same caveats | Possible, weaker | Possible, weaker | IDE: advisory only |

## 3. Per-agent adapter plan

### Claude Code (`ai-defender run claude`)
- Image layer: Node LTS pinned + `@anthropic-ai/claude-code` pinned.
- Baked `/etc/claude-code/managed-settings.json`: `allowManagedHooksOnly: true`, `allowManagedPermissionRulesOnly: true`, `permissions.disableBypassPermissionsMode: "disable"`, `permissions.deny` for `/ag/auth/**` reads other than by the helper, `sandbox.enabled: false`, `hooks.PreToolUse` → `agentguard-shim hook claude` with `onFailure: "block"` and matcher for `Bash|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch|mcp__.*`, `hooks.PermissionRequest` → shim (so the agent's own permission prompts route through AI Defender's decision, and can return `deny` with the AI Defender explanation), `allowedMcpServers: []` unless policy lists some, `disableAllHooks` unavailable to lower levels by construction.
- Auth: provider credential supplied via `apiKeyHelper` → `agentguard-shim auth claude`, which reads `/ag/auth` (ADR-0010). OAuth subscription logins require the credentials file to be mounted read-only; documented.
- Limitation: the Claude Code `Read` tool reads anything in the container, which is only the staging clone and the image. Acceptable.

### OpenAI Codex (`ai-defender run codex`)
- Image layer: pinned `codex` binary.
- Managed `requirements.toml` installed in the image's `managed_dir` with `[hooks]` → shim, `allow_managed_hooks_only = true`, `allowed_approval_policies = ["on-request", "never"]`, `[features] hooks = true`.
- Inner sandbox: attempt `workspace-write` inside the container; if bwrap cannot create namespaces under our seccomp profile, fall back to `danger-full-access` **inside the container only** and log it. The container is the boundary either way (R-11).
- Hook `ask` is unsupported, so the shim returns `deny` with a message telling the agent how to request approval (the approval is then raised through the gateway, not the hook).

### Gemini CLI (`ai-defender run gemini`)
- Image layer: Node + `@google/gemini-cli` pinned.
- Hooks in a read-only system settings location if supported; otherwise `~/.gemini/settings.json` placed on a read-only bind mount. Hooks are fail-open; AI Defender reports the adapter's hook tier as advisory.
- Gemini's own sandbox disabled inside the container.

### Antigravity CLI (`ai-defender run antigravity`)
- Image layer: pinned CLI.
- `~/.gemini/config/hooks.json` on a read-only bind with `PreToolUse` → shim; `permissions.deny` for `sudo *`, `docker *` as defence in depth.
- Failure semantics undocumented: adapter marks hooks advisory.

### Cursor (`ai-defender run cursor`)
- Deferred until `cursor-agent` hook behaviour is verified in a disposable environment. If the CLI honours `.cursor/hooks.json` with `failClosed`, a contained-tier adapter follows the Claude pattern. The IDE remains host-hooked/advisory.

### Generic adapter (`ai-defender run --generic <cmd>`)
- Runs any CLI inside the container with no hooks. Full containment, no early denials. This is the baseline every other adapter must at least equal.

## 4. Capability reporting

Each adapter implements:

```rust
trait AgentAdapter {
    fn kind(&self) -> AgentKind;
    fn detect(&self) -> Result<Option<AgentVersion>>;
    fn validate_integration(&self, image: &ImageRef) -> Result<IntegrationReport>;
    fn capabilities(&self) -> CapabilitySet;   // hooks_enforceable, hooks_fail_closed, inner_sandbox, mcp_lockable, ...
    fn image_layer(&self) -> ImageLayerSpec;
    fn baked_config(&self, policy: &EffectivePolicy) -> Vec<BakedFile>;
    fn auth_strategy(&self) -> AuthStrategy;
    fn launch_spec(&self, task: &TaskContext) -> LaunchSpec;
    fn hook_protocol(&self) -> HookProtocol;   // JSON in/out translation for the shim
    fn tier(&self) -> IntegrationTier;         // Contained | HostHooked(Advisory)
}
```

`ai-defender inspect` prints the tier and capability set so the developer never assumes more than the adapter can deliver.

## 5. Sources

- Claude Code hooks: https://code.claude.com/docs/en/hooks
- Claude Code sandboxing: https://code.claude.com/docs/en/sandboxing
- Claude Code settings and precedence: https://code.claude.com/docs/en/settings
- Claude Code managed settings: https://code.claude.com/docs/en/managed-settings
- Codex approvals and sandbox, rules, managed config: https://developers.openai.com/codex (served from https://learn.chatgpt.com/docs/)
- Codex hooks: https://developers.openai.com/codex/hooks
- Gemini CLI hooks reference: https://geminicli.com/docs/hooks/reference
- Gemini CLI sandbox: https://geminicli.com/docs/cli/sandbox
- Antigravity sandbox: https://www.antigravity.google/docs/sandbox
- Antigravity hooks: https://www.antigravity.google/docs/hooks/
- Cursor hooks: https://cursor.com/docs/agent/hooks
- Community reports consulted for Claude Code `ask` behaviour under bypass mode (not authoritative): claudeissues.com issues 39344 and 77212.
