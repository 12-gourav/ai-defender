# AI Defender CLI

Phase 4. Package `cli/` (npm package `ai-defender`); engine crate `crates/agentguard-engine-cli` (binary `agentguard-engine`).

## 1. Installation versus enforcement

| State | Meaning | Where shown |
|---|---|---|
| Installed | the CLI runs | `ai-defender --version` |
| Engine available | a verified engine binary (or an explicitly allowed development build) responds | `status` → Installation |
| Initialized | a trust store exists on this machine and verifies | `status` → Initialized |
| Registered | the current directory is inside a registered, trusted project whose directory is intact | `status` → Project registered |
| Policy verified | the effective policy was built from verified trusted state | `status` → Policy integrity |
| Integration configured | an agent's hooks call AI Defender | `ai-defender integrations status` (Phase 8: Claude Code, Codex) |
| Enforcement active | AI Defender decides on agent actions | only for the tools `ai-defender integrations coverage` lists as protected, in registered projects; never global |

AI Defender protects nothing until an agent integration is configured (a later phase). The CLI never shows enforcement as active, and never shows a development engine as verified.

Since Phase 7, `ai-defender run` controls the commands routed through it (policy, approval, filtered environment, time limit, audit). That is **managed execution, not enforcement**: commands an agent runs through its own tools are not intercepted, and `status` reports them as such.

## 2. Installing

```sh
npm install -g ai-defender
```

The npm package has **no dependencies** and runs no install scripts. It carries one engine per supported platform under `binaries/<platform>/` and uses the one for the current OS and CPU (see §8). Rust and Cargo are not needed to use a release.

### Supported platforms

| Platform | Status |
|---|---|
| linux-x64 | supported: static musl engine; Rust suite and global-install test on GitHub's Ubuntu runner |
| linux-arm64 | supported: static musl engine; Rust suite and global-install test on GitHub's Ubuntu ARM64 runner |
| darwin-arm64 | supported: Rust suite and global-install test on GitHub's macOS 14 runner |
| darwin-x64 | supported: Rust suite and global-install test on GitHub's macOS 15 Intel runner |
| win32-x64 | **not released**: the engine builds for Windows (owner SIDs, DACLs, reparse points, Job Objects, Windows path rules) and CI runs its suite on `windows-latest`; npm refuses to install `ai-defender` on Windows (`os` field) until an engine is released (KNOWN_LIMITATIONS L117 to L124) |

Configuration directories are XDG-style (`~/.config`) on every platform, including macOS. Any other platform, or a package without an engine for the platform, gets a clear error with exit code 3.

## 3. Commands

Global options:

| Option | Meaning |
|---|---|
| `--json` | one JSON document: `{ ok, command, cli_version, engine: {path, verified, source} \| null, data \| error }` |
| `--no-color` | disable colour (also `NO_COLOR`, `TERM=dumb`, or a non-terminal stdout) |
| `--non-interactive` | never prompt |
| `-y`, `--yes` | explicit confirmation |
| `--passphrase-file F` | the signing-key passphrase from a private file (never accepted by `approve`) |
| `--reason TEXT` | reason recorded with `reject` |
| `--staged`, `--exclude GLOB`, `--no-default-exclusions` | `secrets scan` scope and exclusions |
| `-v`, `--verbose` | show the engine path |

| Command | Effect | Changes state |
|---|---|---|
| `ai-defender --help` | description, commands, examples, options, exit codes | no |
| `ai-defender --version` / `version` | CLI version, engine version, engine protocol (CLI vs engine), authorization protocol, verified/unverified engine; notes when the CLI and engine versions differ | no |
| `ai-defender init [--profile balanced] [--name N]` | detect the project, show the plan, confirm, then (through the engine): create `.agentguard/config.yaml` if no configuration exists, create the trust store and signing keys on first use, register the project, approve its restrictions, validate | yes |
| `ai-defender status` | installation, initialisation, registration, policy integrity, profile, policy version, audit storage, integration, enforcement, project | no |
| `ai-defender check` | diagnostics (see §6); exit 5 on any failure | no |
| `ai-defender policy show` | the effective policy computed and verified by the engine: mandatory baseline, organisation/user policy, approved project restrictions, profile and settings, profile rules, precedence, defaults, version, integrity | no |
| `ai-defender project list` | registered projects, trust status, directory integrity | no |
| `ai-defender project inspect` | the current project's registration, approved restrictions, configuration state, drift | no |
| `ai-defender project trust` | re-trust a revoked project (or register an unregistered one with existing configuration) and approve its restrictions; confirmation and passphrase required | yes |
| `ai-defender project revoke` | revoke the current project's trust; confirmation and passphrase required | yes |
| `ai-defender approvals` | pending and recent approval requests: ID, operation, project, agent, risk, request time, expiry (with countdown), status. Never shows claim tokens | expires due requests |
| `ai-defender approvals show <id>` | the full review of one request (ID or unique prefix of 8+ characters), including digest, rule, decision and grant state | records a "viewed" audit event |
| `ai-defender approve <id>` | shows the exact operation, asks you to type `approve` (or `reject`), then asks for the signing-key passphrase; issues a one-time grant valid for 2 minutes. Requires an interactive terminal; refuses `--yes`, `--json`, `--non-interactive` and `--passphrase-file` (exit 6) | yes |
| `ai-defender reject <id> [--reason T]` | reject a pending request; confirmation (or `--yes`) | yes |
| `ai-defender approvals cancel <id>` | cancel a pending request; confirmation (or `--yes`) | yes |
| `ai-defender approvals revoke <id>` | revoke an approved grant before it is used; confirmation (or `--yes`) | yes |

| `ai-defender secrets scan [PATH…]` | scan the project (or paths inside it) for potential secrets; `--staged` for staged Git changes; redacted previews only; excluded and skipped files listed, never reported clean; exit 5 if anything is found | records the last scan (no values) |
| `ai-defender secrets status` | detectors, policy decisions for sensitive files, protected patterns, exclusions, last scan | no |
| `ai-defender secrets explain <id>` | explain a finding without revealing its value | no |
| `ai-defender secrets preview <file>` | keys of a `.env` file and whether each is set; never values | no |

Secret detection and sensitive-file policy: [SECRETS.md](SECRETS.md).

| Command | Effect | Changes state |
|---|---|---|
| `ai-defender run [--shell sh\|bash] [--timeout S] [--env-profile minimal\|development] [--approval ID] [--no-wait] [--] COMMAND…` | run one command through policy, approval, a filtered environment, a time limit and audit; argv without a shell, or a script in the supported shell subset; waits for `ai-defender approve` in an interactive terminal; exits with the command's own status when it runs | runs the command; records an execution |
| `ai-defender git status` | branch, HEAD, staged and working-tree changes, read through hardened Git plumbing | no |
| `ai-defender git inspect` | repository identity, Git directory, branch, HEAD, status, remotes with credentials removed, hooks | no |
| `ai-defender execution history` | recent managed executions | no |
| `ai-defender execution inspect <id>` | one execution record (redacted; IDs may be abbreviated to 7 characters or more) | no |

Managed execution: [EXECUTION.md](EXECUTION.md). Global options go before `run`; everything after `run` belongs to the command.

| Command | Effect | Changes state |
|---|---|---|
| `ai-defender integrations [list]` | providers, registered events, documentation sources | no |
| `ai-defender integrations status [claude\|codex]` | installed entries, hook executable checks, provider version and compatibility, last health check, enforcement statement | no |
| `ai-defender integrations install claude\|codex` | add AI Defender's hooks to `~/.claude/settings.json` or `~/.codex/hooks.json` (confirmation; backup first; other settings and hooks kept) | provider configuration |
| `ai-defender integrations uninstall claude\|codex` | remove only AI Defender's entries (confirmation and passphrase) | provider configuration |
| `ai-defender uninstall [--purge]` | the supported removal: after confirmation and the passphrase, remove AI Defender's hooks from every provider (other entries kept, backed up) and its engine copies; keep keys, policy, registry and history unless `--purge` is confirmed by typing `purge`; then print `npm uninstall -g ai-defender` | provider configuration, engine copies, trust store with `--purge` |
| `ai-defender integrations verify [claude\|codex]` | configuration, permissions, executable identity, trusted state, synthetic hook checks; exit 5 on any failure | records a health check |
| `ai-defender integrations coverage [claude\|codex]` | protected, observed, unsupported and bypassable tool paths | no |

Hook integrations: [HOOKS.md](HOOKS.md).

| Command | Effect | Changes state |
|---|---|---|
| `ai-defender projects [list]` | every project registered on this machine: name, ID, profile, integration, status | no |
| `ai-defender projects inspect <project>` | one project by ID prefix (6+ hex), folder name or path | no |
| `ai-defender projects add [path]` | register a project (the `init` flow in that directory) | registry |
| `ai-defender projects revoke <project>` | revoke a project's trust (confirmation and passphrase) | registry |
| `ai-defender policy validate` | trusted policy integrity and this project's configuration; exit 5 if either fails | no |
| `ai-defender history [--blocked\|--approvals] [--limit N]` | recent audit events, newest first (last 8 MiB of the log) | no |
| `ai-defender doctor` | engine verification, protocol, versions, Node.js, Git, agent CLIs, trust and project checks, integration health; exit 5 on failure | no |
| `ai-defender dashboard` | one screen: engine, trust, projects, pending approvals, recent blocks, integrations | no |
| `ai-defender repair` | re-point degraded or outdated hooks at a fresh verified engine copy (confirmation); refuses when trusted state does not verify | provider configuration |
| `ai-defender update` | installed versions and the npm upgrade steps; downloads nothing | no |

Engine commands added for these: `history.list`, `prerequisites`, `integrations.repair`; `integrations.status` accepts `probe: false`.

Approval is described in full in [APPROVALS.md](APPROVALS.md). Rejecting, cancelling and revoking only remove authority, so an explicit `--yes` is accepted for them; approving never accepts it.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success (for `check`: no failing check) |
| 1 | the operation failed (including a declined confirmation, a wrong passphrase, invalid configuration) |
| 2 | usage error |
| 3 | engine unavailable: missing, unverified, unsupported platform, did not start, timed out |
| 4 | engine protocol error: malformed or incompatible response |
| 5 | security check failed: integrity failure, or a failing `check` |
| 6 | confirmation or authorization required and not given (typical in non-interactive mode; always for `approve` without a terminal) |
| 7 | not initialised, or the directory is not inside a registered project |
| 8 | `run`: denied by policy; nothing ran |
| 9 | `run`: unsupported syntax, option or program; nothing ran |
| 124 | `run`: timed out and terminated |
| 125 | `run`: outcome unknown, or the command ran but its outcome could not be recorded |

When `run` executes the command, it exits with the command's own status (128+n for a signal), which can coincide with the codes above; `--json` (`data.executed`, `data.outcome`) is authoritative.

## 4. Initialisation

```
$ ai-defender init
AI Defender

Initialize AI Defender
  Project root:         /home/dev/app
  Project kind:         node
  Trust store:          will be created (new signing keys)
  Configuration:        create .agentguard/config.yaml
  Registration:         register this project
  Expected profile:     balanced

Initialize AI Defender for this project? [y/N] y
Choose a passphrase for the new AI Defender signing keys (at least 12 characters).
New passphrase:
Repeat passphrase:
```

1. **Detect the project root:**
   - the registered project containing the current directory; otherwise
   - the nearest ancestor holding `.git`; otherwise
   - the nearest ancestor holding a project marker (`Cargo.toml`, `package.json`, `pyproject.toml`, `go.mod`, …) or `.agentguard/`; otherwise
   - the current directory.

   Registration then canonicalises the path and rejects `/` and any directory that contains, or lies inside, the trust store.
2. **Detect the kind** from the same markers (informational).
3. **Check the current state:**
   - an integrity failure stops with exit 5;
   - an invalid or ambiguous configuration stops with exit 1;
   - a revoked project stops (re-trusting is `project trust`, a deliberate act);
   - an already-registered project with nothing to change completes without a passphrase (idempotent).
4. **Confirm:** a `[y/N]` prompt, or `--yes`. Non-interactive mode without `--yes` exits 6. Declining exits 1, and nothing is changed.
5. **Passphrase:** a hidden prompt (twice when creating keys), or `--passphrase-file`. Non-interactive mode without a file exits 6. Environment variables and command-line arguments are never accepted for the passphrase.
6. **The engine does the work,** checking everything before writing anything:
   - it validates the root and the configuration;
   - it creates the signing keys and the trust store on first use;
   - it unlocks the signing key;
   - then it writes `.agentguard/config.yaml` (only if no configuration exists; never overwritten), registers the project, approves its restrictions, and validates the new registration.

   A wrong passphrase leaves no files behind.
7. **Report** the active profile, the configuration location and the next steps. On first setup, a reminder to back up the signing keys.

## 5. Project configuration

`.agentguard/config.yaml` is **untrusted input**. It contains:

```yaml
version: 1
project:
  name: My App          # optional, display only
  kind: node            # optional, informational
profile: balanced       # expected profile; checked against the global policy, never applied
rules: []               # proposed restrictions: DENY or REQUIRE_APPROVAL only
integrations: {}        # reserved for agent integrations (later phase)
```

- **Unknown fields are rejected.** Rules use the schema in [POLICY_EVALUATION.md](POLICY_EVALUATION.md) §3, and `ALLOW` rules are rejected.
- **Restrictions are a proposal.** They take effect only after a human approves them (`init` or `project trust`, both requiring the signing key), which copies them into the signed trust store. Later edits show up as drift in `status` and `check` and change nothing until approved.
- **What the file must not contain:** private keys, tokens, secrets, global baselines, or authorization state. None of these are read from it.
- **The legacy file** `.agent-security.yml` is still read when `.agentguard/config.yaml` is absent. If both exist, the configuration is ambiguous and refused.
- **Symlinks are refused:** `.agentguard/` and the configuration files must not be symlinks, and nothing is written through one.
- **Validation:** `ai-defender check` reports configuration errors, with the parser's line and column.

## 6. Diagnostics (`check`)

`check` covers:
- engine binary verified (warn for a development build);
- engine responds;
- protocol compatible;
- trusted state available;
- trusted policy integrity;
- policy-signing key available (encrypted key file present);
- project registered and trusted (with directory integrity);
- project configuration valid;
- configuration drift (warn);
- effective policy available;
- expected profile (warn on mismatch);
- audit storage available (the JSON Lines trust log opens and its hash chain verifies);
- agent integration configured (always warn in this release).

`check` executes no project scripts and changes nothing.

## 7. Engine protocol (`agentguard.engine.v1`)

One process per command:
- no shell, no daemon;
- the request arrives on stdin and the response leaves on stdout, as one JSON line each.

```json
{"protocol_version":1,"request_id":"3f0c…","command":"status","arguments":{"working_directory":"/home/dev/app"}}
{"protocol_version":1,"request_id":"3f0c…","success":true,"data":{…},"error":null}
{"protocol_version":1,"request_id":"3f0c…","success":false,"data":null,"error":{"code":"authorization-required","message":"…","recovery":"…"}}
```

| Property | Rule |
|---|---|
| Size | request ≤ 64 KiB, response ≤ 1 MiB, engine stderr ≤ 64 KiB (the engine is killed beyond these) |
| Timeout | 30 s, then SIGTERM, then SIGKILL after 2 s |
| Request | exactly `protocol_version`, `request_id` (1 to 64 of `[A-Za-z0-9_-]`), `command`, `arguments`; unknown fields rejected; per-command arguments reject unknown fields |
| Response | exactly `protocol_version`, `request_id`, `success`, `data`, `error`; `request_id` must match; `success` must agree with `data`/`error` and with the exit status (0 success, 1 command error, 2 protocol error); `error.code` from a fixed list |
| Rejection | any deviation is a protocol error (exit 4), never a success |
| Commands | `version`, `status`, `check`, `policy.show`, `project.list`, `project.inspect`, `config.validate`, `project.init`, `project.trust`, `project.revoke`; approvals: `approval.list`, `approval.show`, `approval.approve`, `approval.reject`, `approval.cancel`, `authorization.revoke`; agent-side (engine launched with `--agent`): `approval.request`, `authorization.validate`, `authorization.consume` ([APPROVALS.md](APPROVALS.md) §8); scanning: `secrets.scan`, `secrets.status`, `secrets.explain`, `secrets.preview` ([SECRETS.md](SECRETS.md) §8); managed execution: `execution.run`, `execution.history`, `execution.inspect`, `git.status`, `git.inspect` ([EXECUTION.md](EXECUTION.md)); integrations: `integrations.list`, `.status`, `.coverage`, `.verify`, `.install`, `.uninstall` ([HOOKS.md](HOOKS.md)). The providers run `agentguard-engine hook <provider> <event>`, which speaks the provider's hook protocol instead |
| Decisions | the CLI never calls the agent-side commands and never interprets a decision (static test); agent actions are authorised by the integration layer |
| Error codes | adds `identity-unavailable`, `approval-not-found`, `approval-conflict`, `authorization-denied` (exit 1) and `audit-unavailable` (exit 5); messages end with a stable reason code such as `(approval.replay)` |
| Secrets | a passphrase may be sent in `arguments` and is never echoed; `passphrase_file` is preferred and checked by the engine (absolute, regular file, owned by the user, mode 600, ≤ 4 KiB) |

## 8. Binary distribution

```
ai-defender (npm, one package)
  build/src/…                              the CLI
  binaries/<platform>/bin/agentguard-engine
  binaries/<platform>/engine-manifest.json { schema, body, key_id, signature }
  release-keys.json                        public keys only
```

**Manifest body:**
- package (always `ai-defender`);
- version;
- platform;
- binary path;
- SHA-256 of the binary;
- engine protocol version.

**Signature:** Ed25519 over `agentguard.engine-manifest.v1\0 ‖ canonical JSON(body)`, where canonical JSON means sorted keys and no whitespace. The key ID is the first 16 bytes of `SHA-256("agentguard.release-key-id.v1\0" ‖ public key)`.

**Before every command the CLI checks:**
1. the manifest structure;
2. that the signature verifies with a key from `release-keys.json`, using Node's built-in Ed25519 (no dependency);
3. that the platform matches and the package is `ai-defender`;
4. that the protocol version is 1;
5. that the binary is inside its directory after resolving symlinks, with the expected file name;
6. that the binary is a regular file of plausible size;
7. that the SHA-256 matches.

Any failure is exit 3, with no fallback.

**Release procedure:** [RELEASING.md](RELEASING.md). CI builds and tests each engine on its own platform; the release owner signs the manifests locally with the offline key, checks the package with `npm run pack:check -- --release`, and publishes the one tarball.

## 9. Local development

```sh
cargo build -p agentguard-engine-cli
cd cli && npm install && npm run build
export AGENTGUARD_DEV_ENGINE="$(realpath ../target/debug/agentguard-engine)"
export AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1
node build/src/index.js status
```

Both variables are required. With only the first, the CLI refuses to run (exit 3). A development engine is reported as `UNVERIFIED development build` in `status`, `version` and `check`, and as `"verified": false` in JSON.

To try it without touching your real configuration, also point `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` at a temporary directory.

| Check | Command |
|---|---|
| Lint | `npm run lint` (strict `tsc --noEmit` plus `scripts/lint.mjs`) |
| Tests | `npm test` (node:test; unit, engine-client with fake engines, real-engine integration, static source checks, release scripts) |
| Package | `npm run pack:check` (exact published file list; entry point shebang; no key material) |

The integration tests need the engine built and fail (rather than skip) without it.

## 10. Where things live

| What | Linux (validated) | macOS (untested) |
|---|---|---|
| Trust store (keys, manifests, registry, integrity, trust audit, encrypted signing keys) | `$XDG_CONFIG_HOME/agentguard` (default `~/.config/agentguard`), mode 0700 | same XDG layout (no `~/Library` mapping yet) |
| Project configuration | `<project>/.agentguard/config.yaml` | same |
| Approval requests and grants | `$XDG_CONFIG_HOME/agentguard/approvals/` (inside the trust store, 0700; records 0600) | same |
| Last secret scan per project (findings without values) | `$XDG_CONFIG_HOME/agentguard/scans/` (0700; records 0600) | same |

The encrypted signing keys are `signing/root.key` and `signing/policy.key`. They are sealed with Argon2id (19 MiB, 2 passes) and XChaCha20-Poly1305 under your passphrase. **Back them up.** Keep `root.key` offline once setup is done: it is needed only to rotate keys.

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `engine package for linux-x64 … is not installed` (exit 3) | Release engine packages are not published yet. Use the development path (§9). |
| `refusing to run an unverified engine` (exit 3) | `AGENTGUARD_DEV_ENGINE` is set without `AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1`. |
| `the AI Defender engine could not be verified: …` (exit 3) | The engine package was modified or is incomplete. Reinstall; never bypass. |
| `does not support this platform` / `not available for win32-x64` (exit 3) | See §2. |
| `requires confirmation` (exit 6) | Run interactively, or add `--yes`. |
| `needs the AI Defender signing key passphrase` (exit 6) | Run interactively, or `--passphrase-file` with a mode-600 file. |
| `the passphrase is wrong or the signing key file was modified` (exit 1) | Wrong passphrase, or the key file changed; restore it from backup. |
| `INTEGRITY FAILURE` / exit 5 | Trusted state was modified, rolled back or is incomplete. See [TRUST_MODEL.md](TRUST_MODEL.md) §6 (recovery). |
| `this project's trust was revoked` | `ai-defender project trust` (deliberate re-trust). |
| `both .agentguard/config.yaml and .agent-security.yml exist` | Keep one. |
| `project policies may only add restrictions` | Remove `ALLOW` rules from the project configuration; grant exceptions in the global policy instead. |
| `--yes cannot approve an operation` (exit 6) | By design. Run `ai-defender approve <id>` yourself in a terminal. |
| `the approval request … has expired` | Pending requests last 5 minutes and grants 2 minutes; the agent must request again. |
| `the policy changed since this approval was made` | Policy or project restrictions changed; the operation must be evaluated and approved again. |

## 12. Security properties and limitations

**Properties, each with tests:**
- **No direct writes to trusted or project files.** The CLI never writes files at all; a static test forbids write APIs in its source. Every write is made by the engine through the trust layer.
- **No manufactured decisions.** The CLI cannot produce an authorization decision: there is no such command in the engine protocol, and a static test forbids constructing one.
- **No shell.** Process start uses an argument vector with `shell: false`, and a test runs a working directory containing `$(…)`, backticks and `;` without any execution.
- **Strict responses.** Malformed, mismatched, oversized, slow or inconsistent engine responses are rejected.
- **No unverified engine by accident.** A missing, tampered, wrongly signed or wrong-platform engine is never run, and the development override needs two explicit variables.
- **Non-interactive mode cannot skip what an interactive user would confirm.** Without `--yes` and a passphrase file, state-changing commands exit 6.
- **Project configuration cannot weaken the baseline.** `ALLOW` rules are rejected, and approved restrictions are floors.
- **Output hygiene.** Engine-provided text is sanitized before printing, the passphrase never appears in output (tested), and JSON output contains no key material.
- **Approval needs a human.** `approve` refuses `--yes`, `--json`, `--non-interactive`, `--passphrase-file` and sessions without a terminal, proceeds only on the typed word `approve`, and the engine requires the passphrase and refuses approval from an engine launched for an agent.

**Limitations** (see [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) L52 onwards):
- engine verification is check-then-execute;
- a same-user process that knows your passphrase, or reads it from a passphrase file, can change trusted state;
- Windows is unsupported, and macOS and arm64 are untested;
- releases are not published;
- `status` cannot prove that an agent is unprotected or protected beyond what AI Defender itself configured;
- local interactive approval cannot distinguish a human from a same-user process that knows the passphrase (L62);
- managed execution covers only commands routed through `ai-defender run` (L83 onwards);
- hooks cover only the tools listed as protected, and depend on the provider running them (L98 onwards).
