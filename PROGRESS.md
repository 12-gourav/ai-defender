# AgentGuard progress checklist

Phases run sequentially. A phase starts only after the developer authorises it.

## Engine track (hook-driven local engine, ADR-0013)

### Phase 0: Repository audit — COMPLETE (2026-10-30)

- [x] Existing workspace inspected; baseline gate green (100 tests) before any change
- [x] Duplications and weaknesses recorded in docs/REPOSITORY_AUDIT.md (W1 to W6)
- [x] Direction change recorded as ADR-0013; ADR-0002/0006/0012 marked partly superseded

### Phase 1: Security foundation — COMPLETE (2026-10-30)

- [x] Core: typed actions for 10 categories, `NormalizedPath` + `PathResolver`, `ProjectIdentity`, `SecurityContext`, tri-state `Decision`, `OperationFingerprint`, `ApprovalId`
- [x] `agentguard-proto`: canonical request/response, strict parsing, non-leaking errors
- [x] `agentguard-engine`: identity verification, risk classifier, trusted-state guards, `PolicyEvaluator` + `RuleSetPolicy`, approval binding, fail-closed `Authorizer`, `FsPathResolver`
- [x] `agentguard-audit`: typed `SecurityEvent`s, correlation fields; JSONL chain verified on open, symlinks refused
- [x] Redaction strengthened (assignments, headers, flags, all whitespace)
- [x] Ten security invariants implemented and tested end to end; enforcement points mutation-checked
- [x] Gate green: fmt --check, clippy -D warnings (all targets/features), check, test (177), build, doc, all `--locked`
- [x] Docs: ENGINE_ARCHITECTURE, PROTOCOL, SECURITY_INVARIANTS, SECURITY_TESTING §0, REPOSITORY_AUDIT, KNOWN_LIMITATIONS L25 to L36
- [ ] Developer installs `build-essential` (build host has no `cc`; tests ran through a `rust-lld` wrapper)
- [ ] Developer authorisation to begin Phase 2

### Phase 2: Trusted policy, root of trust and tamper protection — COMPLETE (2026-10-31)

- [x] `agentguard-trust` crate: trust store layout under XDG config (0700), safe reads (`O_NOFOLLOW`, owner, mode, size), atomic versioned commits
- [x] Ed25519 via `ed25519-dalek` (strict verification, weak keys refused, purpose-separated); root key → key set → policy signers
- [x] Signed, hash-chained manifests (global, per project); signed registry with directory identity; signed integrity state; high-water mark (integrity and key-set versions)
- [x] Hierarchy: mandatory baseline > global > project (restrictions only) > request; floors cannot lower defaults; deterministic merge
- [x] Authorised workflows: initialise, register, revoke, update policy, rotate key set, quarantine (recovery); human requester + trusted signer; audited before and after
- [x] `load_runtime`: verified effective policy and registry, or deny-all lockdown; project policy drift detection
- [x] Optional administrator system anchor (`/etc/agentguard/root.json`)
- [x] Trust audit events (15 kinds) through the existing hash-chained audit
- [x] Phase 0 finding W4 (policy discovery shadowing) resolved
- [x] 12 Phase 2 invariants tested end to end; 13 of 13 enforcement-point mutants caught
- [x] Gate green, all `--locked`: fmt --check, clippy -D warnings, check, build, doc, test (223)
- [x] Docs: TRUST_MODEL.md, ADR-0014, SECURITY_INVARIANTS (Phase 2), KNOWN_LIMITATIONS L37 to L44
- [ ] Developer installs `build-essential` (still no `cc` on the build host)
- [ ] Developer authorisation to begin Phase 3
### Phase 3: Policy and permission evaluation engine — COMPLETE (2026-10-31)

- [x] Categories: package-manager, cloud, configuration, unknown (plus Git branch-list/switch/add/stash/clean, database migrate/bulk-load)
- [x] `SecurityAction` normalisation: executable, capabilities, resource, confidence; side-effect-free terminal analysis (tokeniser, segments, command classes)
- [x] Resource classification interface and default classifier (resolved paths, case-insensitive sensitive names, terminal path arguments resolved)
- [x] Risk: level, factors, confidence, reversibility, scope
- [x] Rule engine: resource kind/pattern, executable, agent, project, risk bounds, typed conditions, bounded globs, priority, conflict reporting
- [x] Mandatory baseline (moved from trust, extended with terminal equivalents, bypass and critical-destructive DENY) and the configurable `balanced` profile
- [x] `LayeredPolicy` precedence: global → profile → default, mandatory and project floors; `PolicyIntegrity` (trust `Verified`, lockdown `Failed`)
- [x] `evaluate(request, context, policy)` API and `EvaluationContext`; `Authorizer` rewired onto it with step events
- [x] 16 Phase 3 invariants tested end to end; 16 of 16 enforcement-point mutants caught
- [x] Gate green, all `--locked`: fmt --check, clippy -D warnings, check, build, doc, test
- [x] Docs: POLICY_EVALUATION.md; SECURITY_INVARIANTS (Phase 3); KNOWN_LIMITATIONS L45 to L51; PROTOCOL, ENGINE_ARCHITECTURE, TRUST_MODEL, SECURITY_TESTING updated
- [x] Developer authorisation to begin Phase 4

### Phase 4: Global npm CLI, installation and project initialisation — COMPLETE (2026-10-31)

- [x] `agentguard-engine-cli` crate: `agentguard-engine` binary, versioned JSON protocol (`agentguard.engine.v1`), bounded stdin/stdout, fixed error codes
- [x] Engine commands: version, status, check, policy.show, project.list, project.inspect, config.validate, project.init, project.trust, project.revoke
- [x] Passphrase-encrypted signing keys (Argon2id + XChaCha20-Poly1305) in the trust store; changes need confirmation and the passphrase
- [x] `.agentguard/config.yaml` (untrusted, restrictions only, never overwritten; legacy `.agent-security.yml` read when alone)
- [x] TypeScript CLI (`cli/`, zero runtime dependencies): init, status, check, policy show, project list/inspect/trust/revoke, version; `--json`, `--no-color`, `--non-interactive`, `--yes`, `--passphrase-file`; exit codes 0 to 7
- [x] Platform engine packages with signed manifests, verified before every run; release scripts; development override (two variables, always reported unverified)
- [x] 15 Phase 4 security requirements tested (SECURITY_INVARIANTS, Phase 4)
- [x] Docs: CLI.md, cli/README.md; SECURITY_INVARIANTS, KNOWN_LIMITATIONS L52 to L61, ENGINE_ARCHITECTURE, TRUST_MODEL updated
- [ ] Developer provisions a release signing key and publishes engine packages (CLI.md §8)
- [x] Developer authorisation to begin Phase 5 (approval workflow, 2026-10-31)

### Phase 5: Human approval workflow and authorization grants — COMPLETE (2026-10-31)

- [x] Canonical operation digest v2 (`binding`): category, operation, tool, normalized arguments, target, project, agent, session, working directory, policy version; operations the protocol cannot bind exactly cannot be approved
- [x] `agentguard_trust::approvals`: typed request, decision, approver identity, grant, status models; file store inside the trust store (schema file, migrations hook, 0600 records); exclusive cross-process transactions
- [x] Approval authenticated by the policy-signing key passphrase; grants Ed25519-signed (`approval-grant` purpose) and verified at every redemption
- [x] Claim tokens (256-bit, RFC 8628 pattern), SHA-256 verifiers only; never in listings, output or audit
- [x] Atomic validate/consume with replay detection; re-verification of identity, policy integrity and policy version; recomputed digest; DENY overrides approvals
- [x] Lifecycle: pending, approved, rejected, expired, cancelled, consumed; duplicates join; revocation; policy-change invalidation; expiry 5 min / 2 min defaults, trusted global settings within hard maximums
- [x] 13 audit event kinds; JSON Lines audit sink made safe across processes
- [x] Engine commands: approval.request/list/show/approve/reject/cancel, authorization.validate/consume/revoke; `--agent` launch for agent-side commands; 5 new error codes
- [x] CLI: `approvals`, `approvals show|cancel|revoke`, `approve`, `reject`; approve refuses `--yes`, `--json`, `--non-interactive`, `--passphrase-file` and non-TTY sessions
- [x] Guard: agents cannot run `approve`, `reject`, `approvals` or the engine binary
- [x] 22 Phase 5 invariants tested, including 16-thread and 8-process consumption races (lock mutation-checked)
- [x] Gate green: fmt --check, clippy -D warnings, check, test, doc (all `--locked`); CLI lint, typecheck, tests, pack check
- [x] Docs: APPROVALS.md; SECURITY_INVARIANTS (Phase 5); KNOWN_LIMITATIONS L62 to L72; CLI.md, ENGINE_ARCHITECTURE, TRUST_MODEL, APPROVAL_MODEL updated
- [x] Developer authorisation to begin Phase 6 (sensitive files and secrets, 2026-10-31)

### Phase 6: Sensitive files, secrets protection and data loss prevention — COMPLETE (2026-10-31)

- [x] `agentguard-secrets` crate: `Detector` interface; 21 built-in provider/structural detectors, credential assignments, high-entropy strings, custom patterns (linear-time regex, `RegexSet` prefilter)
- [x] Redaction keeping only public provider prefixes; core `redact_text` extended with detector spans; CLI output redaction as defence in depth
- [x] Bounded scanner: no symlink following, `O_NOFOLLOW|O_NONBLOCK`, size/file/byte/finding limits, streaming 64 KiB line segments, binary detection, exclusions reported, incomplete scans flagged
- [x] Staged changes from `.git/index` (v2 to v4, cache tree, stat verification) without running Git
- [x] Sensitive categories, trusted `sensitive` configuration (protected patterns, detectors, scan exclusions) in global and project layers (additions only), part of the policy version
- [x] File operations: append, copy, upload, download, archive, traverse; inline `content` for writes (inspected, bound by SHA-256, never stored)
- [x] Content evidence and disclosure assessment as typed rule conditions; mandatory DENY for secret disclosure, secret commits and secrets into ordinary files; `.env` approval floor; balanced profile sensitive read DENY / write approval / delete DENY / source-with-secrets approval
- [x] 11 audit event kinds (sensitivity steps in the decision pipeline, scan events)
- [x] Engine commands `secrets.scan/status/explain/preview`; CLI `agentguard secrets scan|status|explain|preview`
- [x] 18 Phase 6 invariants tested; 10 of 10 enforcement-point mutants caught
- [x] Gate green: fmt --check, clippy -D warnings, check, test, doc (all `--locked`); CLI lint, typecheck, tests, pack check
- [x] Docs: SECRETS.md; SECURITY_INVARIANTS (Phase 6); KNOWN_LIMITATIONS L73 to L82; PROTOCOL, POLICY_EVALUATION, CLI.md, ENGINE_ARCHITECTURE updated
- [x] Developer authorisation to begin Phase 7 (Git security, terminal governance and controlled execution, 2026-10-31)

### Phase 7: Git security, terminal command governance and controlled execution — COMPLETE (2026-10-31)

- [x] `agentguard-exec` crate: request validation, trusted executable resolution and identity, environment profiles, strict shell subset with canonical rendering, Git adapter, bounded process runner (private, behind a sealed `Permit`), executor
- [x] Managed mode (argv, no shell; `quote_argv` round trip into the existing terminal policy) and shell mode (`sh`/`bash` subset; everything else refused)
- [x] Git adapter: structured parsing, refused repository/config-selecting options and unknown subcommands, staged-index-only commits, exact pushes to configured remotes; hardened read-only inspection; repository identity, branch, HEAD, staged tree, push range, remote URL identity (credentials removed)
- [x] Operation digest v3 with an execution binding (program identity, argv, environment, time limit, repository facts); revalidation before spawn; commit and push verification
- [x] Secret scans of staged content and pushed commits as host-supplied evidence (`HostInspection`) into the Phase 6 mandatory rules
- [x] Policy: `Force` condition covers terminal Git; `profile:git-force-push` (DENY, overridable to approval) with `mandatory:git-force-push` floor; `profile:destructive-protected`, `profile:permission-protected`; system administration, environment dumps, secret extraction and destructive database commands classified; mandatory baseline v4, balanced profile v3
- [x] Environment isolation (`env_clear`, profiles, credential and injection names never passed, trusted `PATH`, non-interactive fixed variables), output redaction, `no_new_privs` and no core dumps (engine binary), process groups and signal forwarding (Linux)
- [x] Idempotent execution records in the trust store; no retries; fail-closed audit; indeterminate outcomes reported
- [x] Engine commands `execution.run/history/inspect`, `git.status/inspect`; error codes `execution-duplicate`, `outcome-unrecorded`; `status` enforcement coverage
- [x] CLI `agentguard run`, `agentguard git status|inspect`, `agentguard execution history|inspect`; approval wait loop; exit codes 8, 9, 124, 125
- [x] 13 audit event kinds for execution
- [x] 20 Phase 7 invariants tested; 13 enforcement-point mutants, 11 caught, 2 survive as redundant layers
- [x] Gate green: fmt --check, clippy -D warnings, check, test, doc (all `--locked`); CLI lint, typecheck, tests, pack check
- [x] Docs: EXECUTION.md; SECURITY_INVARIANTS (Phase 7); KNOWN_LIMITATIONS L83 to L97; POLICY_EVALUATION, APPROVALS, CLI.md, ENGINE_ARCHITECTURE, READMEs updated
- [x] Developer authorisation to begin Phase 8 (Claude Code and Codex hooks, 2026-10-31)

### Phase 8: Official Claude Code and OpenAI Codex hook integrations — COMPLETE (2026-10-31)

- [x] Official documentation reviewed 2026-10-31 (Claude Code hooks reference; Codex hooks reference via developers.openai.com → learn.chatgpt.com)
- [x] `agentguard-hooks` crate: per-provider payload validation and normalization (Claude Code tools; Codex Bash, apply_patch parsing, MCP), decisions through the existing evaluator, provider responses, installer, coverage tables
- [x] Hook entry point `agentguard-engine hook <provider> <event>` (Rust, one process per call, no daemon); PreToolUse enforcement, PostToolUse audit, SessionStart context
- [x] Approvals: block, pending request (reused across retries), human `agentguard approve`, retry redeems the one-time grant bound to tool input, content and Git state
- [x] Fail-closed responses for every engine-side failure; Claude Code `onFailure: "block"`; Codex `|| exit 2`
- [x] Guard extended to agent hook configuration and the engine binary (including `~/` and `$HOME/` spellings)
- [x] Engine commands `integrations.list/status/coverage/verify/install/uninstall`; CLI `agentguard integrations …`; install backups, idempotent, user entries preserved; uninstall needs the passphrase
- [x] 8 hook audit event kinds
- [x] 22 Phase 8 invariants tested; 7 of 7 hook mutants caught
- [x] Latency measured (release, Linux): about 16 ms per allowed call, about 17 ms per deny, about 120 ms with Git inspection and approval creation; about 12 MiB peak memory
- [x] Gate green: fmt --check, clippy -D warnings, check, test, doc (all `--locked`); CLI lint, typecheck, tests, pack check
- [x] Docs: HOOKS.md; SECURITY_INVARIANTS (Phase 8); KNOWN_LIMITATIONS L98 to L111; CLI.md, ENGINE_ARCHITECTURE, AGENT_INTEGRATIONS, READMEs updated
- [ ] Developer authorisation to begin Phase 9

## AI Defender productization (brief received 2026-10-31)

Plan and audit: [docs/AI_DEFENDER_PLAN.md](docs/AI_DEFENDER_PLAN.md). This track replaces the earlier Phase 9 plan; the SQLite store is reconsidered there.

### Subphase A: Repository audit and product renaming — COMPLETE (2026-10-31)

- [x] Architecture audit (what works, development-only paths, environment variables, fixed paths, platform-specific code, provider versions, brief mismatches, decisions D1 to D7)
- [x] npm package `ai-defender`; executables `ai-defender` and `agentguard` (alias)
- [x] CLI, engine messages, hook responses and current documentation renamed; crate names, engine binary, storage paths and protocol identifiers kept (D7)
- [x] Hook marker renamed with legacy marker recognition (existing installations upgrade cleanly)
- [x] Guard and managed execution cover the new command name; `integrations` and `projects` added to guarded subcommands; `AI_DEFENDER_*` bypass marker
- [x] Gate green: fmt --check, clippy -D warnings, check, test, doc (all `--locked`); CLI lint, typecheck, tests, pack check
- [x] Developer authorisation to prepare npm publication (decisions D1 to D7 taken as recommended)

### Publication preparation — COMPLETE (2026-10-31), not published

- [x] npm names checked (unpublished): `ai-defender`, `ai-defender-engine-{linux,darwin}-{x64,arm64}`
- [x] package.json: description, keywords, os/cpu, files allowlist, optionalDependencies on per-platform engine packages, prepack docs sync, pack:check (versions, docs, secrets, paths)
- [x] Engine packages renamed to unscoped `ai-defender-engine-<platform>`; Linux targets static musl; LICENSE included
- [x] Hooks run a verified engine copy in trusted storage, bound to the SHA-256 the CLI verified against the signed manifest
- [x] New commands: projects (list/inspect/add/revoke), policy validate, history (--blocked/--approvals/--limit), doctor, repair, update, dashboard; engine `history.list`, `prerequisites`, `integrations.repair`
- [x] README (npm landing page), SECURITY.md, LICENSE (Apache-2.0), docs/RELEASING.md
- [x] Release workflow (tag-only; signing and publishing behind protected environments; npm trusted publishing with provenance); CI: CLI matrix, macOS tests, global-install end-to-end
- [x] Global-install end-to-end test: 10/10 (no Rust on PATH, verified engine, two projects, Claude integration, tamper rejection, reinstall, uninstall keeps data)
- [ ] Release key provisioned, repository published, release workflow run, first manual publish (maintainer)

### Phase 9: Audit store (SQLite) — superseded by the AI Defender plan

## Containment track (optional hardened tier; history)

## Phase 0: Research and threat modelling — COMPLETE (2026-10-30)

- [x] Research official AI provider integrations (Claude Code, Codex, Gemini CLI, Cursor, Antigravity)
- [x] Define attacker capabilities
- [x] Define trust boundaries
- [x] Identify host and container risks
- [x] Define security guarantees and non-guarantees
- [x] Document architecture decisions (ADR-0001 to ADR-0012)
- [x] Create security acceptance criteria
- [x] Initial risk register
- [x] Initial attack coverage matrix
- [x] Architecture review written (docs/PHASE_0_REVIEW.md), independent adversarial review merged
- [x] Review corrections applied to the design documents (2026-10-30)
- [ ] Developer answers to review questions Q1 to Q7 (see docs/PHASE_0_REVIEW.md section 8)
- [x] Developer authorisation to begin Phase 1 (2026-10-30)

## Phase 1: Rust foundation — COMPLETE (2026-10-30)

- [x] Cargo workspace: `agentguard-core`, `agentguard-common`, `agentguard-audit`, `agentguard-cli`, `tests/integration`
- [x] Pinned toolchain (`rust-toolchain.toml`), rustfmt, clippy config, Makefile, .editorconfig, .gitignore, deny.toml
- [x] CLI: `--version`, `--help`, `init`, `validate`, `inspect`, `doctor`, `status` (each honest about Phase 1 scope)
- [x] Domain types: AgentIdentity, SessionId, TaskId, RepositoryId, PolicyVersion, PermissionLevel, OperationType, RiskLevel, SecurityDecision, SecurityError, ApprovalScope, ApprovalTiming, BoundedText, Sensitive
- [x] Centralised errors with stable exit codes; messages carry rules, never values
- [x] Structured redacting logging (pretty and JSON)
- [x] Configuration discovery, size-limited YAML parsing, version dispatch, unknown-key rejection, structural validation interface
- [x] Audit foundation: typed events, redaction at construction, hash chain, memory and JSON Lines sinks
- [x] Tests: 100 (unit, CLI end-to-end, cross-crate integration, error handling, configuration parsing)
- [x] Quality gate green: fmt --check, clippy -D warnings (all targets, all features), check, test, build, all `--locked`
- [x] CI: GitHub Actions and GitLab CI (fmt, clippy, test, build, cargo-deny, cargo-audit)
- [x] Documentation: docs/DEVELOPMENT.md, README, this checklist, design documents amended per the Phase 0 review
- [ ] Developer installs a C compiler driver (`build-essential`) so the standard build works without the local linker shim
- [ ] Developer authorisation to begin Phase 2
## Phase 2: Policy engine — NOT STARTED
## Phase 3: Security controller — NOT STARTED
## Phase 4: Docker sandbox — NOT STARTED
## Phase 5: Execution gateway — NOT STARTED
## Phase 6: Approval engine — NOT STARTED
## Phase 7: Credentials and Git — NOT STARTED
## Phase 8: Secrets and networking — NOT STARTED
## Phase 9: Database and infrastructure — NOT STARTED
## Phase 10: Agent integrations — NOT STARTED
## Phase 11: Security verification — NOT STARTED
## Phase 12: Production pilot — NOT STARTED

## Host prerequisites observed on 2026-10-30 (not installed by AgentGuard)

| Tool | Status | Needed from |
|------|--------|-------------|
| rustc / cargo | installed 1.99.1 (user-level, rustup, no profile edits) | Phase 1 |
| C compiler driver (`cc`, build-essential) | **missing**; needed to link Rust binaries; root install requested | Phase 1 |
| docker (rootless) | missing | Phase 4 |
| gitleaks | missing | Phase 8 |
| trivy | missing | Phase 8 |
| gVisor (runsc) | missing, optional | Phase 4 |
| bubblewrap | not checked | optional, Phase 5 |
| Landlock | kernel 7.0, enabled | Phase 5 |
| AppArmor | active; `apparmor_restrict_unprivileged_userns=1` (profile needed for unconfined userns tools) | Phase 4 |
| cgroup v2 | present, cpu/memory/pids delegated to the user session | Phase 4 |
| unprivileged user namespaces | enabled | Phase 4 |
| claude CLI | present | Phase 10 |
| codex / gemini / cursor-agent / antigravity | missing | Phase 10 |

Installing any of these is a privileged setup step that will be described and approved explicitly before it happens.
