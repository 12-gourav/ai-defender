# Phased Implementation Plan

Each phase: inspect repository, re-read ARCHITECTURE and the relevant design doc, state the plan and affected files, implement only the approved scope, run unit/integration/security tests, review for bypasses, update docs, report, **wait for developer authorisation** before the next phase.

Phases never commit, push, publish or install system packages automatically. Privileged setup steps are listed per phase and requested explicitly.

## Phase 0 — Research and threat modelling — COMPLETE

Deliverables: this document set. Exit: developer review.

## Phase 1 — Rust foundation — COMPLETE (2026-10-30)

Delivered (crate set per the Phase 1 brief; the fuller layout in WORKSPACE_DESIGN remains the target):
- Cargo workspace with `agentguard-core` (domain types), `agentguard-common` (errors, exit codes, redacting logging, configuration discovery/parsing/structural validation, XDG paths), `agentguard-audit` (events, hash chain, memory and JSON Lines sinks) and `agentguard-cli` (`init`, `validate`, `inspect`, `doctor`, `status`), plus `tests/integration`.
- Workspace lints: `unsafe_code = forbid`; clippy denies `unwrap`/`expect`/`panic`/indexing/`todo`/`dbg` outside tests; `clippy.toml` disallows `std::process::Command::new`.
- `Decision` type with mandatory explanation fields; `ApprovalTiming` with the two reviewed limits; `ApprovalScope::check_permitted` encoding the reusable-scope rule.
- Configuration loader: size limit, version dispatch, unknown top-level keys rejected, structural validation, deterministic null-section handling.
- Logging: one redacting layer (field-name denylist plus secret-shape detection) that owns the output stream; JSON or pretty.
- `agentguard_cli::output::sanitise`: the shared renderer for any string that may originate from a policy file, a path or an agent.
- CI for GitHub Actions and GitLab CI: fmt, clippy, check, test, build (all `--locked`), cargo-deny, cargo-audit.

Privileged setup performed: none. User-level: rustup installed the pinned toolchain into `~/.rustup` and `~/.cargo` with `--no-modify-path`.

Open blocker carried forward: the host has no C compiler driver (`cc`); local linking used a scratch-directory linker shim via `RUSTFLAGS`. Installing `build-essential` (root) is requested before Phase 2 so the standard build works unmodified.

Exit criteria met: `cargo test --workspace` (100 tests) green; `cargo clippy --all-targets --all-features -- -D warnings` green; `cargo fmt --check` green; `ai-defender doctor` reports host facts; `ai-defender init` creates a validated template.

## Phase 2 — Policy engine

Scope:
- `schemas/agent-security.v1.json` generated from Rust types via `schemars`, with `deny_unknown_fields` on all security sections.
- Parser and validator; errors name the path and the rule.
- Organisation policy loading, hard-deny and mandatory sections, deterministic precedence and merge, loosening detection.
- `EffectivePolicy` and `PolicyVersion` computation (canonical hash).
- `ai-defender validate`, `ai-defender policy explain <operation>` (prints the rule chain), `ai-defender policy test` (table-driven scenarios from a YAML file).
- Built-in profiles in `policies/`.

Tests: schema fuzzing (unknown keys, type confusion, YAML anchors/aliases bombs, merge keys), precedence property tests (lower never loosens higher), snapshot tests of `explain`.

Exit criteria: all precedence properties hold; malformed policies fail closed with actionable messages.

## Phase 3 — Security controller

Scope:
- **R-06 spike first** (moved from Phase 4 by the Phase 0 review, G15): choose the uid mapping for the agent container under rootless Docker, the control-socket permission model, and what `SO_PEERCRED` can prove under it. The peer check below is written against the spike's result.
- Session and task state machine; state dir layout; policy snapshot pinning; integrity re-check.
- Control socket server (`agentguard-proto` v1): versioned, length-prefixed, schema-validated messages; per-session socket with `0600`; peer credential check (`SO_PEERCRED`) accepting only the expected container uid mapping.
- Permission engine: `Decision = f(policy, mode, task, request)` with full explanation output.
- `ai-defender status`, `sessions`, `revoke` (state only; sandbox kill arrives in Phase 4).
- Audit engine v1: SQLite schema, hash chain, redaction at write, `audit`, `violations`, `approvals` queries.

Tests: state machine property tests; audit chain tamper detection; IPC fuzzing (malformed frames, oversized frames, slowloris).

Exit criteria: a fake client can open a session, ask decisions, and every decision is audited and explainable.

## Phase 4 — Docker sandbox

Scope:
- `Sandbox` trait; `DockerRootless` backend via bollard; fixed run-spec template; `docker inspect` verification; orphan sweep; gVisor runtime option.
- Base image Dockerfile, seccomp profile, AppArmor profile; image digest pinning and verification.
- Staging clone creation (alternates, config rewrite, hooks removal) — read side only.
- `agentguard-shim entry` minimal: start the agent command with constructed environment.
- Resource limits and cgroup delegation check in `doctor`.
- Spike and decision on file ownership under rootless Docker (R-06): subuid mapping vs Podman keep-id vs running container user mapped to host uid.

Privileged setup required (root, each step described and approved individually): `uidmap` package and `/etc/subuid`, `/etc/subgid` entries; rootless Docker installation (`dockerd-rootless-setuptool.sh`); systemd cgroup delegation drop-in; loading the custom AppArmor profile with `apparmor_parser` (otherwise `docker-default` is used and `doctor` reports the downgrade); optionally gVisor runtime registration.

Tests (integration, need rootless docker): invariant assertions; adversarial: Docker socket absent, no network route, no host paths, caps dropped, `nsenter`/`mount`/`setuid` fail, pids limit enforced, memory limit enforced; sandbox refuses to start when any invariant is broken.

Exit criteria: `ai-defender run --generic bash` gives a shell inside a verified container with the staging clone and nothing else.

## Phase 5 — Execution gateway

Scope:
- Gateway dispatcher over the control socket: hook queries, exec requests, sync requests.
- Command guard: structured command model (`Executable`, `Args`), shell detection and higher-risk classification, per-tool `ToolArgs` validators for the host exec table.
- Filesystem guard: canonicalisation, protected-file matching, sync-path validation rules (prepared for Phase 7).
- Host exec: direct spawn without shell, constructed env, Landlock restriction of the spawned process to declared paths where the kernel supports it, timeouts, output size limits.
- `agentguard-shim hook` for the generic JSON protocol; adapters supply translation in Phase 10.

Tests: argument injection corpus (`--` handling, flags that read files, env-var expansion), path corpus (traversal, Unicode normalisation, case folding, NUL, long paths), shell chain corpus (classification only), Landlock escape attempts.

Exit criteria: gateway requests outside the defined request types are denied with explanations; the host-exec path is present only as a hard-deny stub in the pilot (Phase 0 review, Q6).

## Phase 6 — Approval engine

Scope:
- Typed request structs and canonical hashing; token lifecycle; one-time consumption inside the execution critical section; expiry; cancellation on revoke/session end/policy change.
- Approval socket and `ai-defender approvals --watch` TUI; session phrase; untrusted-text box; typed confirmations.
- Task context creation and confirmation at session start; `TaskScopeChangeRequest`; `ai-defender task grant` for non-interactive pre-authorisation; `ai-defender policy approve` privileged flow.
- Non-interactive mode semantics (RequiresApproval → Deny).

Tests: replay, expiry, cross-session, cross-task, substitution (mutate one field after approval), concurrent consumption race, UI anti-spoof (agent output containing fake prompts does not reach the UI), TTL cannot exceed org maximum.

Exit criteria: every security test in the approvals section of SECURITY_TESTING passes.

## Phase 7 — Credentials and Git

Scope:
- Credential broker: keyring integration, locked memory, one-shot credential helper, GitHub App token minting, GitLab token support, SSH-agent-on-host path.
- `git-remote-agentguard` helper in the shim (fetch and push capabilities).
- Git guard: refspec parsing with gix, quarantine repo, locked-down git invocation, validation pipeline, commit sync with compare-and-swap, push with `--force-with-lease`, branch protection checks via provider API.
- `ai-defender sync`.

Tests: hostile `.git/config` and hooks in the staging clone never execute on host; refspec corpus (force, mirror, tags, deletes, odd encodings); CAS races; approval binds exact SHA set; token never appears in container, process list, or logs.

Exit criteria: full workflow "edit, commit, approve, push to feature branch" works with a scripted git client in the generic adapter (Claude Code end to end moves to Phase 10); protected-branch push denied; force push denied; AC-F4 (audit write failure denies a push) verified here.

## Phase 8 — Secrets and networking

Scope:
- Egress proxy: HTTP and CONNECT, allowlist, resolver pinning, deny ranges, metadata hard-deny, per-connection audit without payloads; optional TLS termination and header injection (`api.anthropic.com` credential injection as an alternative to in-container credentials).
- Shim proxy stub.
- Secret guard: gitleaks driver, native fallback, staging-clone scrub option, environment construction, audit redaction improvements.
- `NetworkAccessRequest` from proxy denials when policy allows.
- Trivy integration for lockfile deltas.

Privileged setup required: none (gitleaks and trivy are user-space binaries; absence is reported, never silently skipped).

Tests: exfiltration corpus (IP literals in every notation, DNS rebinding simulation, redirects to denied hosts, IPv6, CONNECT to non-443, WebSocket upgrade, HTTP/2 prior knowledge), DNS unreachable, UDP/ICMP fail, secrets in env absent inside, audit contains no secret from a planted corpus.

Exit criteria: all network and secret acceptance criteria pass.

## Phase 9 — Database and infrastructure

Scope:
- Database guard: Postgres proxy with pg_query classification; Redis RESP; MySQL and Mongo adapters; production hard-deny; destructive approvals; row estimates via EXPLAIN where permitted.
- Deployment guard: tool table (terraform plan/apply, kubectl, helm, gcloud, aws, az, gh workflow run, glab pipeline run), plan parsing for the prompt, typed deployment approval, brokered short-lived cloud credentials (STS / workload identity) on the host.
- Dependency approval flow completion (lockfile adapters per package manager).

Tests: SQL evasion corpus (comments, case, encoding, `DO $$`, prepared statements, `COPY`, multi-statement), production host appearing via DNS or IP, terraform destroy without approval, kubectl delete without approval, lockfile tampering between approval and sync.

Exit criteria: dev DB usable through the guard; destructive statements require typed approval; production unreachable.

## Phase 10 — Agent integrations

Scope: Claude Code adapter (managed settings, hooks with `onFailure: block`, `PermissionRequest` routing, auth helper), Codex adapter (requirements.toml, inner sandbox decision R-11), Gemini CLI adapter, Antigravity CLI adapter, Cursor CLI verification spike, generic adapter polish, `ai-defender inspect` capability reporting, `ai-defender init` templates per agent.

Tests: for each adapter, an adversarial prompt suite executed by the real agent inside the sandbox attempting every item in the attack coverage matrix; results recorded per adapter.

Exit criteria: each adapter's reported tier matches observed behaviour; no adapter claims more than it demonstrates.

## Phase 11 — Security verification

Scope: full unit, integration, adversarial and security suites in CI; fail-closed drills (kill controller mid-push, corrupt policy snapshot mid-session, remove scanner, fill disk, kill shim); isolation verification report; update KNOWN_LIMITATIONS and RISK_REGISTER with evidence; attack coverage matrix completed with pass/fail/untested.

Exit criteria: all acceptance criteria have a passing test or a documented, accepted gap.

## Phase 12 — Production pilot

Scope: install script (user-space), release automation (signed binaries, SBOM, image digests), documentation for developers and administrators, independent security review scheduling and findings remediation, pilot on a non-production project, staged rollout plan.

Exit criteria: independent review completed; pilot project runs one full sprint through AI Defender with no fail-open incidents.
