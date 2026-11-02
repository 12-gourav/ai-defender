# Cargo Workspace Design

## 1. Layout

```
agentguard/
├── Cargo.toml                 # [workspace], shared [workspace.dependencies], lints, MSRV
├── Cargo.lock
├── rust-toolchain.toml        # pinned stable
├── deny.toml                  # cargo-deny: licences, advisories, duplicate crates
├── .agent-security.yml        # AI Defender's own policy (dogfooding)
├── Dockerfile                 # sandbox base image
├── docker-compose.yml         # dev services for integration tests (disposable DBs)
├── crates/
│   ├── agentguard-core/       # newtypes, ids, errors, canonical hashing, time, redaction primitives
│   ├── agentguard-proto/      # IPC schema between shim and controller (serde + versioned, no_std-friendly)
│   ├── agentguard-shim/       # in-container binary: hook client, git remote helper, proxy stub, auth helper
│   ├── agentguard-cli/        # `ai-defender` binary (clap), thin over security-controller
│   ├── security-controller/   # session lifecycle, state dir, socket server, orchestration
│   ├── policy-engine/         # schema, parsing, validation, precedence, EffectivePolicy, policy_version
│   ├── permission-engine/     # Decision = f(policy, mode, task, request)
│   ├── approval-engine/       # typed requests, tokens, lifecycle, approval socket, TUI
│   ├── execution-gateway/     # request dispatcher for boundary crossings; host exec (no shell)
│   ├── sandbox-manager/       # Sandbox trait, DockerRootless backend, run spec, inspect verification, gVisor
│   ├── filesystem-guard/      # path canonicalisation, sync validation, protected files, symlink rules
│   ├── command-guard/         # structured command model, classification, ToolArgs validators
│   ├── secret-guard/          # gitleaks driver, native fallback, redaction, env filtering
│   ├── network-guard/         # egress proxy (HTTP/CONNECT), allowlist, deny ranges, resolver pinning
│   ├── git-guard/             # refspec parsing, quarantine fetch, validation, commit/push pipelines
│   ├── credential-broker/     # keyring, token minting (GitHub App, GitLab), one-shot credential helper
│   ├── database-guard/        # protocol proxies and statement classifiers (pg, mysql, redis, mongo)
│   ├── deployment-guard/      # tool tables (terraform, kubectl, helm, cloud CLIs), plan parsing
│   ├── agent-adapters/        # AgentAdapter trait + claude, codex, gemini, antigravity, cursor, generic
│   └── audit-engine/          # SQLx/SQLite schema, hash chain, redaction at write, query API
├── schemas/                   # agent-security.v1.json, ipc.v1.json, audit export schema
├── policies/                  # org policy examples, built-in profiles (strict, default, permissive-dev)
├── templates/                 # `ai-defender init` templates per stack
├── images/                    # Dockerfiles per agent layer, seccomp and AppArmor profiles
├── tests/
│   ├── unit/                  # (most unit tests live in crates; this holds cross-crate fixtures)
│   ├── integration/           # controller + sandbox + proxy end to end (requires rootless docker, skipped otherwise)
│   ├── adversarial/           # attack scripts run INSIDE a sandbox against a live controller
│   └── security/              # fail-closed, replay, tampering, integrity tests
└── docs/
```

## 2. Dependency direction (no cycles)

```
agentguard-core ◀── agentguard-proto ◀── agentguard-shim
      ▲
      ├── policy-engine ◀── permission-engine ◀── approval-engine
      │                                                ▲
      ├── filesystem-guard, command-guard, secret-guard, network-guard,
      │   git-guard (uses credential-broker, secret-guard, filesystem-guard),
      │   database-guard, deployment-guard (use command-guard)
      │                                                ▲
      ├── audit-engine                                  │
      ├── sandbox-manager                               │
      ├── agent-adapters (uses policy-engine, sandbox-manager, proto)
      └── execution-gateway (uses all guards, approval-engine, audit-engine)
                ▲
      security-controller (uses everything above)
                ▲
      agentguard-cli
```

Guards never depend on each other except as listed; none depends on the controller. The shim depends only on `core` and `proto` to keep it small and auditable.

## 3. Key crates and justification

| Need | Crate | Why |
|---|---|---|
| async runtime | tokio | spec |
| CLI | clap (derive) | spec |
| serialisation | serde, serde_yaml, serde_json, ciborium (canonical CBOR for hashing) | deterministic hashes |
| schema | jsonschema (validation of YAML-as-JSON), schemars (generate schema from types) | single source of truth |
| DB | sqlx (sqlite, runtime-tokio, rustls) | spec |
| logging | tracing, tracing-subscriber (json) | spec |
| crypto | sha2, rand (OsRng), subtle, zeroize, memsec | tokens, hashing, secret memory |
| git | gix (gitoxide) for object inspection and refspec parsing; `git` CLI for fetch/push with locked-down config | gix avoids executing hooks; CLI is still the most compatible transport |
| HTTP proxy | hyper + tokio for the egress proxy; rustls for optional TLS termination | no system OpenSSL dependency |
| SQL classification | pg_query (libpg_query bindings) for Postgres; sqlparser-rs as generic fallback | real parser, not regex |
| keyring | keyring | Secret Service on Linux |
| sandbox syscalls | nix, landlock, seccompiler | host exec restriction, profile generation |
| docker | bollard (Docker API over unix socket from the controller only) | typed API, inspect verification |
| TUI | ratatui + crossterm | approval UI |
| ids/time | uuid (v4), time or chrono (UTC only) | |
| errors | thiserror (libraries), anyhow (binaries) | |
| testing | proptest (refspecs, paths), insta (policy explain snapshots), assert_cmd, tempfile, testcontainers (where docker available) | |

Supply chain: `cargo deny` in CI; `cargo audit`; locked builds (`--locked`); vendored crates considered for release builds.

## 4. Conventions

- `#![forbid(unsafe_code)]` in every crate except `sandbox-manager`, `agentguard-shim` (seccomp/landlock FFI) and `credential-broker` (locked memory), where unsafe blocks are documented and reviewed.
- Clippy `pedantic` as warnings, a curated set as `deny` (`unwrap_used`, `expect_used` in non-test code, `indexing_slicing`, `panic`).
- No `String` in a security decision path: typed newtypes with validating constructors.
- Every `Deny` constructed with all five explanation fields (compile-time enforced by the constructor).
- Workspace-level `[lints]` and `[workspace.dependencies]` so versions are pinned once.
- MSRV pinned in `rust-toolchain.toml`; CI runs stable and MSRV.

## 5. Binaries

| Binary | Crate | Runs where | Trust |
|---|---|---|---|
| `ai-defender` | agentguard-cli | host | trusted |
| `agentguard-shim` (+ `git-remote-agentguard` symlink) | agentguard-shim | container | untrusted, dispensable |

Both are built statically where possible (musl target for the shim) so the image needs no runtime libraries for them.

## 6. CI

- GitHub Actions and GitLab CI pipelines with the same stages: `fmt`, `clippy`, `test` (unit), `deny`, `audit`, `build-image` (Trivy scan, digest output), `integration` (rootless docker runner), `adversarial` (same runner, runs inside disposable sandboxes), `docs` (link check).
- Integration and adversarial jobs are required to pass before a release tag; unit jobs on every push.
