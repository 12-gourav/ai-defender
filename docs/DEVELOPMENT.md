# Development Guide

## Prerequisites

| Requirement | Why | Install |
|---|---|---|
| Rust toolchain pinned in `rust-toolchain.toml` | reproducible builds | `rustup` installs it automatically on first `cargo` invocation |
| A C linker driver (`cc`, from `build-essential` on Debian/Ubuntu) | Rust links through the system C compiler driver on `x86_64-unknown-linux-gnu` | `sudo apt-get install build-essential` (root; requested, never run by AI Defender) |
| `cargo-deny`, `cargo-audit` | licence, advisory and source checks | `cargo install cargo-deny cargo-audit --locked` (user-level) |

Nothing in this repository installs software, edits shell profiles, or touches global developer settings. Phase 1 set-up on the author's host used `rustup-init -y --no-modify-path --profile minimal`, which writes only to `~/.cargo` and `~/.rustup`.

## Everyday commands

```sh
make fmt        # rustfmt
make lint       # clippy --all-targets --all-features -D warnings
make test       # cargo test --workspace
make ci         # fmt-check + lint + check + test + build, exactly what CI runs
make deny       # cargo deny check   (needs cargo-deny)
make audit      # cargo audit        (needs cargo-audit)
```

CI runs every target with `--locked`; a change to dependencies must be accompanied by the updated `Cargo.lock`.

## Workspace layout

| Crate | Role | May depend on |
|---|---|---|
| `agentguard-core` | domain types (actions, paths, project identity, security context, decisions, fingerprints), redaction primitives; no I/O | nothing internal |
| `agentguard-common` | errors, exit codes, logging, configuration, paths | core |
| `agentguard-audit` | audit events, typed security events, hash chain, sinks | core |
| `agentguard-proto` | canonical authorization protocol; strict parsing of untrusted requests | core |
| `agentguard-engine` | identity verification, risk, guards, policy, approvals, the authorization pipeline | core, proto, audit |
| `agentguard-trust` | trust store, signatures, integrity, registry, policy hierarchy, authorised updates | core, common, audit, engine |
| `agentguard-cli` | the `ai-defender` binary | core, common, audit |
| `tests/integration` | cross-crate tests, including the security invariants | all of the above (dev-dependencies only) |

The dependency direction is one-way. See [ENGINE_ARCHITECTURE.md](ENGINE_ARCHITECTURE.md).

## Building without a C compiler driver

Rust links through `cc`. On a host without `build-essential`, a wrapper that drives the toolchain's bundled `rust-lld` against the system glibc objects works for development. Point `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` at it. The wrapper is not part of the repository and not supported for release builds; installing `build-essential` is the fix.

## Engineering rules enforced by the build

- `unsafe_code = "forbid"` workspace-wide. A later crate that genuinely needs FFI (seccomp, Landlock, locked memory) overrides this for itself with a documented justification.
- Clippy denies `unwrap`, `expect`, `panic`, indexing with `[]`, `todo!`, `unimplemented!`, and `dbg!` in non-test code. Test modules opt out at the top of each crate root with a `cfg_attr(test, allow(...))`.
- `clippy.toml` disallows `std::process::Command::new` in this phase: nothing in the foundation spawns a process. The later execution gateway lifts that restriction for itself only.
- Every error `Display` names a field and a rule, never an input value. `agentguard_core::SecurityError` has no field capable of holding user input.
- Every string the CLI prints that might originate from a policy file, a path, or (later) an agent goes through `agentguard_cli::output::sanitise`.
- Logging goes through one redacting layer. Field names on the sensitive list and values that look like credentials are replaced before writing.

## Toolchain upgrades

The compiler is pinned to an exact version. To upgrade:

1. Open a change that edits `rust-toolchain.toml` and, if the minimum supported version moves, `rust-version` in `Cargo.toml`.
2. Run `make ci` locally and let CI run on the change.
3. Read the release notes for new lints that fire and fix them in the same change rather than allowing them.
4. Record the upgrade in the change description with the old and new versions.

Dependencies are upgraded the same way, one change at a time, with `cargo deny check` and `cargo audit` green.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime failure |
| 2 | usage error |
| 3 | command registered but not implemented in this phase |
| 4 | validation failed |
| 5 | preflight or environment check failed |

## Logging

`-v`, `-vv`, `-vvv` raise verbosity; `AGENTGUARD_LOG` accepts a `tracing` filter directive and overrides the flag. `--log-format json` emits one JSON object per line. Logs go to standard error; command output goes to standard output.
