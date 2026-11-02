# Production audit (2026-11-02, version 0.1.1)

Audit of the repository before production hardening: what exists, what it guarantees, and what
blocks a cross-platform release. Earlier phase reviews are in `REPOSITORY_AUDIT.md` and
`KNOWN_LIMITATIONS.md`; this document does not repeat them.

## Architecture as built

| Layer | Where | Role |
|---|---|---|
| Rust engine | `crates/agentguard-engine-cli` (binary `agentguard-engine`) | The only security authority. JSON request/response over stdin/stdout, protocol 1. |
| Decision engine | `crates/agentguard-engine` | Normalises actions; evaluates the mandatory baseline, the balanced profile, global and project rules. |
| Trust store | `crates/agentguard-trust` | Signed policy, project registry, approvals, executions, scans, signing keys. JSON files under `~/.config/agentguard`, written atomically. |
| Audit | `crates/agentguard-audit` | Hash-chained JSONL (`audit/trust.jsonl`). |
| Execution | `crates/agentguard-exec` | `run`: no-shell execution, filtered environment, time limits, process groups, resource limits. |
| Hooks | `crates/agentguard-hooks` | Claude Code and Codex adapters; a verified engine copy is the hook executable. |
| Secrets | `crates/agentguard-secrets` | Pattern detection, sensitive-path classification, Git index scanning. |
| CLI | `cli/` (npm `ai-defender`) | TypeScript user interface. Verifies the engine's signed manifest before every use; makes no decisions. |

Storage is not SQLite: it is signed JSON and hash-chained JSONL. There is no database engine to
port or lock.

## Security guarantees that hold today (Linux, verified by 447 Rust and 54 CLI tests)

- Policy, registry and approvals are Ed25519-signed; tampering is detected and fails closed.
- Signing keys are encrypted at rest: Argon2id (19 MiB, 2 passes, 1 lane: the OWASP minimum) and
  XChaCha20-Poly1305. Passphrases are at least 12 characters, read from a hidden prompt or a
  private file, never from argv or the environment, and zeroised after use.
- Approvals are single-use, expiring, bound to the exact operation and redeemed with a claim token.
  Agents cannot run approval or configuration commands (`guard.self-approval`), nor touch trusted
  state (`guard.trusted-state`).
- The mandatory baseline (40 floors) cannot be weakened by profiles or projects.
- Engine binaries are verified (signed manifest, platform, protocol, SHA-256) before every use; the
  hook executable is a protected copy bound to the verified hash.

## Gaps against the production brief

| Area | Finding | Severity |
|---|---|---|
| Windows | The workspace does not compile for Windows: 59 Unix-specific call sites in 23 files (`O_NOFOLLOW` opens, owner and mode checks on the trust store, process groups, signals, `rlimit`). Each is security-relevant; a port needs Windows equivalents (reparse-point handling, owner and DACL checks, Job Objects), not stubs. | Blocks Windows |
| macOS | Code is POSIX and expected to compile, but it has never been built or tested on macOS. Building needs a macOS runner; cross-compiling from Linux needs Apple's SDK, which is not licensed for that. | Blocks macOS |
| Linux arm64 | Static musl binary builds locally (4.4 MB). Not executed: no arm64 machine or emulator available here. | Blocks claim |
| Distribution | Engines shipped as separate per-platform npm packages (`ai-defender-engine-*`). The brief requires one package. | Done in 0.2.0 |
| Passphrase attempts | No attempt limiting. Offline guessing is bounded by Argon2id; the interactive path has no backoff. | Medium |
| Uninstall | No `ai-defender uninstall`. `integrations uninstall` exists (passphrase-protected). | Missing |
| OS key stores | Not used. Keys are passphrase-encrypted files; see the decision below. | Decision |
| Agents | Claude Code and Codex only. Claude Code before 2.1.295 ignores `onFailure`, so a crashed hook fails open there. | Documented |
| CI | Workflows exist but have never run: there is no Git remote. | Blocks release matrix |
| Development friction | With the Claude integration installed, `guard.self-approval` denies commands that name the engine, including building and testing AI Defender itself. Working as designed; it means AI Defender cannot be developed under its own enforcement. | Process |

## Decisions

- **One package, embedded engines.** `ai-defender` will carry every validated engine under
  `binaries/<platform>/`, each with its signed manifest. npm limits allow it (each static engine is
  4 to 6 MB). No install script and no download: the integrity of every engine is covered by the
  npm tarball hash and by the manifest signature checked before each use.
- **The master password is the existing signing-key passphrase.** It already meets the brief
  (Argon2id, no plaintext, no argv or environment). It is never stored; only the encrypted key
  files, whose authenticated decryption is the verifier.
- **OS key stores are not used for the signing key.** Placing the key, or a key that unwraps it, in
  the Keychain, Credential Manager or Secret Service would let any process in the user's session
  sign policy without the password, which is weaker than the current design. Key stores remain an
  option only for non-authorising material.
- **Only validated platforms are published.** A platform is declared in `os`/`cpu` and documented
  only after its engine has passed the test suite on that platform.

## Outcome for 0.2.0 (2026-11-02)

| Item | Result |
|---|---|
| One package | `ai-defender` bundles the four engines; no dependencies, scripts or downloads |
| Linux x64/arm64, macOS x64/arm64 | Full Rust suite and global-install test on each platform's GitHub runner |
| Windows | Platform layer done (owner SIDs, DACLs, reparse points, file identity, Job Objects) and the audit, secrets, common and trust crates compile for Windows. Not released: path rules for case-insensitive names, trailing dots and spaces, alternate data streams, 8.3 names and device names come first, with a bypass test suite on Windows CI. Planned for 0.3.0 |
| Master password | The signing-key passphrase; wrong attempts now back off (five free, then 30 s doubling to 15 min) |
| Uninstall | `ai-defender uninstall [--purge]`, engine-side `system.uninstall`: passphrase, agents refused, history kept unless purged; `npm uninstall -g` bypass documented |
| Found and fixed during hardening | A repository-planted Git filter ran during `git status`/`inspect` (via `write-tree`); a project directory recreated at the same path was accepted on ext4 (inode reuse) |
| Cursor, Antigravity | Researched (`AGENT_INTEGRATION_RESEARCH.md`); adapters planned for 0.3.0 |
| Perplexity | No interception mechanism exists; unsupported |
