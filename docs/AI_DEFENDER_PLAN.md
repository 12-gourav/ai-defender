# AI Defender: repository audit and productization plan

Status:
- Subphase A, audit and product renaming: **implemented** (2026-10-31).
- Publication preparation (B, C and parts of D, G and H): **implemented** (2026-10-31); see [RELEASING.md](RELEASING.md).
- Decisions D1 to D7 below were taken as recommended.

Scope: turning the AgentGuard repository (Phases 0 to 8) into the globally installable npm
product **AI Defender** (`npm install -g ai-defender`) without weakening any existing security
guarantee.

## 1. Audit: what exists

| Area | State | Where |
|---|---|---|
| Rust security engine (policy, guard, risk, approvals, secrets, managed execution, hooks) | working, tested on Linux (446 Rust tests) | `crates/agentguard-*` |
| Trusted state | working: Ed25519-signed policy, key set, registry and integrity state; Argon2id-sealed signing keys; anti-rollback; JSONL hash-chained audit | `agentguard-trust` |
| Project registration | working: `project init/list/inspect/trust/revoke`; registry entries are signed; moved directories are detected (`directory_matches`) | engine `manage.rs`, `inspect.rs` |
| Approvals and one-time grants | working, file-based with flock transactions | `agentguard_trust::approvals` |
| SQLite storage | **does not exist**. State is signed files plus JSONL; the SQLite store was the planned Phase 9 | — |
| Secret scanning, managed Git and terminal execution | working | `agentguard-secrets`, `agentguard-exec` |
| Claude Code and Codex hooks | working against documented payloads; not yet exercised with the real agents | `agentguard-hooks` |
| TypeScript CLI | working: user interface only, never decides; no network, no shell, no file writes (static tests) | `cli/` (51 tests) |
| Engine distribution design | **designed, not operational**. Per-platform npm packages `@agentguard/engine-<platform>` with a signed `engine-manifest.json` verified against `release-keys.json` before every use; package and signing scripts exist | `cli/src/services/installer.ts`, `cli/scripts/build-engine-package.mjs`, `sign-engine-manifest.mjs` |
| Release keys | **none provisioned** (`release-keys.json` has no keys), so release verification fails closed and only the development override works today | `cli/release-keys.json` |
| CI | GitHub Actions and GitLab CI: fmt, clippy, check, test, build, cargo-deny, cargo-audit. **Linux only**; no CLI job, no release job, no cross-builds | `.github/workflows/ci.yml`, `.gitlab-ci.yml` |
| npm postinstall | none (by design: installation never executes a binary) | `cli/package.json` |

### Development-only today

- **Engine override.** `AGENTGUARD_DEV_ENGINE` plus `AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1` is the
  only way to run the CLI, because no signed release exists. Both are required, and the engine is
  then reported as unverified everywhere.
- **Building.** It needs a Rust toolchain and a C linker (`build-essential`).
- **Legacy crate.** `crates/agentguard-cli` is the Phase 1 Rust CLI. It builds a binary that is
  also called `agentguard` and is superseded by the npm CLI. It is not shipped, but it collides in
  name with the npm alias.

### Environment-variable dependencies

| Variable | Used for | Production? |
|---|---|---|
| `AGENTGUARD_DEV_ENGINE`, `AGENTGUARD_ALLOW_UNVERIFIED_ENGINE` | development engine override | no (to stay development-only, Subphase C) |
| `AGENTGUARD_TEST_ENGINE` | CLI tests | no |
| `AGENTGUARD_CLAIM_TOKEN` | `run --approval` claim token | yes (requester token, not a credential) |
| `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR` | storage locations | yes |
| `CLAUDE_CONFIG_DIR`, `CODEX_HOME` | detected only to refuse installation into relocated directories | yes |
| `NO_COLOR`, `FORCE_COLOR`, `TERM` | output | yes |

### Fixed-path assumptions

- **Hook configuration embeds the engine's absolute path.** Under an npm global install, that path
  lives inside the npm prefix. It changes with `nvm use`, Node upgrades or a new npm prefix, and an
  upgrade replaces the file in place. **This must change** (Subphase C): copy the verified engine
  into AI Defender's own storage (`engine/<version>/`), point hooks there, and re-verify its hash.
- **Storage.**
  - **Location.** It always uses XDG-style paths: `~/.config/agentguard`,
    `~/.local/state/agentguard`. That includes macOS, where `~/Library/Application Support` is
    the platform convention.
  - **Ownership checks.** The trust store's check that it is owned by the current user is
    Unix-specific.
  - **System anchor.** The optional administrator-installed anchor (`/etc/agentguard`) is
    Unix-only.

### Platform-specific code

- **Windows does not build.** 28 source files use `std::os::unix` or `nix`: file modes and
  ownership, `O_NOFOLLOW`, `flock`, process groups, signals, `prctl`, `setrlimit`, and the Git
  index reader's stat checks. Windows needs a port (ACLs, `LockFileEx`, job objects, reparse-point
  handling), not packaging.
- **Linux-only behaviour.** Managed-execution process-group isolation, `signalfd` interruption,
  and `no_new_privs`.
- **macOS.** Compiles from the same code; not built or tested.

### Provider-version-specific behaviour

- **Claude Code.**
  - `onFailure: "block"` needs 2.1.295 or later. Older releases let a tool call continue when the
    hook crashes, is missing or times out.
  - The development host runs 2.1.263.
  - The tool matcher and payload fields follow the documentation as verified on 2026-10-31.
- **Codex.**
  - Hooks run only after the user trusts them with `/hooks`.
  - Codex does not document what a timed-out command hook does.
  - Hosted tools and `write_stdin` are not hooked.
  - Codex is not installed on the development host.

## 2. Mismatches between the brief and the repository

1. **SQLite.** The brief assumes a SQLite store. There is none. Approvals, registry and audit are
   signed files and JSONL, which already survive upgrades as files. A SQLite migration is
   optional and should be decided separately (Subphase G or later). It is not required for
   distribution.
2. **Windows x64.** Listed as a preferred platform, but it is an engine port of a size comparable
   to a phase. Recommendation: ship Linux and macOS first, and track Windows as its own subphase.
   Until then `win32-x64` stays "unsupported" with a clear error.
3. **Validating the engine at install time versus never running unverified binaries at install.**
   A postinstall step that starts the engine runs code during `npm install`, which the brief also
   forbids for unverified binaries. Many installs also use `--ignore-scripts`. Recommendation:
   - no postinstall;
   - verification on every engine use, as today;
   - an explicit `ai-defender doctor` that starts and checks the engine;
   - a first-run message.
4. **Global storage layout.** The brief's layout (`engine/`, `config/`, `trusted/`, `keys/`,
   `registry/`, `approvals/`, `audit/`, `database/`) maps onto the existing trust store, which
   already has `keys/`, `signing/`, `trusted/`, `registry/`, `integrity/`, `approvals/`,
   `executions/`, `scans/`, `hooks/`, `integrations/` and `audit/`. Renaming directories gains
   nothing and risks the trust chain; only `engine/` is new.
5. **"Older Claude Code versions."** Native blocking works on older releases when the hook runs.
   It fails open when the hook crashes or times out. Such versions are classified as **degraded
   enforcement**, not unsafe or full. Actual testing against old versions needs those versions
   installed in disposable environments (Subphase E).

## 3. Decisions needed from you

| # | Decision | Recommendation |
|---|---|---|
| D1 | Who owns the `ai-defender` npm name and an npm organisation for platform packages | Create the `@ai-defender` org; publish `@ai-defender/engine-<platform>`. On 2026-10-31 `ai-defender` and `@ai-defender/engine-linux-x64` returned 404 (unpublished), which does not prove they can be claimed |
| D2 | Release signing key custody | Offline Ed25519 key held by the release owner. Either sign manifests in a protected, manually approved release job using a secret, or sign offline. Never in pull-request CI |
| D3 | Linux libc | Static musl builds (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`): no glibc version requirement, and every dependency is pure Rust |
| D4 | Windows | Separate porting subphase after Linux and macOS ship |
| D5 | Keep the `agentguard` alias | Keep it for at least one release with a notice; retire the legacy `crates/agentguard-cli` binary so the name is not built twice |
| D6 | Storage location on macOS | Keep the current XDG-style paths for compatibility. Moving to `~/Library/Application Support` needs a migration with the trust store's integrity checks (Subphase G) |
| D7 | Storage directory and protocol identifiers (`agentguard`, `agentguard.*` schema IDs, `.agentguard/`) | Keep them. They are inside signatures, digests and installed configuration; renaming would invalidate trusted state for no security benefit |

## 4. Plan by subphase

### A. Audit and product renaming: implemented

- npm package `ai-defender`; executables `ai-defender` and `agentguard` (alias, same entry point).
- Every user-facing CLI string, help text, usage line and error hint says AI Defender and
  `ai-defender`.
- User-facing engine messages, recovery hints, hook block messages and `SessionStart` context say
  the same.
- The hook marker is now `AI Defender security check`. The legacy `AgentGuard security check`
  marker is still recognised, so existing installations are replaced or removed cleanly
  (tested).
- **Security:**
  - the guard treats `ai-defender` exactly like `agentguard`;
  - managed execution refuses both;
  - `AI_DEFENDER_*` variables count as bypass markers like `AGENTGUARD_*`.
  - Fixed during the audit: `integrations` and `projects` were added to the subcommands agents
    may not run. Before this, an agent could run `agentguard integrations install` through its
    shell.
- Current user-facing documentation is renamed. Historical records (ADRs, Phase 0 review,
  repository audit, earlier PROGRESS entries) are unchanged.
- **Unchanged on purpose:**
  - crate names;
  - the engine binary name `agentguard-engine`;
  - storage paths, `.agentguard/` and the protocol and schema identifiers (D7);
  - the development environment variables (Subphase C);
  - the platform package scope (Subphase B, D1).

### B. Rust binary distribution

- **Release matrix:** `x86_64`/`aarch64` musl Linux (D3), `x86_64`/`aarch64` Apple. Windows
  excluded until D4.
- **Build:** release profile with `--locked`; reproducibility (`SOURCE_DATE_EPOCH`,
  `--remap-path-prefix`) recorded; a version and protocol stamp embedded in the binary.
- **Artifacts:** per-platform packages via `build-engine-package.mjs` (renamed scope); manifests
  carrying the version, protocol, SHA-256 and target triple; Ed25519 signatures from the release
  key (D2); a `SHA256SUMS` file signed as well.
- **Keys:** `release-keys.json` gains the public key. The CLI keeps refusing anything unsigned.
- **Tests:** manifest tampering, wrong platform, wrong protocol, missing signature, a development
  override in a release build.

### C. Global npm installation

- `optionalDependencies` on the platform packages (npm installs only the matching one).
  - No postinstall, no downloads, no sudo.
- **Stable engine location.** On first use the CLI verifies the packaged engine and copies it to
  `<state>/engine/<version>/` (0700 directory, 0755 file). It re-verifies the hash there, so
  hooks do not break when the npm prefix or Node version changes.
- The development override stays behind both variables, is reported as unverified, and is never
  suggested in production messages.
- **Prerequisite diagnostics:** Node ≥ 18.17, Git (optional: Git features report unavailable),
  provider CLIs (optional).

### D. Global project registry

- **Existing:** signed registry, `project list/inspect/trust/revoke`.
- **Add:**
  - `projects list|inspect|add|revoke|remove|scan`, with confirmations for destructive changes
    (never deleting project files);
  - registration timestamps and last-verification records;
  - integration status per project;
  - a relocation workflow, since a moved directory must be re-registered deliberately, never
    adopted silently;
  - unregistering that removes a project from the signed registry (needs the policy key).

### E. Agent compatibility framework

- **Provider-neutral adapter interface:** detection, version, capabilities, installation, payload
  parsing, decision mapping, failure behaviour, removal.
- **Compatibility levels:**
  1. native enforcement (fails closed);
  2. degraded native enforcement (blocks decisions but fails open on hook failure, for example
     Claude Code before 2.1.295);
  3. managed execution (`ai-defender run`);
  4. monitoring only.
- `ai-defender agents`: real detection (executable plus `--version`, not configuration
  directories).
- Testing against older Claude Code and Codex versions in disposable environments.
- Cursor and other agents only after reviewing their official hook documentation.

### F. Dashboard

- `ai-defender dashboard`: a read-only terminal view built from existing engine data:
  - status, projects, pending approvals, recent audit events, integrations, coverage.
- No new decision paths. "Unavailable" is always shown distinctly from "zero".

### G. Upgrade and recovery

- **`doctor`:** engine, protocol, storage permissions, integrity, provider configuration.
- **`repair`:** reinstall the engine copy, re-point hooks, fix permissions. It never accepts
  tampered trusted state.
- **`update`:** guidance for `npm install -g ai-defender@latest`, then an engine-copy refresh.
- Schema migrations for stores that carry a schema field. They are interruptible and never
  overwrite keys.
- `policy validate`, `policy diff`, and an authorised global-policy edit command (currently
  missing).

### H. Release engineering

- CI: CLI lint, typecheck and test jobs; a macOS test job.
- **Release job:** protected tags only, manual approval, signing secret unavailable to pull
  requests, cross-builds, package validation (`pack:check` per package), version
  synchronisation (CLI, engine, platform packages, protocol).
- **Clean-machine end-to-end tests:** disposable containers and VMs without Rust, running every
  workflow step in brief §20.
- Publication only on your explicit release authorisation.

## 5. Security impact of Subphase A

- **Strengthened.** A new command name could have been an unguarded path to approval or
  configuration commands; it is guarded and refused. The audit found `integrations` missing from
  the guarded subcommands; it is added.
- **Preserved.** No signature domain, digest schema, storage path or trust check changed. Existing
  trust stores, approvals, audit logs and installed hooks keep working: the legacy marker is
  recognised, and engine paths are unchanged.
