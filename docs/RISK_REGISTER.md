# Initial Risk Register

Likelihood and impact: L/M/H. Owner is the phase that must retire or accept the risk.

| ID | Risk | L | I | Mitigation / plan | Owner | Status |
|---|---|---|---|---|---|---|
| R-01 | Developer runs the agent outside AI Defender because the contained workflow is too slow or awkward (large repo clone, no live working tree) | H | H | alternates for cheap clones; `ai-defender sync` ergonomics; clear docs; measure clone time in Phase 4; keep a LIVE-mode ADR option open (ADR-0004) | 4, 12 | open |
| R-02 | Kernel/runc escape from the container | L | H | rootless, seccomp, AppArmor, gVisor option; documented | 4 | accepted |
| R-03 | Agent credential (provider token) exfiltrated to the provider's own host via crafted API calls or to a second account | L | M | dedicated scoped key; proxy header injection in Phase 8; audit of API host usage | 8, 10 | open |
| R-04 | Approval fatigue leads developers to approve without reading | M | H | high-risk typed confirmations; facts computed by controller; minimal prompt count via task scope; measure prompt counts in pilot | 6, 12 | open |
| R-05 | Vendor changes hook/settings semantics between versions (e.g. `ask` behaviour) | M | M | adapters pin agent versions in the image; `validate_integration` checks real behaviour at image build; CI re-runs agent-driven suite on upgrade | 10 | open |
| R-06 | File ownership under rootless Docker (container uid 1000 → host subuid) complicates controller reads/deletes of the staging tree and alternates permissions | H | M | Phase 4 spike: options are container uid mapped to host uid (container "root" in userns with caps dropped), subuid plus ACLs, or Podman `--userns=keep-id`; choose and record ADR-0006 update | 4 | open |
| R-07 | cgroup delegation absent on developer machines; limits unenforced | M | M | `doctor` detection; strict mode refusal; documented systemd drop-in | 4 | open |
| R-08 | Git provider lacks short-lived scoped tokens; broker must hold a broad PAT | M | M | PAT in keyring, never exported, branch protection server-side; GitHub App recommended | 7 | accepted |
| R-09 | gitleaks/trivy absent on hosts; scanning silently weaker | M | M | never silent: UI shows UNAVAILABLE; native fallback with lower-confidence label | 8 | planned |
| R-10 | Agent's built-in tools (Claude Code Read/Edit) bypass vendor sandbox but inside our container that only reaches the staging clone; however, adapters that mount extra read-only directories (shared libs) expose them to those tools | L | L | FilesystemAccessRequest approval shows the exact path; ro mount | 5 | accepted |
| R-11 | Codex's inner bwrap sandbox cannot run under Docker's seccomp (nested userns); falling back to `danger-full-access` inside the container loses an inner layer and may alarm users | M | L | test in Phase 10; document; the container remains the boundary | 10 | open |
| R-12 | IPC parser vulnerabilities in the controller (untrusted input from the container) | M | H | fixed schema, length limits, fuzzing in Phase 3, Rust memory safety, no `unsafe` in proto | 3 | planned |
| R-13 | Egress proxy bugs (request smuggling, CONNECT to unix paths, header injection) | M | H | hyper-based, strict parsing, corpus tests, no absolute-path CONNECT | 8 | planned |
| R-14 | Host exec gateway argument injection into real tools (terraform, kubectl flags that read files) | M | H | per-tool typed `ToolArgs`, Landlock-confined process, typed approval shows exact argv | 5, 9 | planned |
| R-15 | Staging clone hostile content executed by host git during sync | L | H | locked-down git invocation, gix for inspection, AC-G5 test | 7 | planned |
| R-16 | Sync CAS race: developer and agent modify the same branch | M | L | compare-and-swap; place on `refs/agentguard/...` with guidance | 7 | planned |
| R-17 | Audit DB growth or corruption | L | M | WAL, retention, `audit --verify`, export | 3 | planned |
| R-18 | Project toolchains inside the image diverge from the developer's (different Node/Rust versions) causing build differences | M | M | policy `sandbox.toolchain` layer pinned per project; devcontainer-compatible image layers in future | 4, 12 | open |
| R-19 | Developers disable organisation policy by editing the host org-policy file | M | M | out of host trust model; future signed org policies and MDM delivery | 12 | accepted |
| R-20 | Scope creep: attempting all guards (DB, deploy) before the core is solid | M | H | strict phase gating; Phase 9 only after Phase 11-style verification of 4-8 | all | mitigated by plan |
| R-21 | Claude Code OAuth (subscription) credentials file must be mounted; it contains a refresh token broader than an API key | M | M | document; recommend API key with spend limits for AI Defender use; proxy injection Phase 8 | 10 | open |
| R-22 | Host-side oracle tests themselves are destructive if misconfigured against a real remote | L | H | harness refuses non-disposable remotes (URL allowlist of test hosts, repo name prefix check) | 7 | planned |
| R-23 | Agent output reaching the developer's terminal emulator unfiltered (clipboard write, query responses, injected shell input) | M | H | PTY output filter in the host process, terminal reset on exit, AC-C7 | 4 | planned |
| R-24 | One approved commit changes files the developer's host tooling executes (manifests, lockfiles, build scripts, editor tasks) | H | H | host-executed-content classification, high-risk typed confirmation, lockfile URL validation (M11) | 7 | planned |
| R-25 | `serde_yaml` is unmaintained; a parser vulnerability in the policy loader is not patched upstream | L | M | size limit and schema validation in Phase 1; evaluate maintained replacement in Phase 2 | 2 | open |
| R-26 | The author's host lacks a C compiler driver; local builds used a scratch linker shim | H | L | request `build-essential` before Phase 2; CI uses standard images | 2 | open |
