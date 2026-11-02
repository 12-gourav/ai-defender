# Phase 0 Architecture Review

Date: 2026-10-30. Reviewed documents: ARCHITECTURE, THREAT_MODEL, TRUST_BOUNDARIES, SECURITY_MODEL, APPROVAL_MODEL, GIT_CREDENTIAL_BROKER, DOCKER_ISOLATION, AGENT_INTEGRATIONS, WORKSPACE_DESIGN, IMPLEMENTATION_PLAN, SECURITY_ACCEPTANCE_CRITERIA, SECURITY_TESTING, KNOWN_LIMITATIONS, RISK_REGISTER, and the ADRs under `docs/adr/` (the review brief named `DECISIONS.md`; the ADR index at `docs/adr/README.md` is its equivalent).

Review method: a line-by-line consistency pass by the author, plus an independent cold read by a separate reviewer instance given an adversarial brief and no access to the author's conclusions. Both sets of findings are merged below; section 9 lists the independent findings that the author's pass had missed. Nothing in this review silently changes an approved security requirement. Where a correction changes behaviour it is listed under section 4 with its rationale, and where it needs the developer's decision it is a question in section 8.

## 1. Overall architecture assessment

The documents describe one architecture consistently at the level that matters: a per-session host controller owns all security state and credentials; the agent runs in a rootless container with `--network none`, a read-only root filesystem, dropped capabilities, and a private staging clone; the only paths out are a bind-mounted control socket and a bind-mounted egress proxy socket; sensitive operations require typed approvals whose tokens never leave the controller; the developer's repository is updated only by Git-object synchronisation after approval. Hooks and command classification are consistently labelled advisory.

The design is sound in its central argument (ADR-0002): rather than preventing the agent from doing things, it ensures the things the agent can do are harmless. That argument holds as long as the enumerated boundary crossings in TRUST_BOUNDARIES.md are complete. This review found three crossings that were implicit rather than enumerated (section 2, G1 to G3) and one class of host-side processing of agent-produced input that was under-protected (G4).

Verdict: the architecture is approved for implementation with the corrections in section 4 applied to the documents before Phase 2 begins. None of the gaps require a redesign; all are additions to the enumerated boundaries or tightenings of defaults.

## 2. Critical security gaps

Severity reflects consequence if the gap were left unaddressed through implementation.

**G1 (High) Terminal escape sequences through the attached TTY.** `TRUST_BOUNDARIES.md:51` lists crossing X8 as "none (this is the agent's UI)". That understates it. The container's stdout is written raw to the developer's terminal emulator. Terminal emulators act on escape sequences: OSC 52 can write the clipboard, DCS and CSI query sequences cause the terminal to send responses back on stdin, title and bracketed-paste manipulation can seed input into the shell that resumes after `agentguard run` exits. Consequence: an agent can leave the developer's host shell with injected text, or exfiltrate clipboard contents into its own stdin. Correction: the host process that owns the PTY must filter output, allowing a conservative set of SGR, cursor and clear sequences and stripping OSC 52, DCS, APC, PM, SOS and terminal query sequences, and must issue a full terminal reset on exit. Add as crossing X8 with an enforcing filter and acceptance criterion AC-C7 with an adversarial test.

**G2 (High) Host-side execution of agent-produced content on the developer's machine after sync.** `THREAT_MODEL.md:24` names build scripts and `package.json` lifecycle scripts as a threat, and `APPROVAL_MODEL.md:136` shows lifecycle scripts in the dependency prompt, but the protected-file list in `SECURITY_MODEL.md` covers only policy, CI, infrastructure and deployment files. A commit that edits `package.json` scripts, `Makefile`, `build.rs`, `setup.py`, `.husky/*`, `.pre-commit-config.yaml`, `.vscode/tasks.json`, `.envrc`, `justfile`, or any lockfile is code the developer will execute on the host the next time they run their normal tooling. Consequence: the sandbox is bypassed by one approval click on a commit whose prompt did not highlight the risk. Correction: introduce a built-in "host-executed content" classification (not configurable downward by the project) that is always listed in red in the commit approval and raises the commit to high risk with typed confirmation. The dependency prompt already covers lockfiles; the commit prompt must cover the rest.

**G3 (High) The approval decision channel is not explicitly separated from the control socket.** The design relies on the approval socket never being reachable from the container, but no document states the invariant that (a) only `control.sock` and `egress.sock` are mounted and (b) the control socket protocol contains no message type that records a decision. `TRUST_BOUNDARIES.md` X1 says messages are validated; it does not say decisions are impossible to express. Consequence: a future IPC addition could let the agent approve its own request. Correction: add invariant to TRUST_BOUNDARIES section 3 ("Zone 2 must never contain the approval socket") and to the IPC design: the `agentguard-proto` schema shall define request and outcome messages only; approval decisions arrive through a separate socket with a separate schema and `SO_PEERCRED` check for the developer's uid. Add acceptance criterion AC-A9.

**G4 (Medium) Scanners and parsers run on the host against hostile input.** `GIT_CREDENTIAL_BROKER.md:55` runs gitleaks over an extracted tree; the commit and push flows also run `git fetch` from the agent-controlled staging clone (`GIT_CREDENTIAL_BROKER.md:47`), Trivy over lockfiles, and later `pg_query` and plan parsers. All of these are host processes parsing attacker-controlled bytes as the developer's user. The git invocation is locked down, but `git fetch file://staging` still spawns `git-upload-pack` inside the hostile repository, and the staging files will be owned by a different uid under rootless Docker, which trips git's `safe.directory` check. Correction: (1) perform the staging-to-quarantine object transfer with gix (pure Rust reading of the object store) rather than spawning git in the hostile repository; (2) run external scanners (gitleaks, trivy) inside a disposable AgentGuard container with no network and a read-only mount of the extracted tree, reusing the sandbox manager; (3) fuzz all Rust parsers of agent-produced input in Phase 11. This strengthens AC-G5 and adds AC-F6.

**G5 (Medium) The alternates mount leaks more than documented.** `GIT_CREDENTIAL_BROKER.md:24` says the read-only `.git/objects` mount exposes "history reachable from any ref". It exposes every object in the store, including unreachable objects left by amended commits, dropped stashes and deleted branches that have not been garbage-collected, which is precisely where accidentally committed secrets live. Correction: make `full_copy` the default and alternates an explicit opt-in (`git.staging: alternates`) with the leak stated in the policy schema description. Developer decision requested (Q1) because of the performance trade-off.

**G6 (Medium) Untracked files are absent from the sandbox, and this was not stated.** The staging clone is a git clone, so untracked files (`.env`, local config, `node_modules`, build caches) never enter the container. This is a security benefit (untracked secrets never reach the agent) and a usability cost (dependencies must be installed inside the container, tests needing local untracked config fail). Neither consequence appears in KNOWN_LIMITATIONS or RISK_REGISTER. Correction: document as deliberate; add a narrow, policy-listed `filesystem.copy_untracked` allowlist (read-only, excluded from secret patterns, copied by the controller at session start) for the usability case. Developer decision requested (Q2).

**G7 (Low) AppArmor profile loading and other root-only setup steps are not called out.** `DOCKER_ISOLATION.md:37` references a custom `agentguard-agent` AppArmor profile; loading one requires root. `IMPLEMENTATION_PLAN.md:63` lists rootless Docker setup and the cgroup delegation drop-in but not AppArmor, `uidmap` package installation, or gVisor's runtime registration. Correction: Phase 4 must list every root step explicitly and default to Docker's built-in profile when the custom one is not loaded, reporting the downgrade in `doctor`.


**G8 (High) Scanners read their configuration from the content they scan.** gitleaks honours `.gitleaks.toml` and `.gitleaksignore` found in the scanned tree; Trivy honours `.trivyignore`. An agent commits an allow-everything configuration and the approval prompt reports the scan as clean, defeating TH-G6 and AC-F2 silently. Correction: scanners run with an explicit, controller-owned configuration path and with in-tree configuration files excluded (gitleaks `--config` pointing at controller state, `--no-banner`, ignore files not honoured; Trivy with `--ignorefile` pointing at an empty controller-owned file). The commit prompt flags any change to a scanner configuration file as host-executed content (G2). Add acceptance criterion AC-F7.

**G9 (High) The host-side git invocation during sync has a larger attack surface than the four neutralised keys.** `git fetch` from a local path spawns `git-upload-pack` inside the agent-controlled staging repository. Beyond `core.hooksPath` and `core.fsmonitor`, the staging `.git` can be replaced by a `gitdir:` file or symlink pointing at a guessed host path, `objects/info/alternates` can point at arbitrary host directories, `include.path` can pull host files into config, `extensions.partialClone` plus a remote URL triggers lazy fetches with the host's network, and the subuid ownership problem will tempt an implementer to set `safe.directory=*`, which disables git's own untrusted-repository protection. Correction (strengthens the gix recommendation in G4): the controller never spawns git with the staging clone as its repository. It reads loose and packed objects from the staging object directory with gix, validates them, and writes them into the quarantine repository. The staging `.git` directory is treated as opaque hostile bytes; `.git` symlinks and `gitdir:` files are rejected outright. AC-G5's corpus is extended with every item above and `GIT_NO_LAZY_FETCH=1` is set defensively on all controller git invocations.

**G10 (Medium) Sync must not rewrite commit identity.** `GIT_CREDENTIAL_BROKER.md` rewrites author and committer during sync, which changes the commit SHA, while approvals and the push flow bind to the staging-clone SHA and report `ok` to the agent's git for a SHA the remote never received. Correction: commits are transferred byte-for-byte; identity is set at commit time by the controller-authored staging-clone configuration (`user.name`, `user.email`, and a commit trailer via `trailer.*` configuration) and sync *validates* identity, flagging a mismatch as high risk instead of rewriting. The approved SHA is the pushed SHA.

**G11 (Medium) DNS exfiltration through the proxy's own resolver.** If the proxy resolves a requested hostname before checking the allowlist, or if wildcard patterns such as `*.example.com` are permitted, attacker-chosen labels are sent to the host's resolver. Correction: the allowlist is checked before resolution; wildcards are limited to a policy-declared set of registry hosts and an explicit per-pattern opt-in; `NetworkAccessRequest` carries exact hostnames only. AC-N4 is extended to assert no resolver query occurs for a denied name.

**G12 (Medium) Unicode in approval prompts and in CLI output of stored agent strings.** ANSI stripping is specified for the approval UI, but bidirectional overrides (U+202E), zero-width characters and homoglyphs in branch names, paths and messages can make a trusted fact read as another, and `agentguard audit`, `violations` and `status` print stored agent-supplied strings to the developer's terminal with no stated sanitisation. Correction: one shared rendering function for every agent-originated string in any trusted output: strip C0/C1 controls and ANSI, replace bidi and zero-width code points with visible escapes, and mark non-ASCII identifiers (branch, path) with a warning glyph in prompts. Acceptance criterion AC-A10.

**G13 (Medium) Host-exec inputs must come from approved objects, not the live staging tree.** If a host-side tool reads files from the agent-writable `/workspace` after approval, the agent can edit them between approval and execution. Correction: host-exec inputs are extracted from an approved commit into a controller-owned read-only directory; the approval binds the tree hash. Given the pilot deferral of host exec (section 5) this is recorded for Phase 9.

**G14 (Medium) `policy approve` needs stored state to be enforceable.** ADR-0005 says a policy edit takes effect only after `agentguard policy approve`, but ARCHITECTURE loads `.agent-security.yml` at every session start with no last-approved hash to compare against. Correction: the controller stores the last-approved policy hash per repository in state; a session whose repository policy hash differs from the approved one starts only after the privileged approval flow or with the previously approved snapshot and a warning.

**G15 (Medium) Control-socket connectability versus uid mapping.** A `0600` socket owned by the developer cannot be connected to by container uid 1000 mapped to a subuid. Any fix (ACL for the subuid, or mapping the agent to the developer's real uid) is a trust decision affecting X1 and the approval-socket separation. Correction: this is folded into the R-06 spike as a required output: the chosen mapping, the socket permission model, and what `SO_PEERCRED` can and cannot prove under it. Phase 3's peer check is written against the spike's result, not before it.

**G16 (Low) Alternates file is agent-writable and host-interpreted; controller crash semantics.** The `objects/info/alternates` entry is both wrong on the host side (the in-container path does not exist on the host) and rewritable by the agent. The gix-based transfer (G9) resolves this: the controller reads the staging objects and the developer's objects from host paths it chooses, never from the alternates file. Separately, AC-P4 as written cannot pass because the Docker daemon, not the controller, is the container's parent. Correction: the shim's entry process watches the control socket and terminates the agent when it closes (fail-closed for the cooperative case), every `agentguard` invocation runs the orphan sweep, and AC-P4 is reworded to "container is dead within grace after controller exit *or* on the next AgentGuard invocation, and has no capability in between".

## 3. Contradictions found

| # | Where | Contradiction | Resolution |
|---|---|---|---|
| C1 | `ARCHITECTURE.md:166` vs `SECURITY_MODEL.md:149` | DEVELOPMENT mode: ARCHITECTURE allows only fetch and commit-by-approval; SECURITY_MODEL also allows push and exec requests "which will require approval". That erases the difference between DEVELOPMENT and DEVELOPER_AUTHORIZED. | DEVELOPMENT: no push, no host exec, no dependency approval; such requests are denied with "switch to DEVELOPER_AUTHORIZED through the trusted UI". DEVELOPER_AUTHORIZED: those requests are approvable. SECURITY_MODEL table corrected. |
| C2 | `TRUST_BOUNDARIES.md:46` vs `DOCKER_ISOLATION.md:13` | X3 lists a "read-only shim binary" bind mount; DOCKER_ISOLATION bakes the shim into the image. | Baked into the image. X3 corrected; mount allowlist unchanged. |
| C3 | `ARCHITECTURE.md:125` vs `GIT_CREDENTIAL_BROKER.md:45` | Sync is "controller-initiated" in one and agent-triggerable via `agentguard-shim sync` in the other. | Both: the agent may *request* a sync (a `SyncRequest` on the control socket, which only causes the controller to run its own pipeline); the controller and developer may also initiate. ARCHITECTURE table corrected. |
| C4 | `ARCHITECTURE.md:170` vs `THREAT_MODEL.md` G5 and `GIT_CREDENTIAL_BROKER.md:104` | Force push and protected-branch push are "hard-deny" in ARCHITECTURE but "deny unless organisation policy enables an approval path" elsewhere. | Organisation-configurable. Default deny at every level; only organisation policy may enable an approval path; project policy and task scope never can. ARCHITECTURE wording corrected. |
| C5 | `APPROVAL_MODEL.md:239-245` | One `expires_at` and one 600 s TTL serve two different purposes: how long a pending prompt waits, and how long an approved token stays valid before consumption. Since consumption is atomic with execution start, a long post-approval validity is unnecessary risk. | Two values: `pending_timeout` (default 600 s, waits for the developer) and `token_validity` (default 60 s after approval, consumed immediately). ADR-0008 and APPROVAL_MODEL corrected. |
| C6 | `APPROVAL_MODEL.md:28-31` | `CurrentTask`/`CurrentSession` scopes are described as valid for "repeated push to the same feature branch", which contradicts the specification's "push to feature branch: human approval" and GIT_CREDENTIAL_BROKER's per-push validation. | Reusable scopes apply only to `NetworkAccess` and `FilesystemAccess`. Git push, commit, dependency install, database mutation, deployment and policy change are always `SingleOperation`. Organisation policy may not widen this in the pilot. |
| C7 | `IMPLEMENTATION_PLAN.md:104` | Phase 7 exit criterion requires Claude Code through the generic adapter, but Claude Code's authentication strategy arrives in Phase 10. | Phase 7 exit uses a plain shell session in the generic adapter; Claude Code end-to-end moves to Phase 10. |
| C8 | `IMPLEMENTATION_PLAN.md:16` vs Phase 2 | `agentguard init` writes a policy template in Phase 1, before the schema that validates it exists in Phase 2. | Phase 1 `init` writes a versioned template and performs structural validation only (version, YAML well-formedness, known top-level keys); full semantic validation is Phase 2 and `validate` says so explicitly. |
| C9 | `SECURITY_MODEL.md:151` vs `DOCKER_ISOLATION.md` run spec | RESTRICTED mode is described as per-path read-only bind mounts over the workspace, which the fixed run-spec template does not express. | Simplify (section 5): RESTRICTED is enforced at sync time (commits touching paths outside the task's allowed set are rejected) plus advisory hooks; no per-path mounts. The boundary is the repository, not the container filesystem. |
| C11 | `THREAT_MODEL.md` G4 vs `APPROVAL_MODEL.md` section 7 | G4 mentions a "non-interactive policy grant for feature branches" that the non-interactive mode cannot express. | Non-interactive mode never pushes. G4 reworded: every remote write requires a consumed one-time token. |
| C12 | `SECURITY_MODEL.md:51` vs `APPROVAL_MODEL.md:30` | `commands.allow` is labelled a host-exec allowlist and `npm test` appears as a reusable approval, but project scripts never run on the host and in-container commands need no gate. | `commands` is the in-container advisory allowlist for hooks only. Host exec, if built, has its own typed table. `npm test` examples removed. |
| C13 | `README.md`, `ARCHITECTURE.md`, `TRUST_BOUNDARIES.md:59` vs `DOCKER_ISOLATION.md:43` | "The developer's `.git` is never mounted" vs the default read-only alternates mount of `.git/objects`. | Resolved by G5 and G9: `full_copy` is the default and the object transfer is performed host-side by the controller, so no part of the developer's `.git` is ever mounted. Alternates become an opt-in with the leak stated. |
| C14 | `DOCKER_ISOLATION.md:52,61` vs five other documents | The mount allowlist is "fixed" but database sockets, extra read-only directories, adapter config binds and mode-dependent workspace mounts are all described elsewhere. | The run specification is a template with a small, enumerated set of policy-driven slots (workspace mode, optional database sockets, optional approved read-only directories); the inspect assertion checks the *instantiated* allowlist. X3 lists every slot. |
| C15 | `GIT_CREDENTIAL_BROKER.md:58` vs `KNOWN_LIMITATIONS.md` L12 | Updating the ref of the developer's currently checked-out branch without touching index or working tree makes `git status` show the agent's work as un-done and `git commit -a` would revert it. | Never update a checked-out branch's ref directly. Commits land on `refs/agentguard/<task>/<branch>`; `agentguard sync --apply` performs a fast-forward through the developer's own git with working-tree update when the tree is clean, and explains otherwise. |
| C10 | `AGENT_INTEGRATIONS.md:35` | Routing Claude Code's `PermissionRequest` hook through AgentGuard means AgentGuard answers the agent's native permission prompts on the developer's behalf. This is coherent with ADR-0002 (inside the container those prompts protect nothing) but it is a user-visible behaviour change not stated as a decision. | Recorded as Q3 for the developer. |

## 4. Recommended corrections

Applied to the documents as part of Phase 1 documentation updates (no security requirement is weakened; each either tightens a default or resolves an ambiguity in the stricter direction):

1. TRUST_BOUNDARIES: X8 becomes an enforcing crossing with an output filter; add "approval socket never mounted" and "control protocol cannot express decisions" invariants (G1, G3).
2. SECURITY_MODEL: add the built-in host-executed-content classification to protected-file handling; correct the mode table (G2, C1); RESTRICTED enforced at sync time (C9).
3. GIT_CREDENTIAL_BROKER: staging-to-quarantine transfer via gix, scanners in a disposable container, alternates leak statement corrected (G4, G5).
4. APPROVAL_MODEL and ADR-0008: two TTLs; reusable scopes limited to network and filesystem (C5, C6).
5. ARCHITECTURE: hard-deny wording (C4); sync trigger (C3).
6. IMPLEMENTATION_PLAN: Phase 1 crate set per the Phase 1 brief; Phase 4 root-step list (G7); Phase 7 exit criterion (C7); `init` scope (C8).
7. SECURITY_ACCEPTANCE_CRITERIA: add AC-C7 (terminal filter), AC-A9 (decision channel separation), AC-F6 (scanner containment).
8. KNOWN_LIMITATIONS and RISK_REGISTER: add untracked-file behaviour (G6), terminal escape residual, host-executed content residual.
9. GIT_CREDENTIAL_BROKER and ADR-0009: controller never spawns git inside the staging clone; gix object transfer; identity validated not rewritten; alternates opt-in; checked-out branch never updated directly (G9, G10, G16, C13, C15).
10. SECURITY_MODEL M3 and M7: allowlist-before-resolve and wildcard restriction (G11); scanner configuration isolation (G8); shared sanitised rendering for agent strings (G12).
11. ADR-0005: last-approved policy hash stored per repository (G14).
12. DOCKER_ISOLATION: run specification as a template with enumerated slots (C14); shim watches the control socket (G16).
13. IMPLEMENTATION_PLAN: R-06 spike moved to the start of Phase 3 with required outputs (G15); AC-F4 moved to Phase 7; Phase 5 exit criterion no longer references a tool table.

Pending developer decision (not applied): G5 default (Q1), G6 allowlist (Q2), Q3, Q6, Q7.

## 5. Unnecessary complexity to defer

- **Eighteen crates in the first workspace.** The Phase 1 brief's four crates (`agentguard-cli`, `agentguard-core`, `agentguard-common`, `agentguard-audit`) are the right start; guards are added one per phase when they have code. WORKSPACE_DESIGN remains the target layout.
- **Per-path read-only mounts for RESTRICTED mode.** Replaced by sync-time path enforcement (C9).
- **Four database protocol proxies and seven deployment tools in Phase 9.** Pilot scope: PostgreSQL only, and a host-exec table containing `terraform plan`, `terraform apply`, `kubectl` only. Others follow pilot feedback.
- **TLS-terminating proxy mode.** Keep as an optional Phase 8 item; not required for pilot.
- **gVisor.** Optional, detection only in Phase 4.
- **PTY overlay for approvals.** Second terminal plus desktop notification is sufficient for the pilot. The independent review adds a stronger reason: an overlay drawn on the same stream as agent output can be overdrawn by cursor-positioning and alternate-screen sequences. If an overlay is ever built it must own a separate region the agent stream cannot address, which in practice means a separate window.
- **Host exec gateway (M6).** Deferred out of the pilot entirely. Deployment and infrastructure operations are hard-denied in the pilot; removing the gateway removes TH-C4, R-14, the Landlock confinement work and the TOCTOU in G13 without weakening any core guarantee. Developer decision Q6.
- **Approval token hashing.** Tokens never leave the controller, so storing them hashed protects nothing; dropped.
- **Hook integration for five agents in the pilot.** Pilot with the generic adapter plus Claude Code; the other adapters follow once the contained tier is proven.

## 6. Implementation blockers

| Blocker | Phase | Who resolves | Status |
|---|---|---|---|
| No Rust toolchain on the host | 1 | installed into the user's home by rustup with `--no-modify-path` as part of Phase 1 (user-level, no root, no shell profile edits) | resolved in Phase 1 |
| Rootless Docker, `uidmap`, systemd cgroup delegation drop-in, optional AppArmor profile and gVisor | 4 | developer (root required for apt, systemd drop-in, AppArmor load) | open; exact commands to be presented at Phase 4 start |
| File-ownership model for the staging tree and control-socket connectability under rootless Docker (R-06, G15) | 3 (spike moved earlier) | spike with required outputs | open |
| Disposable Git remote and test accounts for agent-driven tests | 7, 10 | developer provides a throwaway GitHub/GitLab repository and scoped token | open |
| Agent CLIs other than Claude Code are not installed and are only needed inside images | 10 | image build | not a host blocker |
| gitleaks and trivy binaries | 8 | user-space download, to be approved at Phase 8 | open |

## 7. Approved architecture decisions

ADR-0001 through ADR-0012 stand as written, with these amendments recorded in the ADRs during Phase 1 documentation updates:

- ADR-0004: add the host-executed-content classification and the untracked-file property.
- ADR-0006: unchanged; R-06 spike remains a Phase 4 gate.
- ADR-0007: extend to the PTY output filter (the host PTY owner is part of the trusted UI surface).
- ADR-0008: split pending timeout from token validity; restrict reusable scopes.
- ADR-0009: staging-to-quarantine transfer uses gix, never git spawned inside the staging clone.

## 8. Questions for the developer

Each question changes behaviour; a default is proposed so work is not blocked.

- **Q1.** Should the staging clone default to `full_copy` (slower on very large repositories, no object-store leak) with alternates as opt-in? Proposed: yes, `full_copy` default.
- **Q2.** Should policy allow a read-only allowlist of untracked files to be copied into the sandbox (for local test configuration)? Proposed: yes, off by default, paths listed explicitly, secret patterns excluded.
- **Q3.** Should AgentGuard answer Claude Code's native permission prompts (via the `PermissionRequest` hook) using its own policy, so the developer sees only AgentGuard approvals? Proposed: yes; inside the container the native prompts protect nothing and double prompting causes approval fatigue (R-04).
- **Q4.** Should organisation policy be able to enable an approval path for production database access, or is it an absolute deny? Proposed: absolute deny in the pilot; revisit after Phase 11.
- **Q5.** Local `git merge` inside the staging clone is unrestricted in this design (it only affects the staging clone; the result still needs commit approval and a push approval). The specification lists "merge: human approval". Proposed: treat the specification's requirement as satisfied by the commit and push approvals plus the provider merge-request flow for protected branches. Confirm.
- **Q6.** Should the host exec gateway (deployment and infrastructure tooling run on the host after approval) be removed from the pilot scope, with those operations hard-denied until a later release? Proposed: yes.
- **Q7.** The independent review proposes collapsing the two approvals (commit, then push) into one: synced commits land on `refs/agentguard/<task>/<branch>` without a prompt (that ref is not a developer branch), and the single push approval carries all the validated facts; a separate `agentguard sync --apply` moves commits onto the developer's branch when they want them locally. This reduces approval fatigue (R-04) but changes the specification's "git commit: human approval" into "commit reaching a developer branch or a remote: human approval". Proposed: adopt. Confirm.

## 9. Independent review findings

The independent reviewer returned twenty-eight findings. Those that duplicated the author's pass are merged above (terminal escapes, host-executed content, mode-table contradiction, shim mount, sync trigger, force-push wording, two TTLs, reusable push scope, Phase 7 exit criterion, AppArmor root step, uid mapping risk). Findings the author's pass had missed, now incorporated:

| Finding | Severity | Incorporated as |
|---|---|---|
| Scanners load `.gitleaks.toml`, `.gitleaksignore`, `.trivyignore` from the scanned content | High | G8 |
| Host git invocation surface: `gitdir:` files, alternates, `include.path`, partial clone lazy fetch, `safe.directory=*` temptation | High | G9 |
| Sync rewrites commit identity, changing the SHA the approval and push are bound to | Medium | G10 |
| DNS exfiltration via resolver and wildcard patterns | Medium | G11 |
| Unicode bidi/zero-width spoofing in prompts; unsanitised agent strings in CLI output | Medium | G12 |
| Host-exec TOCTOU on live staging tree | Medium | G13 |
| `policy approve` unenforceable without a stored approved hash | Medium | G14 |
| Control socket `0600` unreachable from a subuid | Medium | G15 |
| Alternates file wrong on host side and agent-writable; controller crash semantics | Low | G16 |
| Non-interactive push grant inexpressible; `npm test` conflated examples; `.git` "never mounted" vs alternates; fixed mount template vs five mount sources; checked-out branch `update-ref` footgun | Medium/Low | C11 to C15 |
| `remote set-url` violation "cannot fire" because the helper is never invoked | Low | wording removed from GIT_CREDENTIAL_BROKER; the signal is the proxy denial instead |
| RESTRICTED mode via read-only binds is unenforceable against `git hash-object -w` | Medium | confirms C9 |
| `approval_before_fetch` is cosmetic once a registry is allowlisted | Low | documented; the lockfile-at-sync check is the real control |
| Complexity: remove host exec from pilot, collapse two approvals into one, pilot with two adapters, drop token hashing | – | section 5, Q6, Q7 |
| Plan: R-06 before Phase 3; AC-F4 and Phase 5 exit criteria reference later-phase subjects | Medium/Low | section 4 item 13 |

One independent finding is not adopted: dropping the audit hash chain because it only detects host-user tampering (T8, out of scope). The chain is cheap, is exercised by `agentguard audit --verify`, and gives a pilot's security review something concrete to check. It stays, labelled as detection of out-of-model tampering rather than a guarantee.

## 10. Phase 1 readiness assessment

Ready. Phase 1 (Rust foundation: workspace, CLI skeleton, domain types, errors, logging, configuration discovery and parsing, tests, CI) depends on none of the open gaps. The gaps above affect Phases 4 to 8 and are recorded in the plan. Constraints carried into Phase 1 from this review:

- `agentguard-core` domain types must include the two-TTL approval model and the restricted reusable-scope set so later phases cannot drift (C5, C6).
- `agentguard-common` configuration loading must reject unknown top-level keys and unsupported versions outright (fail closed), and must refuse a state directory that is world-readable or inside the repository.
- The `Decision`/`SecurityDecision` type must make all explanation fields mandatory at construction.
- No Docker, no network, no sandbox code in Phase 1.
