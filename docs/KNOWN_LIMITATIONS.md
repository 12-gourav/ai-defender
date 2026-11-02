# Known Limitations

Updated at every phase. Each limitation names the mitigation and whether it is accepted, planned, or open.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L1 | Container isolation depends on the Linux kernel; a kernel or runc vulnerability can escape to the developer's user | Containers are not VMs | rootless (escape ≠ root), tightened seccomp, caps dropped, AppArmor, gVisor optional | accepted, documented |
| L2 | The agent process holds (or can obtain through the proxy) its own AI provider credential | The agent must authenticate to function | dedicated scoped key per developer/agent; only the provider host is reachable; optional proxy-side header injection in Phase 8 removes the key from the container but the agent can still make provider calls | accepted (ADR-0010) |
| L3 | Any allowlisted HTTPS host is an exfiltration channel | TLS hides payloads | minimal allowlists; optional TLS termination mode; Git host only via broker | accepted; TLS termination planned Phase 8 |
| L4 | Repository content is sent to the AI provider | Inherent to AI coding agents | Secret Guard scrub option; policy-level `filesystem.deny` for sensitive files | accepted |
| L5 | A developer can approve a harmful operation | Humans decide | typed prompts with controller-computed facts; diff review; scans | accepted |
| L6 | Hooks inside agents are advisory and fail-open unless the vendor provides a fail-closed option | Vendor design | never relied upon; `onFailure: block` (Claude), `failClosed` (Cursor) used where available | accepted (ADR-0002) |
| L7 | IDE-only agents (Cursor IDE, Antigravity App) cannot be contained | They run on the host desktop | host-hooked tier reported as advisory; no enforcement claims | accepted |
| L8 | Tools requiring real TCP (plain `ssh`, DB drivers without the guard, UDP) do not work inside the sandbox | `--network none` | Database Guard; host exec gateway for specific tools | accepted by design |
| L9 | Docker-in-Docker for project tests is unsupported inside the sandbox | no socket | host exec entry for specific compose commands after approval (Phase 9) | planned |
| L10 | Read-only alternates expose the full object database (all branches, history) to the agent | performance choice | `git.staging: full_copy` policy option | accepted, configurable |
| L11 | Uncommitted changes in the staging clone are not synced; the agent must commit | object-level sync | documented workflow; `ai-defender sync` lists uncommitted changes | accepted by design |
| L12 | Developer's working tree is not auto-checked-out after sync | avoid clobbering local work | `--checkout` with approval; otherwise the developer merges `refs/agentguard/...` | accepted |
| L13 | Local admin on the host can modify controller state and audit | host trust model | hash chain for detection; optional remote audit sink | accepted (T8 out of scope) |
| L14 | Database statement classification can be evaded by stored procedures, dynamic SQL, prepared statements | parser limits | documented; production hard-deny does not depend on classification | open, Phase 9 |
| L15 | SSH-based Git remotes use the developer's host SSH agent key, which is usually broader than one repository | provider limitation | prefer HTTPS with scoped tokens; document | accepted |
| L16 | Resource limits need systemd cgroup delegation; without it limits are advisory | rootless Docker | `doctor` reports; strict mode refuses | accepted with detection |
| L17 | macOS and Windows unsupported initially | Linux-specific primitives | `Sandbox` trait; future backends with explicitly reduced guarantee sets | planned |
| L18 | Antigravity CLI and Gemini CLI hook failure behaviour undocumented | vendor docs | adapters mark hooks advisory | accepted |
| L19 | Cursor `cursor-agent` hook support unverified | vendor docs | adapter deferred until verified | open |
| L20 | Image supply chain (base image, agent packages) is upstream trust | vendor packages | pinned digests, Trivy, SBOM | accepted |
| L21 | Untracked files (`.env`, local config, `node_modules`, caches) are not present in the sandbox | the staging workspace is a git clone | security benefit by construction; a narrow policy-listed read-only copy allowlist is proposed for local test configuration (Q2) | accepted, decision pending |
| L22 | Terminal escape filtering is an allowlist of common sequences; an unusual but legitimate sequence may be stripped | conservative filter | documented; filter corpus maintained | accepted |
| L23 | Host-executed content classification cannot know every tool a developer runs on the host | open-ended tooling | built-in list plus policy additions; commit prompt always shows the full file list | accepted |
| L24 | `serde_yaml` 0.9 is archived upstream | specification mandates it | Phase 2 evaluates a maintained YAML crate before the policy schema is finalised | open |

## Decision engine (Phase 1 security foundation, 2026-10-30)

These apply to the default hook-driven tier ([ADR-0013](adr/ADR-0013-hook-based-local-engine.md)). L1 to L24 above describe the optional contained tier.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L25 | The engine sees only actions that pass through a hook. A built-in tool without a hook, or a subprocess started by an allowed command, is invisible. | Enforcement is cooperative at the hook layer | Baseline requires approval for every terminal command and custom tool. Integrations must configure hooks fail-closed where the vendor allows it, and the contained tier is available where a hard boundary is needed. | open (hooks phase) |
| L26 | Time-of-check/time-of-use: the decision describes the filesystem when it was made; the agent's tool runs afterwards. A symlink swapped in between is not seen. | Hooks decide before the tool executes, in a different process | Paths are canonicalised at decision time, dangling symlinks are refused, and approvals bind the resolved path and context | accepted |
| L27 | Terminal commands are classified by text, so risk patterns and trusted-state matching can be evaded (variables, interpreters, encodings) | Shell semantics are not modelled in this phase | Terminal commands are never allowed by the baseline. A project policy that allows them accepts this risk explicitly. | accepted; structured command model planned |
| L28 | Trusted state (policy file, hook settings, AI Defender state) is protected at the hook layer only. A command that escapes classification can still write it. | No OS-level boundary in the default tier | Guard rules and the L27 baseline. Per-vendor managed-settings locations and file ownership to be evaluated in the hooks phase. Policy is pinned by version, so an edit does not take effect without a new trusted load. | open |
| L29 | Agent identity is bound to how the engine was launched. Anything able to launch the engine with the same arguments can claim that agent. The agent version string is unverified. | No vendor attestation exists | Agent kind gates nothing by itself; decisions depend on policy and the verified project. The version is recorded only. | accepted |
| L30 | Private-network detection uses the host literal only. A public name that resolves to a private or metadata address (DNS rebinding) is not detected. | The engine performs no DNS resolution | Network actions are never low risk. Resolution-time checks belong to a future network guard. | planned |
| L31 | The approval store is in memory. (Policy and the project registry became persistent and signed in Phase 2.) | Phase scope | `ApprovalStore` interface in place; SQLite arrives with the audit phase | planned |
| L32 | Redaction is pattern-based. A credential in an unknown format inside free text (for example a command line) can reach the audit log. | Free text cannot be fully classified | Known credential shapes, sensitive `key=value`, `Authorization:`/`Bearer`, and sensitive flags are redacted. Policy files must never contain secrets. | accepted |
| L33 | No approval channel exists yet. `ApprovalStore::grant` is a Rust API, so separating approvals from agents is enforced in code and protocol, not yet by process or OS boundaries. | Phase scope | The request protocol cannot carry approvals, agent principals are refused, and approval commands and store paths are guarded | planned (approval phase) |
| L34 | The JSON Lines audit chain detects edits, deletions and reordering, but not removal of the most recent records (tail truncation). Verification on open is linear in file size. | Chain without an external anchor | Records are `0600`, symlinks are refused, and a broken chain refuses to open. SQLite storage and anchoring come in the audit phase. | accepted |
| L35 | If the process aborts mid-decision (release builds use `panic = "abort"`), no response is produced. | Fail-stop | Library code cannot panic by lint; integrations must treat a missing or malformed response as DENY (hooks phase requirement) | open (hooks phase) |
| L36 | New agent kinds require a code change (`AgentKind`) | Closed enum for identity | `generic` covers other agents | accepted |

## Trust store (Phase 2, 2026-10-31)

See [TRUST_MODEL.md](TRUST_MODEL.md) §1. **No local tool can defend against a process with administrator/root privileges, or against a same-user process executing arbitrary code outside AI Defender's hooks.**

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L37 | Without an administrator anchor, a same-user process can delete the trust store and initialise a new one with its own keys and a permissive global policy. Locally this is indistinguishable from a legitimate re-initialisation. | Every user-owned file is writable by the user's processes | Administrator anchor at `/etc/agentguard/root.json` (root-owned) pins the root key. The engine guard denies agent writes to the trust root and the `ai-defender init/keys/recover/...` commands. The trust audit log records initialisation. | accepted; anchor recommended for teams |
| L38 | Replaying an older integrity state *together with* an older high-water mark is not detected | Both are user-writable; there is no monotonic counter outside the user's reach | The high-water mark defeats single-file replay. An anchor-side counter (root-owned) or a remote witness would close this. | accepted |
| L39 | A private signing key stored unencrypted where the agent can read it lets the agent sign its own changes | Keys are the authorisation; the engine cannot know where you keep them | Keep keys offline, encrypted or in hardware. The `Signer` trait allows hardware or agent-socket signers in a later phase. | accepted (operational) |
| L40 | The system anchor's parent directories are not checked for ownership | Scope | Install it under `/etc` (root-owned). A check of the full path may be added. | open |
| L41 | Root-key rotation is not a single operation; it is recovery plus re-initialisation, which drops registrations and approved policies | Scope | Documented procedure (TRUST_MODEL §4.4, §6) | planned |
| L42 | Only Linux (XDG) locations are resolved; macOS and Windows paths and permission models are not supported | Unix permission checks, existing L17 | `TrustStore::new` accepts any root; platform backends later | planned |
| L43 | The trust operations (initialise, register, revoke, update, rotate, quarantine) are library functions. Since Phase 4 the CLI drives initialise, register, revoke and policy approval; the human requester is still asserted by the caller (the OS user name). | No approval UI yet | The signature requirement is the real authorisation: a caller without a trusted private key (and its passphrase, since Phase 4) cannot change anything | partly addressed (Phase 4); rotate and recover remain library-only |
| L44 | A trust store interrupted midway through `initialize` (after the root anchor is written) refuses both load and re-initialisation | Fail closed, no silent regeneration | Recovery via `quarantine` and re-initialise | accepted |

## Evaluation engine (Phase 3, 2026-10-31)

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L45 | Terminal classification is lexical and table-driven. A program not in the tables, a renamed binary, an alias, a shell function, or a project script with an innocent name (`npm run test` running anything) is classified by name only. | Shell semantics and package scripts are not executed or interpreted | Unknown programs are low confidence (never auto-allowed). `npm run <safe-name>` and `make <safe-target>` trust the script name, which the project controls; a project that cannot be trusted with its own scripts should lower `dev-tools` to approval in the global policy. | accepted; documented |
| L46 | Path arguments inside terminal commands are recognised heuristically (looks like a path, dotfile, or sensitive name). An argument that names a file without looking like one (`cat secrets`, a bare file name) is classified by name only, not resolved. | Arguments are not typed | Sensitive names are recognised in any case; the guard checks protected paths textually; unresolvable or wildcard arguments lower confidence | accepted |
| L47 | Path checks describe the filesystem at decision time; nothing stops the tool from accessing a different object later (see L26). String checks alone cannot prove which object will be opened. | Hooks decide before the tool runs | Resolution of typed and terminal paths through symlinks; dangling links rejected. Strong guarantees need filesystem-level enforcement (Landlock or the contained tier). | accepted |
| L48 | Case-insensitivity is applied to sensitive file names and to restrictive rule patterns, not to the project boundary itself; Unicode normalisation (NFC/NFD) differences are not folded | Linux filesystems are case-sensitive; macOS is out of scope (L42) | Restrictive rules widen under case variation; allowances do not | accepted |
| L49 | `REQUIRE_APPROVAL` from a profile rule replaces the default for actions it matches, including critical ones (for example a production `database migrate` is approval-gated rather than denied by default) | Profile rules are explicit action rules (precedence level 4) | Set the environment in the request; add a global or project DENY for production targets; the critical floor still prevents a plain ALLOW | accepted; configurable |
| L50 | Each evaluation writes 4 to 6 audit records, each with an `fsync` on the JSON Lines sink | Step events are required for auditability | Acceptable for hook-rate traffic; the SQLite audit store (next phase) batches writes | planned |
| L51 | The `Unattested` policy integrity (policies built in code) is accepted by `evaluate` | Tests and embedded defaults | The hook runtime builds policies only through the trust layer (`Verified` or `Failed`); requiring `Verified` will be enforced in the integration phase | planned |

## CLI and distribution (Phase 4, 2026-10-31)

See [CLI.md](CLI.md) §12.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L52 | No engine packages are published and no release signing key is provisioned. `release-keys.json` is empty, so every release engine fails verification. | Release infrastructure does not exist yet and was not invented | Development path with two explicit variables, always reported as unverified; release scripts implemented and tested (CLI.md §8) | open (manual action) |
| L53 | The per-platform engine packages are not yet listed as `optionalDependencies` of `ai-defender` | They do not exist on the registry; listing them would break `npm install` | Add them in the release that first publishes them | planned |
| L54 | Only linux-x64 is validated. linux-arm64 and macOS are untested; Windows is unsupported (the trust store depends on Unix ownership, modes and `O_NOFOLLOW`). | No build or test hosts for those targets; no ACL implementation | Untested targets are labelled as such everywhere; win32 resolution fails with exit 3 | open |
| L55 | Engine verification is check-then-execute: the binary is hashed, then spawned by path. A same-user process that swaps the file between the two steps runs its own binary. | Node cannot exec an already-opened file descriptor portably | The package directory is user- or root-owned (global npm prefix); a same-user attacker can already replace the CLI itself (L37). | accepted |
| L56 | An interactively typed passphrase passes through the Node process (as a JS string, not zeroisable) and the engine's stdin pipe | The engine reads the request on stdin; JS strings are immutable | `--passphrase-file` (checked by the engine: absolute, regular, owned, mode 600) keeps it out of Node entirely; the engine zeroises its copy | accepted |
| L57 | The encrypted signing keys live in the trust store under the user's home. A same-user process that learns the passphrase (keylogger, passphrase file readable to it) can sign changes. | Local-user model (L37, L39) | Argon2id-sealed key files; move `root.key` offline after setup; administrator anchor; hardware signers via the `Signer` trait later | accepted (operational) |
| L58 | The agent guard denies terminal commands that start `ai-defender init`, `project`, `trust`, `revoke`, `policy` and similar, but nothing is wired into an agent yet, so no agent is actually blocked | Integration is Phase 5 | `status` reports integration "not configured" and enforcement "not active" | planned (Phase 5) |
| L59 | The guard blocks `ai-defender policy …` for agents as a whole, including the read-only `policy show` | The subcommand list is coarse-grained | Agents can read the same information with `status --json` | accepted |
| L60 | Hidden-input prompting uses raw TTY mode and was tested on Linux only | Platform scope (L54) | `--passphrase-file` works without a TTY | open |
| L61 | The engine's text fields (messages, paths, names) are sanitised for terminal control characters, but the Rust and TS layers do not normalise Unicode lookalikes in project names | Display-only data | Names are bounded (100 chars) and never used for decisions | accepted |

## Human approval and authorization grants (Phase 5, 2026-10-31)

See [APPROVALS.md](APPROVALS.md).

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L62 | Local interactive approval cannot prove that a human, rather than a same-user process, typed the answer. A process that learns the policy-key passphrase (keylogger, readable file, shell history) can approve. Terminal interaction does not protect against a compromised machine or an administrator. | Agent and human share one unrestricted OS account (L37) | The passphrase, not the terminal, is the credential; `--passphrase-file`, `--yes`, `--json` and non-TTY sessions are refused for approval; the guard denies agent commands that run `approve`/`reject`/`approvals`/the engine; `ApproverAuthentication` is extensible to hardware keys or a remote approver | accepted; documented |
| L63 | Pending request records are not signed (the requesting path holds no key). A process with write access to the trust store could plant a pending request whose displayed summary does not match its digest, and a human approving it would authorize the digest's operation. | Only the approver holds a key, and only at approval time | The trust store is 0700 outside every project; the guard denies agent writes to it (exact for file tools, best effort for terminal commands, L45); the reviewed digest is shown and checked | accepted |
| L64 | Binding covers what the protocol carries. `git push` is bound to remote, ref, force, project, agent, session and policy, not to the commits pushed (HEAD) or a repository identity beyond the registered project. Terraform plan digests are unavailable. | No adapter supplies those fields yet | Operations that need a missing field to be meaningful (`terraform apply`, untargeted pushes, database or cloud changes without an environment) cannot be approved at all. Since Phase 7, pushes and commits run through `ai-defender run` are bound to the source commit, pushed range, remote URL identity, HEAD, branch and staged tree ([EXECUTION.md](EXECUTION.md)); typed protocol requests are not | open (typed adapters) |
| L65 | Agent identity is integration-asserted (`agentguard-engine --agent <kind>` from protected hook settings), not attested. A process able to run the engine binary can claim any agent kind for the agent-side commands. | No per-process attestation on a local machine | Claiming an identity grants nothing by itself: approval needs the passphrase, and a grant is bound to the agent recorded at request time; the guard denies agents running the engine binary | accepted |
| L66 | Grant state is mutable file state. A same-user process with write access to the trust store could reset a consumed grant to active or delete records. | No hardware-backed monotonic counter | The signed expiry bounds any replay window (2 minutes by default, 5 at most) and cannot be extended without the key; audit records of consumption remain | accepted |
| L67 | The claim token is returned to the requesting integration. A hook that relays it through agent-visible output exposes it to the agent. | The integration flow is Phase 6 | The token is single-use, bound to one operation, and useless without a human-signed grant; integrations should keep it out of agent-visible text where the vendor allows | planned (Phase 6) |
| L68 | Every approval unlocks the signing key (Argon2id, about 0.1 to 0.5 s) and asks for the passphrase; there is no approval session | Deliberate: no standing approval credential | None needed for the MVP | accepted |
| L69 | Nothing calls `approval.request` or `authorization.consume` yet, and the in-process `Authorizer` still uses its in-memory `MemoryApprovalStore` | Hooks are Phase 6 | The persistent API is complete and tested; Phase 6 wires the authorizer to it with claim tokens | planned (Phase 6) |
| L70 | Expiry uses the system clock; setting it backwards keeps a grant's window open longer in real time | Changing the clock needs administrator rights (out of scope) | Hard maximums; expiry is recorded permanently once observed | accepted |
| L71 | Engine error reason codes are carried as a text suffix (`(approval.replay)`) rather than a structured field | Adding a field to the error object would change the v1 response schema the CLI validates exactly | Codes are stable and tested; a structured field can come with the next protocol version | accepted |
| L72 | Only single-operation approvals exist; task or session scopes from the Phase 0 design are not implemented | Narrowest scope first | `ApprovalScope` vocabulary remains for later | planned |

## Sensitive files, secrets and disclosure (Phase 6, 2026-10-31)

See [SECRETS.md](SECRETS.md). Secret scanning is not data loss prevention.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L73 | Detection is pattern-based: secrets without a recognisable format, split or encoded values, secrets in binary files and unknown provider formats are missed; some non-secrets are reported | No detector can know what is secret | Severity tiers (only `high`+ drive policy by default), placeholder filters, custom detectors, `secrets explain` for review; sensitive files are protected by name regardless of content | accepted; documented |
| L74 | Nothing is enforced for operations no integration submits; no agent hook is installed yet | Agent integrations are a later phase | `secrets scan` works today; `status` reports enforcement as not active | planned |
| L75 | Terminal analysis is lexical: a sensitive file reached through a variable, script, alias or interpreter one-liner may not be recognised | Commands are not executed or interpreted | Such commands are usually unknown or uncertain (approval); existing bare arguments are resolved, so innocent-looking symlinks are followed | accepted |
| L76 | Terminal copies of sensitive files (`cp .env public.txt`) require approval rather than being denied as copies into ordinary files | Terminal path arguments are not split into source and destination | Typed copy operations are denied; the sensitive-write approval still gates the terminal form | open |
| L77 | A write without `content` cannot be inspected for secrets | The protocol makes content optional (64 KiB request limit) | The target's classification still applies; integrations should send content when available | open (integrations) |
| L78 | Decision-time inspection reads files at evaluation time; the tool may later read a different version | Hooks decide before the tool runs (L26, L47) | Bounded inspection, `O_NOFOLLOW`, regular-file checks; strong guarantees need filesystem-level enforcement | accepted |
| L79 | Staged-content verification uses size and modification time like Git; a same-size edit within the timestamp granularity, or staged content differing from the working tree, cannot be verified from disk | Staged blobs are zlib-compressed and no decompressor is in the dependency tree | Unverifiable staged files make the decision uncertain (approval) and the scan incomplete; a `.git` file (worktrees, submodules) is reported unsupported | accepted |
| L80 | Scan path arguments may not contain `..` even when the result would stay inside the project | Boundary checks are lexical plus no-symlink component walks | Run the scan from the project root or give root-relative paths | accepted |
| L81 | The hosted-AI host list is a fixed set of well-known endpoints | No authoritative registry | The destination class is informational; secret data is denied to every external or unknown destination regardless of class | accepted |
| L82 | Once an agent has read a secret (for example after an approved read), AI Defender cannot stop the model from repeating it | Outside any local control | Reads of sensitive files are denied by default; `secrets preview` gives names instead of values | accepted |

## Managed execution and Git security (Phase 7, 2026-10-31)

See [EXECUTION.md](EXECUTION.md). Managed execution is not global enforcement.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L83 | Only commands routed through `ai-defender run` (or `execution.run`) are controlled; an agent's own terminal and file tools, and Git run directly, are not intercepted | Agent hook integrations are Phase 8 | Every outcome, `status` and help state it; the guard's rules are ready for hook-routed calls | planned (Phase 8) |
| L84 | Programs started by an allowed command (package scripts, Makefiles, test suites) are not separately classified | Child processes are not traced | Environment filtering and the time limit still apply; unknown project scripts named directly need approval | accepted |
| L85 | Repository hooks run during approved commits, merges and pushes | They are part of the operation Git performs | Hooks are listed in the approval summary; commit verification detects staged-content changes | accepted |
| L86 | Shell mode accepts a strict subset; most real-world shell syntax is refused | Exact classification is required before anything runs | Use managed mode (argv) or split the work into supported commands | accepted |
| L87 | An executable replaced between the final identity check and `exec` is not detected | No `fexecve` without unsafe code, and scripts need their path | The window is microseconds; identity is bound into the approval and rechecked immediately before spawning | accepted |
| L88 | A command-line caller without `--agent` is evaluated as the generic agent; AI Defender cannot tell a human at a terminal from an agent driving one | Shared OS account (L37) | Approval still needs the passphrase in a separate `ai-defender approve`; never inline | accepted |
| L89 | Output is returned when the command finishes, not streamed; commands cannot read input (stdin is `/dev/null`) | One request, one response | Time limits bound the wait; interactive tools are out of scope | open |
| L90 | Process-group isolation, signal forwarding and `no_new_privs` are Linux-only; macOS is untested; Windows is unsupported | Platform APIs (`signalfd`, `prctl`) | Documented platform table; time limits still apply | open |
| L91 | Git inspection honours the repository's configuration apart from hooks, file-system monitors, pagers, credential helpers, external diff and text conversion; `status` is skipped when content filters are configured | Overriding every config-driven program generically is not possible | Binding facts use plumbing that does not run filters; the repository must lie inside the project | accepted |
| L92 | Push scans stop at 200 commits or 16 MiB, and binary diffs are not scanned | Bounded inspection | Incomplete scans make the decision uncertain (approval) and are reported | accepted |
| L93 | Environment filtering is by name: an allow-listed variable can still carry a credential (a proxy URL with a password), and programs can read credentials from files (`~/.git-credentials`, `~/.npmrc`) or the SSH agent | Values are not inspected; files are outside the environment | Credential-like names are never passed; withheld values are masked in output; the `minimal` profile is available | accepted |
| L94 | A redirection to a file inside the project is classified with the command it belongs to (`echo x > notes.txt` is a read-only command with a write target) | Phase 3 terminal analysis | Redirect targets are resources: outside the project, on sensitive or security files they lead to approval or denial | open |
| L95 | If the engine is killed with `SIGKILL`, the managed process group can outlive it | `PR_SET_PDEATHSIG` needs code that runs in the child (unsafe) | The record stays `started` and is shown as indeterminate; `SIGINT`/`SIGTERM`/`SIGHUP` terminate the group (Linux) | accepted |
| L96 | Execution records (500) and idempotency keys (5000) are pruned oldest first; records are mutable files in the trust store | Bounded local storage; no SQLite yet | Audit events remain in the hash-chained log; the SQLite store is a later phase | planned |
| L97 | Push verification relies on the remote-tracking ref; remotes without a fetch refspec report `unconfirmed` | No network call is made to verify | The approval binds the source commit and range; verification never claims success it cannot see | accepted |

## Agent hook integrations (Phase 8, 2026-10-31)

See [HOOKS.md](HOOKS.md). Hooks are not complete AI-agent protection.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L98 | Claude Code before v2.1.295 ignores `onFailure`, so a crashed, missing or timed-out AI Defender hook lets the tool call continue. The development host runs 2.1.263. | Provider behaviour | `status`/`verify` report compatibility "degraded"; every failure AI Defender itself detects is an explicit deny | open: upgrade Claude Code |
| L99 | Codex documents no general rule for failed or timed-out command hooks | Provider documentation | `\|\| exit 2` blocks when the engine cannot start or crashes; internal failures deny; timeouts listed as bypassable | open (provider) |
| L100 | Hooks do not run until the provider trusts them (Claude Code workspace trust in interactive sessions; Codex `/hooks` review), and AI Defender cannot observe that trust state | Provider trust models | Installation output and `status` say so | accepted |
| L101 | Only listed tools are matched; future provider tools are not covered until added; Codex hosted tools, `write_stdin` and opt-out tool paths are never seen | Matchers and provider coverage | `integrations coverage` lists every gap | accepted |
| L102 | A hooked Bash command runs through the provider's tool, not the managed executor: AI Defender classifies the text but does not filter its environment, time-limit it, or see child processes | Rerouting through `updatedInput` would change commands the agent sees | Single Git commands get the same state binding and scans as managed execution | open |
| L103 | MCP tools, WebSearch and URL fetches are evaluated conservatively (approval by default); MCP arguments are bound but not interpreted | No typed knowledge of arbitrary tools | Global policy can allow specific tools or hosts | accepted |
| L104 | Approval needs a retry within the grant window (2 minutes by default) | Neither provider can pause an interactive call for an external approval | Pending requests are reused across retries; the window is configurable up to 5 minutes | accepted |
| L105 | Unknown payload fields are ignored, so a provider change that adds a security-relevant field is not noticed; missing or mistyped required fields are blocked | Forward compatibility | Adapter version and documentation date recorded; re-verify docs per provider release | accepted |
| L106 | Relocated configuration directories (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`) and project-level installation are not supported | Scope | Installation refuses rather than writing an unread file | open |
| L107 | Sessions outside registered projects are not governed, apart from the trusted-state guard | AI Defender governs registered projects | Register the projects agents work in | accepted |
| L108 | Installation rewrites the JSON file: content and unrelated entries are preserved exactly, but formatting and key order may change | No format-preserving JSON editor in the dependency tree | Backup kept; uninstall restores the same JSON value | accepted |
| L109 | The health check runs synthetic hook calls inside the engine; it cannot prove that the provider actually invokes the hooks | Providers cannot be driven from AI Defender | Audit shows `hook-invoked` events once the provider runs them | accepted |
| L110 | Each protected tool call adds about 16 ms (release build, Linux); calls needing Git inspection or approvals take about 120 ms or more | One process per call, signed-state verification, audit fsyncs | No daemon by design | accepted |
| L111 | Windows is not released | The engine builds for Windows, but has not yet passed its suite on a Windows runner (L117 to L124) | Linux x64/arm64 and macOS x64/arm64 run the full Rust suite in CI; the release workflow runs the global-install test with each released engine | open: Windows port in progress |

## Production hardening (0.2.0, 2026-11-02)

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L112 | Project and policy YAML are parsed by `serde_yaml`, whose backend `unsafe-libyaml` is archived (RUSTSEC-2024-0449): a c2rust translation of libyaml that receives no fixes | No maintained drop-in replacement with identical YAML semantics was adopted in this release | Files are size-limited before parsing; the parsed values are schema-validated; the cargo-deny exception names this entry | open: replace the YAML stack |
| L113 | When a repository's own Git configuration (local or worktree scope) defines content filters, AI Defender computes neither `git status` nor the staged tree, and refuses managed `git commit` there | Computing either can run the filter (Git re-hashes racily clean files), and a filter is an arbitrary command anyone who can write `.git/config` can plant | Filters in system or global configuration (Git LFS) are unaffected; the refusal names the cause | accepted |
| L114 | `npm uninstall -g ai-defender` removes the command without the password, and the owner of the account can edit the agents' settings files or delete `~/.config/agentguard` | npm offers no reliable hook into uninstallation, and a tool must not stop its owner from removing it | `ai-defender uninstall` is the supported, password-protected path; the hooks stay installed and keep blocking after a bare npm uninstall; agents are refused by the guard and by the engine | accepted |
| L115 | The passphrase attempt record is an unsigned file; anyone who can delete it resets the backoff, and concurrent engine processes may each count one failure | It slows guessing through AI Defender; it is not what protects the key | The key files are Argon2id-sealed; the record lives in the private `keys` directory | accepted |
| L116 | Project identity detects a directory recreated at the same path through the inode generation only where the filesystem reports one (ext4, XFS, Btrfs); elsewhere on Linux it relies on device and inode | `FS_IOC_GETVERSION` is filesystem-specific | APFS never reuses inode numbers; NTFS file indexes carry a sequence number | accepted |

## Windows port (in progress, 2026-11-02)

The engine compiles and passes clippy for `x86_64-pc-windows-gnu`, and CI runs the suite on
`windows-latest`. It is not released until that suite is green and the items marked *release
blocker* are closed.

| # | Limitation | Why | Mitigation | Status |
|---|---|---|---|---|
| L117 | The trust-store, approval, managed-execution and `tests/integration` suites, and the unit tests written with Unix path literals, run on Unix only | They assert Unix modes, symlinks and `sh` behaviour, or build paths such as `/work/app` | On Windows: the path-rule tests (`agentguard-core`), the platform layer, the Job Object runner, and the hooks end-to-end suite with a bypass test of Windows spellings | open: release blocker |
| L118 | The global-install test (`npm run e2e:install`) and the release workflow do not cover Windows, and `package.json` does not list `win32` | npm's Windows prefix layout and `.cmd` shims differ; npm refuses `ai-defender` on Windows until `os` lists it | `pack:check --release` refuses an `os`/`cpu` that does not match the bundled engines, so `win32` cannot be declared without a Windows engine | open: release blocker |
| L119 | Codex hooks are not installed on Windows | Codex runs a hook as one shell command line, and which shell runs it on Windows is not documented | `integrations install codex` refuses on Windows; Claude Code hooks use an argument vector, no shell | open |
| L120 | Managed execution on Windows runs only `.exe` and `.com` files, so `npm`, `npx`, `yarn` and other `.cmd` shims cannot be run through it | `cmd.exe` re-parses a batch file's arguments differently from the vector AI Defender evaluated | Run the tool's `.exe` or `node` with its script | accepted |
| L121 | On Windows a timed-out or leftover process is terminated without a graceful stop, and the engine does not suppress Windows Error Reporting crash dumps | Windows has no `SIGTERM` for console-less processes; dump suppression needs a machine policy | The Job Object kills the whole tree and dies with the engine | accepted |
| L122 | Containment ignores case with Unicode upper-casing, not the volume's NTFS upcase table, and directories with per-directory case sensitivity enabled are compared as case-insensitive | The upcase table is not exposed cheaply | Restrictive rules already match without case; existing components are canonicalised to their on-disk spelling | accepted |
| L123 | In terminal commands, Git Bash spellings (`/c/Users/...`) are recognised by the trusted-state guard but not resolved as path arguments | Path arguments are resolved with Windows path rules | The guard matches `C:\`, `c:/`, `/c/`, `~`, `%USERPROFILE%` and `$env:USERPROFILE` spellings of protected paths | open |
| L124 | PowerShell commands are classified with the POSIX shell grammar | There is no PowerShell parser | Commands the grammar cannot analyse are low confidence and assessed as at least medium risk; protected paths are still found by the guard's text match | open |
