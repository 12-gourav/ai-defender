# Threat Model

## 1. Assets

| Asset | Where it lives | Impact if compromised |
|---|---|---|
| A1 Remote repository write access (push, merge, protected branches) | Provider; tokens on host | supply-chain compromise, destroyed history |
| A2 Developer's local repository (`.git`, working tree, stashes, other branches) | Host | data loss, host RCE via hooks/config |
| A3 Host credentials (`~/.ssh`, cloud, registry, DB, provider tokens) | Host | lateral movement to everything |
| A4 Secrets inside the project (`.env`, certs, keys) | Repo working tree | exfiltration |
| A5 Host filesystem and user account | Host | total compromise of the developer |
| A6 Production databases and infrastructure | External | outage, data loss, breach |
| A7 The security policy and task scope | Controller state | silent escalation |
| A8 Approval tokens | Controller memory/state | replay, substitution |
| A9 Audit trail | Controller state | loss of accountability, hidden attacks |
| A10 Developer's attention and trust | Human | social engineering of approvals |
| A11 The sandbox image and shim | Image registry / build | supply chain of the guard itself |

## 2. Threat actors

| Actor | Description | In scope |
|---|---|---|
| T1 Compromised agent | The AI agent, driven by prompt injection (from repo files, issue text, web pages, dependency READMEs, tool outputs), model misbehaviour, or a malicious model/provider. Has arbitrary code execution inside the container. **This is the primary adversary.** | Yes |
| T2 Malicious repository content | Files in the repo that execute when tooling runs: Git hooks, `.gitattributes` filters, build scripts, `package.json` lifecycle scripts, Makefiles, editor config, CI config. | Yes |
| T3 Malicious dependency | Package pulled from a registry with install-time or run-time payloads. | Yes |
| T4 Malicious or compromised MCP server / plugin / extension used by the agent | Executes in the agent's context. | Yes (treated as T1) |
| T5 Network attacker | On-path attacker against allowed egress; DNS manipulation. | Partially (TLS reliance) |
| T6 Negligent developer | Approves something harmful because the prompt was misleading, or sets an unsafe policy. | Mitigated by typed prompts, not prevented |
| T7 Malicious developer | Deliberately exfiltrates using their own access. | **Out of scope.** They own the policy and the host. |
| T8 Compromised host user account or root | Attacker already on the host as the developer or root. | **Out of scope.** Controller and audit are only as safe as the host user. |
| T9 Kernel / runtime vulnerability | Container escape via kernel or runc bug. | Reduced by rootless Docker and optional gVisor; not eliminated. |

## 3. Attacker capability matrix

Capabilities of T1 (the agent) with each layer present. "Yes" means the attacker can do it; the goal is "No" in the rightmost column with a named enforcement mechanism.

| Capability | No AI Defender, agent on host | Provider sandbox only | AI Defender contained tier | Enforcement mechanism |
|---|---|---|---|---|
| Read `~/.ssh`, `~/.aws` | Yes | Yes by default (Claude Code reads broad; Codex ro-sandbox allows reads) | No | Not mounted into container (X3 allowlist) |
| Push to remote with host token | Yes | Yes (network allowed to github.com in typical allowlists; credentials present) | No | No token in container; push only via broker after typed approval |
| Force-push / push to `main` | Yes | Yes | No | Git Guard hard-deny plus provider branch protection |
| Edit `.git/hooks`, `.git/config` of the developer's repo | Yes | Often blocked for Bash, but not for built-in Edit tool in Claude Code | No | Real `.git` never mounted; sync is object-level only |
| Disable or edit its own hooks/permissions | Yes (settings files writable) | Yes unless managed settings are deployed and locked | No | Managed settings baked into read-only image; hook calls reach controller which is authoritative |
| Run `docker` against host daemon | Yes | Sometimes (excluded commands) | No | No socket mounted; `--network none`; adversarial test |
| Exfiltrate over arbitrary network | Yes | Partially (proxy allowlist in Claude Code / Codex when enabled; not for built-in tools) | No, except to allowlisted hosts | `--network none` plus host-side allowlist proxy |
| Exfiltrate via DNS | Yes | Depends | No | No DNS resolver reachable; proxy resolves names |
| Reach cloud metadata (169.254.169.254) | Yes | Depends | No | No route; proxy denies link-local, loopback, private ranges unless explicitly allowed |
| Install arbitrary package with lifecycle scripts | Yes | Yes | Only if registry allowlisted; scripts run inside the container only; lockfile change requires typed approval at sync | Network Guard, Dependency approval, container containment of scripts |
| Connect to production database | Yes if creds present | Yes if network allowed | No | Hard-deny host list; DB only via Database Guard proxy |
| Run `terraform apply`, `kubectl`, cloud CLI | Yes | Yes | No inside; host-side only via Deployment Guard with typed approval | No creds in container; gateway exec requires approval |
| Spoof an approval prompt in the terminal | n/a | n/a | Can print one, but it is never acted on | Approval UI is a separate process; session anti-spoof phrase |
| Replay or reuse an approval | n/a | n/a | No | One-time tokens bound to operation hash, session, task, expiry |
| Modify `.agent-security.yml` to widen scope | Yes | Yes | Modifies only the staging copy; sync flags it as PolicyModification; running session unaffected | Policy snapshot pinned by hash |
| Tamper with audit | Yes | Yes | No | Audit DB in controller state, never mounted; hash chain |
| Consume unbounded CPU/memory/PIDs | Yes | Yes | No | cgroup limits (requires systemd delegation; see risk R-07) |
| Persist across sessions | Yes | Yes | Only in staging clone content, which is reviewed on sync | Fresh container each session; image is immutable |
| Escape the container via kernel bug | n/a | n/a | Possible | Rootless (escape yields host user, not root); gVisor optional; documented limitation |

## 4. Threat catalogue

Each threat lists: ID, actor, scenario, affected assets, mitigation (M-n refers to SECURITY_MODEL.md section 4), residual.

### Filesystem

- **TH-F1** T1 writes outside the workspace (path traversal `../`, absolute paths). Assets A2, A5. Mitigation: no host paths mounted; traversal inside the container only reaches the container. Sync-back validates every path against the workspace root after canonicalisation. Residual: none within the model.
- **TH-F2** T1 creates a symlink in the staging clone pointing to `/etc/passwd` or `~/.ssh/id_ed25519` expecting the host-side sync to follow it. Mitigation: sync is Git-object based; symlinks are stored as blobs with mode 120000 and never dereferenced; checkout into the developer's tree is done by the developer's git, and protected-file rules flag new symlinks. Residual: a developer who approves a commit containing a hostile symlink and then runs tooling that follows it. Flagged in approval prompt.
- **TH-F3** T1 creates hardlinks to shared objects. Mitigation: alternates are mounted read-only; staging clone objects are private; `--no-hardlinks` on clone. Residual: none.
- **TH-F4** T1 writes device nodes, FIFOs, setuid binaries. Mitigation: `nodev,nosuid,noexec` where practical on writable mounts; git does not store these types; sync rejects non-regular modes other than symlink and executable bit. Residual: none.
- **TH-F5** TOCTOU between validation and sync. Mitigation: validation operates on an immutable Git object set (a fetched commit), not on live files. Residual: none.
- **TH-F6** T1 modifies protected files (`.agent-security.yml`, CI config, IaC, deploy config). Mitigation: edits land only in staging; the protected-file diff is highlighted in the commit approval and requires a `PolicyModification`-class approval when it touches policy. Residual: developer approves a bad CI change; CI itself must apply its own protections.

### Commands and processes

- **TH-C1** Shell chaining, `bash -c`, `python -c`, `env`, `xargs`, `find -exec` to evade string filters. Mitigation: string filters are not the boundary. Inside the container nothing sensitive is reachable. Hooks give best-effort early denial for UX. Residual: none at the boundary.
- **TH-C2** Fork bomb, memory exhaustion. Mitigation: `--pids-limit`, `--memory`, `--cpus`. Residual: requires cgroup delegation; doctor verifies.
- **TH-C3** Long-running background process survives session. Mitigation: container is removed at session end. Residual: none.
- **TH-C4** T1 requests the gateway to execute a host-side command (deploy) with crafted arguments. Mitigation: structured `ExecRequest` with an executable from a fixed table and typed, validated argument model; no shell; typed approval. Residual: argument-injection into the tool itself (for example a `kubectl` flag that reads a file) is bounded by a per-tool argument schema.

### Network

- **TH-N1** Direct IP connection bypassing hostname allowlist. Mitigation: no route exists; proxy rejects IP-literal CONNECT unless allowlisted. Residual: none.
- **TH-N2** DNS rebinding or hostile DNS to make an allowed hostname resolve to a private or metadata IP. Mitigation: proxy resolves and checks the resulting IPs against deny ranges before connecting; pins the resolved IP for the connection. Residual: none within model.
- **TH-N3** Tunnelling through an allowed host (for example pushing data into an allowed registry or Git host). Mitigation: Git host access is only via the broker; registries are allowlisted per package manager and read-only paths where the proxy can distinguish (HTTP only). Residual: **an allowed HTTPS host is an exfiltration channel** unless TLS termination is used. Documented; TLS-terminating mode is Phase 8 optional.
- **TH-N4** Exfiltration via the AI provider API (prompts contain repo secrets). Mitigation: Secret Guard scrubs known secret files from the staging clone before the agent sees them, when policy says so. Residual: inherent; the agent must see the code to work on it.
- **TH-N5** UDP, ICMP, QUIC, raw sockets. Mitigation: no route; seccomp can additionally deny `socket(AF_INET, SOCK_RAW)`. Residual: none.
- **TH-N6** Abuse of the proxy stub's unix socket to reach the controller's control socket. Mitigation: separate sockets, separate protocols, controller socket messages are schema-validated and only expose request types the agent is allowed to make. Residual: none.

### Git and credentials

- **TH-G1** T1 extracts a push token. Mitigation: none in container. Residual: none.
- **TH-G2** T1 pushes to an unapproved branch by naming it differently (`refs/heads/main` vs `main`, refspec tricks, `+` force prefix, tag pushes, `--mirror`). Mitigation: Git Guard parses refspecs into typed `RefName` with full canonicalisation; only `refs/heads/<approved>` without force; tags and `--mirror` denied by default. Residual: none.
- **TH-G3** Approval for commit set `A..B` reused after rewriting history. Mitigation: approval binds to the exact commit SHA set and tree hash; any change invalidates. Residual: none.
- **TH-G4** Hostile `.git/config`, hooks, `core.fsmonitor`, `core.sshCommand`, `credential.helper` in the staging clone executed by host git. Mitigation: controller runs git with `GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null -c core.hooksPath=/dev/null -c core.fsmonitor=false` and never runs commands from the staging clone's config; fetches into a bare quarantine repo owned by the controller with `receive.fsckObjects`. Residual: a git vulnerability in object parsing. Pin git version in doctor.
- **TH-G5** Git provider-side token has broader scope than the operation. Mitigation: prefer short-lived installation/project tokens scoped to one repository; branch protection server-side. Residual: providers that only offer broad PATs; documented.
- **TH-G6** Secret committed then pushed. Mitigation: gitleaks (or native fallback) on the exact commit range before approval; high-risk commits require typed confirmation. Residual: unknown secret formats.

### Approvals and authorisation

- **TH-A1** Replay of a previous approval token. Mitigation: one-time consumption, server-side state, expiry. Residual: none.
- **TH-A2** Cross-session or cross-task reuse. Mitigation: token binds `session_id`, `task_id`, `policy_version`. Residual: none.
- **TH-A3** Substitution: approve a benign operation, execute a different one. Mitigation: token binds a canonical hash of the full typed request payload; the broker recomputes the hash of what it is about to execute. Residual: none.
- **TH-A4** Prompt spoofing: agent prints "Approval granted" or a fake prompt in the TTY. Mitigation: approvals only in the trusted UI, which shows a session phrase the agent never sees. Residual: developer ignores the phrase.
- **TH-A5** Approval fatigue / misleading reason text. Mitigation: agent-supplied reason is displayed in a clearly labelled, length-limited, non-formatted box; the trusted facts (branch, diff stats, scan results) are computed by the controller, not supplied by the agent. Residual: human judgement.
- **TH-A6** Agent asks for a task-scope expansion in natural language and the controller "helpfully" widens it. Mitigation: scope changes are a typed `PolicyModification` approval; nothing is inferred from free text. Residual: none.
- **TH-A7** Expired approval still honoured. Mitigation: expiry checked at consumption time, monotonic clock, short TTL (default 10 min, configurable downward only by policy). Residual: none.

### Policy, controller and audit

- **TH-P1** Agent edits `.agent-security.yml` in the workspace. Mitigation: session pinned to a snapshot hash; sync flags the change; new sessions re-validate with the developer. Residual: none.
- **TH-P2** Malformed or unknown keys quietly ignored, producing a weaker policy than intended. Mitigation: schema validation with `deny_unknown_fields` on security sections; fail closed on validation error. Residual: none.
- **TH-P3** Organisation policy overridden by project policy. Mitigation: deterministic precedence, tested. Residual: none.
- **TH-P4** Controller crash leaves container running with open sockets. Mitigation: container is started with the controller as its parent; sockets are removed on exit; a watchdog label lets `ai-defender doctor` find and kill orphans. Residual: brief window; the container still has no credentials or network.
- **TH-P5** Audit tampering by the agent. Mitigation: never mounted. Residual: host user can tamper (T8, out of scope); hash chain plus optional remote sink makes it detectable.
- **TH-P6** Secrets in audit. Mitigation: redaction at the write boundary; structured fields, no raw command environments. Residual: novel formats.

### Sandbox

- **TH-S1** Docker socket reachable. Mitigation: never mounted; `--network none` prevents TCP daemon access; test. Residual: none.
- **TH-S2** Privileged flags, added caps, `--userns=host`. Mitigation: sandbox manager builds the run spec from a fixed template and verifies via `docker inspect` before use. Residual: none.
- **TH-S3** Kernel exploit. Mitigation: rootless, seccomp default profile plus custom tightening, AppArmor, no-new-privileges, gVisor optional. Residual: documented.
- **TH-S4** Sandbox unavailable, AI Defender falls back to running the agent on the host. Mitigation: **never**. Refuse to start. Residual: none.
- **TH-S5** Supply chain of the sandbox image. Mitigation: image built from pinned base digest, Trivy scan in CI, shim built reproducibly, digest pinned in controller state. Residual: upstream base image compromise.

## 5. Security guarantees AI Defender will claim (and test)

Each maps to an acceptance criterion in [SECURITY_ACCEPTANCE_CRITERIA.md](SECURITY_ACCEPTANCE_CRITERIA.md).

- G1 No credential other than the agent's own provider credential is present inside the container.
- G2 No network route exists from the container except the host-side allowlist proxy.
- G3 No host path is visible inside the container except the enumerated mounts.
- G4 No remote Git write occurs without a valid, unexpired, one-time, operation-bound approval token (or an explicit non-interactive policy grant for non-protected feature branches, which is off by default).
- G5 Protected branches and force pushes are denied regardless of approvals, unless organisation policy explicitly enables an approval path.
- G6 The running session's effective policy cannot change through any action the agent takes.
- G7 Every boundary-crossing request and decision is recorded in the audit log with redaction.
- G8 Loss of the controller, the sandbox, or a guard results in denial, never in unrestricted execution.

## 6. Explicit non-guarantees

- Container escape is not impossible.
- An allowlisted HTTPS host can carry exfiltrated data unless TLS termination is enabled.
- The agent sees the code it works on and sends it to its provider.
- A developer can approve a harmful operation.
- Hooks inside agents are advisory.
