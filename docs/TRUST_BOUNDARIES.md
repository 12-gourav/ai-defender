# Trust Boundaries

## 1. Trust zones

```
┌────────────────────────────────────────────────────────────────────────────┐
│ ZONE 0 — Host root / kernel / rootless Docker daemon                       │
│   Fully trusted. Out of scope if compromised.                              │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ ZONE 1 — Developer's host user session                               │  │
│  │   Trusted. Contains: ai-defender CLI, controller, approval UI,        │  │
│  │   credential broker, audit DB, trusted policy snapshot,              │  │
│  │   the developer's real repository, ~/.ssh, ~/.aws, provider tokens.  │  │
│  │                                                                      │  │
│  │   ══════════ BOUNDARY B1: container + userns + netns ══════════      │  │
│  │                                                                      │  │
│  │  ┌────────────────────────────────────────────────────────────────┐  │  │
│  │  │ ZONE 2 — Agent container                                       │  │  │
│  │  │   UNTRUSTED. Contains: agent CLI, agentguard-shim, staging     │  │  │
│  │  │   clone, agent's own provider credential (see ADR-0010),       │  │  │
│  │  │   baked-in managed settings (read-only).                       │  │  │
│  │  │   Assumed: attacker has arbitrary code execution here.         │  │  │
│  │  └────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                      │  │
│  │   ══════════ BOUNDARY B2: egress proxy (allowlist, host-side) ═════  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
          ║ BOUNDARY B3: credential broker / provider APIs ║
┌────────────────────────────────────────────────────────────────────────────┐
│ ZONE 3 — External services                                                 │
│   GitHub/GitLab (with server-side branch protection), package registries,  │
│   AI provider APIs, databases, cloud providers. Semi-trusted; their own    │
│   access controls are a second enforcement layer.                          │
└────────────────────────────────────────────────────────────────────────────┘
```

## 2. Boundary crossings

Every arrow crossing B1 is enumerated. If a crossing is not in this table it must not exist, and the adversarial suite tests that it does not.

| # | Direction | Mechanism | Data | Enforced by | Trust assumption |
|---|---|---|---|---|---|
| X1 | Zone 2 → Zone 1 | Control unix socket (bind-mounted, 0600, owned by host user) | Typed IPC: hook queries, git remote helper stream, exec requests, task-scope requests | Controller validates every message against schema, policy, task, session | Messages are hostile. Length limits, timeouts, no deserialisation of untrusted types beyond the IPC schema. |
| X2 | Zone 2 → Zone 1 → Zone 3 | Egress proxy unix socket (bind-mounted) | HTTP / HTTP CONNECT only | Network Guard allowlist by hostname, resolved IP class, port; metadata endpoints hard-denied | Proxy is the only route. Container has `--network none`. |
| X3 | Zone 1 → Zone 2 | Bind mounts at start | Staging clone (rw), read-only agent credential file, and the enumerated optional slots: read-only object alternates (opt-in), approved read-only extra directories, Database Guard sockets. The shim is baked into the image, not mounted | Sandbox manager mount allowlist; integrity check refuses any other mount | Mounted content is now agent-controlled (except ro mounts, whose *contents* are still readable by the agent). |
| X4 | Zone 2 → Zone 1 | Git-native sync (controller runs `git fetch` *from* the staging clone into a quarantine ref) | Git objects only | Git Guard: hooks disabled, config ignored, object validation, path validation, secret scan, protected-file diff | Objects are untrusted. Never run git in the staging clone with host config or hooks. |
| X5 | Zone 1 → Zone 1 | Approval UI on a separate host terminal | Typed approval prompt and typed developer response | Approval engine; anti-spoof session phrase | The developer's terminal is trusted; the agent's TTY output is not (ADR-0007). |
| X6 | Zone 1 → Zone 3 | Credential broker | Short-lived tokens; exact approved operation | Broker binds credential to operation; provider-side branch protection | Provider access controls are an independent second layer. |
| X7 | Zone 2 → Zone 3 | Agent's own provider API traffic via X2 | Prompts and completions (includes repository content by design) | Allowlist limited to the provider's API host | Repository content leaving to the AI provider is inherent to using the agent. |
| X8 | Zone 2 ↔ Zone 1 | TTY passthrough from `ai-defender run` to the agent | Keystrokes and terminal output | **Output filter in the host PTY owner**: strips OSC 52, DCS/APC/PM/SOS, terminal query sequences and alternate-screen/cursor-addressing outside a conservative SGR/clear/cursor set; full terminal reset on exit | Agent output can look like anything, including a fake approval prompt; never act on it. Escape sequences can otherwise write the clipboard or seed the next shell (Phase 0 review G1). |
| X9 | Zone 2 → Zone 1 | `SyncRequest` over the control socket | A request that the controller run its own sync pipeline | Controller runs the pipeline on its own terms; the request carries no data beyond the branch name | The request is a trigger only; the pipeline reads staging objects through gix, never by spawning git in the staging clone (G9). |
| X10 | Zone 1 → disposable container | Scanner execution (gitleaks, trivy) on extracted agent content | Extracted tree, read-only; controller-owned scanner configuration | Sandbox manager; in-tree scanner configuration files are never honoured (G8) | Scanners are parsers of hostile input and run with the same containment as the agent. |
| X11 | Zone 1 → developer terminal | `ai-defender audit`, `violations`, `status`, approval prompts | Stored strings that originated from the agent | One shared sanitising renderer: control and ANSI stripped, bidi and zero-width code points escaped, non-ASCII identifiers flagged (G12) | Stored agent strings are untrusted output. |

## 3. What each zone may never contain

| Zone 2 (container) must never contain | Reason |
|---|---|
| Docker socket or any Docker API access | container escape equals host user compromise |
| `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.gitconfig` credential helpers | credential theft |
| The developer's real `.git` directory (rw or ro) | hook/config injection executed by host git; ro still leaks reflog, stashes, other branches' secrets |
| The trusted policy snapshot, audit DB, control state | tampering |
| Any long-lived Git remote token | unauthorised push |
| The approval socket, or any control-socket message type that can record a decision | self-approval (G3) |
| Production database credentials or hostnames reachable via proxy | data loss |
| Cloud CLI credentials | infrastructure compromise |
| A writable copy of the agent's own permission/hook configuration | self-authorisation |

| Zone 1 (host) must never do | Reason |
|---|---|
| Run `git` inside the staging clone using the clone's config/hooks | repo-content RCE on host |
| Execute any file from the staging clone | same |
| Deserialise untrusted IPC into anything other than the fixed IPC schema | memory/logic attacks |
| Render approval prompts from agent-supplied free text without labelling it as agent-supplied | prompt spoofing |
| Log credential values, even redacted-looking ones | audit leak |
| Run gitleaks, trivy or any parser of agent content on the host outside a disposable container, or honour scanner configuration found in the scanned tree | scanner compromise or silent bypass (G8, G4) |
| Spawn `git` with the staging clone as its repository | hostile config execution (G9) |

## 4. Boundary-specific assumptions and their verification

| Boundary | Assumption | How verified (phase) |
|---|---|---|
| B1 userns | Container root is not host root; caps dropped; no-new-privileges | `ai-defender doctor` inspects daemon rootless mode; adversarial tests attempt `mount`, `nsenter`, `setuid`, `/proc/sysrq-trigger` (Phase 4, 11) |
| B1 netns | `--network none` yields no route; only loopback | test: `curl 1.1.1.1`, raw socket, DNS to 8.8.8.8, IPv6, all must fail (Phase 8, 11) |
| B1 fs | No host path mounted except the allowlist | sandbox manager asserts via `docker inspect` before handing over the TTY; test scans `/proc/mounts` inside (Phase 4) |
| B2 | Proxy allowlist enforced for CONNECT and plain HTTP; metadata IPs denied even when a hostname resolves to them | tests with hostile DNS answers, IP literals, decimal/octal IP forms, IPv6-mapped v4, redirects (Phase 8, 11) |
| X4 | Host never executes staging-clone content | code review rule plus test: plant a malicious `core.fsmonitor`, `core.hooksPath`, `.git/hooks/*` in the staging clone and prove the sync does not run it (Phase 7, 11) |
| X5 | Agent cannot write to the approval UI terminal | the UI process is not attached to the container TTY; anti-spoof phrase displayed only in UI (Phase 6) |
| B3 | Token is scoped to one repo and one operation where provider supports it | broker unit tests plus live test against a disposable repo (Phase 7) |

## 5. Residual trust the design cannot remove

- The agent process must hold the AI provider's credential (or receive it via the proxy) to function. It is scoped and its only network path is the provider's host, but it is **reachable** by the agent. ADR-0010.
- Container isolation relies on the Linux kernel. A kernel exploit escapes to the host user (not root, under rootless Docker). gVisor reduces this surface and is the recommended runtime for higher-assurance use.
- The developer can be socially engineered by agent output into approving something harmful. Typed approvals that show the exact diff, ranges and targets are the mitigation; they are not a guarantee.
