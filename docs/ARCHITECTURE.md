# AI Defender Architecture

Phase 0 design document. Nothing described here is implemented yet.

## 1. What AI Defender is

AI Defender lets a developer run AI coding agents (Claude Code, OpenAI Codex, Gemini CLI, Antigravity CLI, Cursor's agent CLI, and future agents) inside an existing project under one security policy, enforced by components the agent cannot reach.

The product is three things:

1. A **trusted controller** that runs on the host as the developer, owns all security state, and makes every sensitive decision.
2. An **isolated execution environment** in which the agent runs with no credentials, no network route, and a private copy of the repository.
3. A set of **brokers and gateways** through which the only path to anything sensitive (remote Git, dependencies registries, databases, deployment tooling) passes, each of which validates the exact operation and, where required, obtains a typed human approval.

The canonical project policy is `.agent-security.yml`, but that file is an *input* to the controller, not the boundary. The boundary is the container, the absence of credentials inside it, and the controller's refusal to act without a valid authorisation.

## 2. The one principle that drives the design

> **An AI agent must not be able to do a sensitive thing without a decision made by a component it cannot influence.**

Phase 0 research (see [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md)) established that every provider's hook system is fail-open by default, runs with the developer's full privileges, and is configured from files the agent can usually edit. Provider sandboxes likewise fail open by default and exempt their own built-in file tools. Therefore:

- Hooks are used for **early denial and good error messages**, never as the enforcement mechanism (ADR-0002).
- Command-string inspection is used for **classification and audit**, never as the sole gate (ADR-0002).
- Enforcement comes from **what the agent cannot reach**: no credentials, no network, no host filesystem, no Docker socket, no trusted policy state, no approval channel it can forge.

Anything the agent *can* reach is assumed to be fully under its control. The security argument never depends on the agent behaving.

## 3. Component architecture

```
 Developer (human, host terminal)
   │
   │  ai-defender CLI (trusted, host, developer's uid)
   ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  TRUSTED SECURITY CONTROLLER  (host process, per session)              │
 │                                                                         │
 │   Policy Engine ─── Permission Engine ─── Task Authorization Engine     │
 │        │                   │                      │                     │
 │   Human Approval Engine ───┴─── Credential Broker ─┴─── Audit Engine    │
 │        │  (typed requests, one-time tokens)   (host-side secrets)       │
 │        ▼                                                                │
 │   Approval UI  (separate trusted terminal/TUI, anti-spoof phrase)       │
 │                                                                         │
 │   EXECUTION GATEWAY  (all requests that cross the boundary)             │
 │     Filesystem Guard · Command Guard · Network Guard (egress proxy)     │
 │     Git Guard (remote helper endpoint) · Secret Guard (scan/redact)     │
 │     Database Guard (protocol proxies) · Deployment Guard                │
 └───────────────┬───────────────────────────────────────┬─────────────────┘
                 │ control socket (unix, 0600, per session)│ egress proxy socket
                 │ bind-mounted into container             │ bind-mounted
                 ▼                                         ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  ISOLATED EXECUTION ENVIRONMENT (rootless container, --network none)    │
 │                                                                         │
 │   agentguard-shim  (hook client, git remote helper, local proxy stub)   │
 │   AI agent CLI  (claude / codex / gemini / antigravity / cursor-agent)  │
 │   /workspace  = staging clone (private objects + read-only alternates)  │
 │   no secrets · no docker socket · read-only rootfs · caps dropped       │
 │   managed agent settings baked into image at /etc (not writable)        │
 └─────────────────────────────────────────────────────────────────────────┘
                 ▲
                 │ Git-native sync (fetch objects out, validate, fast-forward)
                 │
 Developer's real repository (host, never mounted into the container)
```

### 3.1 Trusted controller (host)

One controller process per agent session, spawned by `ai-defender run <agent>`. It:

- Loads and validates the project policy, merges it under organisation policy, snapshots the result into controller-owned state, and pins the session to that snapshot's hash (ADR-0005).
- Creates the session, the task context, the control socket, the egress proxy, and the sandbox.
- Answers every request that arrives on the control socket with Allow / Deny / NeedsApproval, and records the decision.
- Holds every credential. Nothing in the container ever receives a long-lived remote credential.
- Shuts down fail-closed: if it dies, the container's control and proxy sockets go away and the agent loses the ability to do anything except edit its private workspace copy.

Trusted state lives in `$XDG_STATE_HOME/agentguard/` (default `~/.local/state/agentguard/`) with mode `0700`, plus per-session runtime sockets under `$XDG_RUNTIME_DIR/agentguard/`. Neither path is ever mounted into a container.

### 3.2 Policy engine

Parses `.agent-security.yml` against a versioned JSON Schema, rejects unknown keys in security-critical sections, and produces a typed `EffectivePolicy` by applying deterministic precedence:

```
organisation hard-deny  >  organisation mandatory  >  project policy  >  task permissions  >  single operation authorisation
```

A lower layer can only *narrow*. Implemented natively in Rust (ADR-0003) with a possible future Rego front-end for organisation policy authoring.

### 3.3 Permission engine

Given an `EffectivePolicy`, the current `PermissionMode` (READ_ONLY, DEVELOPMENT, DEVELOPER_AUTHORIZED, RESTRICTED), the `TaskContext`, and a typed `OperationRequest`, returns a `Decision`:

- `Allow { rule }`
- `Deny { rule, reason, alternative, approvable: bool }`
- `RequiresApproval { request_type, risk }`

Every `Deny` carries the five fields the CLI must show: what was requested, why denied, which rule, whether approval is possible, what the safe alternative is.

### 3.4 Human approval engine

Owns typed `ApprovalRequest`s, their lifecycle, one-time cryptographic tokens, expiry, and binding to the exact operation. Renders prompts only through the trusted approval UI on the host. Details in [APPROVAL_MODEL.md](APPROVAL_MODEL.md).

### 3.5 Task authorisation engine

Creates and validates `TaskContext`s: the narrow, time-boxed envelope of what this session may do (workspace, branches, commands, approvals granted so far). Revocable at any time with `ai-defender revoke`.

### 3.6 Credential broker

The only component that touches remote credentials. Mints short-lived, operation-scoped credentials where the provider supports it (GitHub installation tokens, GitLab project tokens, cloud STS), and otherwise uses a developer-provided token that it never exports. Details in [GIT_CREDENTIAL_BROKER.md](GIT_CREDENTIAL_BROKER.md).

### 3.7 Execution gateway and guards

The gateway is the request dispatcher for everything that crosses the container boundary. It is **not** a wrapper around the agent's shell. Inside the container the agent may run any command it likes; what it can affect is bounded by the container. The gateway handles:

| Request kind | Arrives via | Guard |
|---|---|---|
| Hook decision (pre-tool) | `agentguard-shim hook` over control socket | Command Guard, Filesystem Guard (advisory tier) |
| Outbound connection | egress proxy socket (HTTP CONNECT / HTTP) | Network Guard (enforcing) |
| Git fetch / push | `git-remote-agentguard` over control socket | Git Guard + Credential Broker (enforcing) |
| Package install needing registry | egress proxy, plus lockfile diff on sync | Network Guard + Dependency approval (enforcing) |
| Database connection | Database Guard protocol proxy socket | Database Guard (enforcing) |
| Host-side privileged command (deploy, infra) | control socket `exec` request | Deployment Guard + Command Guard (enforcing, host executes) |
| Workspace sync-back | `SyncRequest` from the agent (a trigger only), the developer, or the controller before a push | Git Guard + Filesystem Guard + Secret Guard (enforcing) |

### 3.8 Sandbox manager

Builds and runs the container (rootless Docker initially; gVisor optional). Verifies integrity before start and refuses to run if any invariant fails (no socket mount, no privileged flag, caps dropped, network none, read-only rootfs, non-root user, seccomp and AppArmor applied, limits set). Details in [DOCKER_ISOLATION.md](DOCKER_ISOLATION.md).

### 3.9 Agent adapters

One adapter per agent. An adapter knows how to detect the agent, build its container image layer, bake in managed settings and hooks, supply its authentication, start it with a TTY, and report which guarantees it can actually make. Adapters never implement policy. Details in [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md).

### 3.10 Audit engine

SQLite database owned by the controller, hash-chained records, secrets redacted before write. Queried by `ai-defender audit | violations | approvals | sessions | status`.

### 3.11 The in-container shim

`agentguard-shim` is a small static Rust binary baked into the image. It is **untrusted** from the controller's point of view (the agent can kill or replace it in memory, though not on the read-only filesystem), and the design never depends on it. It exists for usability:

- `shim hook`: adapter-neutral hook client. Reads the provider's hook JSON, asks the controller, prints the provider's expected decision JSON. Configured with the provider's fail-closed flag where one exists.
- `git-remote-agentguard`: Git remote helper so `git push origin feature/x` inside the container becomes a brokered push request.
- `shim proxy-stub`: listens on `127.0.0.1:3128` inside the container's isolated network namespace and forwards to the bind-mounted egress proxy unix socket, so ordinary `HTTP_PROXY`-aware tools work.

If the agent disables the shim, it loses network, Git remotes and hook-based early denials. Nothing opens up. That is the fail-closed property the design relies on.

## 4. Session lifecycle

1. `ai-defender run claude --task AH-5064 "Implement X, run tests, commit, push to feature/AH-5064"`
2. Controller loads org policy and `.agent-security.yml`, validates, snapshots, computes `policy_version`.
3. Controller runs `doctor` invariants (rootless docker reachable, no socket exposure possible, cgroup delegation, image digest pinned).
4. Controller proposes a `TaskContext` from the task description and policy; developer confirms scope in the trusted UI (branch `feature/AH-5064`, commit allowed with approval, push to that branch allowed with approval).
5. Controller creates a staging clone, starts the egress proxy, opens the control socket, starts the container with the agent.
6. Agent works. Reads, edits, builds and tests happen entirely inside the container. Hook calls give early denials for out-of-policy actions.
7. Agent runs `git commit`. Inside the container this commits to the staging clone. The commit becomes *visible to the developer* only on sync, and reaches the developer's repository only after the typed commit approval (sync-back is an approval-gated fast-forward, see ADR-0004).
8. Agent runs `git push origin feature/AH-5064`. The remote helper sends a push request; Git Guard validates repository, branches, commit range, task context, branch protection; secret scan runs; developer gets a typed push approval; broker performs the push from the host with a short-lived credential; audit records it.
9. Session ends (agent exit, `ai-defender revoke`, policy integrity failure, or controller shutdown). Container removed, sockets closed, temporary credentials revoked, staging clone retained for inspection until `ai-defender clean`.

## 5. Permission modes

| Mode | Inside the container | Through the gateway |
|---|---|---|
| READ_ONLY | workspace mounted read-only, no commits | fetch only, no push, no installs, no exec |
| DEVELOPMENT | edit, build, test in staging clone | fetch; registries on allowlist; commit needs approval |
| DEVELOPER_AUTHORIZED | same as DEVELOPMENT | commit, feature push, dependency install each by typed approval; sensitive ops by approval |
| RESTRICTED | narrowed file set, narrowed command allowlist via hooks, no network | every sensitive action needs approval |

Hard-deny rules apply in every mode and no mode can disable enforcement. Some are absolute (Docker socket, cloud admin credentials in the sandbox, production databases in the pilot); others are deny at every level by default and may be opened to an approval path **only** by organisation policy, never by project policy or task scope (protected-branch push, force push, tag push). Modes change only through the trusted UI; the agent cannot request a mode change (it can request a task-scope change, which is a `PolicyModification`-class approval).

## 6. Platform strategy

Initial target is Linux (Ubuntu). The containment layer is abstracted behind a `Sandbox` trait so macOS (likely Docker Desktop or Apple Containerization plus Seatbelt for host-side pieces) and Windows (WSL2) can be added. The design does not pretend that Landlock, seccomp or AppArmor exist on those platforms; the adapter must report a reduced guarantee set and the controller must refuse to claim "contained" tier where it is not.

## 7. What AI Defender does not do

- It does not make the agent's output trustworthy. Code review remains the developer's job.
- It does not protect against a malicious developer; the developer owns the policy.
- It does not protect against a compromised host user account or root.
- It does not claim container escape is impossible. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
