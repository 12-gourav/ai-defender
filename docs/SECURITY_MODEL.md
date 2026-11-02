# Security Enforcement Design

## 1. Enforcement layers, ordered by trust

```
Layer 0  Provider-side controls      branch protection, scoped tokens, registry policy    (independent second layer)
Layer 1  Containment                 rootless container, userns, netns none, ro rootfs,    (THE boundary)
                                     caps dropped, seccomp, AppArmor, cgroups, no mounts
Layer 2  Credential absence          nothing to steal inside                              (THE boundary)
Layer 3  Host-side gateways          egress proxy, git broker, db proxy, exec gateway     (enforcing: only paths out)
Layer 4  Typed approvals             one-time tokens bound to the exact operation         (enforcing on sensitive ops)
Layer 5  Git-native sync validation  object-level review before anything touches the repo (enforcing)
Layer 6  In-agent hooks              early deny, good messages, fail-closed where possible (advisory: UX and defence-in-depth)
Layer 7  Command classification      audit and risk scoring                               (advisory)
```

A security claim may only rest on layers 1 to 5. Layers 6 and 7 improve the experience and catch mistakes early; the adversarial suite must pass with them disabled.

## 2. Fail-closed rules

| Condition | Behaviour |
|---|---|
| Rootless Docker unavailable or daemon not rootless | refuse to start session |
| Any sandbox invariant fails `docker inspect` verification | kill container, refuse |
| Policy file invalid, unknown security keys, or snapshot hash mismatch mid-session | refuse to start / terminate session |
| Controller process exits | sockets removed; container loses control and egress; container killed by controller's exit handler, and by `doctor` orphan sweep if the handler did not run |
| Hook cannot reach controller | shim returns deny; provider configured fail-closed where supported |
| Approval UI unavailable | request waits until timeout, then Denied(Expired) |
| Secret scanner missing | commit/push approvals are blocked for high-risk and require typed acknowledgement with explicit "scanner unavailable" for others; never silently skipped |
| Audit write fails | operation is denied (audit is on the critical path for sensitive operations) |

There is no "unsandboxed fallback" and no flag to add one. A developer who wants to run an agent without AI Defender runs it without AI Defender.

## 3. Policy

### 3.1 File and schema

`.agent-security.yml` at the repository root. Versioned (`version: 1`). Validated against `schemas/agent-security.v1.json`. Security-critical sections reject unknown keys.

Sketch of the shape (exact schema is a Phase 2 deliverable):

```yaml
version: 1
mode: DEVELOPMENT                    # READ_ONLY | DEVELOPMENT | DEVELOPER_AUTHORIZED | RESTRICTED
profile: default                     # optional named profile from policies/
filesystem:
  workspace: .
  read_only: ["docs/legal/**"]
  protected: [".agent-security.yml", ".github/**", ".gitlab-ci.yml", "infra/**", "deploy/**"]
  deny: [".env", ".env.*", "**/*.pem", "**/id_*"]
commands:                            # advisory (hook) tier inside the sandbox only; never a host allowlist
  allow: ["npm test", "npm run build", "cargo test"]
  deny: ["sudo *", "docker *"]
git:
  remotes: ["origin"]
  protected_branches: ["main", "release/*"]
  push:
    feature_branches: approval      # deny | approval
    protected_branches: deny        # deny | approval (org policy may forbid 'approval')
    force: deny
  commit: approval
  merge: approval
network:
  allow:
    - host: "registry.npmjs.org"
      ports: [443]
    - host: "api.anthropic.com"
      ports: [443]
  deny_private_ranges: true
  deny_metadata: true
dependencies:
  managers: ["npm", "cargo"]
  install: approval
databases:
  - name: dev-postgres
    env: development
    host: "localhost"                # reached via Database Guard proxy only
    port: 5432
    destructive: approval
  production: deny                   # hard-deny; cannot be set to anything else at project level
deployment:
  default: deny
  targets: []
agents:
  claude: { tier: contained }
  codex: { tier: contained }
approvals:
  ttl_seconds: 600
  high_risk_typed_confirmation: true
audit:
  retention_days: 90
```

### 3.2 Precedence

```
organisation hard-deny     (can never be overridden; e.g. production: deny, force: deny, docker socket)
  > organisation mandatory  (e.g. approvals.ttl_seconds <= 900, protected_branches must include main)
    > project policy        (.agent-security.yml)
      > task permissions    (TaskContext, narrower than project)
        > single operation authorisation (one approval, narrowest)
```

Merging rules: lists of denies union; lists of allows intersect downward; scalar limits take the stricter value; a lower layer that attempts to loosen a higher layer's value is a validation error reported by `ai-defender validate`, not a silent ignore.

Organisation policy source: `$XDG_CONFIG_HOME/agentguard/org-policy.yml` (host) or a path from an environment variable set by MDM; it is not in the repository. Future: signed org policies.

### 3.3 Integrity

At session start the controller computes `policy_version = sha256(canonical(effective_policy))`, stores the snapshot under controller state, and stamps every audit record and approval token with it. Before each sensitive operation it re-reads the snapshot (not the repo file) and checks the hash. The repo file may change freely inside the staging clone; that change is content, not policy, until a human approves it via the privileged `PolicyModification` flow and starts a new session. The controller stores the **last-approved policy hash per repository**; a session whose repository file hashes differently starts only after the privileged flow, or on the previously approved snapshot with a warning (Phase 0 review G14).

## 4. Mechanisms (M-n)

- **M1 Containment.** See [DOCKER_ISOLATION.md](DOCKER_ISOLATION.md).
- **M2 Credential absence.** Mount allowlist contains no credential paths. Environment is constructed from scratch: `PATH`, `HOME=/home/agent`, `TERM`, locale, `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`, agent-specific non-secret variables. Host environment is never inherited.
- **M3 Egress proxy.** Host-side Rust HTTP/CONNECT proxy listening on a unix socket bind-mounted into the container. Allowlist of `(host pattern, ports)`. The allowlist is checked **before** any name resolution so a denied name never reaches the resolver; wildcard patterns are limited to policy-declared registry hosts and are an explicit per-pattern opt-in (Phase 0 review G11). Resolution happens host-side; resolved addresses are checked against deny ranges (loopback, link-local including 169.254.169.254 and fd00::/8 metadata, RFC1918 unless explicitly allowed, multicast). Plain HTTP to allowlisted hosts is proxied with method logging; CONNECT is tunnelled. Optional TLS termination mode for inspection and credential header injection (Phase 8, off by default).
- **M4 Git-native synchronisation.** See ADR-0004 and [GIT_CREDENTIAL_BROKER.md](GIT_CREDENTIAL_BROKER.md).
- **M5 Typed approvals.** See [APPROVAL_MODEL.md](APPROVAL_MODEL.md).
- **M6 Host exec gateway.** For operations that must run on the host (deploy, infra), the request is a typed `ExecRequest { tool: ToolId, args: ToolArgs }` where `ToolArgs` is a per-tool validated enum, never a string. The controller spawns the tool directly (no shell), with a constructed environment and brokered short-lived credentials, inside a Landlock-restricted process where supported.
- **M7 Secret Guard.** Pre-session scrub (optional policy: exclude secret-pattern files from the staging clone), pre-commit/push scan (gitleaks when available, native regex fallback with explicit lower-confidence labelling) **run inside a disposable AI Defender container with a controller-owned configuration; `.gitleaks.toml`, `.gitleaksignore` and `.trivyignore` found in the scanned tree are never honoured** (Phase 0 review G8), audit redaction (deny-list of key names plus entropy heuristics), and environment filtering.
- **M8 Database Guard.** Dev databases reachable only through a host-side protocol proxy that authenticates to the database with broker-held credentials, classifies statements (Postgres via a SQL parser; Redis via RESP command table; MySQL via its wire protocol; Mongo via opcode and command name), denies destructive operations without approval, and hard-denies anything tagged production. Limitations are real (prepared statements, stored procedures, obfuscation) and documented.
- **M9 Audit.** SQLite, WAL mode, one table per event family plus a hash-chain column; redaction at write; `0600` file in controller state.
- **M11 Host-executed content classification.** A built-in, non-configurable-downward list of files that the developer's own tooling executes on the host after sync: package manifests and their script sections, lockfiles (including `resolved` and `source` URLs, which are checked against the registry allowlist), `Makefile`, `justfile`, `build.rs`, `setup.py`, `pyproject.toml`, `.cargo/config.toml`, `.npmrc`, `.envrc`, `.husky/*`, `.pre-commit-config.yaml`, `.vscode/tasks.json`, Git attributes and scanner configuration files. Any commit touching one is listed in red in the approval prompt and is high risk with typed confirmation (Phase 0 review G2).
- **M12 Sanitised rendering.** One shared function renders every agent-originated string in any trusted output (prompts, `audit`, `violations`, `status`): controls and ANSI stripped, bidi and zero-width code points escaped, non-ASCII identifiers flagged (G12). Implemented in Phase 1 as `agentguard_cli::output::sanitise`.
- **M10 Advisory hooks.** Per-agent hook configuration baked into the image pointing at `agentguard-shim hook`, with the provider's fail-closed option where it exists. The controller's answer to a hook is derived from the same permission engine; a hook `deny` is an early version of a decision the gateway would make anyway.

## 5. Decision model

```rust
enum Decision {
    Allow { rule: RuleId },
    Deny  { rule: RuleId, reason: DenyReason, approvable: bool, alternative: Option<Alternative> },
    RequiresApproval { request: ApprovalRequest },
}
```

Every denial surfaces to the agent (as hook reason or tool error) and to the audit log with: requested operation, denying rule, approvability, alternative. Example message:

```
Denied: git push origin main
Rule:   git.push.protected_branches = deny (project policy, version 3f9c…)
Approval possible: no (organisation hard-deny)
Alternative: push to feature/AH-5064 and open a merge request
```

## 6. Permission modes in enforcement terms

| Mode | Mount of /workspace | Egress allowlist | Gateway requests permitted |
|---|---|---|---|
| READ_ONLY | ro | provider API only | hook queries, fetch |
| DEVELOPMENT | rw | provider API, allowlisted registries | fetch, sync request (commit approval). Push, dependency and host-exec requests are **denied** with "switch to DEVELOPER_AUTHORIZED through the trusted UI" |
| DEVELOPER_AUTHORIZED | rw | same as DEVELOPMENT | fetch, sync, push, dependency and other sensitive requests, each gated by its typed approval |
| RESTRICTED | rw | provider API only | everything requires approval; the task's path allowlist is enforced at sync time (commits touching other paths are rejected) and advised by hooks, not by per-path mounts (Phase 0 review C9) |

## 7. Where enforcement does not happen (and why that is fine)

Inside the container the agent can run `rm -rf /workspace`, `curl` anything (it fails), `sudo` (there is none), `docker` (no socket), `git push` (routes to broker). None of this touches an asset. The staging clone is disposable; the developer's repository is untouched until a validated, approved sync. This is the central simplification of the design: **we do not try to stop the agent from doing things; we make sure the things it can do are harmless.**
