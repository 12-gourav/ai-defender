# Decision Engine Architecture

Status: implemented in Phase 1 (security foundation, 2026-10-30). Direction: [ADR-0013](adr/ADR-0013-hook-based-local-engine.md).

## 1. What the engine is

A library that takes one authorization request (an agent asking to take one action) and returns `ALLOW`, `DENY` or `REQUIRE_APPROVAL`. Properties:

- **Deterministic.** The same request, trusted state and policy version always give the same decision. No AI model, network call or wall-clock rule takes part. The clock is used only for approval expiry.
- **Fail-closed.** There is no error return. Any failure produces `DENY`.
- **Provider-independent.** Requests use one canonical protocol ([PROTOCOL.md](PROTOCOL.md)). Mapping a vendor's hook payload onto it belongs to the integration layer in a later phase.
- **Local and short-lived.** No daemon, container or server. A hook invocation builds an `Authorizer`, decides, records and exits.

## 2. Crates and responsibilities

```
agentguard-core ◀── agentguard-proto ◀── agentguard-engine ◀── agentguard-trust
      ▲                                       │                      │
      └──── agentguard-audit ◀────────────────┴──────────────────────┘
agentguard-common (config, logging, paths) ◀── agentguard-trust, agentguard-cli
agentguard-trust, agentguard-engine ◀── agentguard-engine-cli (binary agentguard-engine) ◀─JSON─ cli/ (npm)
agentguard-secrets (leaf: detectors, redaction, scanning) ◀── agentguard-core, agentguard-engine, agentguard-engine-cli
agentguard-engine, agentguard-trust, agentguard-secrets ◀── agentguard-exec (managed execution) ◀── agentguard-engine-cli
agentguard-exec, agentguard-trust, agentguard-engine ◀── agentguard-hooks (Claude Code, Codex adapters) ◀── agentguard-engine-cli
```

| Crate | Responsibility | I/O |
|---|---|---|
| `agentguard-core` | The security vocabulary: typed actions and categories (`action`), absolute normalised paths and the `PathResolver` interface (`path`), project identity (`project`), the verified `SecurityContext` (`context`), the tri-state `Decision` (`decision`), `RiskLevel`, `OperationFingerprint` and approval bounds (`approval`), typed IDs, bounded text, redaction, `SecurityError`. | none |
| `agentguard-proto` | The untrusted-input boundary. `parse_request` turns bytes into a validated `AuthorizationRequest` or a `Rejection`. `AuthorizationResponse` keeps decision and approval requirement consistent by construction. | none (paths go through the injected resolver) |
| `agentguard-engine` | Decisions. `evaluate` (the `evaluate(request, context, policy)` API and `EvaluationContext`), `normalize` (`SecurityAction`, capabilities, terminal analysis), `resource` (resource classification), `classify` (risk), `guard` (non-overridable rules), `rules` + `pattern` (matching, conditions, priority, bounded globs), `policy` (`PolicyEvaluator`, `RuleSetPolicy`, integrity), `profile` (mandatory baseline, balanced profile), `layered` (precedence), `approval`, `authorize` (records and binds), `resolve` (`FsPathResolver`), `clock`. See [POLICY_EVALUATION.md](POLICY_EVALUATION.md). | filesystem reads for path resolution |
| `agentguard-audit` | Audit events, the typed `SecurityEvent` interface (including trust events), redaction at construction, hash chain, memory and JSON Lines sinks. | the JSONL sink writes a `0600` file |
| `agentguard-trust` | Root of trust (Phase 2): signed trust store, Ed25519, integrity and anti-rollback, project registry, policy hierarchy and merge, authorised updates, and `load_runtime`, which yields the engine's policy and registry or a deny-all lockdown. See [TRUST_MODEL.md](TRUST_MODEL.md). Phase 5: `approvals` (pending requests, signed one-time grants, claim tokens, locked transactions); see [APPROVALS.md](APPROVALS.md). | reads/writes the private trust store |
| `agentguard-secrets` | Phase 6: secret detectors (provider, structural, assignment, entropy, custom), redaction keeping only public prefixes, bounded local scanning, `.git/index` staged-change reading, secret-safe access (`SecretSource`). No network, no processes, no stored values. See [SECRETS.md](SECRETS.md). | reads files it is asked to inspect |
| `agentguard-exec` | Phase 7: managed execution. Request validation, trusted executable resolution and identity, environment profiles, the strict shell subset, the Git adapter (parsing, hardened inspection, binding facts, scans, verification), and the executor, which evaluates through `agentguard-engine`, approves or redeems through `agentguard_trust::approvals`, and alone reaches the private process runner through a sealed `Permit`. See [EXECUTION.md](EXECUTION.md). | starts processes (the only crate that does); reads repositories; writes execution records |
| `agentguard-hooks` | Phase 8: provider adapters for Claude Code and Codex hooks. Payload validation and normalization (separate per provider; Codex `apply_patch` parsing), decisions through `agentguard-engine` and the approval store with the approve-and-retry protocol, provider responses with fail-closed behaviour, safe installation into user-level hook configuration, coverage tables. Adapters translate; they never decide. See [HOOKS.md](HOOKS.md). | reads payloads; writes hook configuration (install), claim tokens and audit events |
| `agentguard-engine-cli` | Phase 4: the `agentguard-engine` binary that the npm CLI drives. One `agentguard.engine.v1` JSON request on stdin, one response on stdout (`protocol`); read-only commands (`inspect`) and authorised changes (`manage`: init, trust, revoke, each requiring confirmation and the signing-key passphrase). Phase 5 adds the approval commands (`approvals`); the agent-side ones need the engine to be launched with `--agent` and are never called by the npm CLI. See [CLI.md](CLI.md) §7 and [APPROVALS.md](APPROVALS.md) §8. | reads/writes the trust store and `.agentguard/config.yaml` |

Phase 7 adds `agentguard-exec`, which keeps process execution out of `agentguard-engine`: the engine still decides without executing anything. Two crates were added in Phase 1, not more. `agentguard-proto` is separate because it is the hostile-input parser that hook adapters, fuzzers and future clients link without the engine. The existing workspace design already called for it. Everything else is a module.

## 3. The pipeline

Since Phase 3 the decision itself is made by `evaluate` (see [POLICY_EVALUATION.md](POLICY_EVALUATION.md) §1); the diagram below shows the `Authorizer` around it, which adds auditing and approval binding.

```
bytes
 └─ parse_request ─────────────── invalid?  → DENY protocol.invalid-request (risk CRITICAL)
     └─ audit AuthorizationRequested ─ fails? → DENY audit.unavailable
         └─ identity::verify ──── mismatch? → DENY identity.* (risk CRITICAL)
             └─ classify (risk)
                 └─ policy version ── differs? → DENY policy.version-mismatch
                     └─ guards ───── violation? → DENY guard.* (+ TamperDetected)
                         └─ policy.evaluate ── error? → DENY engine.error (+ SecurityError)
                             └─ critical floor: CRITICAL ∧ ALLOW → REQUIRE_APPROVAL
                                 └─ REQUIRE_APPROVAL? consume grant for fingerprint
                                      grant  → ALLOW approval.granted
                                      none   → REQUIRE_APPROVAL (+ fingerprint)
                                      error  → DENY engine.error
                                     └─ audit Decision ─ fails? → DENY audit.unavailable
                                         └─ response
```

Ordering rules that matter:

1. **Identity before anything that uses the project.** Risk classification needs the verified project, so it runs after verification. A request with unverified identity is reported at risk `CRITICAL` because it cannot be classified.
2. **Guards before policy.** No rule can allow an unknown operation or a write to trusted state.
3. **Decisions only get stricter.** The final decision is the most restrictive of guard, policy and floor (`Allow < RequireApproval < Deny`). An approval converts `REQUIRE_APPROVAL` to `ALLOW` and nothing else. A property test (`property_final_decision_never_weaker_than_policy_and_deterministic`) checks this over random rule sets.
4. **Recording is part of deciding.** A decision that cannot be recorded is not returned. If the request record or the decision record fails, the result is `DENY`.

## 4. Trust model of the inputs

| Input | Source | Trusted? |
|---|---|---|
| Request bytes | the agent integration (hook) | no: parsed strictly, every claim verified |
| `TrustedInvocation.agent` | how the engine was launched (set at install) | yes |
| `ProjectRegistry` | developer-registered projects, stored outside every project | yes |
| `PolicyEvaluator` | policy loaded from trusted state | yes |
| `ApprovalStore` | grants written only by the trusted approval channel | yes |
| `TrustedStateGuard` roots | AI Defender's own state/config directories, user-level hook settings | yes |
| Filesystem (path resolution) | the live filesystem at decision time | observed, not trusted to stay unchanged (see L26) |

The agent's version string and the `context` block are recorded but never used in a decision.

## 5. Policy

`PolicyEvaluator` is the interface. `RuleSetPolicy` is the built-in implementation:

- Rules match on category, operation, path prefix, inside/outside project, host, and maximum risk.
- Among matching rules the most restrictive decision wins. Ties cite the smallest rule ID, so rule order never changes a verdict. The policy version is the SHA-256 of the canonical, ID-sorted rule list.
- A rule that would `ALLOW` without constraining *what* it matches (category, operation, path or host) is refused at construction.
- For unmatched actions the baseline applies:
  - read-only and low risk → `ALLOW`;
  - critical risk → `DENY`;
  - everything else → `REQUIRE_APPROVAL`.

Since Phase 2, the engine runs with the trust layer's `EffectivePolicy` (mandatory + global + project). `RuleSetPolicy` evaluates the global layer, and mandatory and project rules apply as floors via `RuleSetPolicy::matching_verdict`. See [TRUST_MODEL.md](TRUST_MODEL.md) §2.

## 6. Risk

`classify` is a fixed table over the typed action (see `crates/agentguard-engine/src/classify.rs`). It returns the highest level any factor assigned plus the sorted list of factors. Risk never decides on its own. It feeds the policy (`max_risk`), the baseline, and the critical floor.

## 7. Approvals

- **Binding.** `binding::operation_digest(ctx, request)` (Phase 5, digest v2) is SHA-256 over the canonical operation: category, operation, tool, every normalized argument, target, project ID and root, agent, session, working directory and policy version. The request ID is excluded: a retry of the same operation matches, a different operation does not. `binding_gap` names operations the protocol cannot bind exactly (Terraform apply without a plan digest, untargeted pushes, database or cloud changes without an environment); those cannot be approved.
- **Persistent lifecycle.** `agentguard_trust::approvals`: pending requests, human decisions, policy-key-signed one-time grants, requester claim tokens, and consumption inside an exclusive cross-process transaction. See [APPROVALS.md](APPROVALS.md).
- **In-process grant (authorizer tests).** `ApprovalGrant::new` refuses `Approver::Agent` and any validity outside 1 to 300 seconds (`ApprovalTiming::MAX_TOKEN_VALIDITY`); `MemoryApprovalStore::consume` removes a live grant atomically. The authorizer is wired to the persistent store in the integration phase (L69).
- **No path from the agent.** The request schema has no approval field, and unknown fields reject the request. The guard denies terminal commands that invoke AI Defender's privileged subcommands and writes to the approval store's location.

## 8. Error-handling strategy

- **Validation errors** (`SecurityError`, `ProtocolError`) name the field and rule, never the value. JSON errors report only category, line and column, because serde's messages quote input.
- **Engine errors** are internal. `Authorizer::authorize*` returns a response, never a `Result`. Every internal failure becomes `DENY` with rule `engine.error`, plus a `SecurityError` event with a static stage and detail.
- **Audit failure** is decision failure (`audit.unavailable`). Tamper and error events are written best effort, because the outcome is already a denial.
- **Panics.** Library code cannot `unwrap`, `expect`, `panic` or index (`clippy` denies them). The release profile uses `panic = "abort"`. A crash produces no response, and the hook integration must treat a missing or malformed response as `DENY` (hooks phase requirement).
- **Clients** must call `AuthorizationResponse::check` (or `permits_execution`) and treat inconsistency as `DENY`.

## 9. Events

`SecurityEvent` is the structured interface (authorization requested, decision, approval decided, execution result, tamper detected, security error). `into_audit_event` maps each one to an `AuditEvent`, so every event passes through the same redaction and hash chain. Secrets are referred to by name only. Resources and reasons are redacted at construction: credential shapes, `key=value` with sensitive keys, `Bearer`/`Authorization:` values, and sensitive flags.
