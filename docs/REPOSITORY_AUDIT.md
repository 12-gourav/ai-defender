# Repository Audit (Phase 0 of the engine track, 2026-10-30)

Scope: the AgentGuard workspace as delivered by the containment-track Phase 1 (`agentguard-core`, `-common`, `-audit`, `-cli`, `tests/integration`, 25 design documents and 12 ADRs). The workspace was copied unchanged into this repository. The baseline gate was run before any change and was green:
- `fmt --check`, `clippy --all-targets --all-features -D warnings`, `check`;
- `test`: 100 tests passing.

## 1. What existed and was kept

| Area | Assessment | Action |
|---|---|---|
| Typed IDs (`SessionId`, `RequestId`, `TaskId`, `AgentIdentity`, `RepositoryId`, `PolicyVersion`) | sound, validated newtypes | kept; `RequestId` (previously unused) now correlates authorization requests; `ApprovalId` added |
| `BoundedText`, `Sensitive`, `SecurityError` (values never in messages) | sound | kept and reused everywhere new |
| `SecurityDecision` / `DecisionOutcome` (five-part denial) | sound, but tied to the containment-era `OperationType` | kept; tri-state `Decision` added with `DecisionOutcome::decision()` |
| `RiskLevel` | sound | reused as the risk classification |
| `ApprovalScope`, `ApprovalTiming` bounds (C5, C6 of the Phase 0 review) | sound | reused: approval validity is capped by `MAX_TOKEN_VALIDITY` |
| Redaction (`redact_text`, field denylist) | partially effective (W1) | strengthened |
| Audit chain, memory and JSON Lines sinks | sound chain, unsafe open (W2, W3) | fixed; typed `SecurityEvent` interface added on top |
| Configuration loader (size limit, version dispatch, unknown-key rejection) | sound for structure; sections are opaque | kept unchanged; semantic loading is the next phase |
| Redacting logging, XDG paths with permission checks, CLI | sound | unchanged |
| Lint regime (`forbid(unsafe)`, no unwrap/expect/panic/indexing, pedantic) | strong | applied to all new code |

## 2. Duplicated functionality found

| Duplication | Resolution |
|---|---|
| `AuditDecision` (audit) and the new `Decision` (core) both model allow/deny/approval | kept both. `AuditDecision`'s kebab-case wire format is part of existing records and tests; `From<Decision>` converts. Merge when the audit schema is versioned (SQLite phase). |
| `OperationType` (containment-era boundary crossings) and `ActionCategory`/`Action` (hook-era actions) | kept both. `OperationType` still drives the approval-scope rule and old audit events. New code uses `Action`. Retire or map `OperationType` when the containment tier is revisited. |
| Three hex digest newtypes (`PolicyVersion`, `ProjectId`, `OperationFingerprint`) plus audit `Digest32` | small and deliberately distinct types (they must not be interchangeable); not merged |

## 3. Security weaknesses found

| # | Weakness | Severity | Resolution |
|---|---|---|---|
| W1 | `redact_text` split only on ASCII spaces and recognised only credential shapes. `DB_PASSWORD=hunter2`, `--token=x`, `--password x` and `Authorization: Bearer x` passed through to logs and audit. | High | fixed: whitespace-preserving tokeniser, sensitive assignments, header/flag/`Bearer` lookahead; property test over 3,000 cases |
| W2 | `JsonlSink::open` continued the chain from the last record without verifying it, so new records were chained onto a tampered history and vouched for it | Medium | fixed: the chain is verified on open; regression test |
| W3 | `JsonlSink::open` followed symlinks, so the audit log could be redirected | Medium | fixed: non-regular files are refused; regression test |
| W4 | Policy discovery walks up from the current directory and takes the first `.agent-security.yml`. An agent can plant a nearer file to shadow the real one. | High (once policy is enforced) | **resolved in Phase 2**: enforced policy comes only from the signed trust store. The project file is read only at the registered canonical root, only as a proposal for a human-approved update; differences are reported as drift. (`agentguard validate` still uses discovery for structural checks only.) |
| W5 | The containment architecture (ADR-0002) contradicts the new product direction. Hook enforcement has the gaps ADR-0002 documented. | Design | ADR-0013 records the change; the gaps are engine rules and limitations L25 to L36 |
| W6 | Hostnames like `0177.0.0.1` / `2130706433` are not IP literals to `std` but resolvers treat them as loopback | Medium | fixed in the new `Host` type: non-canonical numeric names are rejected |

## 4. What the foundation lacked for this objective

There was no request/response protocol, no typed actions for the ten categories, no project identity, no identity verification, no policy decision interface, no risk classifier, no approval binding, and no fail-closed decision path. Phase 1 added these as `agentguard-proto`, `agentguard-engine` and new core modules (see [ENGINE_ARCHITECTURE.md](ENGINE_ARCHITECTURE.md)).
