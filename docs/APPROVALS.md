# Human Approval and Authorization Grants

An AI agent may request approval; it can never approve its own operation or manufacture an
authorization. This document describes the approval lifecycle implemented in Phase 5: how a
`REQUIRE_APPROVAL` operation becomes a pending request, how a human approves exactly that
operation, and how the resulting one-time grant is consumed.

Code: `agentguard_engine::binding` (operation digest), `agentguard_trust::approvals` (models,
store, lifecycle, tokens), `agentguard-engine-cli` `approvals.rs` (protocol commands),
`cli/src/commands/approvals.ts` (human interface). Tests: `crates/agentguard-trust/tests/approvals.rs`,
`crates/agentguard-engine-cli/tests/approvals.rs`, `cli/test/approvals.test.ts`.

**Not in this phase:** nothing executes the approved operation, and no agent hook calls the
API yet. Phase 5 provides the approval API that future integrations use; until an integration
is installed, `ai-defender status` keeps reporting enforcement as not active.

## 1. Lifecycle

```text
agent integration ── approval.request ─> Rust: verify identity, evaluate policy
                                           ├─ ALLOW / DENY ─> returned, no approval created
                                           └─ REQUIRE_APPROVAL ─> binding check, digest
                                                                    └─> pending  (+ claim token to the requester)
human ── ai-defender approve <id> ── review exact operation ── type "approve" ── passphrase
                                           └─> Rust: re-check state, policy, digest;
                                               sign one-time grant with the policy key ─> approved
agent integration ── authorization.consume (operation + approval ID + claim token)
                                           └─> Rust: re-verify identity, re-evaluate policy,
                                               recompute digest, check grant ─> consumed (atomic)
```

| Status | Meaning | Next |
|---|---|---|
| `pending` | waiting for a human (default 5 minutes) | approved, rejected, cancelled, expired |
| `approved` | grant issued, unused (default 2 minutes) | consumed, expired, cancelled (revoked or policy change) |
| `rejected` | a human rejected it | terminal |
| `cancelled` | cancelled before a decision, grant revoked, or invalidated by a policy change or a now-denying policy | terminal |
| `expired` | nobody decided in time, or the grant aged out unused | terminal |
| `consumed` | the grant authorized one operation | terminal |

Transitions only move forward. Nothing returns to `pending` or `approved`; expired approvals are
never renewed. A materially changed operation has a different digest and needs a new request.

**Duplicate requests.** A request whose digest equals a *pending* request joins it (up to 8
claims) instead of creating a second prompt; the joined requester gets its own claim token, and
the single grant can still be consumed only once. After a decision, the same operation needs a
new request.

## 2. Human authentication and authorization

| Decision | Required | Why |
|---|---|---|
| approve | interactive terminal in the CLI; the typed word `approve` after the exact operation is shown; the policy-signing key passphrase, entered at a hidden prompt, which the engine uses to unlock the key and sign the grant | grants authority |
| reject | confirmation (interactive, or explicit `--yes`) | removes authority only |
| cancel | confirmation, or the requester's own claim token | removes authority only |
| revoke (grant) | confirmation | removes authority only |

The approver is authenticated by possession of the policy-signing key's passphrase: the engine
unlocks the key, checks that it is one of the trust store's current trusted signers, and signs
the grant with it (signature purpose `agentguard.approval-grant.v1`). The CLI's account name is
attribution only. The `ApproverAuthentication` type names the method
(`signing-key-passphrase`, `interactive-confirmation`, `requester-claim`); stronger methods (a
hardware key, a remote approval service) are new variants.

What is refused, and where:

| Attempt | Refused by |
|---|---|
| `ai-defender approve … --yes` / `--json` / `--non-interactive` / `--passphrase-file`, or no TTY | CLI, before anything is asked (exit 6) |
| answering `y`, `yes` or anything other than `approve` | CLI: no passphrase is asked, nothing is recorded |
| `approval.approve` with `passphrase_file`, or any unknown field (`approved`, `yes`) | engine: unknown fields reject the request |
| `approval.approve` without the passphrase, with a wrong one, or without `confirm: true` | engine |
| `approval.approve` when the engine was launched by an integration (`--agent`) | engine (`approval.self-approval`) |
| an agent terminal command running `ai-defender approve`, `reject`, `approvals …`, or the `agentguard-engine` binary | guard (best effort for terminal text; see L58) |
| a grant written into the store by anything but a trusted signer | signature verification at every redemption |
| approval decisions from project configuration | there is no such field; project policy cannot set approval timing either |

**Limits of local interactive approval.** When the agent and the human share one unrestricted
operating-system account, the agent's process can, in principle, read the human's files and
terminal. The terminal step proves only that someone at a terminal typed the right words; the
passphrase is what an agent should not have. A same-user process that obtains the passphrase (a
keylogger, a passphrase stored in a readable file, a shell history line) can approve. Terminal
interaction does not protect against a compromised machine or an administrator. See
[TRUST_MODEL.md](TRUST_MODEL.md) §1 and the known limitations L62 to L72.

## 3. Exact operation binding

Every approval is bound to one `OperationFingerprint`: SHA-256 over the domain prefix
`agentguard.operation-digest.v3\0` and the canonical JSON of `CanonicalOperation` (v3 since
Phase 7: the form gained an `execution` field, `null` for operations that are not managed
executions):

| Field | Source |
|---|---|
| category, operation | the validated action |
| tool | the integration's tool name (`context.tool`), when supplied |
| action | every normalized argument (paths resolved, typed values) |
| target | the action's resource description |
| project id and root | verified through the trusted registry |
| agent kind and version | the trusted invocation (`--agent`) and the request |
| session, working directory | the request, after verification |
| policy version | the effective policy in force |
| execution (Phase 7) | for `ai-defender run`: program identity, exact argv, environment profile, time limit, and repository facts (HEAD, branch, staged tree, push source, range, remote URL identity, named refs), observed by the engine; see [EXECUTION.md](EXECUTION.md) |

The canonical form has a fixed field order, ordered maps, and explicit `null`s, so equal
operations serialize to equal bytes. The digest is always computed by the engine from a freshly
verified context; a digest supplied by anyone is never trusted (the human's reviewed digest is
only compared with the stored one).

Examples from the tests: `git push origin feature-a` vs `main`; deleting `a.txt` vs `b.txt`; a
migration against `staging` vs `production`; the same push from another project, another
agent, or under another policy version: each produces a different digest.

**Fields the protocol cannot supply yet**, and what happens:

| Operation | Missing | Behaviour |
|---|---|---|
| `terraform apply` | reviewed plan digest | cannot be approved (`approval.binding.terraform-plan`); stays denied |
| state-changing Terraform without workspace or environment | target | cannot be approved |
| `git push` without remote and target ref | target | cannot be approved |
| database change with unknown environment | environment | cannot be approved |
| cloud change without resource or environment | target | cannot be approved |
| `git push` | the commits pushed (HEAD), repository identity beyond the project | bound to remote + ref + force + project; documented (L64) |

## 4. Claim tokens and grants

The design follows the OAuth 2.0 Device Authorization Grant (RFC 8628): the requester holds a
secret (the device code), the human approves by a public reference (the user code), and only
the secret's holder can redeem the approval.

- **Approval ID, grant ID**: UUID v4 from the OS CSPRNG. Public references: shown to humans and
  agents; neither authorizes anything.
- **Claim token**: 256 bits from the OS CSPRNG (`getrandom`), transported as `agc1_` + 64 hex.
  Returned once, in the `approval.request` response, to the requester. Never shown to the
  human, never in listings, logs, audit records, configuration, environment or arguments.
- **Stored verifier**: `SHA-256("agentguard.claim-token.v1\0" || token)`. Comparison is constant
  time. A fast hash suffices for a 256-bit random secret (slow password hashing protects
  low-entropy secrets).
- **Grant**: `AuthorizationGrant` (grant ID, approval ID, request ID, digest, project, agent,
  session, policy version, claim verifiers fixed at approval, the human decision, issue and
  expiry time), signed by the approver's policy key. No new token format: the grant is an
  Ed25519-signed canonical JSON document like every other trusted object.

A redemption succeeds only if **all** hold: the claim token matches; the request is `approved`;
the grant signature verifies against a current trusted signer for the grant purpose; the grant
is consistent with the stored request and its approver's key; the grant state is `active`; now
is before expiry; the project, agent and policy version presented now equal the grant's; and
the recomputed digest equals the grant's. Before any of that, identity and policy are evaluated
again: a `DENY` now wins over any approval and voids it (`approval.now-denied`).

## 5. Atomic consumption and replay

Every transition runs inside one transaction holding an exclusive `flock` on
`<trust root>/approvals/lock`. Check and transition happen in the same transaction, so two
consumers cannot both observe an active grant: exactly one sees `active` and writes `consumed`;
the others see `consumed` and get `approval.replay` (audited as a replay attempt).

- Tested with 16 threads per round (separate store handles) and with 8 concurrent engine
  processes; replacing the exclusive lock with a shared one makes the tests fail (12 of 16
  "succeeded").
- A consumed grant is never restored: if the audit record of the consumption cannot be written,
  the caller gets an error and the grant stays consumed.
- Transactions are short; no lock is held while a human reads or types (the CLI collects the
  decision first, the engine unlocks the key before taking the lock).
- State survives restarts (tests reopen the store from fresh handles).

## 6. Persistence and migration

SQLite is not used: the project's state is the file-based trust store, and the SQLite audit
store is a later phase. Approval state extends the trust store instead of adding a competing
database:

```text
<trust root>/approvals/            0700
  schema.json                      {"schema": 1}; a newer schema is refused (fail closed)
  lock                             transaction lock
  requests/<approval-id>.json      one record per request, 0600, atomically replaced
```

- Reads refuse symlinks, foreign owners, group/other-writable files and oversized files (the
  trust store's existing checks). A malformed record fails closed (`approval.corrupt`) and is
  never shown or usable.
- Records hold the request, claim verifiers (never tokens), status, decision, the signed grant,
  grant state and closure. Operation details are the redacted summary and the digest; raw
  operation arguments are not stored.
- Migration: `migrate()` brings an older layout to the current schema and rewrites
  `schema.json` last, so an interrupted migration is retried. There is one schema so far.
- Retention: closed records are pruned 7 days after their last transition; the audit log keeps
  the history. At most 256 open requests exist at once.

The JSON Lines audit sink was made safe across processes in this phase: each append takes an
exclusive `flock` on the log and continues from the record actually at its end.

## 7. Timing

| Limit | Default | Hard maximum | Set by |
|---|---|---|---|
| pending request | 5 minutes | 15 minutes | trusted global policy `approvals.pending_timeout_seconds` |
| issued grant | 2 minutes | 5 minutes | trusted global policy `approvals.grant_validity_seconds` |

Out-of-range values are rejected when the global policy is validated. Project policy and project
configuration cannot set either; agents have no input that affects timing. There is no CLI
command to edit the global policy yet (`update_policy` in the trust library).

## 8. Protocol commands (`agentguard.engine.v1`)

| Command | Arguments | Notes |
|---|---|---|
| `approval.request` | `request` (an `agentguard.authz.v1` request) | needs `--agent`; returns the evaluation and, for `REQUIRE_APPROVAL`, the approval view plus `claim_token` (this response only) |
| `approval.list` | `include_closed?` | views only; expires what is due |
| `approval.show` | `approval_id` (full or unique prefix of 8+ characters) | audited as viewed |
| `approval.approve` | `approval_id` (full), `operation_digest` (as reviewed), `requested_by`, `confirm`, `passphrase` | no `passphrase_file`; refused under `--agent` |
| `approval.reject` | `approval_id`, `requested_by`, `confirm`, `reason?` | |
| `approval.cancel` | `approval_id` and either `claim_token`, or `requested_by` + `confirm` | |
| `authorization.validate` | `request`, `approval_id`, `claim_token` | needs `--agent`; checks without consuming |
| `authorization.consume` | `request`, `approval_id`, `claim_token` | needs `--agent`; atomic |
| `authorization.revoke` | `approval_id`, `requested_by`, `confirm` | |

New error codes: `identity-unavailable`, `approval-not-found`, `approval-conflict`,
`authorization-denied`, `audit-unavailable`. Each message ends with a stable reason code in
parentheses (for example `(approval.replay)`). The npm CLI never calls the three agent-side
commands and never interprets a decision; a static test enforces it.

## 9. Audit events

Recorded in the trust audit log (`audit/trust.jsonl`) with `approval_id`, `grant_id`,
`operation_digest`, `approver`, `reason_code`, request ID, agent, project, policy version,
category and operation. Never: claim tokens, verifiers, signatures, operation arguments.

| Event | When | Required |
|---|---|---|
| `approval-request-created` | request created or joined | yes (otherwise the request is cancelled) |
| `approval-request-viewed` | `show` / review | best effort |
| `approval-approved`, `authorization-grant-issued` | approval | yes (otherwise the grant is revoked) |
| `approval-rejected`, `approval-cancelled`, `approval-expired` | withdrawal | best effort |
| `authorization-validation-succeeded` | validate | yes |
| `authorization-validation-failed` | any refused redemption | best effort |
| `authorization-consumed` | consume | yes (the grant stays consumed either way) |
| `authorization-replay-detected` | consumed grant presented again | best effort |
| `authorization-grant-revoked` | revoke | best effort |
| `approval-invalidated-by-policy-change` | policy changed, or policy now denies | best effort |

"Required" events grant authority; if one cannot be written, the operation reports failure and
authority is withdrawn. Events for refusals and withdrawals are best effort because the outcome
is already the safe one.
