# ADR-0008: Approval tokens are internal; nothing replayable is handed to the agent

Status: accepted. Date: 2026-10-30.

## Context
The specification asks for opaque approval tokens with cryptographic randomness, short expiry and one-time consumption, and forbids replay, cross-session reuse and substitution.

## Decision
Tokens are generated and consumed entirely inside the controller. The agent never receives a token; it receives only the outcome of the operation it requested. A token binds `request_id`, `session_id`, `task_id`, `policy_version`, and `operation_hash` (canonical CBOR of the typed payload). Consumption is atomic with execution start. Expiry defaults to 600 s and cannot exceed an organisation maximum.

## Consequences
- Replay is structurally impossible from the agent's side; the security tests target the controller's own state handling (double-consume, clock, mutation).
- `CurrentTask`/`CurrentSession` scopes are implemented as grants recorded in the task context, limited to operation kinds the policy marks reusable; push, deploy, DB mutation and policy change are always single-operation.

## Amendment (Phase 0 review, 2026-10-30)

Two limits replace the single TTL: `pending_timeout` (default 600 s, max 900 s) and `token_validity` (default 60 s, max 300 s). Reusable scopes are permitted only for `NetworkAccess` and `FilesystemAccess` (C5, C6). Token hashing at rest is dropped because tokens never leave the controller process.
