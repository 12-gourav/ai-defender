# ADR-0012: Per-session controller process, no long-running daemon

Status: accepted. Date: 2026-10-30.

## Context
The controller could be a user-level daemon (systemd user service) or a process spawned per `agentguard run`.

## Decision
One controller process per session, spawned by the CLI, owning the container's lifetime, the sockets and the credentials for that session. Shared state (policy snapshots, audit DB, keyring access) lives in the XDG state directory with file locking.

## Rationale
- Fail-closed by construction: controller exit removes the session's capabilities.
- No daemon to secure, upgrade or keep in sync with CLI versions.
- Simpler privilege story (everything runs as the developer).

## Consequences
- Multiple concurrent sessions each have their own controller; the audit DB uses SQLite WAL with locking.
- `agentguard approvals --watch` discovers sessions via the runtime directory.
- A future daemon mode for organisation-level features (remote audit sink, signed policy fetch) can be added without changing the per-session model.
