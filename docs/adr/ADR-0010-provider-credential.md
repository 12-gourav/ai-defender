# ADR-0010: The agent's own provider credential is reachable by the agent; scope it, do not hide it

Status: accepted. Date: 2026-10-30.

## Context
The specification says: do not claim a credential is invisible to an agent process that must use it. The agent CLI must authenticate to its AI provider.

## Decision
The provider credential is delivered read-only at `/ag/auth` and consumed through the vendor's supported helper mechanism (for example Claude Code `apiKeyHelper` → `agentguard-shim auth`). The design states plainly that the agent process can read it. Mitigations: use a dedicated, spend-limited key per developer for AgentGuard sessions; the only reachable network host for it is the provider's API; audit API host usage. Phase 8 adds optional proxy-side header injection (TLS termination for the provider host only), which removes the key from the container but does not remove the agent's ability to call the provider.

## Consequences
- OAuth/subscription logins that store refresh tokens require mounting the vendor credential file read-only; this is documented as broader than an API key (R-21).
- No document or UI claims the provider credential is hidden from the agent.
