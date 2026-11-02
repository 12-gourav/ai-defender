# ADR-0002: Containment and credential absence are the boundary; hooks and command filtering are advisory

Status: partly superseded by [ADR-0013](ADR-0013-hook-based-local-engine.md) (2026-10-30): it still governs the optional contained tier, and its threat findings are carried into the engine's guards and known limitations. Originally accepted 2026-10-30.

## Context
The specification describes an execution gateway with filesystem, command and network guards, and agent hook integration. Phase 0 research found that every provider's hook system is fail-open by default, runs with the developer's privileges, and is configured from files the agent can usually edit. Command-string filtering is bypassable by construction (alternative interpreters, encodings, chaining).

## Decision
The security boundary is: the agent runs in a container with no credentials, no network route, no host paths, no Docker socket, and no trusted state. Everything sensitive requires a request to a host-side gateway that the agent can only *ask*, never *instruct*. Hooks are configured (fail-closed where the vendor allows) to deny early and explain, and command classification feeds audit and risk scoring. The adversarial suite must pass with hooks disabled and the shim killed.

## Alternatives rejected
- Host-side hook enforcement without a container: the agent's built-in tools bypass vendor sandboxes, hooks fail open, and the agent can edit its own settings.
- Relying on vendor sandboxes: off by default, fail open, exempt built-in tools, inconsistent across vendors.

## Consequences
- The gateway is a request dispatcher for boundary crossings, not a wrapper around the agent's shell.
- Inside the container the agent is free; the design argues that nothing it can reach is an asset.
- Hook quality affects usability (good early messages), not security.
