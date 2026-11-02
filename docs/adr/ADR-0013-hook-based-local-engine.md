# ADR-0013: A local, hook-driven decision engine is the primary product; containment becomes an optional hardening tier

Status: accepted (product direction set by the developer, 2026-10-30). Partly supersedes ADR-0002, ADR-0006 and ADR-0012.

## Context
The product objective changed: AgentGuard is a lightweight, local-first engine installed globally through npm. It controls agent actions through the agents' official hooks and returns `ALLOW`, `DENY` or `REQUIRE_APPROVAL`. Docker, cloud services, a database server and background daemons must not be mandatory.

ADR-0002 rejected exactly this model as the security boundary, for reasons that remain true:
- vendor hook systems are fail-open by default;
- hooks run with the developer's privileges;
- hook configuration usually lives in files the agent can edit;
- command-string filtering can be bypassed (interpreters, encodings, chaining).

## Decision
1. The decision engine (`agentguard-proto` + `agentguard-engine`) is the product core. Each hook invocation sends one canonical request. The engine decides deterministically from trusted state (policy, project registry, approvals) and records every decision.
2. ADR-0002's findings become explicit engine rules and limitations rather than reasons to require a container:
   - Hard guards deny writes to trusted state, including the agent hook settings files, regardless of policy.
   - Terminal commands and unmodelled tools are never allowed by the baseline.
   - Critical-risk actions can never be plain-allowed.
   - Unknown operations are always denied.
   - Integrations must configure hooks fail-closed wherever the vendor allows it (hooks phase).
3. The container design (ADR-0004, 0006, 0009, 0011) is kept as an optional hardening tier for environments that need a boundary the agent cannot reach. Its documents stay as the design of that tier.
4. Docs that describe the containment architecture remain valid for that tier. Wherever they say "the boundary is the container", read "the boundary in the contained tier".

## Consequences
- Enforcement in the default tier is only as complete as the agent's hook coverage. An action that does not pass through a hook (a built-in tool without a hook, a subprocess spawned by an allowed command) is not seen. This is recorded as limitation L25 and is the main residual risk of the product.
- An agent that can run arbitrary terminal commands can do anything those commands can. The baseline therefore requires approval for every terminal command. A project that allows terminal commands by policy accepts that risk explicitly.
- Trusted state must live outside the agent's write reach where possible. The guards protect it at the hook layer, but a command that escapes classification can still reach it. OS-level protection (file ownership, vendor-managed settings locations) is evaluated per vendor in the hooks phase.
- No long-running process is needed: each hook invocation runs the engine, reads trusted state, decides, records and exits. SQLite holds state from the audit phase onwards.
