# ADR-0003: Native Rust policy engine instead of embedded OPA/Rego

Status: accepted. Date: 2026-10-30.

## Context
The specification allows OPA/Rego or a justified native engine.

## Decision
Policy is a typed Rust data model validated by a generated JSON Schema, with precedence and merge rules implemented as plain Rust functions and property-tested. Rego is not embedded in the pilot.

## Rationale
- The policy vocabulary is small and fixed (modes, allow/deny lists, gates). A general-purpose policy language adds a second trust-critical interpreter, a second schema, and a way to express rules the typed system cannot explain in the five-field denial format.
- Deterministic precedence with "lower layer can only narrow" is easier to prove over a typed tree than over arbitrary Rego.
- `policy explain` must cite a rule id; typed rules make that trivial.

## Consequences
- Organisations wanting Rego can get a future `regorus`-based front-end that *compiles* to the typed model (never evaluated at decision time).
- Adding a new policy dimension requires a Rust change and schema regeneration, which is acceptable for a security product.
