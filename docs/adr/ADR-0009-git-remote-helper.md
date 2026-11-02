# ADR-0009: Git integration via a custom remote helper and a host-side broker

Status: accepted. Date: 2026-10-30.

## Context
The agent must be able to run ordinary `git push origin feature/x`. The container has no network and no credentials. Options: a bind-mounted bare repository the agent pushes to (host then forwards), or a Git remote helper speaking to the controller.

## Decision
The staging clone's `origin` uses the `agentguard::` transport implemented by `git-remote-agentguard` (part of the shim), which streams fetch/push over the control socket. The host-side Git Guard validates refspecs, ranges, protection and task scope, runs scans, raises typed approvals, and the broker executes the real push from a controller-owned quarantine repository with a one-shot in-memory credential helper and `--force-with-lease` compare-and-swap.

## Alternatives rejected
- Bind-mounted bare repository: the agent could tamper with that repository's config/hooks; the host would then run git against hostile config.
- Allowing the Git host through the proxy with injected credentials: the agent could push anything the credential allows, bypassing range and branch validation.

## Consequences
- Fetch also goes through the broker (read-scoped credential), which keeps the network allowlist free of Git hosts.
- Remote helper protocol edge cases (LFS, shallow, large packs) need testing in Phase 7.

## Amendment (Phase 0 review, 2026-10-30)

The controller never spawns `git` with the staging clone as its repository; the staging-to-quarantine transfer reads objects with gix. Commit identity is validated, not rewritten, so the approved SHA is the pushed SHA (G9, G10).
