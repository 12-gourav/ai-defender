# ADR-0004: Never mount the developer's repository; Git-native synchronisation

Status: accepted. Date: 2026-10-30.

## Context
The specification requires an isolated workspace, protected files, and independent validation before synchronisation into the original repository. Vendor sandboxes (Gemini CLI, Claude Code) mount the real working directory. A writable `.git` lets the agent plant hooks and config that execute on the host when the developer next runs git; a read-only `.git` breaks normal git use and still leaks reflog and stashes. File-copy synchronisation has a large validation surface (symlinks, special files, TOCTOU, case folding).

## Decision
The container gets a private staging clone (its own `.git`, rewritten config, no hooks), optionally backed by the developer's `.git/objects` mounted read-only as alternates. The developer's working tree and `.git` are never mounted. Synchronisation is Git-native: the controller fetches commits *from* the staging clone into a controller-owned quarantine repository with hooks and config neutralised, validates the objects (paths, modes, symlinks, submodules, protected files, secrets), obtains a typed commit approval, and updates the developer's branch with compare-and-swap. Uncommitted changes are never synced.

## Alternatives considered
- LIVE mode (bind-mount working tree rw, mask `.git`, bind-mount protected files ro): gives the developer's IDE live visibility but removes pre-sync validation and leaves many file-level edge cases. Kept as a possible future opt-in with explicitly reduced guarantees, gated on pilot feedback (R-01).
- rsync-style copy with validation: larger attack surface than object inspection.

## Consequences
- The developer sees agent changes after sync, not live. `agentguard sync` and adapter post-commit steps make this frequent and cheap.
- All host-side git invocations on untrusted repositories must use the locked-down environment (AC-G5).
- Large repositories remain cheap through alternates; `full_copy` is available when history exposure is unacceptable.

## Amendments (Phase 0 review, 2026-10-30)

- `full_copy` is the default; alternates are opt-in with the unreachable-object leak stated (G5).
- Untracked files are absent from the sandbox by construction; a narrow, policy-listed read-only copy allowlist is proposed (G6, Q2).
- A built-in host-executed-content classification raises commits touching build and tooling files to high risk (G2).
- Commits land on `refs/agentguard/<task>/<branch>`; a checked-out branch is never updated directly (C15).
