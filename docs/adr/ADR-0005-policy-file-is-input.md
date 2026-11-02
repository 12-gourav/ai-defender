# ADR-0005: `.agent-security.yml` is an input; the trusted policy is a pinned snapshot

Status: accepted. Date: 2026-10-30.

## Context
The canonical policy lives in the repository, which the agent edits (in its staging copy). The specification already states the file is not the boundary.

## Decision
At session start the controller reads the repository's policy file, validates it, merges it under organisation policy, writes the effective policy to controller-owned state, and computes `policy_version` as a canonical hash. The session, all decisions, approvals and audit records reference that snapshot. The file in the staging clone is ordinary content. A change to it is surfaced on sync as a `PolicyModification` privileged approval and takes effect only for new sessions after `agentguard policy approve`.

## Consequences
- The running session cannot be weakened by any edit the agent makes.
- Organisation policy lives outside the repository (host config path or MDM-delivered), so the repository can never relax it.
- Policy changes are reviewable diffs with security-impact labels.

## Amendment (Phase 0 review, 2026-10-30)

The controller stores the last-approved policy hash per repository so that "takes effect only after `agentguard policy approve`" is enforceable (G14).
