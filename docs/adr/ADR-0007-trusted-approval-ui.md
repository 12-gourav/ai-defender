# ADR-0007: Approval UI is a separate host process with an anti-spoof session phrase

Status: accepted. Date: 2026-10-30.

## Context
The agent's TTY is passed through to the developer's terminal. The agent can print anything, including text that looks like an AgentGuard approval prompt or confirmation. The specification requires that the approval interface not be rendered by untrusted content.

## Decision
Approvals are rendered only by `agentguard approvals --watch` (or a later overlay owned by the host PTY process), never by anything inside the container and never by parsing agent output. Each session has a random three-word phrase shown in the UI and never sent to the container; prompts display it. Agent-supplied text appears in a labelled, ANSI-stripped, bounded box. Trusted facts are computed by the controller. Typed confirmations are required for high-risk operations.

## Consequences
- The pilot needs a second terminal (or desktop notification plus terminal). A PTY overlay is a usability follow-up.
- Developers are trained to act only on prompts showing the session phrase.

## Amendment (Phase 0 review, 2026-10-30)

The host process that owns the agent's PTY is part of the trusted UI surface: it filters terminal escape sequences in the agent's output and resets the terminal on exit (G1). Any future overlay must own a region the agent stream cannot address, which in practice means a separate window. All agent-originated strings in any trusted output pass through one sanitiser (G12).
