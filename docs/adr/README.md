# Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [0001](ADR-0001-rust-core.md) | Rust as the sole trusted implementation language | accepted |
| [0002](ADR-0002-containment-not-hooks.md) | Containment and credential absence are the boundary; hooks and command filtering are advisory | partly superseded by 0013 (applies to the contained tier) |
| [0003](ADR-0003-native-policy-engine.md) | Native Rust policy engine instead of embedded OPA/Rego | accepted |
| [0004](ADR-0004-staging-clone-git-native-sync.md) | Never mount the developer's repository; Git-native synchronisation | accepted |
| [0005](ADR-0005-policy-file-is-input.md) | `.agent-security.yml` is an input; the trusted policy is a pinned snapshot | accepted |
| [0006](ADR-0006-rootless-docker-first.md) | Rootless Docker first, gVisor optional, Podman as alternative backend | partly superseded by 0013 (Docker is optional) |
| [0007](ADR-0007-trusted-approval-ui.md) | Approval UI is a separate host process with an anti-spoof session phrase | accepted |
| [0008](ADR-0008-approval-tokens-never-leave-controller.md) | Approval tokens are internal; nothing replayable is handed to the agent | accepted |
| [0009](ADR-0009-git-remote-helper.md) | Git integration via a custom remote helper and a host-side broker | accepted |
| [0010](ADR-0010-provider-credential.md) | The agent's own provider credential is reachable by the agent; scope it, do not hide it | accepted |
| [0011](ADR-0011-network-none-plus-proxy.md) | `--network none` plus a host-side allowlist proxy over a unix socket | accepted |
| [0012](ADR-0012-per-session-controller.md) | Per-session controller process, no long-running daemon | partly superseded by 0013 (per-invocation engine) |
| [0013](ADR-0013-hook-based-local-engine.md) | A local, hook-driven decision engine is the primary product; containment becomes an optional hardening tier | accepted |
| [0014](ADR-0014-signed-local-trust-store.md) | Signed, pinned local trust store with Ed25519 and an optional administrator anchor | accepted |
