# ADR-0006: Rootless Docker first, gVisor optional, Podman as alternative backend

Status: accepted; file-ownership spike pending (R-06). Date: 2026-10-30.

## Context
The specification names Docker (rootless) with gVisor optional. Rootless Docker maps container root to the developer's uid, so an escape yields the developer's user rather than host root. Podman rootless offers `--userns=keep-id`, which simplifies file ownership of the staging tree, but the specification names Docker.

## Decision
Implement a `Sandbox` trait with a `DockerRootless` backend first, verified through `docker inspect` assertions, with `--runtime=runsc` as a policy option. Keep the backend abstract so a `PodmanRootless` backend can be added without touching guards. Resolve the subuid file-ownership question in a Phase 4 spike and record the outcome here.

## Consequences
- Requires rootless Docker and cgroup delegation on developer machines; `doctor` reports and `strict` mode refuses otherwise.
- Docker-in-Docker inside the sandbox is unsupported.
- Agent-side vendor sandboxes that need nested user namespaces will not work inside the container; they are not relied upon.
