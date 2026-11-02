# Docker Isolation Design

## 1. Runtime choice

- **Initial:** rootless Docker (daemon running as the developer's user). Container root maps to the developer's uid; a full escape yields the developer's user, not host root.
- **Optional:** gVisor (`runsc`) as the runtime for the same image, selected by policy `sandbox.runtime: gvisor`. Recommended for higher-assurance environments. `doctor` reports availability.
- **Considered:** Podman rootless (`--userns=keep-id` solves file-ownership issues more cleanly). Kept as an alternative backend behind the `Sandbox` trait; see ADR-0006 and risk R-06.

## 2. Image

- Base: pinned digest of a minimal distro image (Debian slim or Ubuntu minimal), rebuilt in CI, Trivy-scanned, digest recorded in controller state and verified before every run.
- Layers per agent adapter (node + the agent package, or the agent's native binary), pinned versions.
- `agentguard-shim` static binary at `/usr/local/bin/`, plus `git-remote-agentguard` symlink.
- Managed/system configuration for the agent baked in under `/etc` (read-only), for example:
  - Claude Code: `/etc/claude-code/managed-settings.json` with `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `permissions.disableBypassPermissionsMode: "disable"`, hooks → shim with `onFailure: "block"`, `sandbox.enabled: false` (the container is the sandbox; bubblewrap inside Docker without nested userns does not work), `permissions.deny` for credential paths as defence in depth.
  - Codex: `requirements.toml` via `managed_dir` with `[hooks]` → shim, `allow_managed_hooks_only = true`, `allowed_approval_policies`, sandbox mode `danger-full-access` is **not** used; `workspace-write` with `network_access = false` is kept as an inner layer where it works inside the container (needs verification, R-11).
  - Gemini CLI, Antigravity CLI, cursor-agent: system-level settings where supported; otherwise a read-only bind over the user config path.
- Non-root user `agent` (uid 1000 in container).
- No package manager cache, no compilers beyond what the project needs (project toolchains come from a per-project layer declared in policy `sandbox.toolchain`).

## 3. Run specification (fixed template)

```
docker run
  --rm
  --name agentguard-<session>
  --label agentguard.session=<sid> --label agentguard.controller_pid=<pid>
  --user 1000:1000
  --read-only
  --tmpfs /tmp:rw,nosuid,nodev,size=<policy>
  --tmpfs /home/agent:rw,nosuid,nodev,size=<policy>
  --cap-drop ALL
  --security-opt no-new-privileges
  --security-opt seccomp=<agentguard-seccomp.json>      # default profile minus: mount family, ptrace of others,
                                                        # keyctl, unshare/clone3 with CLONE_NEWUSER, bpf, perf_event_open,
                                                        # io_uring, userfaultfd, kexec, open_by_handle_at, AF_PACKET sockets
  --security-opt apparmor=agentguard-agent               # when AppArmor available; else docker-default
  --network none
  --pids-limit <policy, default 512>
  --memory <policy> --memory-swap <same> --cpus <policy>
  --ulimit nofile=4096:4096 --ulimit nproc=512:512
  --mount type=bind,src=<state>/sessions/<sid>/staging,dst=/workspace,rw
  --mount type=bind,src=<dev repo>/.git/objects,dst=/ag/alternates,ro        # unless git.staging: full_copy
  --mount type=bind,src=<runtime>/agentguard/<sid>/control.sock,dst=/ag/control.sock
  --mount type=bind,src=<runtime>/agentguard/<sid>/egress.sock,dst=/ag/egress.sock
  --mount type=bind,src=<state>/sessions/<sid>/agent-auth,dst=/ag/auth,ro    # provider credential only, see ADR-0010
  --env-file <constructed, non-secret>
  --init
  <image@sha256:digest> agentguard-shim entry <agent> -- <agent args>
```

The specification is a template with a small enumerated set of policy-driven slots: the workspace mount mode (`rw`, or `ro` in READ_ONLY), the optional alternates mount (opt-in), approved read-only extra directories, and Database Guard sockets. The inspect assertion in section 4 checks the *instantiated* allowlist. Everything else is forbidden. Specifically forbidden and asserted absent: `--privileged`, `--cap-add`, `--device`, `--pid=host`, `--ipc=host`, `--network` other than `none`, `--userns=host`, any `-v /var/run/docker.sock`, any mount of `$HOME` or `/`, `--security-opt seccomp=unconfined`, `--security-opt apparmor=unconfined`.

Optional: `--runtime=runsc` for gVisor. With gVisor the seccomp/AppArmor options still apply to the sandbox process.

## 4. Integrity verification before handover

After `docker create` and before `docker start`, the sandbox manager runs `docker inspect` and asserts on the JSON:

- `HostConfig.Privileged == false`, `CapAdd == null`, `CapDrop == ["ALL"]`, `SecurityOpt` contains `no-new-privileges` and the expected seccomp/apparmor, `NetworkMode == "none"`, `ReadonlyRootfs == true`, `PidsLimit`, `Memory`, `NanoCpus` set, `UsernsMode == ""` (daemon userns), `Devices == []`, `IpcMode != "host"`, `PidMode != "host"`.
- `Mounts` is exactly the allowlist (source paths canonicalised and compared; any extra mount → abort).
- `Config.User == "1000:1000"`, `Config.Image` digest equals the pinned digest.
- Daemon: `docker info` reports `Rootless: true` (or `runsc` runtime present when selected); `SecurityOptions` includes `seccomp` and, when expected, `apparmor`; cgroup v2 with controllers `cpu memory pids` delegated to the user (checked via `/sys/fs/cgroup/user.slice/.../cgroup.controllers`).

If any assertion fails: remove the container, write a `SandboxIntegrityFailure` audit event, exit non-zero. No session.

## 5. Networking

- `--network none`: only `lo` exists. No DNS, no default route.
- Egress: the shim's proxy stub listens on `127.0.0.1:3128` and forwards bytes to `/ag/egress.sock`. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` are set; `NO_PROXY` is empty. Tools that ignore proxies simply fail.
- The host-side Network Guard enforces the allowlist. The stub is untrusted and dispensable.
- Database Guard, when a dev DB is configured, bind-mounts one more unix socket per database (`/ag/db/<name>.sock`) and the shim exposes it on a loopback port; the host-side protocol proxy terminates the database protocol.
- Localhost services on the host are **not** reachable (this is deliberate; expose them via a Database Guard or a network allowlist entry for `host.docker.internal` only when policy says so, and note that rootless Docker needs `--add-host` plumbing which is a Phase 8 item).

## 6. Filesystem

| Path in container | Source | Mode | Notes |
|---|---|---|---|
| `/` | image | ro | |
| `/workspace` | staging working tree | rw | `nosuid,nodev`; `noexec` is **not** set because projects need to run their own build scripts; execution is contained anyway |
| `/ag/alternates` | developer `.git/objects` | ro | optional |
| `/ag/control.sock`, `/ag/egress.sock` | runtime sockets | – | |
| `/ag/auth` | provider credential | ro | |
| `/tmp`, `/home/agent` | tmpfs | rw | size-limited; `/home/agent/.claude` etc. live here and are discarded at session end except files the adapter chooses to persist via the controller (never secrets) |

No other path exists. Protected policy files are not in the container at all except as ordinary content in the staging clone, where editing them is harmless.

## 7. Resource controls

`--pids-limit`, `--memory`, `--cpus`, `--ulimit`, tmpfs sizes, plus a session wall-clock limit enforced by the controller (`task.expires_at`). Rootless Docker needs cgroup v2 and systemd delegation (`/etc/systemd/system/user@.service.d/delegate.conf` with `Delegate=cpu cpuset io memory pids`); `doctor` reports whether limits can actually be enforced and the session refuses to start in `strict` resource mode if not.

## 8. Lifecycle and cleanup

- Start: create staging clone, create sockets, `docker create`, verify, `docker start -ai` (TTY attached to the developer's terminal for interactive agents).
- Stop: agent exit or revoke → `docker kill` (SIGTERM, then SIGKILL after grace) → `--rm` removes it → sockets unlinked → temporary credentials revoked → session audit closed. The Docker daemon, not the controller, is the container's parent, so the shim's entry process watches the control socket and terminates the agent when it closes, and every `ai-defender` invocation runs the orphan sweep (Phase 0 review G16).
- `ai-defender clean`: removes staging clones and quarantine refs for ended sessions older than retention, after confirming nothing unsynced remains (or with `--force` after listing what will be lost).
- Orphan sweep in `doctor`: containers labelled `agentguard.session` whose controller pid is gone are killed and reported.

## 9. Why not the agents' own sandboxes

They are kept **inside** the container where they work (defence in depth) but never relied upon:

- Claude Code's bubblewrap sandbox is off by default, fails open without `failIfUnavailable`, does not cover built-in Read/Edit/Write/WebFetch tools, allows broad reads by default, and needs nested user namespaces which Docker's default seccomp blocks.
- Codex's bwrap+seccomp sandbox is strong for Bash but hooks returning `ask` are ignored and the proxy does not cover MCP connections.
- Gemini CLI's container sandbox mounts the real working directory at the same absolute path and documents no network policy for containers.
- Antigravity's Linux sandbox uses namespaces and is unavailable where unprivileged userns is blocked; no fail-closed statement.
- Cursor's agent has no documented Linux OS-level sandbox in the material reviewed.

## 10. Known weaknesses of this layer

- Kernel attack surface. Mitigated by seccomp tightening, caps dropped, rootless; gVisor optional.
- The staging working tree lives on host disk and is written by a container uid; file ownership mapping under rootless Docker (subuid) complicates controller reads and deletions. Spike in Phase 4 (R-06).
- `--network none` breaks any tool that insists on real TCP (plain `ssh`, most DB drivers without the DB guard). Documented; this is the intended behaviour.
- Docker-in-Docker for the project's own containers is not supported inside the sandbox. Projects that need to run containers as part of tests must run those via an approved host exec entry (Phase 9) or accept the limitation.
