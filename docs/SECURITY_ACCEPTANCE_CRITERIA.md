# Security Acceptance Criteria

Each criterion names its enforcement mechanism and the test that proves it. A criterion without a passing test is not claimed. "Phase" is where the test first exists.

## Containment

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-C1 | No Docker socket or Docker API is reachable from inside the sandbox | no mount, `--network none` | adversarial: enumerate `/var/run`, `/run`, scan for unix sockets, attempt TCP 2375/2376 | 4 |
| AC-C2 | No host path other than the enumerated mounts is visible | mount allowlist + inspect assertion | adversarial: diff `/proc/self/mountinfo` against allowlist; attempt to read `$HOME`, `/etc/passwd` of host (should see image's) | 4 |
| AC-C3 | Container runs as non-root with all capabilities dropped and no-new-privileges | run spec + inspect assertion | adversarial: `capsh --print`, `setuid` binaries, `mount -t proc`, `nsenter` | 4 |
| AC-C4 | Sandbox refuses to start if any invariant fails | inspect verification | security: tamper the run spec in a test build; expect refusal and audit event | 4 |
| AC-C5 | Resource limits are enforced or the session refuses to start in strict mode | cgroup v2 delegation | integration: fork bomb hits pids limit; allocate past memory limit gets OOM-killed | 4 |
| AC-C6 | Seccomp blocks namespace creation, mount, keyctl, bpf, ptrace of other processes | profile | adversarial: `unshare -U`, `bwrap`, `keyctl`, `bpf()` return EPERM | 4 |
| AC-C7 | Agent terminal output cannot write the clipboard, query the terminal, or leave the developer's shell with injected input | PTY output filter and reset | corpus of OSC 52, DCS, CSI queries, alternate screen, title sequences; oracle on a pseudo-terminal | 4 |

## Credentials

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-K1 | No file under `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.gitconfig` exists inside the sandbox | mount allowlist | adversarial: find by path and by content pattern | 4 |
| AC-K2 | The host environment is not inherited; only the constructed allowlist appears | env construction | adversarial: dump `env` and `/proc/*/environ`; compare | 5 |
| AC-K3 | No Git remote credential exists in the container, in the shim's memory, in process arguments, or in logs | broker design | adversarial: grep container fs, `/proc/*/cmdline`, controller logs, audit DB for a canary token | 7 |
| AC-K4 | Only the agent's own provider credential is present, scoped as documented | ADR-0010 | inspection test listing `/ag/auth` | 10 |

## Network

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-N1 | No route exists except loopback | `--network none` | `ip route`, `curl 1.1.1.1`, `curl [2606:4700::1111]`, `ping`, `nc -u` all fail | 4 |
| AC-N2 | Only allowlisted host:port pairs are reachable via the proxy | Network Guard | corpus of allowed and denied hosts, IP literal notations, ports | 8 |
| AC-N3 | Metadata, loopback, link-local and private ranges are denied even when an allowlisted hostname resolves to them | resolver pinning + deny ranges | simulated DNS answers | 8 |
| AC-N4 | DNS is not reachable from the sandbox | no route; proxy resolves | `dig @8.8.8.8`, `nslookup` fail; DoH to non-allowlisted host fails | 8 |
| AC-N5 | Denied and allowed connections are audited without payloads | audit | inspect audit after corpus; assert no request bodies present | 8 |
| AC-N6 | Killing the proxy stub or the egress proxy results in no connectivity, never direct connectivity | fail-closed | kill stub, kill proxy; all egress fails | 8 |

## Git

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-G1 | No commit enters the developer's repository without an approved `GitCommitRequest` | sync pipeline | attempt sync without approval; developer's refs unchanged | 7 |
| AC-G2 | No push occurs without a consumed, unexpired, operation-bound token | broker | attempt push with expired/consumed/mismatched token; remote unchanged | 7 |
| AC-G3 | Push to protected branch is denied regardless of task scope | hard-deny | attempt with task scope naming `main`; denied with rule id | 7 |
| AC-G4 | Force push, mirror, tag push and ref deletion are denied by default | refspec parser | corpus | 7 |
| AC-G5 | Hostile config and hooks in the staging clone never execute on the host | locked-down git invocation | plant `core.fsmonitor`, `core.hooksPath`, `credential.helper`, `.git/hooks/*`, `core.sshCommand`, `filter.*.clean`; canary file must not appear | 7 |
| AC-G6 | The pushed range equals the approved range even under concurrent remote changes | `--force-with-lease` CAS | race test against a disposable remote | 7 |
| AC-G7 | The developer's `.git` directory is never mounted writable, and not mounted at all except `objects` read-only when alternates are enabled | mount allowlist | inspect | 4 |

## Approvals

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-A1 | A token is consumable exactly once | atomic consumption | concurrent double-consume test | 6 |
| AC-A2 | A token is invalid after `expires_at` | expiry check | clock-advanced test | 6 |
| AC-A3 | A token from session S1 cannot authorise an operation in S2; same for tasks | binding | cross-session test | 6 |
| AC-A4 | Changing any field of the approved operation invalidates the token | canonical hash | mutation fuzz across all request types | 6 |
| AC-A5 | Approval prompts are rendered only by the host UI process, show the session phrase, and label agent text as untrusted | UI design | UI snapshot tests; agent prints fake prompts, UI unaffected | 6 |
| AC-A6 | Natural-language requests from the agent never change task scope or policy | typed privileged flows | fuzz agent messages; scope unchanged | 6 |
| AC-A7 | Non-interactive mode never auto-approves | mode semantics | run with pending approvals; all denied | 6 |
| AC-A8 | Pending timeout and token validity cannot exceed their maximums | `ApprovalTiming` bounds | unit tests (Phase 1) and precedence tests | 1, 2 |
| AC-A9 | No message on the control socket can record an approval decision; the approval socket is never mounted | IPC schema separation, mount allowlist | schema review test; mount inspection | 3, 6 |
| AC-A10 | Every agent-originated string in prompts and CLI output is sanitised (controls, ANSI, bidi, zero-width) | shared renderer | corpus test on `output::sanitise` (Phase 1) and prompt snapshot tests | 1, 6 |

## Policy and controller

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-P1 | Unknown keys in security sections are rejected | schema | corpus | 2 |
| AC-P2 | Lower-precedence policy cannot loosen higher-precedence rules | merge rules | property test | 2 |
| AC-P3 | Editing `.agent-security.yml` inside the sandbox does not change the running session's policy | snapshot pinning | edit in container; `policy explain` unchanged; sync flags PolicyModification | 7 |
| AC-P4 | Controller exit leaves the container with no capability; the container is dead within grace when the shim is intact, and at the next AI Defender invocation otherwise | lifecycle, shim watchdog, orphan sweep | kill -9 controller; sockets unlinked; shim exits; sweep kills a container whose shim was killed first | 4 |
| AC-P5 | Audit records are hash-chained and tampering is detected | audit engine | modify a row; `ai-defender audit --verify` fails | 3 |
| AC-P6 | No secret value appears in audit or logs | redaction | canary corpus planted in every input path | 8 |
| AC-P7 | Every denial includes request, rule, reason, approvability and alternative | `Decision` constructor | compile-time plus snapshot tests | 3 |

## Fail-closed

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-F1 | Sandbox unavailable → no session, never host execution | refusal | run without docker; exit non-zero; no agent process spawned | 4 |
| AC-F2 | Scanner unavailable → high-risk approvals blocked, others require typed acknowledgement | approval rules | remove gitleaks; observe | 8 |
| AC-F3 | Hook cannot reach controller → tool denied for adapters with fail-closed support; documented advisory for others | shim + provider flag | kill controller socket during hook | 10 |
| AC-F4 | Audit write failure → sensitive operation denied | critical path | make DB read-only; push denied | 7 |
| AC-F5 | Policy snapshot corruption mid-session → session terminated | integrity check | corrupt file; next sensitive op terminates session | 3 |
| AC-F6 | Scanners and parsers of agent content run only inside a disposable container | sandbox manager reuse | process-tree oracle during a scan | 8 |
| AC-F7 | Scanner configuration found in the scanned tree is never honoured | controller-owned config paths | plant allow-all `.gitleaks.toml` and `.trivyignore`; findings still reported | 8 |

## Databases and deployment

| ID | Criterion | Mechanism | Test | Phase |
|---|---|---|---|---|
| AC-D1 | Production-tagged databases are unreachable and unapprovable | hard-deny | attempt via guard and via proxy | 9 |
| AC-D2 | Destructive statements require typed approval | classifier | SQL corpus | 9 |
| AC-D3 | Infrastructure tools never run inside the sandbox with credentials; host exec requires typed approval | Deployment Guard | attempt terraform apply inside; attempt via gateway without approval | 9 |
