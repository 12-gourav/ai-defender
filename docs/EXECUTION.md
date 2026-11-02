# Managed execution, Git security and command governance

Status: Phase 7 (2026-10-31). Code: `crates/agentguard-exec` (planning, Git adapter, shell
subset, environment, process runner, executor), `agentguard_engine` (terminal classification,
force detection, rules, operation digest), `agentguard_trust::executions` (records),
`crates/agentguard-engine-cli/src/execution.rs` (protocol commands),
`cli/src/commands/execution.ts` (`ai-defender run`, `git`, `execution`).

## 1. What managed execution is, and what it is not

`ai-defender run <command>` runs one command through AI Defender. AI Defender first evaluates the
command, gets approval if policy requires it, and binds that approval to the exact operation and
repository state. Only then does it run the command, with a filtered environment and a time
limit, verify the result, and record everything.

**This is not global enforcement.** AI Defender controls only commands routed through
`ai-defender run`, or through the `execution.run` engine command an integration may call. A
command an AI agent runs through its own terminal tool, a Git command typed directly, or a
script started any other way is **not intercepted**. Every execution result, `ai-defender status`
and the help text say so. Routing an agent's own tool calls through this layer needs the agent
hook integrations of Phase 8 (section 11).

## 2. Pipeline

```text
ai-defender run …  (CLI: forwards argv or a script; displays results; never decides)
  │
  ▼ engine: execution.run
validate request ─ resolve working directory ─ verify trusted state ─ project from registry
  ─ audit: execution-request-received
  ─ plan:  resolve executable through the trusted search path; refuse privilege wrappers,
           set-ID programs and AI Defender itself
           managed mode: argv, no shell   │   shell mode: strict parse → canonical script
           Git: structured parse → repository inspection → secret scan of what a commit or
           push would publish
  ─ audit: command-classified, git-context-inspected, pre-execution-scan-completed
  ─ evaluate: identity (trusted invocation + registry), the existing policy engine
  ─ digest: canonical operation + execution binding (v3)
  ─ audit: execution-policy-decision
  ─ DENY → refused, nothing runs
  ─ REQUIRE_APPROVAL → create a request (claim token to the requester), or redeem a grant
  ─ reserve idempotency key ─ consume grant (atomic, once) ─ Permit
  ─ revalidate: executables unchanged, repository facts unchanged
  ─ record started + audit execution-started  (either failing → nothing runs)
  ─ spawn: absolute path, argv, filtered env, stdin /dev/null, own process group, time limit
  ─ verify: commit tree / remote-tracking ref
  ─ record outcome + audit execution-completed|failed|timed-out|indeterminate
```

Classification, authorization and execution are separate components. The process runner is a
private module of `agentguard-exec`. It accepts only a `Permit`, which only the executor can
construct (a `compile_fail` doctest checks this), after an `ALLOW` decision or a consumed grant.
The engine protocol has no command that starts a process any other way (tested).

## 3. Modes

**Managed mode (preferred).** The request carries an argument vector. Nothing is interpreted by
a shell: `echo 'x; touch pwned' '$(touch y)'` prints its arguments literally. For policy, the
vector is quoted into terminal command text with `agentguard_engine::normalize::quote_argv`.
A property test proves that the engine's tokenizer reads this text back as exactly the same
words. So the same terminal rules apply whether a command arrives typed or managed. The
digest binds the exact vector as well.

**Shell mode (`--shell sh|bash`).** Only an exactly-classifiable subset is accepted:

- Simple commands of literal words: bare, single-quoted, or double-quoted without `$`,
  backquotes or escapes other than `\"` and `\\`.
- Commands joined by `;`, newline, `&&`, `||` and `|`.
- Redirections `>`, `>>`, `<`, `2>`, `2>>` and `2>&1` to literal targets.

The following are refused and never executed:

- Command substitution; parameter and arithmetic expansion.
- Globbing; brace and tilde expansion.
- Background jobs (`&`); subshells and groups.
- Here-documents; process substitution.
- Comments; history expansion.
- Variable assignments.
- Reserved words (`if`, `for`, functions, …).
- Builtins that change how later words are read (`eval`, `exec`, `source`, `.`, `cd`,
  `export`, `set`, `alias`, `trap`, …).
- Git changes (use managed mode, so repository state can be bound).

The executor runs the **canonical rendering** of the parsed script, not the submitted text.
Every word is re-quoted, so the interpreter sees exactly the structure that was evaluated.
`bash` is started with `--noprofile --norc`. `BASH_ENV`, `ENV` and exported functions never
reach it. This is a classifier for a subset, not a shell implementation. AI Defender does not
claim coverage of arbitrary shell syntax, and never falls back to running unclassified text.

## 4. Git classification

The Git adapter (`agentguard_exec::git`) parses argument vectors structurally. It applies
whenever the executable is Git itself: a `git` binary in a trusted directory outside the
project, however it was named (`git`, `/usr/bin/git`, a symlink).

| Class | Commands | Balanced default |
|---|---|---|
| Read-only | `status`, `diff`, `log`, `show`, `blame`, `rev-parse`, `ls-files`, `describe`, `grep`, … and the list forms `branch --list`/`-a`, `tag -l`, `remote -v`/`show`/`get-url`, `stash list`/`show`, `config --get`/`--list` | ALLOW |
| Staging | `add` | ALLOW |
| Commit | `commit -m …` (staged index only) | REQUIRE_APPROVAL |
| History and branches | `branch <name>`, `switch`, `checkout`, `merge`, `rebase`, `cherry-pick`, `revert`, `reset`, `stash push`/`pop`, `tag <name>`, `restore`, `rm`, `mv` | REQUIRE_APPROVAL |
| Remote | `push <remote> <refspec>`, `fetch`, `pull` | REQUIRE_APPROVAL (push: mandatory) |
| Remote configuration | `remote add`/`remove`/`set-url`/`rename`, `config` writes | REQUIRE_APPROVAL |
| Force | `push --force`, `--force-with-lease`, `+refspec`, `--delete`, `:ref` | **DENY**; the trusted global policy may lower it to approval, never to allow |
| Destructive | `reset --hard` on protected state, `clean -f`, `branch -D` | approval, or DENY on protected resources |
| Trusted security files | anything touching `.agentguard`, `.agent-security.yml`, hook settings | DENY (guard) |
| Secrets | a commit whose staged changes, or a push whose commits, contain a detected credential | DENY (mandatory) |

The following are refused in managed mode:

- Options that select another repository or configuration (`-C`, `-c`, `--git-dir`,
  `--work-tree`, `--exec-path`, …).
- Unknown subcommands. They may be aliases, and an alias can run anything.
- `commit` with `-a`, `-i`, `-o`, `-p`, pathspecs or an editor. Stage first; give `-m`.
- `push` without exactly one remote name and one refspec, or with `--all`, `--mirror`,
  `--tags` or `--prune`.
- Remote URLs as push, fetch or pull targets. A configured remote must be named.
- Options that run other programs: `--exec`, `--upload-pack`, `--receive-pack`, `--ext-diff`,
  `--textconv`, `--output`, custom merge strategies, interactive rebase, and `ext::` or `fd::`
  remotes.
- Mutating operations in a repository whose working tree or Git directory lies outside the
  registered project.

### Repository context

Before a mutating Git operation, the adapter reads, without hooks, file-system monitors, pagers,
optional locks or credential helpers:

- Repository root, Git directory and repository identity: SHA-256 over the root, the common Git
  directory and the root commits.
- Current branch and HEAD.
- The staged tree (`git write-tree`) and the staged file list.
- Remotes. Push URLs are reduced to scheme, host and path; credentials, queries and fragments
  are removed.
- For a push: the source commit, the remote-tracking commit, and the commits not yet on any
  remote-tracking ref of that remote.
- Every ref the command names, resolved to a commit.
- The hooks that will run.

`git status` (for `ai-defender git status|inspect` only) is skipped when the repository
configures content filters, which computing status could run. A repository is not trusted
merely because `.git` exists: the working tree and Git directory must lie inside the registered
project for any change.

### Binding and revalidation

The operation digest (v3, `agentguard.operation-digest.v3`) covers the Phase 5 canonical
operation plus an **execution binding**:

- The program path and identity: device, inode, size, mtime, mode and SHA-256.
- A digest of the exact argument vector.
- The environment profile and the names it passes.
- The time limit.
- Every script program in shell mode.
- `git.repository`, `git.head`, `git.branch` and `git.staged-tree`.
- For a push: `git.push.remote`, `git.push.remote-url` (identity), `git.push.source`,
  `git.push.destination`, `git.push.remote-tracking` and `git.push.range`.
- `git.ref.<name>` for every ref the command names.

Consequences, each tested:

- An approved push to `origin/feature-a` cannot push to `origin/main`.
- A new commit on the branch, or a re-pointed source branch, voids the grant.
- An approved commit cannot include newly staged files.
- An approved checkout or merge cannot use another branch.

Redemption recomputes the digest from a fresh inspection and the store compares it before
consuming the grant (one atomic, locked transaction). Immediately before spawning, the executor
re-inspects once more. It also re-checks every executable's identity. Any difference means
nothing runs (`context-changed`, audited) and a new approval is needed.

### Verification

After a commit, the new HEAD must record exactly the approved staged tree. A hook that changes
the staged content is reported as a verification mismatch, audited as
`execution-verification-failed`, and is never silently accepted. History is never rewritten
automatically. After a push, the remote-tracking ref must point at the approved commit.

## 5. Secret scanning integration

- **Commit:** `git diff --cached` (exact staged content, external diff and text conversion
  disabled) is scanned with the policy's detectors. Detections become host-supplied evidence
  (`HostInspection`), which can only add to the engine's own inspection. A credential triggers
  `mandatory:secret-commit` (DENY).
- **Push:** the patches of the commits being pushed are scanned (up to 200 commits and 16 MiB;
  beyond that the scan is incomplete and the decision uncertain). A credential is secret data
  bound for a Git remote, which triggers `mandatory:secret-disclosure` (DENY). This covers
  commits made outside AI Defender.
- Results carry counts and severities only. Nothing is rewritten, deleted or rotated.

## 6. Terminal classification

Policy decides from the engine's `CommandClass`, resource classification and risk. The same
analysis applies to typed terminal requests and managed executions. Phase 7 extends it:

- Structured `git` force detection (`CommandAnalysis.git_forced`). The `Force` condition now
  matches terminal Git commands as well as typed Git actions.
- System administration (process termination, services, firewalls, users, kernel modules,
  power, OS security controls) maps to `privileged`.
- Environment dumps (`env`, `printenv`, `set`, `export -p`), `gpg --export-secret-keys` and
  `kubectl get secret` map to `secret-access`.
- Database clients with destructive statements (`DROP`, `TRUNCATE`, `DELETE FROM`, `FLUSHALL`),
  `dropdb` and `dropuser` map to `destructive`.

Each execution also gets a display category: read-only, build, test, formatting, package
management, filesystem modification, network, process management, privilege escalation, system
configuration, destructive, security configuration or unknown. It is derived from the same
analysis and never decides anything.

| Default | Examples |
|---|---|
| ALLOW | `npm test`, `npm run build`, `npm run lint`, `pnpm test`, `cargo test`, `cargo check`, `cargo fmt`, `git status`, `git diff`, `ls`, `cat src/main.rs` (ordinary files, confident classification) |
| REQUIRE_APPROVAL | `npm install x`, `npm uninstall`, `pnpm add`, `git commit`, `git push`, `git checkout`/`switch`/`merge`/`rebase`, `docker run`, unknown programs and project scripts (`./deploy.sh`, migration tools), `rm -rf build` (ordinary project files), `kill`, `systemctl`, `printenv` |
| DENY | `git push --force`; `rm -rf` or `chmod -R` outside the project, on `.git`, or on sensitive or security files (`profile:destructive-protected`, `profile:permission-protected`); `rm -rf /`, `mkfs`, `dd if=`, `curl … \| sh` (critical); bypass attempts; trusted-state changes; secret commits and disclosures |
| Refused (never evaluated as runnable) | `sudo`, `doas`, `su`, `pkexec`, set-ID programs, `ai-defender …`, `agentguard-engine`; unsupported shell or Git syntax |

Unfamiliar but harmless commands are not denied: they are `unknown` and require approval.
Classification is a fixed set of tables. It cannot recognise every dangerous command, and
anything it cannot see through lowers confidence instead of being guessed.

### Configuration

The trusted global policy may set:

```yaml
profile:
  git_force_push: REQUIRE_APPROVAL   # default DENY; ALLOW rejected; mandatory floor is approval
  protected_destruction: DENY        # default DENY; ALLOW rejected
execution:
  default_profile: development       # or minimal
  default_timeout_seconds: 600       # 1 to 3600
  environment: [MY_TOOL_HOME]        # extra names; credential-like and code-injecting names rejected
```

Project policies may only add restrictions and may not configure `execution`.

## 7. Approval integration

For a `REQUIRE_APPROVAL` operation without a grant, the executor creates a Phase 5 approval
request. Its summary shows the exact command plus the repository line: repository, branch,
HEAD, staged change count and tree, push source → remote, destination, URL, commit count,
FORCED, and the hooks that will run. The requester receives the claim token.

- In an interactive terminal, `ai-defender run` waits and tells you to run
  `ai-defender approve <id>` in another terminal. Approval is never inline, so a passphrase prompt
  never appears in a terminal an agent may be driving. Ctrl-C cancels the request.
- Without a terminal, `run` prints the approval ID and claim token and exits 6. Rerun it with
  `AGENTGUARD_CLAIM_TOKEN=<token> ai-defender run --approval <id> -- <same command>`.

Redemption re-evaluates identity and policy (a now-denied operation stays denied), recomputes
the digest, and consumes the grant atomically. A consumed grant is never reused (replay
detected and audited). Changed arguments or state never match.

## 8. Identity

The request never names an agent, a project or a digest; such fields are rejected.

- **Agent identity** comes from how the engine was launched. `--agent <kind>` is set by agent
  integrations from protected hook settings. A command-line caller without it is evaluated as
  the **generic agent**, because AI Defender cannot tell a human at a terminal from an agent typing
  into one. A grant is bound to the identity it was requested under, so a grant obtained under
  one identity cannot be redeemed under another.
- **Project identity** comes from the trusted registry and the resolved working directory. A
  symlinked directory resolves to its target before lookup.

## 9. Environment isolation

Nothing is inherited by default (`env_clear`). Profiles:

| Profile | Passed from the caller |
|---|---|
| `minimal` | `HOME`, `USER`, `LOGNAME`, `LANG`, `LANGUAGE`, `TZ`, `TMPDIR`, `LC_*` |
| `development` (default) | minimal plus toolchain homes (`CARGO_HOME`, `RUSTUP_HOME`, `GOPATH`, `JAVA_HOME`, `NVM_DIR`, `PNPM_HOME`, `VIRTUAL_ENV`, …), XDG directories, certificate bundles, proxies, `CI`, `NO_COLOR`, `RUST_BACKTRACE`, `NODE_ENV`, the agent sockets `SSH_AUTH_SOCK`/`GPG_AGENT_INFO`, and names the global policy adds |

Never passed, whatever a profile or policy says (`agentguard_core::envvars`):

- Names that look like credentials: `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`, `*_KEY`,
  `*AUTH*`, `*SESSION*`, `*CREDENTIAL*`, `*PRIVATE*`, `*DSN*`, ….
- Names that inject code or redirect tools: `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `BASH_FUNC_*`,
  `NODE_OPTIONS`, `PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `GIT_*`, `EDITOR`,
  `PAGER`, `RUSTC_WRAPPER`, ….

`PATH` is rebuilt from trusted directories only. Those are the caller's `PATH` entries that are
absolute, outside the project, owned by root or the user, and not writable by group or others,
followed by the system directories. A `git` planted in `node_modules/.bin`, `./bin` or `.` is
never found (tested). AI Defender sets `TERM=dumb`, `PAGER=cat`, `GIT_TERMINAL_PROMPT=0`,
`GIT_EDITOR=true` and `GIT_SEQUENCE_EDITOR=true`. Standard input is `/dev/null`. Nothing can
wait for a password, an editor or a pager.

Records and audit events list the names passed and the count withheld, never values. Captured
output is redacted in three ways:

- Values of withheld credential-like variables are masked.
- Detector matches are masked.
- Sensitive assignments, bearer tokens and URL credentials are masked.

Control characters are replaced, and the CLI sanitises again before printing.

### Process safety

- Absolute program path, argument vector, `arg0` as requested; no string concatenation.
- Working directory resolved, canonical and inside the registered project.
- Output read concurrently through `poll`. Up to 128 KiB per stream is kept in memory and
  returned, and 16 KiB is kept in the record. The rest is counted and discarded, so a noisy
  process neither exhausts memory nor blocks.
- Time limit: 600 s by default, at most 3600. The process group gets `SIGTERM`, then `SIGKILL`
  after 2 s. Processes left in the group after the main process exits are killed.
- The engine binary disables core dumps (`RLIMIT_CORE=0`). On Linux it also sets `no_new_privs`,
  which descendants inherit, so a set-user-ID program cannot raise privileges.
- An interrupted engine (`SIGINT`, `SIGTERM`, `SIGHUP`, received via `signalfd` on Linux)
  terminates the process group and records the run as interrupted. The run is then reported
  as indeterminate.
- **No retries.** Each request carries an idempotency key, reserved with `O_EXCL` before
  anything runs. A retry with the same key is refused (`execution-duplicate`), whatever happened
  the first time.
- **Fail closed.** If the `started` record or audit event cannot be written, nothing runs. If
  the outcome cannot be recorded afterwards, the result is `outcome-unrecorded` (exit 125),
  never success. A run left in `started` past its time limit is shown as `indeterminate`.

### Platform behaviour

| | Linux | macOS | Windows |
|---|---|---|---|
| Managed execution | supported, tested | builds; same code paths except below; not tested in this phase | not supported (Unix process model) |
| Process group isolation and group kill | yes | no: the process shares the engine's group; time-outs signal the main process only | — |
| Signal forwarding on interruption | `signalfd` | not available (default signal behaviour) | — |
| `no_new_privs` | yes | no | — |
| `RLIMIT_CORE=0` | yes | yes | — |
| Trusted search path | system directories plus trusted `PATH` entries | adds `/opt/homebrew/bin` | — |

## 10. CLI

```text
ai-defender run [--shell sh|bash] [--timeout S] [--env-profile minimal|development]
               [--approval ID] [--no-wait] [--] COMMAND [ARGS...]
ai-defender git status | inspect
ai-defender execution history | inspect <execution-id>
```

Global options (`--json`, `--no-color`, `--non-interactive`) go before `run`. Everything after
`run` belongs to the command. When the command runs, AI Defender exits with its status (signals
as 128+n). Otherwise:

| Exit | Meaning |
|---|---|
| 6 | approval required (not run), approval not granted, or context changed |
| 8 | denied by policy |
| 9 | unsupported syntax, option or program |
| 124 | timed out and terminated |
| 125 | outcome unknown or not recorded |

With `--json`, `data.executed` and `data.outcome` are authoritative.

Engine commands: `execution.run`, `execution.history`, `execution.inspect`, `git.status`,
`git.inspect`. New error codes: `execution-duplicate`, `outcome-unrecorded`.

## 11. Enforcement coverage and known bypass paths

| Path | Covered? |
|---|---|
| `ai-defender run …` (human or agent) | yes: full pipeline |
| `execution.run` from an integration launched with `--agent` | yes |
| An agent's own terminal tool running `git push`, `rm -rf`, `curl \| sh` directly | with Phase 8 hooks installed: evaluated before it runs (Claude Code Bash, Codex Bash), but executed by the agent's tool, not this executor; without hooks: **no** |
| An agent's file tools writing files | no (Phase 8 hooks) |
| Git commands typed by a developer | no |
| Git hooks, editors and IDE integrations running Git | no |
| Commands started by an allowed command (an npm script running `git push`, a test spawning `curl`) | not separately evaluated; covered only by the parent's classification and the environment restrictions |
| Programs that read credentials from files the user can read | not prevented by environment filtering |
| An executable replaced between the final identity check and `exec` | not prevented (narrow window; L87) |

Known bypass paths, tested where they apply:

- **Direct execution.** The agent simply does not use `ai-defender run`. Nothing in this phase
  prevents it, and `status` says so. With hooks (Phase 8), the agent's terminal tool calls are
  evaluated, and the guard already denies agent commands that run the engine, `approve` or
  similar.
- **Indirection inside an allowed command.** Package scripts (`npm test` running arbitrary
  `package.json` scripts), Makefiles, test suites and build tools run code the classifier never
  sees. `npm test` is allowed by default because it is ordinary development; its scripts are
  project content.
- **Repository hooks.** An approved `git commit` or `git push` runs the repository's hooks.
  They are listed in the approval summary, and commit verification detects staged-content
  changes, but hooks can do anything else the user can.
- **Unclassifiable syntax.** It is refused in shell mode. In typed terminal requests it lowers
  confidence, which leads to approval.

Why hooks are still required: managed execution guarantees properties *for the commands that
reach it*. Only an integration that sits in the agent's tool-call path can make the agent's
commands reach it. Phase 8 will route agent terminal and Git tool calls to `execution.run` (or
evaluate and deny them), using the same pipeline, digest and records.

## 12. Audit

Each kind below is recorded with:

- `execution_id`, request ID, project, agent and policy version;
- the decision, operation digest, approval and grant IDs, and a reason code;
- the redacted command summary.

Kinds:

| Kind | When |
|---|---|
| `execution-request-received` | the request arrives |
| `command-classified` | mode, category, class, confidence and program |
| `git-context-inspected` | number of bound facts |
| `pre-execution-scan-completed` | lines scanned, detections, incomplete |
| `execution-policy-decision` | the decision |
| `approval-request-created`, `authorization-consumed`, `authorization-replay-detected`, … | Phase 5 approval events |
| `execution-started` | written before spawning; a failed write means nothing runs |
| `execution-completed`, `execution-failed`, `execution-timed-out`, `execution-indeterminate` | the outcome |
| `unsupported-operation-detected` | refused syntax, options or programs |
| `execution-context-changed` | state changed after authorization |
| `execution-verification-failed` | the result differs from what was approved |

Raw credentials, environment values and unredacted output are never recorded.

## 13. Examples

```text
$ ai-defender run cargo test                       # ALLOW: runs, exits with cargo's status
$ ai-defender run git push origin feature-a        # waits for `ai-defender approve <id>`, then pushes exactly that
$ ai-defender run git push --force origin main     # exit 8: profile:git-force-push
$ ai-defender run --shell sh 'cargo fmt && cargo test'
$ ai-defender run --shell sh 'echo $(cat ~/.ssh/id_rsa)'   # exit 9: unsupported shell syntax
$ ai-defender run sudo apt install x               # exit 9: privilege escalation is never managed
$ ai-defender --json run git status                # structured result, redacted output
$ ai-defender git inspect                          # identity, branch, HEAD, remotes without credentials
$ ai-defender execution history
```
