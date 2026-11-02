# Git Security and Credential Broker Design

## 1. Goals

- The agent can complete a normal Git workflow (status, diff, log, branch, add, commit, fetch, push to a feature branch) without friction.
- The agent never holds a remote credential and never touches the developer's `.git`.
- Every remote write is validated, approved where required, executed exactly as approved, audited, and its temporary credential revoked.
- Provider-side protections are used as an independent second layer.

## 2. Repository topology

```
Host (Zone 1)                                        Container (Zone 2)
──────────────────────────────────────               ─────────────────────────────────
~/code/app/.git          (developer's repo)          /workspace            (staging clone working tree)
   objects/  ───── bind mount, read-only ─────────▶  /workspace/.git/objects/info/alternates → /ag/alternates
~/.local/state/agentguard/sessions/<sid>/
   quarantine.git        (bare, controller-owned)    /workspace/.git       (private objects, refs, index, config)
   staging/              (the clone's working tree,  ─ bind mount, rw ──▶ /workspace
                          lives on host disk)
```

- The staging clone is created by the controller with `git clone --no-hardlinks --reference-if-able <dev repo> --dissociate=false` style alternates so large repos are cheap, then its config is rewritten to a minimal, controller-authored config. `.git/hooks` is emptied. The clone's `origin` is set to `ai-defender::origin` (the remote helper), with the real URL recorded host-side only.
- **Default is `git.staging: full_copy`**: the staging clone has its own complete object store and nothing of the developer's `.git` is mounted. `git.staging: alternates` is an opt-in that mounts the developer's `.git/objects` read-only for very large repositories; it exposes **every object in the store, including unreachable objects** left by amended commits, dropped stashes and deleted branches, which is where accidentally committed secrets live. The policy schema states this on the option (Phase 0 review G5, C13).
- The staging clone's working tree lives on the host disk under controller state (needed so the controller can run its own git against it); the container sees it at `/workspace`. The container **never** sees the developer's working tree or `.git` directory beyond the read-only objects.

Why not mount the real repository (ADR-0004): writable `.git` lets the agent plant hooks and config (`core.fsmonitor`, `core.sshCommand`, `credential.helper`, `core.hooksPath`) that execute on the host the next time the developer runs any git command. Read-only `.git` still leaks reflog, stashes, and breaks `git add`. A separate clone removes the whole class.

## 3. Inside the container: what git does

| Command | Behaviour |
|---|---|
| `git status / diff / log / branch / blame / show` | local, unrestricted |
| `git add / commit / stash / checkout / rebase (local)` | local, unrestricted; commits land in staging clone only |
| `git fetch origin` | remote helper → controller → broker fetch from real remote (read credential) → objects returned over the helper stream |
| `git push origin <branch>` | remote helper → controller → Git Guard pipeline (section 5) |
| `git push --force`, `--mirror`, tags, `refs/notes`, deleting refs | remote helper sends it; Git Guard denies unless policy allows and approval granted; force never approvable at project level |
| `git remote set-url origin https://...` | config change inside the clone; the real URL is host-side; a direct URL has no route (network none), so the push fails. The egress proxy's denial of the Git host is the audit signal. |
| `git config core.hooksPath / credential.helper` | affects only the staging clone inside the container; the host never honours its config |

The remote helper `git-remote-agentguard` implements the `gitremote-helpers(7)` capabilities `fetch`, `push`, `option`, using `connect`-less transport: it speaks the controller IPC and streams packfiles. It is part of `agentguard-shim`.

## 4. Commit flow (sync into the developer's repository)

The agent's `git commit` is instant and local. The commit reaches the developer's repository through **sync**, triggered by the agent (`agentguard-shim sync`, which the adapters expose as the natural post-commit step), by the developer (`ai-defender sync`), or automatically before a push request.

1. Controller transfers objects **from** the staging object directory **into** `quarantine.git` using gix (pure Rust reading of loose and packed objects). The controller **never spawns `git` with the staging clone as its repository**: the staging `.git` is treated as opaque hostile bytes, a `.git` that is a symlink or a `gitdir:` file is rejected outright, and `objects/info/alternates` inside it is ignored (Phase 0 review G9, G16). Any controller git invocation on the quarantine or developer repository runs with:
   `GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 -c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.file.allow=always -c fetch.fsckObjects=true -c transfer.fsckObjects=true -c receive.fsckObjects=true`
   into `refs/quarantine/<task>/<branch>`.
2. Validation on the quarantine ref (pure object inspection, no checkout):
   - every path canonical, no `..`, no NUL, no path that becomes `.git` under case-folding or Unicode normalisation on the host filesystem;
   - no submodule additions (`.gitmodules` changes require approval; new gitlinks denied by default);
   - symlinks allowed only if policy permits and flagged in prompt; absolute or escaping symlink targets flagged high risk;
   - protected files diffed and listed;
   - secret scan on the added lines (gitleaks over a temporary extraction, run inside a disposable AI Defender container with a controller-owned configuration; in-tree `.gitleaks.toml`/`.gitleaksignore` ignored; native fallback when unavailable) (G8);
   - host-executed-content classification of every touched path (SECURITY_MODEL M11) (G2);
   - author/committer **validated, never rewritten** (rewriting would change the SHA the approval and push bind to). The controller-authored staging-clone configuration sets `user.name`, `user.email` and `trailer` entries so commits carry the developer's identity plus `Agent:` and `AI Defender-Task:` trailers at commit time; a mismatch is flagged high risk in the prompt (G10).
3. `GitCommitRequest` is raised. Approval shows the facts from step 2.
4. On approval: the commit is placed at `refs/agentguard/<task>/<branch>` in the developer's repository. A **checked-out branch is never updated directly** (that would make `git status` show the work as un-done and `git commit -a` revert it). `ai-defender sync --apply` fast-forwards the developer's branch through the developer's own git with a working-tree update when the tree is clean, and explains what to do otherwise (C15).
5. Audit records the quarantine ref, final ref, approval id.

Uncommitted staging-clone changes are never synced; the agent must commit (which it can do freely). This keeps sync object-based and removes file-copy attack surface entirely.

## 5. Push flow

1. Agent: `git push origin feature/AH-5064`.
2. Remote helper sends `PushRequest { remote, refspecs, objects available }`.
3. Git Guard:
   1. Resolves `origin` to the host-side canonical `RepositoryId`; mismatch → deny + violation.
   2. Parses each refspec into `(src: BranchName, dst: BranchName, force: bool)`. Any `+`, `--force`, `--mirror`, `:refs/tags/*`, `:refs/notes/*`, deletions → deny unless policy allows that class and approval is granted; force is a hard-deny by default.
   3. Checks `dst` against `task.git.push_branches` and `policy.git.protected_branches`. Protected → deny unless org policy allows approval for it.
   4. Ensures all commits are already synced and approved (section 4). Unsynced commits trigger the commit flow first.
   5. Fetches the remote tip of `dst` via the broker (read credential) to compute the exact range and `creates_branch`.
   6. Queries provider API for branch protection when a token with read scope exists; otherwise relies on policy and marks "provider check unavailable".
   7. Secret scan on the commit range; Trivy on lockfile deltas.
   8. Raises `GitPushRequest` with typed confirmations (repository, destination branch, `push`).
4. On approval the broker executes, host-side, from `quarantine.git`:
   `git push <real-url> <approved-sha>:refs/heads/<dst> --force-with-lease=refs/heads/<dst>:<expected-old-sha>` with the credential injected via a one-shot `credential.helper` that reads from the broker's memory (never from a file) and an environment constructed from scratch.
5. The broker verifies the remote ref now equals the approved SHA, records the outcome, revokes the temporary credential if it minted one, and returns success to the remote helper, which reports `ok refs/heads/<dst>` to the agent's git.

Concurrency: the compare-and-swap lease guarantees the pushed range is exactly what was approved even if someone else pushed in between (then the push fails and a new request is needed).

## 6. Credentials

| Provider | Preferred credential | Scope | Lifetime | Fallback |
|---|---|---|---|---|
| GitHub | GitHub App installation token minted by the broker (app private key held by the developer/organisation on the host, outside any container) | single repository, `contents:write` | 1 h, revoked after use | fine-grained PAT held in OS keyring, never exported |
| GitLab | Project access token or job-token style short-lived token via API where the organisation permits | single project, `write_repository` | shortest configurable | PAT in keyring |
| Bitbucket | Repository access token | single repository | per provider | app password in keyring |
| Generic SSH remote | Broker uses the developer's SSH agent **on the host** via `SSH_AUTH_SOCK` for the one push command; the socket is never mounted into the container | whatever the key allows (documented as broad) | per command | none |

Storage: the broker reads long-lived secrets from the OS keyring (Secret Service on Linux via the `keyring` crate) or an environment variable the developer passes to `ai-defender`, keeps them only in locked memory (`memsec`/`zeroize`), and never writes them to disk or logs.

Provider-side enforcement the design relies on and `ai-defender doctor` checks where it can: branch protection on `main`/release branches, required reviews, token scope limited to the repository.

## 7. Default command policy

| Operation | Default |
|---|---|
| status, diff, log, branch, blame, show, add, commit (local), stash, local rebase | allowed |
| fetch | allowed (read credential via broker) |
| commit entering developer's repo | approval |
| push to feature branch matching task scope | approval |
| push to protected branch | deny (org may allow `approval`) |
| force push, `--mirror`, ref deletion, tag push | deny (org may allow approval for tags) |
| merge into protected branch | approval via provider merge request, never a local push |
| submodule add / `.gitmodules` change | approval, high risk |
| LFS | fetch allowed if host allowlisted; push follows push rules |

## 8. Failure handling

- Controller unreachable from the helper → git reports `error: remote helper unavailable`; nothing happens.
- Approval expires while waiting → helper reports `remote rejected: approval expired`.
- Remote tip moved → `rejected (stale info)`, new request required.
- Scanner unavailable → approval prompt shows "secret scan UNAVAILABLE" in red; high-risk pushes blocked; others require typed acknowledgement `scan unavailable`.
