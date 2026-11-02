# Typed Approval Architecture and Task-Scoped Authorisation

> Design history (containment track). The implemented approval lifecycle (engine track, Phase 5) is described in [APPROVALS.md](APPROVALS.md); where the two differ, APPROVALS.md describes the code. Notably: defaults are now 5 minutes pending and 2 minutes grant validity, approval is authenticated by the policy-signing key, and only single-operation scope exists.

## 1. Principles

1. There is no generic "allow this?" prompt. Every sensitive operation has its own request type, its own display, and its own validation.
2. The facts shown to the developer are computed by the controller (diff stats, resolved IPs, scan results, protection status). Text supplied by the agent (its stated reason) is shown in a labelled, bounded box and never used for a decision.
3. An approval authorises exactly one canonical operation. Change any byte of the operation and the approval is void.
4. Approvals are consumed once, expire quickly, and are bound to session, task and policy version.
5. The prompt is rendered by a process the agent cannot write to.

## 2. Core types (Rust sketch, final definitions in Phase 6)

```rust
// Newtypes: no bare strings cross the boundary.
pub struct RequestId(Uuid);          // v4 from OS CSPRNG
pub struct SessionId(Uuid);
pub struct TaskId(String);           // validated: ^[A-Z][A-Z0-9]+-[0-9]+$ or opaque slug, max 64
pub struct AgentId(AgentKind, Version);
pub struct RepositoryId { provider: GitProvider, owner: Owner, name: RepoName, canonical_url: Url }
pub struct BranchName(String);       // validated with git check-ref-format rules, no refspec syntax
pub struct CommitSha(/* 20 or 32 bytes */);
pub struct WorkspacePath(PathBuf);   // canonical, relative to workspace root, no `..`, no NUL
pub struct PolicyVersion([u8; 32]);
pub struct Timestamp(DateTime<Utc>);

pub enum RiskLevel { Low, Medium, High, Critical }

pub enum ApprovalScope { SingleOperation, CurrentTask, CurrentSession }
// CurrentTask / CurrentSession are valid only for NetworkAccess and FilesystemAccess.
// Git commit, push, merge, dependency install, database mutation, deployment, host exec,
// policy modification and task scope change are always SingleOperation (Phase 0 review C6).
// Enforced by `agentguard_core::ApprovalScope::check_permitted`.

pub struct ApprovalRequest {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub repository_id: RepositoryId,
    pub policy_version: PolicyVersion,
    pub operation: ApprovalOperation,   // the typed payload
    pub scope: ApprovalScope,
    pub risk_level: RiskLevel,
    pub agent_reason: BoundedText<512>, // displayed as untrusted
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub operation_hash: [u8; 32],       // sha256(canonical CBOR of `operation` + ids + policy_version)
}

pub enum ApprovalOperation {
    GitCommit(GitCommitRequest),
    GitPush(GitPushRequest),
    GitMerge(GitMergeRequest),
    DependencyInstall(DependencyInstallRequest),
    DatabaseMutation(DatabaseMutationRequest),
    Deployment(DeploymentRequest),
    FilesystemAccess(FilesystemAccessRequest),
    NetworkAccess(NetworkAccessRequest),
    HostExec(HostExecRequest),
    PolicyModification(PolicyChangeRequest),   // privileged flow
    TaskScopeChange(TaskScopeChangeRequest),   // privileged flow
}

pub enum ApprovalDecision {
    Approved { token: ApprovalToken, decided_at: Timestamp, typed_confirmation: Option<TypedConfirmation> },
    Rejected { decided_at: Timestamp, reason: Option<BoundedText<256>> },
    Expired  { at: Timestamp },
    Cancelled{ at: Timestamp, by: CancelSource },  // revoke, session end, policy change
}

pub struct ApprovalToken {
    pub token_id: [u8; 32],        // 256-bit CSPRNG, opaque; stored hashed (sha256) server-side
    pub request_id: RequestId,
    pub operation_hash: [u8; 32],
    pub expires_at: Timestamp,
    pub consumed: AtomicOnce,      // one-time; consumption and execution are the same critical section
}
```

The token never leaves the controller process. The agent never sees it. The broker/gateway receives the token *reference* internally when it executes the operation. There is nothing for the agent to replay because nothing is handed to it.

Canonicalisation: operation payloads are serialised with deterministic CBOR (sorted keys, no floats) for hashing. Any re-ordering of files, refspecs or arguments produces the same hash only if the set is semantically identical; otherwise the approval does not match.

## 3. Per-operation request types and prompts

### 3.1 GitCommitRequest

```rust
pub struct GitCommitRequest {
    pub repository: RepositoryId,
    pub branch: BranchName,                  // branch in the staging clone
    pub parent: CommitSha,
    pub resulting_commit: CommitSha,         // commit already exists in staging clone
    pub tree: TreeSha,
    pub message: BoundedText<4096>,
    pub files: Vec<FileChange>,              // path, kind (A/M/D/R/T), additions, deletions, mode change
    pub protected_files_touched: Vec<WorkspacePath>,
    pub secret_scan: ScanResult,             // Clean | Findings(Vec<Finding>) | Unavailable
    pub security_scan: ScanResult,           // Trivy on lockfile deltas if present
    pub author: Signature,                   // validated against the developer's identity; mismatch is high risk (never rewritten)
}
```

Prompt shows: repo, branch, message, N files (expandable list), +/- summary, protected files in red, scan statuses. Options: Approve / Reject / Review diff (opens pager with the controller-generated diff). High risk (protected files touched, scan findings, > N files, deletions > threshold) requires typing the repository name.

What "commit approval" means mechanically: the agent's commit in the staging clone is fetched into quarantine, validated, and fast-forwarded onto the developer's branch (or placed on `refs/agentguard/<task>` if the developer's branch has diverged, with the developer told). The agent's `git commit` inside the container never blocks; only its appearance in the real repo does. See ADR-0004.

### 3.2 GitPushRequest

```rust
pub struct GitPushRequest {
    pub provider: GitProvider,
    pub repository: RepositoryId,
    pub remote: RemoteName,
    pub source_branch: BranchName,
    pub destination_branch: BranchName,
    pub force: bool,                          // always false unless org policy permits approval of force
    pub commits: Vec<CommitSha>,              // exact set, in order
    pub range: (Option<CommitSha>, CommitSha),// remote tip (expected old) .. new tip; compare-and-swap push
    pub diff_summary: DiffSummary,
    pub destination_protected: bool,          // from policy AND provider API when reachable
    pub secret_scan: ScanResult,
    pub lockfile_changes: Vec<LockfileDelta>,
    pub creates_branch: bool,
}
```

Typed inputs: repository name, destination branch name, and the word `push`. The push is executed with `--force-with-lease=<dest>:<expected old>` semantics (never plain force) so the approved range cannot be substituted by a concurrent change.

### 3.3 DependencyInstallRequest

```rust
pub struct DependencyInstallRequest {
    pub manager: PackageManager,              // npm | pnpm | yarn | pip | uv | cargo | go | maven | gradle | composer | gem | ...
    pub packages: Vec<PackageSpec>,           // name, exact version, registry URL, integrity hash when known
    pub lockfile_delta: LockfileDelta,        // added/removed/changed entries, parsed by manager-specific adapter
    pub lifecycle_scripts: Vec<LifecycleScript>, // from package metadata when obtainable
    pub vulnerability_findings: ScanResult,   // Trivy / OSV
    pub registry: RegistryId,
}
```

Approval covers the exact set and versions. Mechanically: installation already happened inside the container (it only needed the allowlisted registry); what the approval gates is the lockfile/manifest change entering the developer's repository through sync, and whether the registry should remain allowlisted for this task. If policy sets `dependencies.install: approval_before_fetch`, the egress proxy blocks registry access until approval and the request is raised from the proxy denial.

### 3.4 DatabaseMutationRequest

```rust
pub struct DatabaseMutationRequest {
    pub database: DatabaseId,                 // from policy, never from the agent
    pub environment: Environment,             // Development | Staging | Production(hard-denied)
    pub host: HostPort,
    pub operation: DbOperation,               // typed: Select | Insert | Update | Delete | Ddl(DdlKind) | Admin(..)
    pub statement_fingerprint: Fingerprint,   // normalised SQL/command, literals stripped
    pub tables: Vec<TableName>,
    pub estimated_rows: Option<u64>,          // from EXPLAIN when the guard can run it
    pub destructive: bool,
}
```

Destructive requires typing the database name. Production is a hard-deny and never produces a request.

### 3.5 DeploymentRequest

```rust
pub struct DeploymentRequest {
    pub application: AppId,
    pub environment: Environment,
    pub version: VersionTag,
    pub commit: CommitSha,
    pub target: DeploymentTarget,             // from policy table
    pub tool: DeployTool,                     // terraform | kubectl | helm | gcloud | aws | gh-workflow | gitlab-pipeline
    pub plan_summary: PlanSummary,            // e.g. terraform plan: add/change/destroy counts and resource list
    pub rollback: RollbackStrategy,
}
```

Always SingleOperation, always typed confirmation (environment name), never auto-approved by any mode.

### 3.6 FilesystemAccessRequest

```rust
pub struct FilesystemAccessRequest {
    pub path: WorkspacePath,                  // or HostPath for explicit, policy-listed extra directories
    pub operation: FsOp,                      // Read | Write | Delete | Rename
    pub affected_files: u32,
    pub protected: bool,
    pub duration: ApprovalScope,
}
```

Used in RESTRICTED mode and for policy-listed extra directories (for example a sibling shared library) that can be bind-mounted read-only at session start upon approval. Never used to grant host paths outside the policy's enumerated list.

### 3.7 NetworkAccessRequest

```rust
pub struct NetworkAccessRequest {
    pub host: HostPattern,                    // exact host; wildcards only from policy, not from the agent
    pub resolved: Vec<IpAddr>,
    pub port: u16,
    pub protocol: NetProto,                   // Https | Http
    pub duration: ApprovalScope,              // SingleOperation = one connection; CurrentTask = allowlist for task
}
```

Raised by the egress proxy when a denied host is requested and the policy marks network as `approvable`. Private ranges and metadata are never approvable.

### 3.8 PolicyChangeRequest (privileged)

```rust
pub struct PolicyChangeRequest {
    pub current: PolicyVersion,
    pub proposed_document: PolicyDocument,    // validated
    pub proposed_version: PolicyVersion,
    pub rule_diff: Vec<RuleDiff>,             // added / removed / tightened / loosened with security impact label
    pub loosening: bool,
    pub affected_projects: Vec<RepositoryId>,
}
```

Rendered only by `ai-defender policy approve`, a separate CLI entry point, never inside a running agent session's approval stream. Requires typing `modify policy` and the repository name. Takes effect for *new* sessions only. If organisation policy marks a rule as hard-deny, a loosening diff is rejected before the prompt is shown.

### 3.9 TaskScopeChangeRequest (privileged)

Same treatment as policy change but scoped to one task. The agent can *request* ("I need to also push to feature/AH-5064-docs"); the developer sees the typed delta; nothing is inferred from prose.

## 4. Approval UI

- A host-side process, `ai-defender approvals --watch` (TUI), connected to the controller's approval socket. Phase 6 ships this as a second-terminal tool; a TTY overlay inside `ai-defender run` is a later usability improvement, implemented in the host process that owns the PTY, never inside the container.
- At session start the UI shows a **session phrase** (three random words). Every approval prompt shows it. Anything the agent prints in its own TTY cannot contain it because the agent never receives it.
- Agent-supplied text is shown in a box titled "Agent's stated reason (untrusted)", ANSI-stripped, length-limited, no markdown rendering.
- Every string that originated from the agent, including branch names, paths and commit messages shown as "facts", passes through the shared sanitiser: bidirectional overrides and zero-width code points are escaped and non-ASCII identifiers carry a warning glyph (G12).
- Controller-computed facts are shown above the box and are the basis for the decision.
- Typed confirmations are compared exactly (case-sensitive) and never pre-filled.
- Desktop notification (`notify-send`) is optional and contains only the request kind and risk level, never details.

## 5. Lifecycle and state machine

```
Pending ──(developer approves)──▶ Approved ──(consumed by execution)──▶ Consumed
   │                                  │
   ├──(developer rejects)──▶ Rejected  ├──(expires_at passes)──▶ Expired
   ├──(ttl passes)──▶ Expired          └──(revoke / session end / policy change)──▶ Cancelled
   └──(revoke / session end)──▶ Cancelled
```

- Consumption is atomic with execution start: the executing component takes the token under a mutex, checks `consumed == false`, `now < expires_at`, `operation_hash == hash(what I am about to do)`, `session/task/policy_version` match, then marks consumed and proceeds. Failure of the operation does not un-consume; a retry is a new request.
- Two limits (Phase 0 review C5), both in `agentguard_core::ApprovalTiming`: `pending_timeout` (how long a prompt waits for the developer; default 300 s since Phase 5, maximum 900 s) and `token_validity` (how long an approved grant may wait for consumption; default 120 s since Phase 5, maximum 300 s). Policy may lower either, never raise above the organisation maximum.
- All transitions are audited.

## 6. Task-scoped authorisation

### 6.1 TaskContext

```rust
pub struct TaskContext {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub repository: RepositoryId,
    pub agent: AgentId,
    pub policy_version: PolicyVersion,
    pub description: BoundedText<2048>,        // developer-entered, informational
    pub workspace: WorkspaceScope,             // whole repo or path subset (RESTRICTED)
    pub file_ops: FileOpSet,                   // read / write / delete allowed
    pub commands: CommandAllowlist,            // advisory tier plus host exec table
    pub git: GitTaskPermissions {
        commit: Gate,                          // Deny | Approval | Granted(scope)
        push_branches: Vec<BranchPattern>,     // destination allowlist, e.g. feature/AH-5064
        merge: Gate,
    },
    pub network_extra: Vec<HostPattern>,       // task-level additions, within project allowlist
    pub dependencies: Gate,
    pub databases: Vec<DatabaseId>,
    pub deployment: Gate,                      // Deny unless developer explicitly enables
    pub expires_at: Timestamp,                 // default 8 h, max 24 h
    pub granted_approvals: Vec<RequestId>,     // CurrentTask-scoped grants
    pub revoked: bool,
}
```

### 6.2 Flow

1. Developer runs `ai-defender run claude --task AH-5064 "Implement AH-5064, run tests, commit and push to feature/AH-5064"`.
2. The controller derives a *proposal* from the policy defaults and the explicit branch named by the developer. The agent may later propose amendments through `TaskScopeChangeRequest`; proposals from the agent are shown as diffs and never applied automatically.
3. The developer confirms the task scope in the trusted UI before the agent starts. This is the only place task permissions are granted.
4. Every gateway decision is evaluated as `policy ∩ task ∩ approval`.
5. `ai-defender revoke --task AH-5064` (or `--session`) cancels all pending and granted approvals, marks the task revoked, and terminates the session. Revocation also invalidates any temporary provider credential the broker minted.

### 6.3 What task scope cannot do

- Exceed project policy or organisation policy.
- Grant protected-branch push, force push, production DB, or cloud admin access.
- Outlive its expiry.
- Be modified by the agent.

## 7. Non-interactive sessions

`ai-defender run --non-interactive` (for CI-like use) cannot answer approvals. In this mode every `RequiresApproval` becomes `Deny` unless the task context was pre-authorised by the developer with explicit `CurrentTask` grants created interactively beforehand (`ai-defender task grant ...`). There is no flag that auto-approves.
