# Policy and Permission Evaluation

Implemented in Phase 3 (`crates/agentguard-engine`: `evaluate`, `normalize`, `resource`, `classify`, `rules`, `pattern`, `profile`, `layered`). The engine consumes normalised requests in the canonical protocol ([PROTOCOL.md](PROTOCOL.md)), never provider-specific hook payloads, and it never executes the operation it evaluates.

## 1. Evaluation pipeline

```
request bytes
 └ parse + validate                     agentguard-proto (strict schema, size, paths resolved)
   └ EvaluationContext::establish       agent vs trusted invocation; project from trusted registry
     └ evaluate(request, context, policy)
        ├ request ⇄ context consistency agent, working directory, project, session must match
        ├ policy integrity              Failed → error (deny); Verified / Unattested → continue
        ├ normalise → SecurityAction    operation, executable, capabilities, resource, confidence
        ├ risk assessment               level, factors, confidence, reversibility, scope
        ├ policy version                stale → DENY policy.version-mismatch
        ├ guards                        unknown operation, trusted state, self-approval → DENY
        ├ policy                        global → profile → default, then mandatory/project floors
        └ critical floor                CRITICAL + ALLOW → REQUIRE_APPROVAL
   └ Authorizer: audit steps, bind approval, audit decision → response
```

- **Result.** `evaluate` returns `Result<Evaluation, EvaluationError>`. An `Evaluation` carries:
  - the normalised action and resource classification;
  - the risk assessment;
  - the decision, the deciding rule and its reason;
  - the deciding layer;
  - every matching rule with its effect;
  - every conflict and how it was resolved;
  - the policy version.
- **Errors.** Every `EvaluationError` (identity, context mismatch, policy integrity, policy failure) becomes `DENY` in the `Authorizer`.
- **What `evaluate` touches.** It performs no writes and spawns nothing. Its only contact with the outside world is read-only path resolution, used to see through symlinks.

## 2. Decision model

| Decision | Meaning |
|---|---|
| `ALLOW` | may proceed now |
| `REQUIRE_APPROVAL` | may proceed after a human approval bound to this exact operation (Phase 1 binding) |
| `DENY` | may not proceed |

Every decision cites a rule (`profile:dev-tools`, `mandatory:git-push`, `global:…`, `project:…`, `baseline.*`, `guard.*`, `identity.*`, `trust.lockdown`, …), a reason, the layer that decided, and the policy version.

## 3. Rule schema

```yaml
- id: allow-make-docs          # unique within its layer; namespaced on load (global:, project:)
  decision: ALLOW              # ALLOW | REQUIRE_APPROVAL | DENY
  reason: building docs is routine
  priority: 10                 # optional, default 0; see §4
  match:                       # every stated field must hold; absent fields match anything
    category: terminal         # filesystem terminal git github secrets database terraform
                               # network external-transfer custom-tool package-manager cloud
                               # configuration unknown
    operation: "push"          # exact or glob, e.g. "create-*"
    resource: "src/**"         # glob on the resource: project-relative path inside the
                               # project, absolute path outside it, target name otherwise
    resource_kind: source-code # see §7
    executable: "make"         # glob on the executable / tool
    path_prefix: /abs/path     # every path lies beneath this absolute path
    inside_project: true
    host: api.example.com      # network / transfer destination, exact
    min_risk: medium
    max_risk: high
    agent: claude              # verified agent kind
    project: <64-hex id>       # verified project
    conditions:                # typed; all must hold; at most 8
      - command-class: dev-tool        # see §6
      - capability: network            # read write delete execute network remote-write
                                       # credential privileged infrastructure
      - environment: production        # database / terraform / cloud targets
      - force: true                    # git: typed force, or a terminal git command that forces (Phase 7)
      - global: true                   # package manager
      - min-confidence: medium         # low < medium < high
      - ordinary-resource: true        # source code in the project, or no local resource
      - location: outside-project      # not-applicable inside-project outside-project
                                       # trusted-state remote
      - reversible: false
      # Phase 6 (docs/SECRETS.md):
      - sensitive-resource: true       # .env, keys, credentials, protected patterns, secret stores
      - sensitive: environment-config  # environment-config private-key-material cloud-credential
                                       # infrastructure-state application-credential secret-store
                                       # source-with-secrets configured-protected
      - secrets-detected: high         # detected secrets at or above: low medium high critical
      - secret-data: true              # sensitive resource, or detected secret >= high
      - destination: ai-service        # none local-project-file local-file agent-context
                                       # git-history git-remote package-registry ai-service
                                       # external-api external-network unknown
      - external-destination: true     # remote, registry, API, network or unknown
      - into-ordinary-file: true       # secret data written or copied into an ordinary file
```

Constraints:
- **Unknown fields** are rejected.
- **Patterns** are bounded globs only: `*`, `**`, `?`, at most 256 bytes, no `..` segments. There are no regular expressions, scripts or executable conditions.
- **Bounded ALLOW.** An `ALLOW` must constrain *what* it matches (category, operation, path prefix, host, resource, resource kind or executable). Risk, agent, project or conditions alone are not enough.
- **Case handling.** Restrictive rules (`DENY`, `REQUIRE_APPROVAL`) match paths, resources and executables case-insensitively; `ALLOW` rules match case-sensitively. A case variation can widen a restriction, never an allowance.
- **Paths.** Path rules see the *resolved* path (symlinks followed, `..` removed), not the string the agent sent.
- **Adding fields keeps signatures.** New fields are omitted from the canonical form when empty, so policies signed in Phase 2 keep their signatures.

## 4. Precedence and conflict resolution

```
1. mandatory baseline        floors, built in                          (can only raise)
2. global policy             trusted organisation/user layer           (decides first)
3. project policy            floors, restrictions only                 (can only raise)
4. profile action rules      e.g. balanced                             (if 2 had no match)
5. default behaviour         read-only+low → ALLOW; critical → DENY;   (if 2 and 4 had no match)
                             uncertain → profile.uncertain; else REQUIRE_APPROVAL
```

`final = max(authorised verdict, mandatory floor, project floor)` with `DENY > REQUIRE_APPROVAL > ALLOW`. Guards (layer 0) run before all of this and cannot be overridden; the engine's critical floor runs after.

**Within one layer** (global or profile):
1. A matching `DENY` wins, whatever the priorities.
2. Otherwise only the matching rules with the highest `priority` take part, and the more restrictive of them wins.
3. Ties cite the smallest rule ID.

Priority therefore lets a specific `ALLOW` carve an exception out of a broader `REQUIRE_APPROVAL` in the same layer. It never outranks a `DENY`, never crosses layers, and never lowers a floor.

**Floors** (mandatory and project) ignore priority: the most restrictive matching floor rule applies. A floor that is *equal* to a decision produced by the default behaviour is cited in its place, because it is the more specific explanation.

**Conflicts** are reported in the evaluation and audited as `PolicyConflictDetected`:

| Kind | When |
|---|---|
| `same-layer` | rules in one layer disagreed |
| `priority-override` | a higher-priority rule outranked a more restrictive one |
| `floor-raised` | a floor raised the authorised decision |

Rule order never changes a result, and the policy version is a hash of the canonical, ID-sorted layers.

## 5. The balanced profile

Selected by default. The global policy can configure it:

```yaml
profile:
  name: balanced
  dependency_changes: REQUIRE_APPROVAL   # or ALLOW / DENY
  git_commit: REQUIRE_APPROVAL
  git_branching: REQUIRE_APPROVAL        # branch, checkout, switch, merge, rebase, reset, stash, tag, clean
  git_remote: REQUIRE_APPROVAL           # push, pull, fetch, clone (push stays gated by the baseline)
  database_migrations: REQUIRE_APPROVAL  # migrate, bulk-load
  uncertain: REQUIRE_APPROVAL            # or DENY; ALLOW is rejected
  secret_files: DENY                     # private keys, credential files; ALLOW is rejected
  sensitive_read: DENY                   # Phase 6: read .env, keys, credentials, protected paths; ALLOW rejected
  sensitive_write: REQUIRE_APPROVAL      # modify them; ALLOW rejected
  sensitive_delete: DENY                 # delete them; ALLOW rejected
  source_with_secrets: REQUIRE_APPROVAL  # read an ordinary file containing a detected credential
  git_force_push: DENY                   # Phase 7: push --force/--force-with-lease/+refspec/--delete; ALLOW rejected,
                                         # REQUIRE_APPROVAL is the most it can grant (mandatory floor)
  protected_destruction: DENY            # Phase 7: rm/chmod and similar outside the project, on .git, sensitive
                                         # or security files; ALLOW rejected
```

Version tags: mandatory baseline `agentguard.mandatory-baseline.v4`, balanced profile
`agentguard.profile.balanced.v3` (Phase 7). Settings at their defaults are omitted from the
canonical form, so existing signed policies keep their signatures; the version tags change the
policy version, which voids approvals made under the previous one.

| Default | Examples |
|---|---|
| **ALLOW** | read, list, edit and rename ordinary project files; `cargo test/build/check/clippy/fmt/run`, `npm test`, `npm run lint/build/dev/start/...`, `pytest`, `go test`, `make test`, `prettier`, `eslint`, `ruff`, `tsc`, …; `ls`, `cat`, `grep`, `find` (without `-exec`/`-delete`); `git status/diff/log/show/blame`, `git branch` (listing), `git add`; `mkdir`/`cp`/`mv` of ordinary project files; typed Git reads and `branch-list`. Compound commands are allowed only when every segment is allowed (`cargo fmt && cargo test`). |
| **REQUIRE_APPROVAL** | commits; creating, switching, merging, rebasing or resetting branches; push, pull, fetch, clone; installing, removing or updating dependencies (always for machine-wide installs); writes to security configuration (CI pipelines, scanner config); modifying `.env` and other sensitive files; reading a source file that contains a detected credential; database migrations and bulk loads; `terraform apply`; GitHub comments, issues and pull requests; network clients; `printenv` and secret tools; commands that cannot be classified with confidence; the `unknown` category |
| **DENY** | reading `.env`, private keys, credential files and protected paths, and deleting them (unless the global policy lowers this to approval); secret data sent to any external or unknown destination, committed, or written into an ordinary file (mandatory, Phase 6); AI Defender trusted state and agent hook settings (guard); agent-side `ai-defender` admin commands (guard); bypass flags such as `--dangerously-skip-permissions` or `AGENTGUARD_*` variables (mandatory); critical destructive commands such as `rm -rf /` or `curl … \| sh` (mandatory); GitHub repository deletion (mandatory); unknown operations inside typed categories (guard); critical risk without an explicit rule (default); invalid identity, context or policy integrity (engine) |

The mandatory baseline additionally requires approval for:
- secrets, external transfers, package publishing;
- GitHub merges, releases, workflows and settings;
- database writes, schema changes, drops and administration;
- Terraform apply, destroy, import and state changes;
- cloud create, modify, delete and IAM changes;
- private keys, credential files and `.env` files (Phase 6);
- filesystem changes outside the project;

requires approval for every force push or remote ref deletion, typed or terminal
(`mandatory:git-force-push`, Phase 7; the profile denies them by default, see
[EXECUTION.md](EXECUTION.md)), and denies (Phase 6): secret data to an external or unknown destination (`mandatory:secret-disclosure`), committing detected credentials (`mandatory:secret-commit`), and secret data written or copied into an ordinary file (`mandatory:secret-into-ordinary-file`). See [SECRETS.md](SECRETS.md).
- the terminal equivalents (remote VCS, infrastructure changes, publishing, secret access, privileged commands), so a shell cannot be used to sidestep a typed floor.

## 6. Risk classification

`classify::assess` is a fixed, deterministic function of the normalised action. It reports:
- **level** (`low` … `critical`), the highest any factor assigned;
- **factors**: unknown-operation, outside-project, sensitive-path, destructive, history-rewrite, remote-write, credential-access, production-target, infrastructure-change, arbitrary-execution, dangerous-command, private-network-target, data-egress, permission-change, security-configuration, privilege-escalation, supply-chain, irreversible, uncertain-classification, bypass-attempt;
- **confidence** (how sure the operation classification is);
- **reversibility**;
- **scope** (local, project, machine, remote).

Risk informs policy through `min_risk`/`max_risk`, the default behaviour and the critical floor. It never authorises on its own and never overrides a rule, a floor or a guard.

**Terminal commands** are tokenised without execution:
- quotes, escapes and operators are handled;
- the command is split at `;`, `&&`, `||`, `|`, `&` and newlines;
- each segment is classified from tables of executable and subcommand into one of: read-only, vcs-read, dev-tool, vcs-local, infra-read, file-write, unknown, vcs-write, package-change, vcs-remote, network, permission-change, interpreter, container, package-publish, infra-change, secret-access, privileged, destructive, bypass.

The most severe segment class wins.

Confidence drops (and is reported) for:
- command substitution, variable expansion and environment-variable prefixes (`PATH=… cmd`);
- `git -C`/`-c`;
- unknown programs, project scripts and interpreters;
- unterminated quotes, truncation and unresolvable or wildcard paths.

Low confidence never auto-allows: profile ALLOW rules require at least medium confidence, and the default treats uncertainty as `profile.uncertain`.

## 7. Resource classification

`resource::DefaultResourceClassifier` classifies **resolved** paths, matching file names case-insensitively:

| Kind | Examples |
|---|---|
| `source-code` | ordinary files inside the project |
| `security-configuration` | AI Defender trust/state roots, `.agent-security.yml`, `.agentguard/`, agent hook settings (location `trusted-state`); `.github/workflows/*`, `.gitlab-ci.yml`, `CODEOWNERS`, `.pre-commit-config.yaml`, scanner config |
| `environment-file` | `.env`, `.env.*`, `*.env` (not `.env.example`/`.sample`/`.template`/`.dist`) |
| `credential-file` | `credentials*`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass`, `secrets.*`, keystores, anything under `.aws`, `.kube`, `.docker`, `.azure`, `gcloud` |
| `private-key` | `id_rsa`/`id_ed25519`/…, `*.pem`, `*.key`, `*.ppk`, anything under `.ssh` or `.gnupg` except `*.pub`, `known_hosts`, `authorized_keys` |
| `database`, `infrastructure`, `git-repository` | `*.sqlite`/`*.db`; `*.tf`/`*.tfstate`/`*.tfvars`; anything under `.git/` (hooks are code execution); plus typed database, Terraform/cloud and Git targets |
| `external-service`, `secret-store` | network, GitHub, registries; the secrets category |
| `unknown` | outside-project ordinary files, custom tools, the unknown category |

How targets are combined and checked:
- **Combining several targets.** An action naming several targets (a rename, a command with several path arguments) takes the most sensitive kind and the most exposed location.
- **Terminal path arguments** are resolved through the same resolver as typed paths, so `cat src/link` where `link → ~/.ssh/id_rsa` is classified as a private key. `~/…` arguments are classified by name as outside the project. Unresolvable arguments are classified by name and marked uncertain.

## 8. Failure behaviour

| Failure | Result |
|---|---|
| invalid request, unknown field, invalid action metadata | `DENY protocol.invalid-request`, `RequestValidationFailed` event |
| identity mismatch, unregistered project | `DENY identity.*`, `IdentityValidationFailed` event |
| request does not match its context | `DENY evaluation.context-mismatch` |
| policy integrity failed (e.g. trust lockdown) | `DENY` with the policy's rule (`trust.lockdown`), `PolicyIntegrityFailed` event |
| policy evaluator error | `DENY engine.error`, `SecurityError` event |
| any audit record cannot be written | `DENY audit.unavailable` |

## 9. Audit

Each evaluation records, all hash-chained and redacted:
1. `AuthorizationRequested`;
2. the step events `ResourceClassified`, `RiskAssessed`, `PolicyRuleMatched`, and `PolicyConflictDetected` when there is a conflict;
3. the decision event (`AuthorizationAllowed`, `AuthorizationDenied` or `ApprovalRequested`).

The decision record carries the request ID, timestamp, agent, project, category, operation, risk, decision, rule, policy version and reason.

Terminal commands are **never stored raw**. The audit summary keeps:
- the executable;
- the subcommand of recognised tools;
- flag names, with any glued or `=` values masked;
- path-like arguments;
- URLs without credentials or query.

Every other argument becomes `***`, and the result is redacted again on write.

## 10. Examples

A team policy: allow documentation builds and edits under `docs/`, deny touching generated code, keep everything else at balanced defaults.

```yaml
profile: { name: balanced, dependency_changes: REQUIRE_APPROVAL }
rules:
  - id: allow-docs-build
    decision: ALLOW
    reason: documentation builds are routine
    priority: 10
    match: { category: terminal, executable: "mkdocs" }
  - id: no-generated-edits
    decision: DENY
    reason: generated code is rebuilt by CI; edit the schema instead
    match: { category: filesystem, resource: "src/generated/**" }
  - id: prod-db-read-approval
    decision: REQUIRE_APPROVAL
    reason: production data access is reviewed
    match: { category: database, operation: read, conditions: [ { environment: production } ] }
```

A project restriction (only `DENY` / `REQUIRE_APPROVAL` are accepted from projects):

```yaml
rules:
  - id: migrations-need-review
    decision: REQUIRE_APPROVAL
    reason: schema changes in this service need a DBA
    match: { category: filesystem, resource: "db/migrations/**", conditions: [ { capability: write } ] }
```

## 11. Known limitations

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) L45 onwards. In short:
- terminal classification is lexical and table-driven;
- the decision is made before the tool runs (check-then-act gap, L26);
- filesystem-level enforcement (Landlock, the contained tier) is what would turn path decisions into guarantees.
