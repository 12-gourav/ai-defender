# Authorization Protocol `agentguard.authz.v1`

The canonical request/response exchanged between an agent integration and the decision engine. Implementation: `crates/agentguard-proto`.

## 1. Transport-independent rules

- UTF-8 JSON. A request is at most **65,536 bytes**.
- Every object rejects **unknown fields** and **duplicate keys**. A request either parses completely or is denied.
- No field asserts a decision, a risk level or an approval. Sending `decision`, `risk`, `approved`, `approval` or any other unknown field rejects the request.
- All text is validated: length limits, no control characters (paths, names, hosts, identifiers). Free text (`command`, attribute values) allows newline and tab only.
- Identity fields are **claims**. The engine verifies them independently (see §4).

## 2. Request

```json
{
  "protocol": "agentguard.authz.v1",
  "request_id": "6f1c1f0e-8a5b-4c3e-9a7e-1c2b3d4e5f60",
  "agent": { "kind": "claude", "version": "2.1.0" },
  "project": { "root": "/home/dev/app", "id": "<64 hex, optional>" },
  "session_id": "0b1c2d3e-4f50-4617-8899-aabbccddeeff",
  "action": { "category": "filesystem", "operation": "write", "path": "src/main.rs" },
  "working_directory": "/home/dev/app",
  "policy_version": "<64 hex>",
  "context": { "tool": "Edit", "attributes": { "hook": "pre-tool-use" } }
}
```

| Field | Required | Rules |
|---|---|---|
| `protocol` | yes | exactly `agentguard.authz.v1` |
| `request_id` | yes | UUID; echoed in the response |
| `agent.kind` | yes | `claude`, `codex`, `gemini`, `antigravity`, `cursor`, `generic` (case-sensitive) |
| `agent.version` | no | 1 to 64 of `[A-Za-z0-9.+-]`; recorded, never used to decide |
| `project.root` | yes | absolute path; must equal the registered project root |
| `project.id` | no | 64 hex; if present must equal the registered project's ID |
| `session_id` | no | UUID; part of the approval binding when present |
| `action` | yes | see §3 |
| `working_directory` | yes | absolute; resolved through symlinks; must lie in a registered project |
| `policy_version` | yes | 64 hex; must equal the engine's active policy version |
| `context.tool` | no | name; informational |
| `context.attributes` | no | at most 16 entries, name keys, values up to 256 chars; informational |

### Paths

Relative action paths resolve against `working_directory`. The engine's resolver canonicalises the longest existing ancestor, following symlinks, and appends the rest. It rejects:
- a dangling symlink anywhere in the path;
- `..` below a directory that does not exist;
- control characters;
- non-UTF-8 results;
- anything longer than 4,096 bytes.

Policy only ever sees the resolved path.

## 3. Actions

`category` selects the shape. An `operation` (or `kind`) that is well-formed but unrecognised parses as *unknown* and is **always denied**. An unrecognised `category` is a schema error and is also denied.

| `category` | Fields | Operations |
|---|---|---|
| `filesystem` | `operation`, `path`, `destination?`, `remote?`, `content?` | `read`, `list`, `traverse`, `write`, `append`, `delete`, `rename`, `copy`, `archive` (these three use `destination`), `upload`, `download` (use `remote`, a host), `change-permissions`. `content` (at most 48 KiB) is the text a `write` or `append` would write; the engine inspects it for secrets and binds approvals to its SHA-256, never storing or logging it (Phase 6, [SECRETS.md](SECRETS.md)) |
| `terminal` | `command` (≤ 8,192 chars, non-empty) | n/a (`execute`) |
| `git` | `operation`, `remote?`, `target_ref?`, `force?` (default false) | `status`, `diff`, `log`, `show`, `branch-list`, `fetch`, `pull`, `clone`, `checkout`, `switch`, `branch`, `add`, `stash`, `clean`, `commit`, `merge`, `rebase`, `reset`, `push`, `tag`, `config` |
| `github` | `operation`, `repository?` (`provider:owner/name`) | `read`, `comment`, `create-issue`, `create-pull-request`, `merge-pull-request`, `create-release`, `trigger-workflow`, `modify-settings`, `delete-repository` |
| `secrets` | `operation`, `name` | `list`, `read`, `write`, `delete` (names only; values never cross the protocol) |
| `database` | `operation`, `target`, `environment?` | `read`, `write`, `schema-change`, `drop`, `admin`, `migrate`, `bulk-load` |
| `terraform` | `operation`, `workspace?`, `environment?` | `init`, `validate`, `plan`, `apply`, `destroy`, `import`, `state-modify` |
| `network` | `operation`, `host`, `port?` | `request`, `connect` |
| `external-transfer` | `kind`, `destination` | `upload`, `share` |
| `custom-tool` | `tool`, `server?` | n/a (`invoke`) |
| `package-manager` | `operation`, `manager`, `packages?` (≤ 64 names), `global?` | `install`, `uninstall`, `update`, `list`, `audit`, `publish` |
| `cloud` | `operation`, `provider`, `service`, `resource?`, `environment?` | `read`, `list`, `create`, `modify`, `delete`, `modify-iam` |
| `configuration` | `operation`, `scope`, `key?`, `path?` | `read`, `modify`, `delete`; scope: `ai-defender`, `agent-settings`, `security`, `ci`, `build`, `editor`, `other` |
| `unknown` | `kind`, `operation`, `target?` | any name: evaluated with explicit uncertainty (never auto-allowed, not denied as an anomaly) |

- `environment` is one of `development`, `staging`, `production`, `unknown`. When absent it is `unknown`, which risk classification treats as production.
- `host` is a lowercase DNS name (ASCII/punycode) or a canonical IP literal. Octal, hex and integer IPv4 spellings are rejected.

## 4. Verification performed by the engine

1. `agent.kind` must equal the agent this engine instance was installed for (`identity.agent-mismatch`).
2. The resolved `working_directory` must lie in a registered project, deepest root first (`identity.project-unregistered`).
3. `project.root` (and `project.id` if present) must equal that project (`identity.project-mismatch`).
4. `policy_version` must equal the active policy (`policy.version-mismatch`). The response carries the active version, so the client can rebuild the request.

## 5. Response

```json
{
  "protocol": "agentguard.authz.v1",
  "request_id": "6f1c1f0e-8a5b-4c3e-9a7e-1c2b3d4e5f60",
  "decision": "REQUIRE_APPROVAL",
  "risk": "medium",
  "reason": "actions with side effects or elevated risk require approval unless a policy rule allows them",
  "rule": "baseline.elevated",
  "policy_version": "<64 hex>",
  "approval": { "required": true, "fingerprint": "<64 hex>", "scope": "single-operation" }
}
```

| Field | Meaning |
|---|---|
| `request_id` | correlation ID; `null` only if the request was rejected before a valid ID could be read |
| `decision` | `ALLOW`, `DENY` or `REQUIRE_APPROVAL` |
| `risk` | `low`, `medium`, `high`, `critical`; independent of the decision; `critical` when the request could not be classified |
| `reason` | human-readable explanation; never contains submitted secret values |
| `rule` | the rule that decided (policy rule ID, or a built-in rule, see §6) |
| `policy_version` | the policy the decision was made under |
| `approval` | `required` is true exactly when `decision` is `REQUIRE_APPROVAL`, and then `fingerprint` names the operation an approval must bind to |

Clients **must** call `AuthorizationResponse::check` (or implement the same consistency check) and treat a failure, a missing response, or a malformed response as `DENY`. Only `ALLOW` permits execution.

## 6. Built-in rule identifiers

| Rule | Decision | When |
|---|---|---|
| `protocol.invalid-request` | DENY | the request failed parsing or validation |
| `identity.agent-mismatch` / `identity.project-unregistered` / `identity.project-mismatch` | DENY | identity verification failed |
| `policy.version-mismatch` | DENY | stale or wrong policy version |
| `guard.unknown-operation` | DENY | unrecognised operation |
| `guard.trusted-state` | DENY | the action would change policy, approvals, audit, AI Defender state or hook settings |
| `guard.self-approval` | DENY | the action would run an AI Defender approval or configuration command |
| `engine.error` | DENY | the policy evaluator, fingerprinting or the approval store failed |
| `evaluation.context-mismatch` | DENY | the request does not match the verified context it is evaluated in |
| `trust.lockdown` | DENY | trusted policy state failed verification (policy integrity) |
| `baseline.uncertain` | REQUIRE_APPROVAL (or DENY if configured) | nothing matched and the classification is uncertain |
| `mandatory:*` | per rule | a mandatory baseline floor ([POLICY_EVALUATION.md](POLICY_EVALUATION.md) §5) |
| `profile:*` | per rule | a security profile action rule |
| `global:*`, `project:*` | per rule | a trusted global or approved project policy rule |
| `audit.unavailable` | DENY | the decision could not be recorded |
| `baseline.read-only-low-risk` | ALLOW | no rule matched; read-only, low risk |
| `baseline.elevated` | REQUIRE_APPROVAL | no rule matched; side effects or medium/high risk |
| `baseline.critical` | DENY | no rule matched; critical risk |
| `floor.critical-requires-approval` | REQUIRE_APPROVAL | a rule allowed a critical-risk action |
| `approval.granted` | ALLOW | a live human approval bound to this exact operation was consumed |

## 7. Versioning

The `protocol` string changes for any incompatible change. Adding an operation name within a category is compatible: older engines see it as unknown and deny it.
