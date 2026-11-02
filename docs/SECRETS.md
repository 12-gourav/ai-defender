# Sensitive Files, Secret Detection and Disclosure Controls

**Secret scanning is not data loss prevention.** AI Defender recognises common credential formats
and sensitive file locations, and its policy engine uses that evidence to deny or gate
operations that integrations submit. It cannot find every secret, it cannot see operations no
integration reports, and it cannot make a model forget something it has already read. What it
guarantees is narrower and stated below, each with its tests.

Code: `crates/agentguard-secrets` (detectors, redaction, scanning, Git index, secret-safe
access), `agentguard_engine::{sensitive, content, disclosure}` (policy integration),
`agentguard-engine-cli` `secrets.rs` (commands), `cli/src/commands/secrets.ts` (CLI).

## 1. How it fits the existing engine

```text
operation ─ resource classification (names) ─ sensitivity (configured patterns, categories)
          ─ content evidence (bounded inspection) ─ disclosure assessment (destination, secret data)
          ─ risk ─ the existing policy engine (mandatory floors, global, project, profile)
          ─ ALLOW / DENY / REQUIRE_APPROVAL ─ Phase 5 approval workflow ─ audit
```

No second policy engine: sensitivity, content evidence and disclosure become typed rule
conditions (`sensitive-resource`, `sensitive`, `secrets-detected`, `secret-data`,
`destination`, `external-destination`, `into-ordinary-file`), and the decisions come from
mandatory and profile rules like every other decision ([POLICY_EVALUATION.md](POLICY_EVALUATION.md)).

## 2. Sensitive resource categories

| Category | Recognised by |
|---|---|
| `environment-config` | `.env`, `.env.*`, `*.env` (templates such as `.env.example` excluded) |
| `private-key-material` | `id_rsa`/`id_ed25519`/..., `*.pem`, `*.key`, `*.ppk`, `~/.ssh`, `~/.gnupg`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` |
| `cloud-credential` | `.aws/`, `.kube/`, `.azure/`, `gcloud/`, `service-account*.json`, kubeconfig |
| `infrastructure-state` | `*.tfstate*`, `*.tfvars` |
| `application-credential` | `credentials.*`, `secrets.*`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass`, `.my.cnf`, `.htpasswd`, `*.kdbx` |
| `secret-store` | the `secrets` action category |
| `configured-protected` | a `protected_patterns` entry in trusted policy, or a directory containing a sensitive file (for copy, archive, upload) |
| `source-with-secrets` | an otherwise ordinary file in which a credential of severity `high` or more was detected |

Names are matched case-insensitively on resolved paths (symlinks followed, `..` removed), so
`notes.txt → .env` is `.env`. Content detection means classification does not rely only on names.

**Configuration** (trusted policy; global and project layers, additions only):

```yaml
sensitive:
  protected_patterns: ["config/keys/**", "*.secret"]   # treated as credential files
  detectors:                                            # extra detectors (regex, linear time)
    - { id: acme-key, pattern: "\\b(acme_[a-z0-9]{32})\\b", severity: high, public_prefix: "acme_" }
  scan_exclusions: ["fixtures/**"]                      # scan reporting only; never "safe"
```

A project may add these in `.agentguard/config.yaml`; like its rules, they apply only after a
human approves them (`ai-defender project trust`). Decisions for sensitive resources are set only
by the global profile (§4); no layer can set them to `ALLOW`.

## 3. Secret detection

A `Detector` reports byte ranges in a line; adding a provider is a new `ProviderSpec` row or a
new `Detector` implementation, with no change to scanning. All patterns use the `regex` crate
(linear time, no backtracking); a single `RegexSet` prefilter makes a line that no detector
could match cost one pass. Custom patterns are capped at 512 characters and 1 MiB compiled.

| Detector | Matches | Severity |
|---|---|---|
| `private-key` | `-----BEGIN … PRIVATE KEY-----` (PEM, OpenSSH, PGP blocks) | critical |
| `aws-access-key-id` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 | critical |
| `aws-secret-access-key` | 40-character key assigned to an AWS-named key | critical |
| `gcp-service-account` | `"type": "service_account"` | critical |
| `azure-storage-key` | `AccountKey=…` | critical |
| `stripe-key` | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` | critical |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36, `github_pat_` | high |
| `gitlab-token` | `glpat-`, `glptt-`, `gldt-`, `glrt-` | high |
| `npm-token`, `pypi-token`, `docker-pat` | `npm_`, `pypi-`, `dckr_pat_` | high |
| `slack-token` | `xoxb-`, `xoxp-`, … | high |
| `anthropic-key`, `openai-key`, `google-api-key`, `sendgrid-key`, `huggingface-token` | `sk-ant-`, `sk-`/`sk-proj-`, `AIza`, `SG.`, `hf_` | high |
| `connection-string-password` | password in `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis://`, `amqp://`, `mssql://`, `jdbc:…://` URLs | high |
| `url-credentials` | password in `http(s)://` or `ftp(s)://` URLs | high |
| `bearer-token` | the token after `Bearer` | high |
| `jwt` | three base64url segments with a JSON header | medium |
| `credential-assignment` | credential-like value assigned to a key named password, secret, token, api key, private key, client secret, signing/encryption/session key | medium |
| `high-entropy` | 32+ random-looking characters in a quoted or assigned position | low |
| `custom:<id>` | configured patterns | configured |

**False positives** (reported, reviewable with `secrets explain` without exposing the value):
test fixtures with real-looking fake keys; high-entropy identifiers, nonces and encoded data;
generic `sk-` prefixes in unrelated strings; JWTs in test data; example URLs with passwords.
Placeholders and references are filtered for the generic detectors (`${VAR}`,
`process.env…`, `os.environ[…]`, `your_api_key`, `changeme`, `example`, `xxxx`, repeated
characters). Hex digests (32/40/64/128), UUID-like strings and lock-file integrity hashes are
not reported as entropy.

**False negatives** (not detected): secrets without a recognisable format (a plain password
assigned to an unremarkable name, a token split across lines or strings, encoded or encrypted
values, secrets in binary files, secrets assembled at run time); provider formats not in the
table; values shorter than 8 characters; anything in a file larger than the limits or excluded.

## 4. File access policy (balanced profile)

| Operation (agent) | Ordinary file | Sensitive resource | Ordinary file with a detected credential |
|---|---|---|---|
| read, list, traverse | ALLOW | **DENY** (`sensitive_read`) | REQUIRE_APPROVAL (`source_with_secrets`) |
| write, append, rename | ALLOW | REQUIRE_APPROVAL (`sensitive_write`); private keys and credential files DENY (`secret_files`) | ALLOW, unless the written content carries a secret (below) |
| delete | approval (default) | **DENY** (`sensitive_delete`) | approval |
| copy | ALLOW | DENY into an ordinary file (mandatory) | DENY into an ordinary file (mandatory) |
| upload | approval | DENY (mandatory) | DENY (mandatory) |
| run tests and builds | ALLOW | — | — |

Configurable in the trusted global policy (`profile:`): `sensitive_read`, `sensitive_write`,
`sensitive_delete` (`DENY` or `REQUIRE_APPROVAL`; `ALLOW` is rejected), `source_with_secrets`,
`secret_files`. The mandatory baseline keeps a floor of `REQUIRE_APPROVAL` for `.env` files,
private keys and credential files whatever the global policy says.

Every authorization request carries a verified agent identity (the hook integration). Human
secret-management work goes through the CLI commands below, which never return a value; there is
no "human" principal in the authorization path, and developer-initiated operations are not
assumed safe.

## 5. Data disclosure

Every operation gets a destination: `agent-context` (what the agent reads or sees in command
output, and therefore its model provider), `local-project-file`, `local-file`, `git-history`,
`git-remote`, `package-registry`, `ai-service` (known hosted AI endpoints), `external-api`,
`external-network`, `unknown` (interpreters, containers, unmodelled tools), or `none`.
**Secret data** is a sensitive resource or a detected credential of severity `high` or more.

| Rule (mandatory, cannot be weakened) | Decision |
|---|---|
| `mandatory:secret-disclosure`: secret data to any external or unknown destination (an upload of `.env` or a private key, `curl -d @.env …`, a bearer token in a `curl` command, a credential passed to an interpreter) | DENY |
| `mandatory:secret-commit`: a `git commit` (typed or terminal) whose staged changes contain a detected credential | DENY |
| `mandatory:secret-into-ordinary-file`: writing, appending, copying or archiving secret data into an ordinary file | DENY |
| `.env`, private keys, credential files | REQUIRE_APPROVAL at least |

Non-sensitive data to an external destination follows ordinary policy (approval by default; a
trusted global rule may allow a host). An allow-listed host never makes secret disclosure
acceptable, and unknown destinations get no implicit permission.

**Staged changes** are read from `.git/index` without running Git: the cache tree narrows the
check to changed directories, and a staged file is scanned from the working tree when its size
and modification time match the index (as Git itself compares). A staged file whose working copy
differs cannot be verified and makes the decision uncertain (approval), never clean.

## 6. Redaction

| Where | How |
|---|---|
| audit records | `redact_text` (field-name and token rules) then every detector span; private-key blocks replaced whole |
| approval descriptions | the same redaction on the target before it is stored |
| scan results, `explain`, `status` | redacted previews only: `ghp_****REDACTED`, `sk_live_****REDACTED`, `****REDACTED`, `[PRIVATE KEY ****REDACTED]` |
| CLI output | defence in depth: the CLI masks the most recognisable shapes in anything it prints |
| command summaries | non-path, non-flag arguments are masked in terminal summaries (Phase 3) |

Only a public, provider-defined prefix is ever kept; no suffix, length or hash of a value is
shown or stored. Finding IDs are derived from path, line, column and detector, so the same
location yields the same ID whatever the value, and no finding field can be used to recover or
confirm a secret. Inline `content` sent with a write is inspected in memory and represented in
the approval digest only by its SHA-256 (it is bound, not stored).

## 7. Secret-safe AI access

An agent should not need a raw secret when the task can be done by name. Implemented now:
- `ai-defender secrets preview <file>` / `secrets.preview`: the keys of a `.env` file and whether
  each is set, empty or a reference; never values (`SecretSource`, `DotenvFile`);
- existence checks (`SecretSource::is_set`);
- the policy itself: reading `.env` is denied by default, so the agent is steered to names.

Designed for later (interfaces only, nothing resolves a value yet): `SecretReference` (a secret
by name for a broker that injects it into a process environment at execution time), scoped
credentials and provider integrations. No cloud secret manager is required.

## 8. Commands

| Command | Effect |
|---|---|
| `ai-defender secrets scan [PATH…]` | scan the project (or paths inside it); `--staged` for staged changes; `--exclude GLOB` (repeatable); `--no-default-exclusions`; `--json`. Exit 5 when anything is found |
| `ai-defender secrets status` | detectors and categories, policy decisions, protected patterns, exclusions, last scan |
| `ai-defender secrets explain <id>` | what the detector matches, where, severity, redacted preview, remediation, how to handle a false positive |
| `ai-defender secrets preview <file>` | `.env` keys and states, never values |

Scans never upload anything (the secrets crate and the CLI contain no network code; tests
enforce it), never modify or delete files, and never rotate credentials. The last scan per
project is stored without values in the trust store (`scans/`, 0600) for `explain`.

## 9. Scan limits and behaviour

| Limit | Default |
|---|---|
| file size | 2 MiB (larger files are skipped and listed) |
| files per scan | 20,000 |
| bytes per scan | 256 MiB |
| findings recorded | 1,000 (then marked truncated) |
| line length | 64 KiB segments (longer lines are scanned in pieces) |
| default exclusions | `.git`, `node_modules`, `target`, `dist`, `build`, `vendor`, `.venv`, `venv`, `__pycache__`, `.next`, `.nuxt`, `coverage`, `.tox`, `.gradle`, `.terraform`, `.cache` |
| decision-time inspection | first 1 MiB of a file; directories: 500 files, 16 MiB |

Symlinks are never followed (listed as skipped); files are opened with `O_NOFOLLOW | O_NONBLOCK`
and re-checked as regular files; binary files (a NUL in the first 8 KiB) are skipped and listed;
FIFOs and devices are skipped; malformed text is decoded lossily. **Excluded and skipped files are
always listed and make no claim of being clean**; a scan with anything skipped is reported as
`INCOMPLETE`.

**Performance** (linux-x64 development machine): the release engine scanned 10,001 source files
(40.8 MB) in 0.26 to 0.28 s with 8.9 MB peak memory, finding the one planted fake token; the
debug test build scans 2,000 files (8.2 MB) in about 1 s. Memory is bounded by one line segment
per file plus the report. The `regex` dependency grows the release engine from 1.9 MB to 4.4 MB.

## 10. Coverage and limitations

- Enforcement happens only for operations an integration submits to the engine. No agent hook is
  installed yet (agent integrations are a later phase), so today the policy protects nothing on
  its own; `ai-defender secrets scan` works today.
- Terminal commands are analysed lexically. A secret file read through a variable, a script, an
  alias or an interpreter one-liner may not be recognised; such commands are usually unknown or
  uncertain and gated by approval, not denied.
- Terminal copies (`cp .env public.txt`) are gated by approval (sensitive write), not denied as
  "into an ordinary file"; only typed file operations carry a separate destination.
- A write without `content` cannot be inspected; the target's classification still applies.
- Decision-time inspection reads the file at evaluation time; the tool may read a different
  version later (time of check versus time of use). Path checks do not prevent filesystem races.
- Staged-content verification relies on file size and modification time, as Git does; a
  same-size edit within the same timestamp granularity would go unnoticed.
- Detection is pattern-based (§3). Excluding a path hides it from scans, never makes it safe.

Known limitations L73 to L82 in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
