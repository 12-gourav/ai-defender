# Security policy

AI Defender is a security tool, and we treat reports about it with priority.

## Reporting a vulnerability

**Please do not report vulnerabilities in public issues, discussions or pull requests.**

Send the report privately to: **`<SECURITY-CONTACT — to be published by the maintainers before
the first release>`**

Include:
- the AI Defender version (`ai-defender --version`), operating system and architecture;
- the agent and its version, if a hook is involved (`ai-defender doctor` shows both);
- steps to reproduce, the expected and the actual result, and the security impact;
- whether the issue is already public.

Please use fake credentials in reports. Never send real secrets.

### What to expect

- Acknowledgement within 5 working days.
- An initial assessment, and a fix or mitigation plan, as soon as we can reproduce the issue.
- Credit in the release notes if you want it.
- Please give us reasonable time to release a fix before public disclosure (we aim for 90 days at
  most), and do not access data that is not yours or degrade others' systems while testing.

### Supported versions

Only the latest released version receives security fixes until 1.0.

## Threat model

AI Defender assumes an **AI coding agent that may be mistaken or manipulated** (for example by
prompt injection in a README, issue or dependency) and that acts through its tools with the
developer's permissions. AI Defender's goal is that, for the operations it sees:
- prohibited operations are blocked;
- sensitive operations happen only after a human approves that exact operation;
- every decision is recorded;
- the agent cannot change the rules or approve itself.

Out of scope, for this release:
- **A malicious local process running as the developer.** It can read and write anything the
  developer can. AI Defender does not defend against malware on the machine.
- **An attacker who knows the policy-key passphrase**, or administrator or root access.
- **Model-side behaviour.** AI Defender cannot remove information a model has already received.
- **Kernel-level enforcement or sandboxing.** Allowed operations run with the user's permissions.

## Trust boundaries

| Component | Trust |
|---|---|
| `agentguard-engine` (Rust) | The only authorization authority. Verifies trusted state, evaluates policy, binds and consumes approvals, writes audit records |
| `ai-defender` CLI (Node.js) | User interface only. It cannot produce a decision, has no network access, and never writes files (enforced by tests) |
| Hook adapters | Translate provider payloads into engine requests and decisions into provider responses. They never decide, and never take identity or decisions from a payload |
| Trusted state (`~/.config/agentguard/`, mode 0700) | Signed policy, key set, project registry and integrity state; Argon2id-sealed signing keys; approvals; audit log |
| Project configuration (`.agentguard/config.yaml`) | **Untrusted input.** It can only add restrictions, and only after a human approves it with the passphrase |
| Agent payloads, tool arguments, file contents, repository configuration | Untrusted input. Validated, bounded and classified, never believed |

## Binary verification

- The `ai-defender` npm package carries one engine per supported platform under
  `binaries/<platform>/`, each with an `engine-manifest.json` holding:
  - the package name and version;
  - the platform and binary path;
  - the binary's SHA-256 and the engine protocol version.
- Engines are built and tested in CI on each platform's own runner; their manifests are signed
  afterwards on the release owner's machine, so CI never holds the release key.
- The manifest is signed with an Ed25519 **release key**. Only the public key is embedded in the
  `ai-defender` package (`release-keys.json`). The private key is held offline by the release
  owner and never enters the repository, CI logs or packages.
- Before every engine use, the CLI checks the manifest signature against the embedded keys, the
  platform, the protocol version, and the binary's SHA-256 against the manifest. Any failure is
  fatal. There is no fallback binary, no download and no installation script.
- Agent hooks run a copy of the verified engine kept inside trusted state. AI Defender records
  its SHA-256 at installation, and `ai-defender integrations status` and `verify` re-check it.
- The development override (`AGENTGUARD_DEV_ENGINE` plus `AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1`)
  requires both variables. The engine is then reported as **unverified** everywhere.

## Policy integrity and tamper protection

- Every trusted object is signed and version-pinned. Rollback to an older signed version is
  detected.
- If trusted state does not verify, AI Defender enters lockdown: every protected operation is
  denied. `repair` never accepts modified trusted state.
- Agents are denied changes to:
  - trusted state;
  - project policy files;
  - agent hook settings (`~/.claude/settings.json`, `~/.codex/hooks.json`);
  - the engine binary.

  They are also denied running AI Defender's administrative commands. This is exact for file
  tools and best effort for shell commands.
- Project policies cannot weaken the mandatory baseline, which is compiled into the engine.

## Human approval security

- Approving needs an interactive terminal, the typed word `approve` after the exact operation is
  shown, and the signing-key passphrase. `--yes`, `--json`, piped input and passphrase files are
  refused. An engine launched for an agent refuses to approve.
- A grant is Ed25519-signed and bound to an operation digest computed by the engine. The digest
  covers:
  - the exact arguments or content;
  - the project, agent, session and policy version;
  - for Git, the repository state.

  A grant is single-use, consumed atomically, and expires after 2 minutes by default (5 at most).
- **Limitation:** local approval cannot prove that a human, rather than a same-user process that
  learned the passphrase, typed it.

## Audit history limitations

- The audit log is append-only JSON Lines with a hash chain. Content is redacted before it is
  written; tokens, secret values, file contents and tool arguments are never recorded.
- The chain shows reordering or editing. It cannot prevent deletion by a process running as the
  user, and it is local only.
- If an audit record cannot be written, the operation is denied rather than performed
  unrecorded.

## Known enforcement limitations

- **Coverage.** Only tool calls the agent's hooks report are checked, for the tools listed by
  `ai-defender integrations coverage`, in registered projects.
- **Claude Code before 2.1.295.** These versions continue a tool call when the hook itself
  crashes, is missing or times out. Codex does not document what happens when a hook times out.
- **Provider trust.** Hooks run only after the provider trusts them: the Claude Code workspace
  trust dialog, or Codex `/hooks`.
- **Child processes and indirection.** Child processes of an allowed command, scripts and
  interpreters, and input written to running processes are not individually checked. Shell
  commands are classified lexically.
- **Secret detection is pattern-based.** It is not data loss prevention.
- **Platforms.** Windows is not supported. On macOS, managed execution lacks Linux's
  process-group isolation and `no_new_privs`.

The complete list, with mitigations, is maintained in
[docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).
