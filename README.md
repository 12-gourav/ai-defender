# AI Defender

**A Rust-powered security governance layer for AI coding agents.**

AI Defender checks what AI coding agents such as Claude Code and OpenAI Codex try to do before
they do it. It decides `ALLOW`, `DENY` or `REQUIRE_APPROVAL` under a signed, tamper-protected
policy. It blocks what policy forbids and asks a human for anything sensitive, and the human
approves one exact operation, once. Every decision is recorded.

It runs locally. There is no daemon, no Docker, no cloud service and no database server, and
no AI model takes part in a decision.

```bash
npm install -g ai-defender
cd ~/code/my-project && ai-defender init
ai-defender integrations install claude
```

> AI Defender reduces risk; it does not make an AI agent safe. It only sees the tool calls the
> agent's official hooks report, and only in projects you register. Read
> [What AI Defender does not do](#what-ai-defender-does-not-do) before relying on it.

---

## Why

Coding agents run shell commands, edit files, push to Git and call external tools with your
permissions. A single bad step can be enough to cause real harm:
- a misread instruction;
- a poisoned README or dependency;
- an over-eager "fix".

Examples include:
- `rm -rf` outside the project;
- a force push;
- reading `.env`;
- committing a key;
- piping a script from the internet into a shell.

Prompts and model-side safety help, but they are not enforcement. AI Defender puts a
deterministic, auditable policy check in front of the agent's tools, and keeps the authority to
approve with you.

## How it works

```text
Claude Code / Codex  ──hook──▶  agentguard-engine (Rust, one process per call)
                                  │ validate payload, normalize the tool call
                                  │ verify signed policy and project registration
                                  │ classify: files, commands, Git, secrets, network
                                  │ evaluate policy  ─▶ ALLOW / DENY / REQUIRE_APPROVAL
                                  │ record (hash-chained audit log)
                                  ▼
                       the agent proceeds, or is told why it was blocked
                       and which `ai-defender approve <id>` a human must run
```

- **The Rust engine is the only authority.** The `ai-defender` CLI and the hook adapters only
  translate and display.
- **Trusted state is signed.** Policy, the project registry and approvals are Ed25519-signed
  with keys protected by your passphrase (Argon2id). A tampered policy is detected, and every
  protected operation is then blocked.
- **Approval is human and exact.** An approval binds one operation:
  - the exact arguments or file content;
  - the project and agent;
  - for Git, the repository state (HEAD, branch, staged tree, the commits a push would send).

  Any change needs a new approval. Grants are single-use and expire after 2 minutes by default.
- **It fails closed.** An invalid payload, unverified policy, unwritable audit log or internal
  error blocks the operation; it never allows it.

## What it protects

| Area | Default behaviour (balanced profile) |
|---|---|
| Ordinary development | Reading and editing project files, tests, builds, linters, formatters and `git status` are allowed without prompts |
| Sensitive files | Reading `.env`, private keys and credential files is denied; changing them needs approval |
| Secrets | Writing a detected credential into a file, committing it, or sending it anywhere external is denied |
| Git | Commits, branch changes and pushes need approval; force pushes are denied |
| Destructive commands | `rm -rf` or `chmod -R` outside the project, or on `.git` or security files, is denied; `rm -rf /`, `curl … \| sh` and similar are always denied |
| Dependencies | Installing or removing packages needs approval |
| AI Defender itself | Agents cannot change its policy, approvals, audit log, hook settings or engine, or run its approval commands |
| Unknown programs | Need approval (unfamiliar is not the same as dangerous, so they are not denied) |

## Coverage: enforced, managed, monitored, not covered

| Kind | What it means | Examples |
|---|---|---|
| **Enforced (before execution)** | The agent's hook sends the tool call to AI Defender, which can block it | Claude Code: Bash, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch, MCP tools. Codex: shell, `apply_patch`, MCP tools |
| **Managed execution** | You or an agent run a command through `ai-defender run`; AI Defender evaluates it, gets approval if needed, and runs it itself with a filtered environment and a time limit | `ai-defender run git push origin feature-a` |
| **Monitoring only** | Recorded after the fact; cannot be blocked | Post-tool events, session start |
| **Not covered or bypassable** | AI Defender does not see it | Commands you type yourself; child processes of an allowed command (an `npm test` script); Codex hosted tools and `write_stdin`; any agent without an installed integration; unregistered directories |

`ai-defender integrations coverage` prints the exact table for each agent.

## Supported agents

| Agent | Integration | Notes |
|---|---|---|
| Claude Code | Native `PreToolUse` hooks (blocking), post-tool audit, session context | Hook failures (crash, timeout, missing engine) block only on **Claude Code 2.1.295 or later**. Older versions continue the tool call when the hook itself fails, and `ai-defender doctor` reports them as degraded |
| OpenAI Codex | Native `PreToolUse` hooks (blocking), post-tool audit, session context | Codex runs new hooks only after you trust them with `/hooks`. It does not document timeout behaviour, and hosted tools are not hooked |
| Any other agent, or your own terminal | Managed execution with `ai-defender run` | Only what you route through it |

## Installation

Requirements:
- Node.js 18.17 or later;
- Linux (x64, arm64) or macOS (x64, arm64);
- Git, optional, for Git features.

No Rust toolchain, compiler, Docker or database is needed.

```bash
npm install -g ai-defender
ai-defender --version
ai-defender doctor
```

The one `ai-defender` package carries a precompiled engine for each supported platform and
picks yours. Before every use, the CLI checks that the engine's manifest is signed by an AI
Defender release key shipped in the package. It also checks the platform and the binary's
SHA-256. A binary that fails any check is never executed. Installation runs no scripts, has no
dependencies and downloads nothing.

## Quick start

```bash
cd ~/code/my-project
ai-defender init                          # first time: creates your signing keys (choose a passphrase)
ai-defender status
ai-defender integrations install claude   # or: codex
ai-defender integrations verify
```

- **On the first `init`,** AI Defender creates your signing keys, protected by a passphrase of at
  least 12 characters. Back up the keys directory it names; without the keys and passphrase,
  trusted policy cannot be changed. Later projects reuse the same identity.
- **After installing the Claude Code integration,** restart Claude Code and accept the workspace
  trust prompt.
- **After installing the Codex integration,** trust the new hooks with `/hooks`.

### The approval workflow

When an agent tries something that needs approval, for example `git push origin feature-a`, it
is blocked with a message such as:

```text
AI Defender requires human approval for this exact operation … Ask the user to run
`ai-defender approve 3f2a9c1e` in their own terminal …
```

1. In **your own terminal**, never through the agent:

   ```bash
   ai-defender approvals              # what is pending
   ai-defender approve 3f2a9c1e       # review the exact operation, type "approve", enter your passphrase
   ```

2. Tell the agent to retry the same command. It runs once; any change needs a new approval.

`approve` refuses `--yes`, `--json`, piped input and passphrase files: it needs a human at a
terminal.

## Multiple projects

One trusted identity covers every project on the machine.

```bash
ai-defender projects list                 # all registered projects
ai-defender projects inspect my-api       # by folder name, ID prefix or path
ai-defender projects add ~/code/other     # register another project
ai-defender projects revoke my-api        # stop trusting one (passphrase)
ai-defender dashboard                     # one-screen overview
```

```text
AI DEFENDER — REGISTERED PROJECTS

PROJECT                ID         SECURITY   INTEGRATION      STATUS
--------------------------------------------------------------------------
alpha-service          5f0c2a91   Balanced   Claude           Verified
beta-web               b81e7d03   Balanced   Claude           Verified

Total projects: 2
```

A project that is moved or replaced is reported as such and loses its trust until you register
it again. A registration never silently follows a directory.

## Command reference

| Command | Purpose |
|---|---|
| `ai-defender init` | Register the current project (first run: create signing keys) |
| `ai-defender status` | Installation, trust, project, policy, integration and enforcement state |
| `ai-defender check` | Diagnostics for trust and the current project (exit 5 on failure) |
| `ai-defender doctor` | Full diagnostics: engine, versions, Node.js, Git, agents, trust, integrations |
| `ai-defender dashboard` | Overview of projects, approvals, recent blocks and integrations |
| `ai-defender projects list\|inspect\|add\|revoke` | The global project registry |
| `ai-defender project trust` | Approve a changed project configuration (passphrase) |
| `ai-defender policy show` | The effective policy, exactly as evaluated |
| `ai-defender policy validate` | Check the trusted policy and this project's configuration |
| `ai-defender approvals` / `approve <id>` / `reject <id>` | Human approval |
| `ai-defender history [--blocked\|--approvals] [--limit N]` | Recent security events |
| `ai-defender secrets scan [--staged]` | Scan for potential secrets (redacted output; exit 5 if found) |
| `ai-defender secrets explain <id>` | Explain a finding without revealing it |
| `ai-defender run [--shell sh\|bash] -- <command>` | Run a command through managed execution |
| `ai-defender git status\|inspect` | Repository state; remotes shown without credentials |
| `ai-defender execution history\|inspect <id>` | Managed execution records |
| `ai-defender integrations [list\|status\|install\|uninstall\|verify\|coverage]` | Agent hooks |
| `ai-defender repair` | Re-point degraded or outdated hooks at a verified engine (never repairs tampered trust) |
| `ai-defender update` | Show versions and how to upgrade |
| `ai-defender uninstall [--purge]` | Remove hooks and engine copies (password); `--purge` also deletes keys and history |
| `ai-defender --version`, `--help` | |

Global options: `--json` (machine-readable output), `--no-color`, `--non-interactive`, `--yes`.
`agentguard` is accepted as an alias of `ai-defender`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | failure |
| 2 | usage |
| 3 | engine unavailable or unverified |
| 4 | engine protocol error |
| 5 | security check failed |
| 6 | confirmation or approval required |
| 7 | not initialised |
| 8 | denied |
| 9 | unsupported |
| 124 | timed out |
| 125 | outcome unknown |

When `run` executes a command, it exits with that command's own status.

## Policy

The **trusted global policy** sets machine-wide rules and the security profile. It is signed and
can only be changed with your passphrase.

**Project policy** lives in `.agentguard/config.yaml` and can only add restrictions:

```yaml
version: 1
name: payments-service
rules:
  - id: no-push-to-main
    decision: DENY
    reason: main is protected; open a pull request instead
    match: { category: git, operation: push }
sensitive:
  protected_patterns: ["config/production/**"]
```

```bash
ai-defender policy validate
ai-defender project trust        # approve it (passphrase); it is not applied until approved
ai-defender policy show
```

A project file can never allow something the baseline forbids. A changed file is ignored until a
human approves it again.

## Secrets and sensitive files

```bash
ai-defender secrets scan              # whole project, redacted previews (ghp_****REDACTED)
ai-defender secrets scan --staged     # what you are about to commit
ai-defender secrets explain f_1a2b3c4d5e6f7a8b
```

What AI Defender does:
- denies agent reads of `.env`, keys, credential files and paths you protect;
- denies writing detected credentials into ordinary files, committing them, and sending them to
  any external or unknown destination;
- withholds credential-like environment variables from managed commands, and redacts output.

Pattern detection finds common credential formats. It cannot prove a file holds no secret, and
once a model has read a secret it cannot be taken back. This is secret scanning, not data loss
prevention.

## Security history

```bash
ai-defender history                   # recent events
ai-defender history --blocked         # what was denied
ai-defender history --approvals       # approval activity
```

- **Format.** History is a local, append-only, hash-chained JSON Lines log. Values are redacted
  before they are written, so it holds no secrets, tokens, file contents or tool arguments.
- **Integrity.** It shows when it was changed out of order; it cannot prevent deletion by a
  process running as your user.

## Upgrading

```bash
npm install -g ai-defender@latest
ai-defender repair        # re-point agent hooks at the new engine
ai-defender doctor
```

Upgrades keep your signing keys, trusted policy, project registry, approvals and history. Agent
hooks run a verified copy of the engine kept in AI Defender's own storage, so a Node.js or npm
change does not break them. `repair` refreshes that copy.

**From `agentguard`:** AI Defender is the same software under a new name. It uses the same
storage, so your identity, projects and history carry over unchanged. Hooks installed by
`agentguard` are recognised and replaced by `ai-defender integrations install …` or
`ai-defender repair`.

## Uninstalling

```bash
ai-defender uninstall          # asks for your AI Defender password
npm uninstall -g ai-defender   # the last step it prints
```

`ai-defender uninstall` is the supported way to remove AI Defender. After checking your password
it removes AI Defender's hooks from Claude Code and Codex (your other settings and hooks are kept,
with a backup) and its verified engine copies. Nothing is enforced after that. It keeps:
- `~/.config/agentguard/`: signing keys, trusted policy, project registry, audit history and
  hook backups (add `--purge` and type `purge` to delete these too);
- `.agentguard/` in each project (it lives in your repositories; delete it yourself).

**What the password does and does not protect.** It stops an AI agent, or anyone without the
password, from switching AI Defender off through AI Defender. It cannot stop the owner of the
machine:
- `npm uninstall -g ai-defender` removes the command without asking. npm runs no script AI
  Defender could rely on, and AI Defender does not try to interfere with npm. The hooks stay
  installed and keep blocking until you remove them, either by reinstalling and running
  `ai-defender uninstall`, or by deleting AI Defender's entries from `~/.claude/settings.json`
  and `~/.codex/hooks.json`.
- Anyone who can edit those files, or delete `~/.config/agentguard`, can remove AI Defender.
  Agents are blocked from both by AI Defender's own guard, but other software on your account is
  not.

After five wrong passwords in a row, each further attempt waits: 30 seconds, doubling up to 15
minutes. A correct password resets the count. This slows guessing through AI Defender; the
signing keys themselves are protected by Argon2id encryption.

## Platform compatibility

| Platform | Status |
|---|---|
| Linux x64 | Supported. Static musl engine (no glibc requirement); full test suite and global-install test on GitHub's Ubuntu runner |
| Linux arm64 | Supported. Static musl engine; full test suite and global-install test on GitHub's Ubuntu ARM64 runner |
| macOS arm64 (Apple Silicon) | Supported. Full test suite and global-install test on GitHub's macOS 14 runner |
| macOS x64 (Intel) | Supported. Full test suite and global-install test on GitHub's macOS 15 Intel runner |
| Windows | **Not released yet**; npm refuses to install. The engine builds for Windows (owner SIDs, DACLs, Job Objects, and path rules for case, trailing dots and spaces, alternate data streams, device names and `\\?\` prefixes), and CI runs its suite on a Windows runner; it ships once that suite and the remaining items in [KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) (L117 to L124) are closed |

Storage uses `~/.config/agentguard` on every supported platform (or `$XDG_CONFIG_HOME`).

## What AI Defender does not do

- **It does not intercept everything an agent does.** It sees only:
  - tool calls the agent's hooks report;
  - for listed tools;
  - in registered projects;
  - while the hooks run.

  Commands started by an allowed command, input sent to a running process, hosted tools, and
  agents without an integration are outside its view.
- **It does not sandbox anything.** Allowed operations run with your permissions.
- **It does not stop a determined local attacker.** A process running as your user that knows
  your passphrase can change trusted state.
- **It cannot remove what a model has already seen.**
- **It does not provide data loss prevention, and is not a guarantee.**

See [SECURITY.md](SECURITY.md) for the threat model and the full list of limitations.

## Reporting a vulnerability

Please report security issues privately as described in [SECURITY.md](SECURITY.md). Do not open
public issues for vulnerabilities.

## Building from source

```bash
git clone https://github.com/12-gourav/ai-defender.git && cd ai-defender
cargo build --release --locked -p agentguard-engine-cli       # needs Rust and a C linker
cd cli && npm ci && npm run build
AGENTGUARD_DEV_ENGINE="$PWD/../target/release/agentguard-engine" AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1 \
  node build/src/index.js doctor
```

A development engine is always reported as **unverified**. Both variables are required, and
neither is used in a normal installation.

Development notes: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Architecture:
[docs/ENGINE_ARCHITECTURE.md](docs/ENGINE_ARCHITECTURE.md). Releases:
[docs/RELEASING.md](docs/RELEASING.md).

## Contributing

- Before opening a change, run `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --locked`
  and, in `cli/`, `npm run lint && npm test`.
- Security-relevant changes need tests that demonstrate the property they protect.
- Internal crate names (`agentguard-*`), the engine binary (`agentguard-engine`) and storage
  paths keep the project's earlier name. They are part of signed state and installed
  configuration.

## License

Apache License 2.0. See [LICENSE](LICENSE).
