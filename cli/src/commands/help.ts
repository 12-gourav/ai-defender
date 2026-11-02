import type { Output } from "../services/output.js";

const TEXT = `AI Defender — local-first security governance for AI coding agents

The CLI is a user interface over the AI Defender Rust engine, which alone holds trusted state
and makes security decisions. Installing AI Defender does not, by itself, protect anything:
enforcement starts once an agent integration is installed (\`ai-defender integrations install
claude|codex\`), and then covers only the tools \`ai-defender integrations coverage\` lists.

Usage:
  ai-defender <command> [options]

  \`agentguard\` is the earlier name of this command and remains available as an alias.

Commands:
  init                  Initialise AI Defender in the current project (asks for confirmation)
  status                Show installation, trust, project, policy and enforcement status
  check                 Run diagnostics; exit 5 if any check fails
  doctor                Full diagnostics: engine, versions, Node.js, Git, agents, trust,
                        project, integrations; exit 5 on failure
  dashboard             One-screen summary: engine, trust, projects, approvals, recent
                        blocks, integrations
  projects [list]       All projects registered on this machine
  projects inspect P    One project (P: ID prefix, folder name or path)
  projects add [PATH]   Register a project (same as init in that directory)
  projects revoke P     Revoke a project's trust (passphrase)
  policy show           Show the effective policy as the engine evaluates it
  policy validate       Check the trusted policy and this project's configuration
  history               Recent security events (--blocked, --approvals, --limit N)
  project list          List registered projects
  project inspect       Show the current project's registration and approved restrictions
  project trust         Re-trust a revoked project and approve its restrictions
  project revoke        Revoke the current project's trust
  approvals             List pending and recent approval requests
  approvals show ID     Show one approval request in full
  approve ID            Review one pending operation and approve or reject it
                        (interactive terminal and signing key passphrase required)
  reject ID             Reject a pending operation (--reason TEXT optional)
  approvals cancel ID   Cancel a pending request
  approvals revoke ID   Revoke an approved grant before it is used
  secrets scan [PATH]   Scan the project (or paths) for potential secrets; exit 5 if found
                        --staged: only staged Git changes; --exclude GLOB (repeatable)
  secrets status        Detection engine, policy, exclusions and the last scan
  secrets explain ID    Explain a finding without revealing its value
  secrets preview FILE  List the keys of a .env file and whether each is set (never values)
  run [--] COMMAND...    Run a command through AI Defender: policy, approval, a filtered
                        environment, time limit and audit (no shell; see --shell)
                        --shell sh|bash: run a script in the supported shell subset
                        --timeout S, --env-profile minimal|development, --no-wait
                        --approval ID: redeem an approved request (claim token in
                        AGENTGUARD_CLAIM_TOKEN)
  git status            Repository status, read safely
  git inspect           Repository identity, branch, HEAD, status, remotes (no credentials)
  execution history     Recent managed executions
  execution inspect ID  One execution record (redacted)
  integrations          List the agent hook integrations (Claude Code, Codex)
  integrations status   Installed hooks, hook executable, provider version, health
  integrations install claude|codex    Add AI Defender's hooks (backup first; keeps
                        your other settings and hooks)
  integrations uninstall claude|codex  Remove only AI Defender's hooks (passphrase)
  integrations verify   Check configuration, executable and enforcement; exit 5 on failure
  integrations coverage Protected, observed, unsupported and bypassable tool paths
  repair                Re-point degraded or outdated agent hooks at a verified engine copy
                        (never repairs tampered trusted state)
  update                Show versions and how to upgrade (npm upgrades; nothing is downloaded)
  version               Show CLI, engine and protocol versions

Options:
  --json                Machine-readable output
  --no-color            Disable colour (also honoured: NO_COLOR)
  --non-interactive     Never prompt; required confirmations must be given explicitly
  -y, --yes             Confirm a state-changing command explicitly
  --passphrase-file F   Read the signing key passphrase from a private file (chmod 600)
  --profile NAME        Expected security profile for init (default: balanced)
  --name NAME           Project display name for init
  --reason TEXT         Reason recorded with a rejection
  --staged              Scan staged Git changes only (secrets scan)
  --exclude GLOB        Exclude paths from a scan (reported as excluded, never as clean)
  --no-default-exclusions  Also scan node_modules, target, build output and similar
  --blocked, --approvals   Filter history
  --limit N             Number of history events (1 to 500, default 30)
  -v, --verbose         Show engine location details
  -h, --help            Show this help
  -V, --version         Show versions

Examples:
  ai-defender init
  ai-defender init --non-interactive --yes --passphrase-file ~/.config/ai-defender-pass
  ai-defender status --json
  ai-defender check
  ai-defender approvals
  ai-defender approve 3f2a9c1e
  ai-defender run npm test
  ai-defender run git push origin feature-a
  ai-defender run --shell sh 'cargo fmt && cargo test'

Approval is never automatic: \`approve\` refuses --yes, --json, --non-interactive and
--passphrase-file, and needs you to type "approve" after reviewing the exact operation.

Managed execution controls only commands run through \`ai-defender run\`. With hooks
installed, Claude Code and Codex tool calls listed as protected are checked before they run;
other tools, other agents and commands you run yourself are not intercepted.

Exit codes: 0 ok, 1 failure, 2 usage, 3 engine unavailable or unverified, 4 engine protocol
error, 5 security check failed, 6 confirmation or authorization required, 7 not initialised,
8 denied by policy (run), 9 unsupported command (run), 124 timed out (run), 125 outcome
unknown (run). When \`run\` executes the command, it exits with the command's own status.

Documentation: docs/CLI.md, docs/TRUST_MODEL.md, docs/POLICY_EVALUATION.md
`;

export function help(out: Output): void {
  out.line(TEXT.trimEnd());
}
