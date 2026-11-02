/**
 * `ai-defender integrations` and the hook entry point against the real engine, with provider
 * configuration in an isolated HOME. The developer's own Claude Code and Codex configuration
 * is never read or written.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { before, test } from "node:test";

import { ExitCode } from "../src/utils/exit-codes.js";
import { ENGINE, cli, sandbox, tempDir, type Sandbox } from "./helpers.js";

const PASS = "correct horse battery staple";

before(() => {
  assert.ok(existsSync(ENGINE), `engine binary not found at ${ENGINE}; run cargo build -p agentguard-engine-cli`);
});

interface World {
  box: Sandbox;
  cwd: string;
  engine: string;
  pass: string;
}

/** An installed-looking engine: owner-only write access on the file and its directory. */
function installedEngine(): string {
  const dir = path.join(tempDir("agentguard-engine-"), "bin");
  mkdirSync(dir);
  chmodSync(dir, 0o755);
  const file = path.join(dir, "agentguard-engine");
  copyFileSync(ENGINE, file);
  chmodSync(file, 0o755);
  return file;
}

async function world(): Promise<World> {
  const engine = installedEngine();
  const box = sandbox(engine);
  const cwd = path.join(tempDir("agentguard-hooks-"), "app");
  mkdirSync(cwd);
  writeFileSync(path.join(cwd, "package.json"), "{}\n");
  writeFileSync(path.join(box.home, ".gitconfig"), "[user]\n\tname = T\n\temail = t@example.invalid\n");
  spawnSync("git", ["init", "-q"], { cwd, env: { PATH: process.env["PATH"], HOME: box.home } });
  const pass = path.join(box.home, "pass.txt");
  writeFileSync(pass, `${PASS}\n`);
  chmodSync(pass, 0o600);
  const r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", pass], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  return { box, cwd, engine, pass };
}

function hook(w: World, provider: string, event: string, payload: unknown): { status: number | null; stdout: string; ms: number } {
  const start = process.hrtime.bigint();
  const r = spawnSync(w.engine, ["hook", provider, event], {
    input: JSON.stringify(payload),
    env: w.box.env as NodeJS.ProcessEnv,
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, ms: Number(process.hrtime.bigint() - start) / 1e6 };
}

test("install keeps user hooks, verify passes, uninstall removes only AI Defender's entries", async () => {
  const w = await world();
  const settings = path.join(w.box.home, ".claude", "settings.json");
  mkdirSync(path.dirname(settings), { recursive: true });
  const user = { model: "opus", hooks: { Stop: [{ hooks: [{ type: "command", command: "notify-send done" }] }] } };
  writeFileSync(settings, JSON.stringify(user, null, 2));
  const refused = await cli(["integrations", "install", "claude"], { env: w.box.env, cwd: w.cwd });
  assert.equal(refused.code, ExitCode.ActionRequired, "installation needs explicit confirmation");
  for (const p of ["claude", "codex"]) {
    const r = await cli(["integrations", "install", p, "--non-interactive", "--yes"], { env: w.box.env, cwd: w.cwd });
    assert.equal(r.code, ExitCode.Ok, r.stderr + r.stdout);
  }
  const installed = JSON.parse(readFileSync(settings, "utf8")) as { model: string; hooks: Record<string, unknown[]> };
  assert.equal(installed.model, "opus");
  assert.equal(installed.hooks["Stop"]?.length, 1);
  assert.ok(existsSync(path.join(w.box.home, ".codex", "hooks.json")));
  const status = await cli(["--json", "integrations", "status"], { env: w.box.env, cwd: w.cwd });
  const doc = JSON.parse(status.stdout) as { data: { integrations: Array<{ provider: string; state: string }>; global_enforcement: boolean } };
  assert.deepEqual(doc.data.integrations.map((i) => i.state), ["installed", "installed"]);
  assert.equal(doc.data.global_enforcement, false);
  const verify = await cli(["integrations", "verify"], { env: w.box.env, cwd: w.cwd });
  assert.equal(verify.code, ExitCode.Ok, verify.stdout + verify.stderr);
  assert.doesNotMatch(verify.stdout, /FAIL/);
  const coverage = await cli(["integrations", "coverage", "codex"], { env: w.box.env, cwd: w.cwd });
  assert.match(coverage.stdout, /UNSUPPORTED\s+Hosted tools/);
  assert.match(coverage.stdout, /not complete/);
  const noPass = await cli(["integrations", "uninstall", "claude", "--non-interactive", "--yes"], { env: w.box.env, cwd: w.cwd });
  assert.equal(noPass.code, ExitCode.ActionRequired, "removing hooks needs the passphrase");
  const removed = await cli(["integrations", "uninstall", "claude", "--non-interactive", "--yes", "--passphrase-file", w.pass], { env: w.box.env, cwd: w.cwd });
  assert.equal(removed.code, ExitCode.Ok, removed.stderr);
  assert.deepEqual(JSON.parse(readFileSync(settings, "utf8")), user, "the user's configuration is restored exactly");
});

test("the hook process blocks with the documented response and allows ordinary work silently", async () => {
  const w = await world();
  const base = { session_id: "8d9c1f0e-1111-4c4c-9d9d-123456789abc", cwd: w.cwd, hook_event_name: "PreToolUse", tool_use_id: "t" };
  const push = hook(w, "claude", "PreToolUse", { ...base, tool_name: "Bash", tool_input: { command: "git push origin main" } });
  assert.equal(push.status, 0);
  const out = JSON.parse(push.stdout) as { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /ai-defender approve [0-9a-f]{8}/);
  const ok = hook(w, "codex", "PreToolUse", { ...base, model: "m", turn_id: "x", tool_name: "Bash", tool_input: { command: "npm test" } });
  assert.equal(ok.status, 0);
  assert.equal(ok.stdout, "", "ALLOW adds no decision");
  const broken = spawnSync(w.engine, ["hook", "claude", "PreToolUse"], { input: "{", env: w.box.env as NodeJS.ProcessEnv, encoding: "utf8" });
  assert.match(broken.stdout, /"permissionDecision":"deny"/);
});

test("help and status describe hook coverage without claiming full protection", async () => {
  const r = await cli(["--help"], { env: sandbox().env, cwd: tempDir() });
  assert.match(r.stdout, /integrations install claude\|codex/);
  assert.match(r.stdout, /not intercepted/);
});
