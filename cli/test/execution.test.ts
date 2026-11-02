/**
 * `ai-defender run`, `ai-defender git` and `ai-defender execution` against the real engine in
 * isolated HOME/XDG directories, with a temporary repository and a local bare remote. Every
 * credential below is fake and nonfunctional.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { before, test } from "node:test";

import { splitRun } from "../src/cli.js";
import { parseRunArgs } from "../src/commands/execution.js";
import { ExitCode } from "../src/utils/exit-codes.js";
import { ENGINE, ScriptedPrompter, cli, sandbox, tempDir, type Sandbox } from "./helpers.js";

const PASS = "correct horse battery staple";
const GITHUB = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000";

before(() => {
  assert.ok(existsSync(ENGINE), `engine binary not found at ${ENGINE}; run cargo build -p agentguard-engine-cli`);
});

interface World {
  box: Sandbox;
  cwd: string;
}

function git(cwd: string, home: string, ...args: string[]): void {
  const r = spawnSync("git", args, { cwd, env: { PATH: process.env["PATH"], HOME: home, GIT_CONFIG_NOSYSTEM: "1" }, stdio: "ignore" });
  assert.equal(r.status, 0, `git ${args.join(" ")}`);
}

async function world(): Promise<World> {
  const box = sandbox();
  writeFileSync(path.join(box.home, ".gitconfig"), "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n");
  const base = tempDir("agentguard-run-");
  const cwd = path.join(base, "app");
  const remote = path.join(base, "remote.git");
  mkdirSync(cwd);
  writeFileSync(path.join(cwd, "package.json"), "{}\n");
  git(base, box.home, "init", "-q", "--bare", remote);
  git(cwd, box.home, "init", "-q");
  git(cwd, box.home, "add", "package.json");
  git(cwd, box.home, "commit", "-qm", "init");
  git(cwd, box.home, "remote", "add", "origin", remote);
  git(cwd, box.home, "remote", "add", "creds", `https://user:${GITHUB}@example.invalid/org/repo.git`);
  const pass = path.join(box.home, "pass.txt");
  writeFileSync(pass, `${PASS}\n`);
  chmodSync(pass, 0o600);
  const r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", pass], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  return { box, cwd };
}

test("run options and the command's own flags are kept apart", () => {
  assert.deepEqual(splitRun(["--json", "run", "git", "log", "--oneline", "-n", "3"]), {
    global: ["--json"],
    command: ["git", "log", "--oneline", "-n", "3"],
  });
  assert.deepEqual(splitRun(["status", "--json"]), { global: ["status", "--json"], command: undefined });
  const o = parseRunArgs(["--timeout", "30", "--shell", "sh", "--", "cargo fmt && cargo test"]);
  assert.equal(o.timeout, 30);
  assert.equal(o.shell, "sh");
  assert.deepEqual(o.command, ["cargo fmt && cargo test"]);
  assert.deepEqual(parseRunArgs(["npm", "test", "--", "--watch"]).command, ["npm", "test", "--", "--watch"]);
  assert.throws(() => parseRunArgs([]));
  assert.throws(() => parseRunArgs(["--timeout", "0", "ls"]));
  assert.throws(() => parseRunArgs(["--shell", "zsh", "ls"]));
});

test("an allowed command runs and exits with its own status; output is redacted", async () => {
  const w = await world();
  const ok = await cli(["run", "git", "status"], { env: w.box.env, cwd: w.cwd });
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stdout, /On branch main/);
  assert.match(ok.stderr, /ai-defender: completed · exit 0 · execution ex_/);
  const failing = await cli(["run", "false"], { env: w.box.env, cwd: w.cwd });
  assert.equal(failing.code, 1, failing.stderr);
  const printed = await cli(["run", "printf", "%s\\n", GITHUB], { env: w.box.env, cwd: w.cwd });
  assert.equal(printed.code, 0, printed.stderr);
  assert.ok(!printed.stdout.includes(GITHUB.slice(4)), "secrets printed by a command are redacted");
  const json = await cli(["--json", "run", "git", "rev-parse", "--abbrev-ref", "HEAD"], { env: w.box.env, cwd: w.cwd });
  assert.equal(json.code, 0, json.stderr);
  const doc = JSON.parse(json.stdout) as { data: { outcome: string; stdout: string; enforcement: { global_enforcement: boolean } } };
  assert.equal(doc.data.outcome, "executed");
  assert.equal(doc.data.stdout.trim(), "main");
  assert.equal(doc.data.enforcement.global_enforcement, false);
});

test("denied and unsupported commands never run", async () => {
  const w = await world();
  const denied = await cli(["run", "rm", "-rf", "../"], { env: w.box.env, cwd: w.cwd });
  assert.equal(denied.code, ExitCode.Denied, denied.stdout + denied.stderr);
  assert.match(denied.stdout, /Denied/);
  assert.ok(existsSync(path.join(w.cwd, "package.json")));
  const sudo = await cli(["run", "sudo", "ls"], { env: w.box.env, cwd: w.cwd });
  assert.equal(sudo.code, ExitCode.Unsupported, sudo.stderr);
  const shell = await cli(["run", "--shell", "sh", "echo $(touch pwned)"], { env: w.box.env, cwd: w.cwd });
  assert.equal(shell.code, ExitCode.Unsupported, shell.stderr);
  assert.match(shell.stderr, /unsupported shell syntax/);
  assert.ok(!existsSync(path.join(w.cwd, "pwned")));
  const force = await cli(["run", "git", "push", "--force", "origin", "main"], { env: w.box.env, cwd: w.cwd });
  assert.equal(force.code, ExitCode.Denied, force.stdout);
  assert.match(force.stdout, /profile:git-force-push/);
});

test("a push needs approval; the approved grant runs exactly that push once", async () => {
  const w = await world();
  const first = await cli(["--json", "run", "git", "push", "origin", "main"], { env: w.box.env, cwd: w.cwd });
  assert.equal(first.code, ExitCode.ActionRequired, first.stderr);
  const doc = JSON.parse(first.stdout) as { data: { outcome: string; approval: { approval_id: string; claim_token: string } } };
  assert.equal(doc.data.outcome, "approval-required");
  const { approval_id: id, claim_token: token } = doc.data.approval;
  const approved = await cli(["approve", id], { env: w.box.env, cwd: w.cwd, prompter: new ScriptedPrompter(true, ["approve", PASS]) });
  assert.equal(approved.code, ExitCode.Ok, approved.stderr);
  const env = { ...w.box.env, AGENTGUARD_CLAIM_TOKEN: token };
  const other = await cli(["run", "--approval", id, "--", "git", "push", "origin", "HEAD:other"], { env, cwd: w.cwd });
  assert.equal(other.code, ExitCode.Failure, "a different push is not authorized");
  assert.match(other.stderr, /operation-mismatch/);
  const pushed = await cli(["run", "--approval", id, "--", "git", "push", "origin", "main"], { env, cwd: w.cwd });
  assert.equal(pushed.code, 0, pushed.stderr);
  const again = await cli(["run", "--approval", id, "--", "git", "push", "origin", "main"], { env, cwd: w.cwd });
  assert.notEqual(again.code, 0);
  assert.match(again.stderr, /replay/);
  const history = await cli(["execution", "history"], { env: w.box.env, cwd: w.cwd });
  assert.equal(history.code, ExitCode.Ok, history.stderr);
  assert.match(history.stdout, /completed/);
  assert.match(history.stdout, /not intercepted/);
});

test("in a terminal, run waits for the human approval and then runs", async () => {
  const w = await world();
  writeFileSync(path.join(w.cwd, "a.txt"), "a\n");
  git(w.cwd, w.box.home, "add", "a.txt");
  const waiting = cli(["run", "git", "commit", "-m", "add a"], { env: w.box.env, cwd: w.cwd, prompter: new ScriptedPrompter(true) });
  let id: string | undefined;
  for (let i = 0; i < 40 && id === undefined; i += 1) {
    await new Promise((r) => setTimeout(r, 250));
    const list = await cli(["--json", "approvals"], { env: w.box.env, cwd: w.cwd });
    const pending = (JSON.parse(list.stdout) as { data: { approvals: Array<{ approval_id: string; status: string }> } }).data.approvals.find((a) => a.status === "pending");
    id = pending?.approval_id;
  }
  assert.ok(id, "an approval request was created");
  const approved = await cli(["approve", id], { env: w.box.env, cwd: w.cwd, prompter: new ScriptedPrompter(true, ["approve", PASS]) });
  assert.equal(approved.code, ExitCode.Ok, approved.stderr);
  const r = await waiting;
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /ai-defender approve/);
  assert.match(r.stderr, /completed · exit 0/);
});

test("git inspect and status show state without credentials", async () => {
  const w = await world();
  const r = await cli(["git", "inspect"], { env: w.box.env, cwd: w.cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  assert.match(r.stdout, /https:\/\/example\.invalid\/org\/repo\.git/);
  assert.ok(!r.stdout.includes(GITHUB.slice(4)) && !r.stdout.includes("user:"));
  const s = await cli(["git", "status"], { env: w.box.env, cwd: w.cwd });
  assert.equal(s.code, ExitCode.Ok, s.stderr);
  assert.match(s.stdout, /Branch:\s+main/);
});

test("help states that managed execution is not global enforcement", async () => {
  const r = await cli(["--help"], { env: sandbox().env, cwd: tempDir() });
  assert.match(r.stdout, /not intercepted/);
  assert.match(r.stdout, /ai-defender run/);
});
