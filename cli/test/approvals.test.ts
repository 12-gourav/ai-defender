/**
 * Human approval commands against the real engine, in isolated HOME/XDG directories. Pending
 * requests are created the way an agent integration would: by launching the engine with
 * `--agent claude` (the CLI itself never does this).
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { before, test } from "node:test";

import { ExitCode } from "../src/utils/exit-codes.js";
import { ENGINE, ScriptedPrompter, cli, sandbox, tempDir, type Sandbox } from "./helpers.js";

const PASS = "correct horse battery staple";

before(() => {
  assert.ok(existsSync(ENGINE), `engine binary not found at ${ENGINE}; run cargo build -p agentguard-engine-cli`);
});

/** Run one engine request as an agent integration would. */
function asAgent(box: Sandbox, command: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const child = spawn(ENGINE, ["--agent", "claude"], { env: box.env as NodeJS.ProcessEnv, stdio: ["pipe", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (chunk: Buffer) => (out += chunk.toString("utf8")));
    child.on("error", reject);
    child.on("close", () => resolve(JSON.parse(out) as Record<string, unknown>));
    child.stdin.end(JSON.stringify({ protocol_version: 1, request_id: "agent", command, arguments: args }));
  });
}

interface World {
  box: Sandbox;
  cwd: string;
}

async function world(): Promise<World> {
  const box = sandbox();
  const cwd = path.join(tempDir("agentguard-proj-"), "app");
  mkdirSync(path.join(cwd, ".git"), { recursive: true });
  writeFileSync(path.join(cwd, "package.json"), "{}\n");
  const pass = path.join(box.home, "pass.txt");
  writeFileSync(pass, `${PASS}\n`);
  chmodSync(pass, 0o600);
  const r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", pass], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  return { box, cwd };
}

async function operation(w: World, target: string): Promise<Record<string, unknown>> {
  const status = await cli(["status", "--json"], { env: w.box.env, cwd: w.cwd });
  const version = JSON.parse(status.stdout).data.policy.version as string;
  return {
    protocol: "agentguard.authz.v1",
    request_id: randomUUID(),
    agent: { kind: "claude" },
    project: { root: w.cwd },
    action: { category: "git", operation: "push", remote: "origin", target_ref: target },
    working_directory: w.cwd,
    policy_version: version,
  };
}

async function pending(w: World, target = "feature-security"): Promise<{ id: string; token: string; request: Record<string, unknown> }> {
  const request = await operation(w, target);
  const r = await asAgent(w.box, "approval.request", { request });
  assert.equal(r["success"], true, JSON.stringify(r));
  const approval = (r["data"] as { approval: { approval_id: string; claim_token: string } }).approval;
  return { id: approval.approval_id, token: approval.claim_token, request };
}

async function statusOf(w: World, id: string): Promise<string> {
  const r = await cli(["approvals", "show", id, "--json"], { env: w.box.env, cwd: w.cwd });
  return JSON.parse(r.stdout).data.approval.status as string;
}

test("approve refuses every non-human route and leaves the request pending", async () => {
  const w = await world();
  const { id } = await pending(w);
  const attempts: Array<[string[], ScriptedPrompter]> = [
    [["approve", id, "--yes"], new ScriptedPrompter(true, ["approve", PASS])],
    [["approve", id, "--json"], new ScriptedPrompter(true, ["approve", PASS])],
    [["approve", id, "--non-interactive"], new ScriptedPrompter(true, ["approve", PASS])],
    [["approve", id, "--passphrase-file", path.join(w.box.home, "pass.txt")], new ScriptedPrompter(true, ["approve", PASS])],
    [["approve", id], new ScriptedPrompter(false)],
  ];
  for (const [argv, prompter] of attempts) {
    const r = await cli(argv, { env: w.box.env, cwd: w.cwd, prompter });
    assert.equal(r.code, ExitCode.ActionRequired, `${argv.join(" ")}: ${r.stderr}`);
    assert.match(r.stderr + r.stdout, /cannot approve an operation/);
    assert.equal(prompter.asked.length, 0, "nothing was even asked");
  }
  assert.equal(await statusOf(w, id), "pending");
});

test("only the typed word approve approves; anything else records no decision", async () => {
  const w = await world();
  const { id } = await pending(w);
  for (const answer of ["", "y", "yes", "approved", "APPROVE please"]) {
    const prompter = new ScriptedPrompter(true, [answer, PASS]);
    const r = await cli(["approve", id], { env: w.box.env, cwd: w.cwd, prompter });
    assert.equal(r.code, ExitCode.Failure, answer);
    assert.equal(prompter.asked.length, 1, "no passphrase is asked without an explicit approve");
  }
  assert.equal(await statusOf(w, id), "pending");
});

test("interactive approval shows the exact operation and issues a one-time grant the agent can use once", async () => {
  const w = await world();
  const { id, token, request } = await pending(w);
  const prompter = new ScriptedPrompter(true, ["approve", PASS]);
  const r = await cli(["approve", id.slice(0, 8)], { env: w.box.env, cwd: w.cwd, prompter });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  for (const expected of [/Approval Required/, /Git push/, /origin feature-security/, /Claude Code/, /High/, /One exact operation/, /sends local commits to a remote repository/, /APPROVED: one exact operation, once/]) {
    assert.match(r.stdout, expected);
  }
  assert.ok(!r.stdout.includes(token) && !r.stderr.includes(token), "the claim token is never shown to the human");
  assert.match(prompter.asked[0] ?? "", /Type "approve"/);
  assert.match(prompter.asked[1] ?? "", /passphrase/i);

  const used = await asAgent(w.box, "authorization.consume", { request: { ...request, request_id: randomUUID() }, approval_id: id, claim_token: token });
  assert.equal(used["success"], true, JSON.stringify(used));
  const replay = await asAgent(w.box, "authorization.consume", { request: { ...request, request_id: randomUUID() }, approval_id: id, claim_token: token });
  assert.equal(replay["success"], false);
  assert.match(JSON.stringify(replay), /approval\.replay/);

  const changed = await pending(w, "main");
  const p2 = new ScriptedPrompter(true, ["approve", PASS]);
  assert.equal((await cli(["approve", changed.id], { env: w.box.env, cwd: w.cwd, prompter: p2 })).code, ExitCode.Ok);
  const wrong = await asAgent(w.box, "authorization.consume", { request: { ...changed.request, action: { category: "git", operation: "push", remote: "origin", target_ref: "feature-security" } }, approval_id: changed.id, claim_token: changed.token });
  assert.match(JSON.stringify(wrong), /approval\.operation-mismatch/);
});

test("the CLI cannot act for an agent, and a wrong passphrase approves nothing", async () => {
  const w = await world();
  const { id } = await pending(w);
  const prompter = new ScriptedPrompter(true, ["approve", "not the passphrase"]);
  const r = await cli(["approve", id], { env: w.box.env, cwd: w.cwd, prompter });
  assert.equal(r.code, ExitCode.Failure);
  assert.equal(await statusOf(w, id), "pending");
});

test("reject, cancel and revoke withdraw authority with explicit confirmation", async () => {
  const w = await world();
  const a = await pending(w, "a");
  let r = await cli(["reject", a.id, "--non-interactive"], { env: w.box.env, cwd: w.cwd });
  assert.equal(r.code, ExitCode.ActionRequired, "never silently assumed");
  r = await cli(["reject", a.id, "--yes", "--reason", "not during the freeze"], { env: w.box.env, cwd: w.cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  assert.equal(await statusOf(w, a.id), "rejected");

  const b = await pending(w, "b");
  r = await cli(["approvals", "cancel", b.id], { env: w.box.env, cwd: w.cwd, prompter: new ScriptedPrompter(true, [true]) });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  assert.equal(await statusOf(w, b.id), "cancelled");

  const c = await pending(w, "c");
  assert.equal((await cli(["approve", c.id], { env: w.box.env, cwd: w.cwd, prompter: new ScriptedPrompter(true, ["approve", PASS]) })).code, ExitCode.Ok);
  r = await cli(["approvals", "revoke", c.id, "--yes"], { env: w.box.env, cwd: w.cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  const used = await asAgent(w.box, "authorization.consume", { request: c.request, approval_id: c.id, claim_token: c.token });
  assert.equal(used["success"], false);

  const d = await pending(w, "d");
  r = await cli(["approve", d.id], { env: w.box.env, cwd: w.cwd, prompter: new ScriptedPrompter(true, ["reject"]) });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  assert.equal(await statusOf(w, d.id), "rejected");
});

test("listings and JSON output never expose claim tokens or secrets", async () => {
  const w = await world();
  const { id, token } = await pending(w);
  const human = await cli(["approvals"], { env: w.box.env, cwd: w.cwd });
  assert.equal(human.code, ExitCode.Ok, human.stderr);
  assert.match(human.stdout, /1 pending/);
  assert.match(human.stdout, new RegExp(id));
  assert.match(human.stdout, /expires|Expires/);
  const outputs = [human.stdout];
  for (const argv of [["approvals", "--json"], ["approvals", "show", id, "--json"]]) {
    const r = await cli(argv, { env: w.box.env, cwd: w.cwd });
    assert.equal(r.code, ExitCode.Ok, r.stderr);
    outputs.push(r.stdout);
  }
  const text = outputs.join("\n");
  assert.ok(!text.includes(token) && !text.includes(token.slice(5)));
  assert.ok(!/claim|verifier|signature|passphrase/i.test(text.replace(/"decided_by"/g, "")), "no secret-bearing fields");
  const audit = readFileSync(path.join(w.box.home, ".config", "agentguard", "audit", "trust.jsonl"), "utf8");
  assert.ok(!audit.includes(token.slice(5)));
  assert.equal((await cli(["approvals", "show", "00000000-0000-4000-8000-000000000000"], { env: w.box.env, cwd: w.cwd })).code, ExitCode.Failure);
});
