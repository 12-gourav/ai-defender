/**
 * The CLI against the real Rust engine (target/debug/agentguard-engine, or
 * AGENTGUARD_TEST_ENGINE), in isolated temporary HOME/XDG directories. These tests fail, not
 * skip, when the engine is missing: build it with `cargo build -p agentguard-engine-cli`.
 */

import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { before, test } from "node:test";

import { ExitCode } from "../src/utils/exit-codes.js";
import { ENGINE, ScriptedPrompter, cli, sandbox, tempDir } from "./helpers.js";

const PASS = "correct horse battery staple";

before(() => {
  assert.ok(existsSync(ENGINE), `engine binary not found at ${ENGINE}; run cargo build -p agentguard-engine-cli`);
});

function project(): string {
  const dir = path.join(tempDir("agentguard-proj-"), "app");
  mkdirSync(path.join(dir, ".git"), { recursive: true });
  writeFileSync(path.join(dir, "package.json"), "{}\n");
  return dir;
}

function passFile(home: string, mode = 0o600): string {
  const file = path.join(home, "pass.txt");
  writeFileSync(file, `${PASS}\n`);
  chmodSync(file, mode);
  return file;
}

async function initialised() {
  const box = sandbox();
  const cwd = project();
  const r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", passFile(box.home)], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  return { box, cwd };
}

test("non-interactive init cannot bypass confirmation or authorization", async () => {
  const box = sandbox();
  const cwd = project();
  let r = await cli(["init", "--non-interactive"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.ActionRequired);
  r = await cli(["init", "--non-interactive", "--yes"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.ActionRequired);
  assert.match(r.stderr, /passphrase/);
  r = await cli(["init", "--yes"], { env: box.env, cwd, prompter: new ScriptedPrompter(false) });
  assert.equal(r.code, ExitCode.ActionRequired, "no terminal means no prompt and no default");
  r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", passFile(box.home, 0o644)], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Failure, "a readable passphrase file is refused");
  assert.equal(existsSync(path.join(cwd, ".agentguard")), false);
  assert.equal(existsSync(path.join(box.home, ".config", "agentguard")), false);
});

test("interactive init asks, creates trust, registers, and declining changes nothing", async () => {
  const box = sandbox();
  const cwd = project();
  const declined = await cli(["init"], { env: box.env, cwd, prompter: new ScriptedPrompter(true, [false]) });
  assert.equal(declined.code, ExitCode.Failure);
  assert.equal(existsSync(path.join(cwd, ".agentguard")), false);
  const prompter = new ScriptedPrompter(true, [true, PASS, PASS]);
  const r = await cli(["init", "--name", "Demo"], { env: box.env, cwd, prompter });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  assert.equal(prompter.asked.length, 3);
  assert.match(r.stdout, /Security profile:\s+balanced/);
  assert.match(r.stderr, /Back them up/);
  assert.ok(readFileSync(path.join(cwd, ".agentguard", "config.yaml"), "utf8").includes("Demo"));
});

test("init is idempotent and never overwrites existing configuration", async () => {
  const { box, cwd } = await initialised();
  const config = path.join(cwd, ".agentguard", "config.yaml");
  const edited = `${readFileSync(config, "utf8")}# my note\n`;
  writeFileSync(config, edited);
  const r = await cli(["init", "--non-interactive", "--yes"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  assert.match(r.stdout, /already registered/);
  assert.equal(readFileSync(config, "utf8"), edited);
});

test("status distinguishes installed, initialized, registered, verified, integration and enforcement", async () => {
  const box = sandbox();
  const cwd = project();
  let r = await cli(["status", "--json"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok);
  let data = JSON.parse(r.stdout).data;
  assert.equal(data.trust_store.state, "uninitialized");
  assert.equal(data.enforcement.state, "inactive");
  await cli(["init", "--non-interactive", "--yes", "--passphrase-file", passFile(box.home)], { env: box.env, cwd });
  r = await cli(["status", "--json"], { env: box.env, cwd });
  const envelope = JSON.parse(r.stdout);
  data = envelope.data;
  assert.equal(envelope.engine.verified, false, "development engine is never reported as verified");
  assert.equal(data.trust_store.state, "verified");
  assert.equal(data.project.registration.state, "registered");
  assert.equal(data.policy.state, "verified");
  assert.equal(data.integration.state, "not-configured");
  assert.equal(data.enforcement.state, "inactive");
  const human = await cli(["status"], { env: box.env, cwd });
  assert.match(human.stdout, /Enforcement:\s+Not active/);
  assert.match(human.stdout, /UNVERIFIED development build/);
});

test("check passes with warnings when healthy and exits 5 on integrity failure", async () => {
  const { box, cwd } = await initialised();
  let r = await cli(["check"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stdout);
  assert.match(r.stdout, /WARN\s+Agent integration configured/);
  const registry = path.join(box.home, ".config", "agentguard", "registry");
  const latest = readdirSync(registry).sort().at(-1)!;
  const file = path.join(registry, latest);
  writeFileSync(file, readFileSync(file, "utf8").replace('"trusted"', '"revoked"'));
  r = await cli(["check"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.CheckFailed);
  assert.match(r.stdout, /FAIL\s+Trusted policy integrity/);
  r = await cli(["policy", "show"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.CheckFailed);
});

test("policy show displays the engine's effective policy and project config cannot weaken it", async () => {
  const { box, cwd } = await initialised();
  const r = await cli(["policy", "show", "--json"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok);
  const data = JSON.parse(r.stdout).data;
  assert.ok(data.layers.mandatory.length > 10);
  assert.equal(data.integrity, "verified");
  assert.equal(data.profile.name, "balanced");

  const other = project();
  mkdirSync(path.join(other, ".agentguard"));
  writeFileSync(path.join(other, ".agentguard", "config.yaml"), "version: 1\nrules:\n- id: yolo\n  decision: ALLOW\n  reason: allow everything\n  match: { category: terminal }\n");
  const bad = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", passFile(box.home)], { env: box.env, cwd: other });
  assert.equal(bad.code, ExitCode.Failure);
  assert.match(bad.stderr, /ALLOW rules are not permitted|only add restrictions/);
});

test("project list, inspect and revocation with explicit confirmation", async () => {
  const { box, cwd } = await initialised();
  let r = await cli(["project", "list", "--json"], { env: box.env, cwd });
  assert.equal(JSON.parse(r.stdout).data.projects.length, 1);
  r = await cli(["project", "inspect", "--json"], { env: box.env, cwd });
  assert.equal(JSON.parse(r.stdout).data.registration.status, "trusted");

  r = await cli(["project", "revoke", "--non-interactive"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.ActionRequired, "revocation is never silently skipped or assumed");
  r = await cli(["project", "revoke", "--non-interactive", "--yes"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.ActionRequired);
  r = await cli(["project", "inspect", "--json"], { env: box.env, cwd });
  assert.equal(JSON.parse(r.stdout).data.registration.status, "trusted", "refusals change nothing");
  r = await cli(["project", "revoke", "--non-interactive", "--yes", "--passphrase-file", passFile(box.home)], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  r = await cli(["status", "--json"], { env: box.env, cwd });
  assert.equal(JSON.parse(r.stdout).data.project.registration.state, "revoked");
  r = await cli(["init", "--non-interactive", "--yes"], { env: box.env, cwd });
  assert.notEqual(r.code, ExitCode.Ok, "init does not silently re-trust a revoked project");
});

test("unregistered directories are reported, and outputs never contain the passphrase", async () => {
  const { box, cwd } = await initialised();
  const elsewhere = tempDir("agentguard-else-");
  const r = await cli(["project", "inspect"], { env: box.env, cwd: elsewhere });
  assert.equal(r.code, ExitCode.NotInitialized);
  const outputs: string[] = [];
  for (const argv of [["status", "--json"], ["check", "--json"], ["policy", "show", "--json"], ["project", "list", "--json"], ["version", "--json"]]) {
    const res = await cli(argv, { env: box.env, cwd });
    outputs.push(res.stdout, res.stderr);
  }
  const text = outputs.join("\n");
  assert.ok(!text.includes(PASS));
  assert.ok(!/"ciphertext"|"seed"|PRIVATE KEY/.test(text));
});
