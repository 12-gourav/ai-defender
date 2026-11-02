/**
 * The multi-project and maintenance commands against the real engine in isolated HOME/XDG
 * directories: projects, history, doctor, dashboard, policy validate, update, repair.
 */

import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { before, test } from "node:test";

import { ExitCode } from "../src/utils/exit-codes.js";
import { ENGINE, cli, sandbox, tempDir, type Sandbox } from "./helpers.js";

before(() => {
  assert.ok(existsSync(ENGINE), `engine binary not found at ${ENGINE}`);
});

interface World {
  box: Sandbox;
  a: string;
  b: string;
  pass: string;
}

function project(base: string, name: string): string {
  const dir = path.join(base, name);
  mkdirSync(dir);
  writeFileSync(path.join(dir, "package.json"), "{}\n");
  return dir;
}

async function world(): Promise<World> {
  const box = sandbox();
  const base = tempDir("ai-defender-projects-");
  const a = project(base, "alpha-service");
  const b = project(base, "beta-web");
  const pass = path.join(box.home, "pass.txt");
  writeFileSync(pass, "correct horse battery staple\n");
  chmodSync(pass, 0o600);
  for (const cwd of [a, b]) {
    const r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", pass], { env: box.env, cwd });
    assert.equal(r.code, ExitCode.Ok, r.stderr);
  }
  return { box, a, b, pass };
}

interface Listed {
  id: string;
  name: string;
  status: string;
  profile: string;
}

async function listed(w: World): Promise<Listed[]> {
  const r = await cli(["--json", "projects", "list"], { env: w.box.env, cwd: w.a });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  return (JSON.parse(r.stdout) as { data: { projects: Listed[] } }).data.projects;
}

test("two projects share one trusted identity and are listed, inspected, added and revoked", async () => {
  const w = await world();
  const table = await cli(["projects", "list"], { env: w.box.env, cwd: w.a });
  assert.match(table.stdout, /AI DEFENDER — REGISTERED PROJECTS/);
  assert.match(table.stdout, /alpha-service .*Balanced .*None .*Verified/);
  assert.match(table.stdout, /Total projects: 2/);
  const projects = await listed(w);
  assert.deepEqual(projects.map((p) => p.name).sort(), ["alpha-service", "beta-web"]);
  const beta = projects.find((p) => p.name === "beta-web");
  assert.ok(beta);
  const inspected = await cli(["projects", "inspect", beta.id.slice(0, 10)], { env: w.box.env, cwd: w.a });
  assert.equal(inspected.code, ExitCode.Ok, inspected.stderr);
  assert.match(inspected.stdout, /beta-web/);
  assert.match(inspected.stdout, /Security coverage/);
  assert.equal((await cli(["projects", "inspect", "nonexistent"], { env: w.box.env, cwd: w.a })).code, ExitCode.NotInitialized);
  const third = project(path.dirname(w.a), "gamma-cli");
  const added = await cli(["projects", "add", third, "--non-interactive", "--yes", "--passphrase-file", w.pass], { env: w.box.env, cwd: w.a });
  assert.equal(added.code, ExitCode.Ok, added.stderr);
  assert.equal((await listed(w)).length, 3);
  const noPass = await cli(["projects", "revoke", "gamma-cli", "--non-interactive", "--yes"], { env: w.box.env, cwd: w.a });
  assert.equal(noPass.code, ExitCode.ActionRequired, "revoking needs the passphrase");
  const revoked = await cli(["projects", "revoke", "gamma-cli", "--non-interactive", "--yes", "--passphrase-file", w.pass], { env: w.box.env, cwd: w.a });
  assert.equal(revoked.code, ExitCode.Ok, revoked.stderr);
  assert.equal((await listed(w)).find((p) => p.name === "gamma-cli")?.status, "Revoked");
});

test("history shows blocked operations and approval activity from the audit log", async () => {
  const w = await world();
  assert.equal((await cli(["run", "rm", "-rf", "../"], { env: w.box.env, cwd: w.a })).code, ExitCode.Denied);
  const blocked = await cli(["--json", "history", "--blocked"], { env: w.box.env, cwd: w.a });
  const events = (JSON.parse(blocked.stdout) as { data: { events: Array<{ decision: string | null; kind: string }> } }).data.events;
  assert.ok(events.length > 0);
  assert.ok(events.some((e) => e.kind === "execution-policy-decision" && e.decision === "deny"), JSON.stringify(events));
  const text = await cli(["history", "--limit", "5"], { env: w.box.env, cwd: w.a });
  assert.match(text.stdout, /Recent security events \([1-5], newest first\)/);
  assert.equal((await cli(["history", "--limit", "0"], { env: w.box.env, cwd: w.a })).code, ExitCode.Usage);
  assert.equal((await cli(["history", "--blocked", "--approvals"], { env: w.box.env, cwd: w.a })).code, ExitCode.Usage);
});

test("doctor, dashboard, policy validate, update and repair report real state", async () => {
  const w = await world();
  const doctor = await cli(["--json", "doctor"], { env: w.box.env, cwd: w.a });
  const checks = (JSON.parse(doctor.stdout) as { data: { checks: Array<{ id: string; status: string; detail: string }> } }).data.checks;
  assert.equal(checks.find((c) => c.id === "engine")?.status, "warn", "a development engine is never reported as verified");
  assert.equal(checks.find((c) => c.id === "protocol")?.status, "pass");
  assert.equal(checks.find((c) => c.id === "git")?.status, "pass");
  assert.equal(doctor.code, checks.some((c) => c.status === "fail") ? ExitCode.CheckFailed : ExitCode.Ok);
  const dash = await cli(["--json", "dashboard"], { env: w.box.env, cwd: w.a });
  const d = (JSON.parse(dash.stdout) as { data: { projects: { total: number; verified: number }; pending_approvals: number; trust: string; integrations: unknown[] } }).data;
  assert.equal(d.projects.total, 2);
  assert.equal(d.projects.verified, 2);
  assert.equal(d.pending_approvals, 0);
  assert.equal(d.trust, "verified");
  assert.equal(d.integrations.length, 2);
  const screen = await cli(["dashboard"], { env: w.box.env, cwd: w.a });
  assert.match(screen.stdout, /AI DEFENDER — DASHBOARD/);
  assert.match(screen.stdout, /UNVERIFIED development build/);
  assert.equal((await cli(["policy", "validate"], { env: w.box.env, cwd: w.a })).code, ExitCode.Ok);
  const update = await cli(["--json", "update"], { env: w.box.env, cwd: w.a });
  const u = (JSON.parse(update.stdout) as { data: { downloads: boolean; upgrade: string[] } }).data;
  assert.equal(u.downloads, false);
  assert.equal(u.upgrade[0], "npm install -g ai-defender@latest");
  assert.equal((await cli(["repair", "--non-interactive"], { env: w.box.env, cwd: w.a })).code, ExitCode.ActionRequired, "repair asks for confirmation");
  const repaired = await cli(["--json", "repair", "--non-interactive", "--yes"], { env: w.box.env, cwd: w.a });
  assert.equal(repaired.code, ExitCode.Ok, repaired.stderr);
  const actions = (JSON.parse(repaired.stdout) as { data: { actions: Array<{ action: string }> } }).data.actions;
  assert.deepEqual(actions.map((a) => a.action), ["skipped", "skipped"], "nothing installed, nothing repaired");
});
