/**
 * `ai-defender secrets` against the real engine in isolated HOME/XDG directories. Every
 * credential below is fake and nonfunctional.
 */

import assert from "node:assert/strict";
import { spawnSync as runGit } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { before, test } from "node:test";

import { ExitCode } from "../src/utils/exit-codes.js";
import { ENGINE, cli, sandbox, tempDir, type Sandbox } from "./helpers.js";

const PASS = "correct horse battery staple";
const GITHUB = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000";
const PG = "Sup3rS3cretPw9";
const KEY = "MIIEFAKEFAKEFAKEFAKEKEYBODYFAKE";
const SECRETS = [GITHUB.slice(4), PG, KEY];

before(() => {
  assert.ok(existsSync(ENGINE), `engine binary not found at ${ENGINE}; run cargo build -p agentguard-engine-cli`);
});

function put(root: string, rel: string, content: string | Buffer): void {
  const file = path.join(root, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}

function fixture(): string {
  const root = path.join(tempDir("agentguard-scan-"), "app");
  put(root, "package.json", "{}\n");
  put(root, "src/index.js", "console.log('hello');\n");
  put(root, "src/config.js", `export const token = "${GITHUB}";\n`);
  put(root, ".env", `DATABASE_URL=postgres://app:${PG}@db/app\n`);
  put(root, "deploy/id_rsa", `-----BEGIN RSA PRIVATE KEY-----\n${KEY}\n-----END RSA PRIVATE KEY-----\n`);
  put(root, "node_modules/x/index.js", `const t = "${GITHUB}";\n`);
  mkdirSync(path.join(root, ".git"));
  return root;
}

function noSecrets(...texts: string[]): void {
  const all = texts.join("\n");
  for (const s of SECRETS) assert.ok(!all.includes(s), `secret material in CLI output: ${s}`);
}

async function initialised(box: Sandbox, cwd: string): Promise<void> {
  const pass = path.join(box.home, "pass.txt");
  writeFileSync(pass, `${PASS}\n`);
  chmodSync(pass, 0o600);
  const r = await cli(["init", "--non-interactive", "--yes", "--passphrase-file", pass], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
}

test("scan finds secrets, prints only redacted previews, and exits 5", async () => {
  const box = sandbox();
  const cwd = fixture();
  const r = await cli(["secrets", "scan"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.CheckFailed, r.stderr);
  noSecrets(r.stdout, r.stderr);
  assert.match(r.stdout, /ghp_\*\*\*\*REDACTED/);
  assert.match(r.stdout, /src\/config\.js:1/);
  assert.match(r.stdout, /\[PRIVATE KEY \*\*\*\*REDACTED\]/);
  assert.match(r.stdout, /Excluded: \d+ \(not scanned and not checked; never reported as clean\)/);
  assert.match(r.stdout, /node_modules/);
  assert.match(r.stdout, /cannot prove that a file contains no secrets/);
  const json = await cli(["secrets", "scan", "--json"], { env: box.env, cwd });
  assert.equal(json.code, ExitCode.CheckFailed);
  noSecrets(json.stdout);
  const data = JSON.parse(json.stdout).data;
  assert.ok(data.report.findings.length >= 3);
  for (const f of data.report.findings) {
    assert.match(f.id, /^f_[0-9a-f]{16}$/);
    assert.ok(["low", "medium", "high", "critical"].includes(f.severity));
  }
});

test("a clean project exits 0; exclusions and skips are reported, never as clean", async () => {
  const box = sandbox();
  const cwd = path.join(tempDir("agentguard-clean-"), "app");
  put(cwd, "src/a.js", "export const a = 1;\n");
  let r = await cli(["secrets", "scan"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stdout);
  assert.match(r.stdout, /No secrets detected in the scanned files/);

  put(cwd, "fixtures/fake.env", `TOKEN=${GITHUB}\n`);
  put(cwd, "assets/logo.bin", Buffer.from([0, 1, 2, 3, 0, 0, 7]));
  r = await cli(["secrets", "scan", "--exclude", "fixtures/**"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok);
  assert.match(r.stdout, /Excluded: 1/);
  assert.match(r.stdout, /fixtures\s+\(fixtures\/\*\*\)/);
  assert.match(r.stdout, /Skipped: 1/);
  assert.match(r.stdout, /assets\/logo\.bin\s+\(binary\)/);
  assert.match(r.stdout, /INCOMPLETE/);
  assert.doesNotMatch(r.stdout, /No secrets detected in the scanned files\./);
});

test("paths outside the project are refused", async () => {
  const box = sandbox();
  const cwd = fixture();
  for (const bad of ["../elsewhere", "/etc"]) {
    const r = await cli(["secrets", "scan", bad], { env: box.env, cwd });
    assert.notEqual(r.code, ExitCode.Ok, bad);
    assert.notEqual(r.code, ExitCode.CheckFailed, bad);
  }
  const r = await cli(["secrets", "scan", "src"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.CheckFailed);
  assert.doesNotMatch(r.stdout, /\.env:/);
});

test("explain reviews a finding without its value; status reports engine, policy and last scan", async () => {
  const box = sandbox();
  const cwd = fixture();
  await initialised(box, cwd);
  const scan = await cli(["secrets", "scan", "--json"], { env: box.env, cwd });
  const finding = JSON.parse(scan.stdout).data.report.findings.find((f: { path: string }) => f.path === "src/config.js");
  const r = await cli(["secrets", "explain", finding.id], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  noSecrets(r.stdout, r.stderr);
  assert.match(r.stdout, /ghp_\*\*\*\*REDACTED \(never stored or shown\)/);
  assert.match(r.stdout, /Revoke the token/);
  assert.match(r.stdout, /does not make its contents safe/);

  const s = await cli(["secrets", "status"], { env: box.env, cwd });
  assert.equal(s.code, ExitCode.Ok, s.stderr);
  assert.match(s.stdout, /Read sensitive files:\s+DENY/);
  assert.match(s.stdout, /Modify sensitive files:\s+REQUIRE_APPROVAL/);
  assert.match(s.stdout, /Last result:\s+\d+ finding/);
  const bad = await cli(["secrets", "explain", "nope"], { env: box.env, cwd });
  assert.notEqual(bad.code, ExitCode.Ok);
});

test("--staged scans only staged changes", async (t) => {
  if (runGit("git", ["--version"]).status !== 0) {
    t.skip("git not installed");
    return;
  }
  const box = sandbox();
  const cwd = fixture();
  const git = (...args: string[]) => {
    const r = runGit("git", args, { cwd, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", HOME: cwd, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" } });
    assert.equal(r.status, 0, String(r.stderr));
  };
  runGit("rm", ["-rf", path.join(cwd, ".git")]);
  git("init", "-q");
  git("add", "src/index.js", "package.json");
  git("commit", "-qm", "init");
  git("add", "src/config.js");
  const r = await cli(["secrets", "scan", "--staged", "--json"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.CheckFailed, r.stdout);
  const paths = JSON.parse(r.stdout).data.report.findings.map((f: { path: string }) => f.path);
  assert.deepEqual(paths, ["src/config.js"]);
});

test("preview lists configuration keys and states, never values", async () => {
  const box = sandbox();
  const cwd = fixture();
  put(cwd, ".env.local", `API_KEY=${GITHUB}\nEMPTY=\nREF=\${API_KEY}\n`);
  const r = await cli(["secrets", "preview", ".env.local"], { env: box.env, cwd });
  assert.equal(r.code, ExitCode.Ok, r.stderr);
  noSecrets(r.stdout, r.stderr);
  assert.match(r.stdout, /API_KEY:\s+set/);
  assert.match(r.stdout, /EMPTY:\s+empty/);
  assert.match(r.stdout, /REF:\s+reference/);
  const outside = await cli(["secrets", "preview", "../x.env"], { env: box.env, cwd });
  assert.notEqual(outside.code, ExitCode.Ok);
});
