// End-to-end test of a global npm installation, in disposable directories.
//
// It packs `ai-defender` with this platform's engine bundled, exactly as a release would. The
// engine manifest is signed with a throwaway key generated for this run and trusted only by the
// packed copy, never by the repository. The single tarball is installed with
// `npm install -g --prefix <tmp>`. The installed product is then exercised on a PATH that
// contains only Node.js and the prefix: no Rust, no Cargo, no compiler. Nothing outside the
// temporary directory is touched; HOME is temporary too.
//
// Usage (after building the engine):
//   node scripts/e2e-global-install.mjs [--engine ../target/release/agentguard-engine] [--keep]
import { execFileSync, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";

const cli = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const repo = path.resolve(cli, "..");
const { values } = parseArgs({ options: { engine: { type: "string" }, keep: { type: "boolean" } }, strict: true });
const engine = path.resolve(values.engine ?? path.join(repo, "target", "release", "agentguard-engine"));
const platform = `${process.platform}-${process.arch}`;
if (!existsSync(engine)) {
  console.error(`engine binary not found: ${engine} (cargo build --release -p agentguard-engine-cli)`);
  process.exit(2);
}

const work = realpathSync(mkdtempSync(path.join(os.tmpdir(), "ai-defender-e2e-")));
const results = [];
function step(name, fn) {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail });
    console.log(`PASS  ${name}${detail ? `: ${detail}` : ""}`);
  } catch (e) {
    results.push({ name, ok: false, detail: e instanceof Error ? e.message : String(e) });
    console.log(`FAIL  ${name}: ${e instanceof Error ? e.message : String(e)}`);
  }
}
function assert(cond, message) {
  if (!cond) throw new Error(message);
}

// 1. Package the CLI as `npm pack` would, trusting a throwaway release key in the copy only.
const { privateKey } = generateKeyPairSync("ed25519");
const keyFile = path.join(work, "throwaway-release.pem");
writeFileSync(keyFile, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
const pub = JSON.parse(execFileSync("node", [path.join(cli, "scripts", "sign-engine-manifest.mjs"), "--print-public-key", "--key", keyFile], { encoding: "utf8" }));
execFileSync("npm", ["run", "--silent", "sync-docs"], { cwd: cli });
execFileSync("npm", ["run", "--silent", "build"], { cwd: cli });
const pkgCopy = path.join(work, "cli-package");
mkdirSync(pkgCopy);
for (const entry of ["package.json", "README.md", "SECURITY.md", "LICENSE", "release-keys.json", "build"]) {
  cpSync(path.join(cli, entry), path.join(pkgCopy, entry), { recursive: true });
}
rmSync(path.join(pkgCopy, "build", "test"), { recursive: true, force: true });
const keys = JSON.parse(readFileSync(path.join(pkgCopy, "release-keys.json"), "utf8"));
keys.keys = [{ publicKey: pub.publicKey, label: "throwaway e2e key (this run only)" }];
writeFileSync(path.join(pkgCopy, "release-keys.json"), `${JSON.stringify(keys, null, 2)}\n`);

// 2. Stage and sign this platform's engine inside the copy, then pack the single tarball.
const version = JSON.parse(readFileSync(path.join(cli, "package.json"), "utf8")).version;
execFileSync("node", [path.join(cli, "scripts", "stage-engine.mjs"), "--platform", platform, "--binary", engine, "--version", version, "--out", path.join(pkgCopy, "binaries")], { stdio: "pipe" });
execFileSync("node", [path.join(cli, "scripts", "sign-engine-manifest.mjs"), "--manifest", path.join(pkgCopy, "binaries", platform, "engine-manifest.json"), "--key", keyFile], { stdio: "pipe" });
rmSync(keyFile);
const tarballs = path.join(work, "tarballs");
mkdirSync(tarballs);
execFileSync("npm", ["pack", "--ignore-scripts", "--pack-destination", tarballs], { cwd: pkgCopy, stdio: "pipe" });
const cliTgz = path.join(tarballs, readdirSync(tarballs).find((x) => x.endsWith(".tgz")));

// 3. Global installation into a disposable prefix, and a sandboxed user.
const prefix = path.join(work, "prefix");
const home = path.join(work, "home");
mkdirSync(home);
const npmInstall = () =>
  execFileSync("npm", ["install", "-g", "--prefix", prefix, "--omit=optional", "--no-audit", "--no-fund", "--ignore-scripts", cliTgz], { stdio: "pipe", encoding: "utf8" });
const bin = path.join(prefix, "bin");
const env = { PATH: `${bin}:${path.dirname(process.execPath)}`, HOME: home, NO_COLOR: "1", LANG: "C" };
function run(args, options = {}) {
  const r = spawnSync(path.join(bin, options.as ?? "ai-defender"), args, { env, cwd: options.cwd ?? home, encoding: "utf8" });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
const json = (args, cwd) => {
  const r = run(["--json", ...args], { cwd });
  return { ...r, doc: JSON.parse(r.stdout) };
};

step("npm install -g from the single packed tarball (no install scripts, no dependencies)", () => {
  npmInstall();
  assert(existsSync(path.join(bin, "ai-defender")) && existsSync(path.join(bin, "agentguard")), "executables were not linked");
  const installed = readdirSync(path.join(prefix, "lib", "node_modules"));
  assert(installed.length === 1 && installed[0] === "ai-defender", `installed: ${installed.join(", ")}`);
  return `${path.basename(cliTgz)} (one package)`;
});
step("no Rust toolchain on the PATH", () => {
  for (const tool of ["cargo", "rustc", "cc"]) {
    const found = spawnSync("/bin/sh", ["-c", `command -v ${tool}`], { env, encoding: "utf8" });
    assert(found.status !== 0, `${tool} is reachable: ${found.stdout.trim()}`);
  }
  return "cargo, rustc and cc are absent";
});
step("ai-defender --version", () => {
  const r = run(["--version"]);
  assert(r.code === 0 && r.stdout.includes(version), r.stdout + r.stderr);
  return r.stdout.trim().split("\n")[0];
});
step("ai-defender --help and the agentguard alias", () => {
  const h = run(["--help"]);
  assert(h.code === 0 && h.stdout.startsWith("AI Defender"), h.stderr);
  const a = run(["--version"], { as: "agentguard" });
  assert(a.code === 0, a.stderr);
  return "help and alias work";
});
step("the installed engine is a verified release (signed manifest, checksum, platform)", () => {
  const d = json(["doctor"]);
  const engineCheck = d.doc.data.checks.find((c) => c.id === "engine");
  assert(engineCheck.status === "pass" && engineCheck.detail.includes("verified release"), JSON.stringify(engineCheck));
  return engineCheck.detail;
});

const projectA = path.join(work, "projects", "alpha");
const projectB = path.join(work, "projects", "beta");
for (const p of [projectA, projectB]) {
  mkdirSync(p, { recursive: true });
  writeFileSync(path.join(p, "package.json"), "{}\n");
}
const pass = path.join(home, "pass.txt");
writeFileSync(pass, "correct horse battery staple e2e\n", { mode: 0o600 });
let identity;
step("two projects initialised with one trusted identity", () => {
  for (const p of [projectA, projectB]) {
    const r = run(["init", "--non-interactive", "--yes", "--passphrase-file", pass], { cwd: p });
    assert(r.code === 0, r.stderr);
  }
  const s = json(["status"], projectA);
  identity = JSON.stringify(s.doc.data.trust_store);
  const list = json(["projects", "list"], projectA);
  assert(list.doc.data.total === 2, JSON.stringify(list.doc.data));
  return list.doc.data.projects.map((p) => `${p.name} (${p.status})`).join(", ");
});
step("Claude Code integration installs and verifies in the sandboxed HOME", () => {
  const i = run(["integrations", "install", "claude", "--non-interactive", "--yes"], { cwd: projectA });
  assert(i.code === 0, i.stderr + i.stdout);
  const v = run(["integrations", "verify", "claude"], { cwd: projectA });
  assert(v.code === 0, v.stdout + v.stderr);
  const settings = JSON.parse(readFileSync(path.join(home, ".claude", "settings.json"), "utf8"));
  const command = settings.hooks.PreToolUse[0].hooks[0].command;
  assert(command.startsWith(path.join(home, ".config", "agentguard", "engine")), command);
  return `hooks run the verified copy ${path.relative(home, command)}`;
});
step("a tampered engine binary is rejected and never executed", () => {
  const installed = path.join(prefix, "lib", "node_modules", "ai-defender", "binaries", platform, "bin", "agentguard-engine");
  const original = readFileSync(installed);
  const tampered = Buffer.from(original);
  tampered[tampered.length - 1] ^= 0xff;
  chmodSync(installed, 0o755);
  writeFileSync(installed, tampered);
  const r = run(["status"], { cwd: projectA });
  writeFileSync(installed, original);
  assert(r.code === 3 && /could not be verified/.test(r.stderr), `exit ${r.code}: ${r.stderr}`);
  return r.stderr.trim().split("\n")[0];
});
step("reinstalling (upgrade path) keeps the identity, projects and hooks", () => {
  npmInstall();
  const s = json(["status"], projectA);
  assert(JSON.stringify(s.doc.data.trust_store) === identity, "the trusted identity changed");
  assert(json(["projects", "list"], projectA).doc.data.total === 2, "projects were lost");
  const v = run(["integrations", "verify", "claude"], { cwd: projectA });
  assert(v.code === 0, v.stdout);
  return "identity, 2 projects and the Claude integration intact";
});
step("npm uninstall -g keeps signing keys, registry and history", () => {
  execFileSync("npm", ["uninstall", "-g", "--prefix", prefix, "ai-defender"], { stdio: "pipe" });
  assert(!existsSync(path.join(bin, "ai-defender")), "the executable is still linked");
  const store = path.join(home, ".config", "agentguard");
  for (const kept of ["signing", "registry", "audit", "trusted"]) assert(existsSync(path.join(store, kept)), `${kept} was deleted`);
  assert(existsSync(path.join(projectA, ".agentguard", "config.yaml")), "project configuration was deleted");
  return "user data preserved";
});

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed (work directory ${values.keep ? work : "removed"})`);
if (!values.keep) rmSync(work, { recursive: true, force: true });
process.exit(failed.length > 0 ? 1 : 0);
