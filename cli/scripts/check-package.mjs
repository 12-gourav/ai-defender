// Validate what `npm pack` would publish. Fails on:
// - a missing required file, or any file outside the allowlist (no tests, sources, maps, keys);
// - an entry point without a shebang, or a `bin` target that is not the built entry point;
// - documents that differ from the repository root copies (README, SECURITY, LICENSE);
// - versions that disagree (package, engine crates, bundled engine manifests);
// - per-platform dependencies (engines are bundled under binaries/, never separate packages);
// - private key material, personal machine paths or environment files in packaged content,
//   including inside the engine binaries;
// - private material in release-keys.json;
// - with --release: no staged engine, or `os`/`cpu` that differ from the engines bundled.
// Usage: npm run pack:check [-- --release]
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const cli = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const root = path.resolve(cli, "..");
const [result] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: cli, encoding: "utf8" }));
const files = result.files.map((f) => f.path).sort();
const problems = [];
const release = process.argv.includes("--release");
const ENGINE_FILE = /^binaries\/(linux-x64|linux-arm64|darwin-x64|darwin-arm64|win32-x64)\/(bin\/agentguard-engine(\.exe)?|engine-manifest\.json)$/;

const REQUIRED = ["package.json", "README.md", "LICENSE", "SECURITY.md", "release-keys.json", "build/src/index.js", "build/src/cli.js"];
for (const required of REQUIRED) {
  if (!files.includes(required)) problems.push(`missing ${required}`);
}
for (const f of files) {
  if (!/^(package\.json|README\.md|LICENSE|SECURITY\.md|release-keys\.json|build\/src\/.+\.js)$/.test(f) && !ENGINE_FILE.test(f)) problems.push(`unexpected file ${f}`);
  if (/\.(pem|key|p12|pfx|sqlite|db|jsonl)$|(^|\/)\.env|(^|\/)id_(rsa|ed25519|ecdsa)/i.test(f)) problems.push(`sensitive-looking file ${f}`);
}

const pkg = JSON.parse(readFileSync(path.join(cli, "package.json"), "utf8"));
for (const [name, target] of Object.entries(pkg.bin ?? {})) {
  if (target !== "build/src/index.js") problems.push(`bin ${name} does not point at the built entry point`);
}
if (!pkg.bin?.["ai-defender"]) problems.push("missing the ai-defender executable");
if (!readFileSync(path.join(cli, "build/src/index.js"), "utf8").startsWith("#!/usr/bin/env node")) problems.push("entry point lacks a shebang");

for (const doc of ["README.md", "SECURITY.md", "LICENSE"]) {
  if (readFileSync(path.join(cli, doc), "utf8") !== readFileSync(path.join(root, doc), "utf8")) problems.push(`${doc} differs from the repository copy (run npm run sync-docs)`);
}

const cargo = readFileSync(path.join(root, "Cargo.toml"), "utf8");
const engineVersion = /\[workspace\.package\][^[]*?\nversion = "([^"]+)"/.exec(cargo)?.[1];
if (engineVersion !== pkg.version) problems.push(`package version ${pkg.version} differs from the engine version ${engineVersion}`);
for (const field of ["dependencies", "optionalDependencies", "peerDependencies", "bundleDependencies", "bundledDependencies"]) {
  if (pkg[field] && Object.keys(pkg[field]).length > 0) problems.push(`${field} must be empty: the package runs on Node.js built-ins and bundles its engines`);
}
if (pkg.scripts && ["preinstall", "install", "postinstall"].some((s) => s in pkg.scripts)) problems.push("install scripts are not allowed");

const OS_CPU = { "linux-x64": ["linux", "x64"], "linux-arm64": ["linux", "arm64"], "darwin-x64": ["darwin", "x64"], "darwin-arm64": ["darwin", "arm64"], "win32-x64": ["win32", "x64"] };
const binariesDir = path.join(cli, "binaries");
const staged = existsSync(binariesDir) ? readdirSync(binariesDir).sort() : [];
for (const platform of staged) {
  if (!OS_CPU[platform]) {
    problems.push(`unknown engine directory binaries/${platform}`);
    continue;
  }
  const manifestFile = `binaries/${platform}/engine-manifest.json`;
  if (!files.includes(manifestFile)) {
    problems.push(`binaries/${platform} is not packed (check "files")`);
    continue;
  }
  const manifest = JSON.parse(readFileSync(path.join(cli, manifestFile), "utf8"));
  if (manifest.body?.version !== pkg.version) problems.push(`${platform} engine is ${manifest.body?.version}, not ${pkg.version}`);
  if (!manifest.signature) problems.push(`${platform} engine manifest is unsigned`);
}
if (release) {
  if (staged.length === 0) problems.push("--release: no engine is staged in binaries/");
  const wantOs = [...new Set(staged.map((p) => OS_CPU[p]?.[0]))].sort().join(",");
  const wantCpu = [...new Set(staged.map((p) => OS_CPU[p]?.[1]))].sort().join(",");
  if ([...(pkg.os ?? [])].sort().join(",") !== wantOs) problems.push(`--release: "os" must be [${wantOs}] to match the bundled engines`);
  if ([...(pkg.cpu ?? [])].sort().join(",") !== wantCpu) problems.push(`--release: "cpu" must be [${wantCpu}] to match the bundled engines`);
  for (const [os, cpu] of (pkg.os ?? []).flatMap((o) => (pkg.cpu ?? []).map((c) => [o, c]))) {
    const key = `${os}-${cpu}`;
    if (OS_CPU[key] && !staged.includes(key)) problems.push(`--release: ${key} is allowed by os/cpu but has no engine (npm would install a package that cannot run there)`);
  }
}

for (const f of files) {
  const text = readFileSync(path.join(cli, f), ENGINE_FILE.test(f) ? "latin1" : "utf8");
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) problems.push(`${f} contains a private key block`);
  if (/\/home\/[a-z][\w.-]*\/|\/Users\/[A-Za-z][\w.-]*\/|[A-Z]:\\Users\\[A-Za-z]/.test(text) && f !== "README.md" && f !== "SECURITY.md") problems.push(`${f} contains a personal machine path`);
}
const keys = JSON.parse(readFileSync(path.join(cli, "release-keys.json"), "utf8"));
if (keys.keys.some((k) => Object.keys(k).some((field) => /private|secret|seed/i.test(field)))) problems.push("release-keys.json contains private material");

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`package ok: ${pkg.name}@${pkg.version}, ${files.length} files, ${result.size} bytes packed, ${result.unpackedSize} unpacked`);
console.log(staged.length === 0 ? "engines: none staged (development build; releases need --release)" : `engines: ${staged.join(", ")}`);
console.log(keys.keys.length === 0 ? "note: no release signing key provisioned; release engine verification will fail closed" : `release keys: ${keys.keys.length}`);
