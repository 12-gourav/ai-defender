// Stage a built engine into this package: cli/binaries/<platform>/bin/<exe> and an unsigned
// engine-manifest.json. Sign the manifest with sign-engine-manifest.mjs (the private key never
// enters this repository), then check it with verify-engine-package.mjs.
//
// Usage:
//   node scripts/stage-engine.mjs --platform linux-x64 \
//        --binary ../artifacts/engine-linux-x64/agentguard-engine --version 0.2.0 [--out binaries]
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

const PLATFORMS = {
  "linux-x64": "agentguard-engine",
  "linux-arm64": "agentguard-engine",
  "darwin-x64": "agentguard-engine",
  "darwin-arm64": "agentguard-engine",
  "win32-x64": "agentguard-engine.exe",
};

const cli = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const { values } = parseArgs({
  options: { platform: { type: "string" }, binary: { type: "string" }, version: { type: "string" }, out: { type: "string" } },
  strict: true,
});
const exe = PLATFORMS[values.platform ?? ""];
if (!exe || !values.binary || !values.version) {
  console.error("usage: stage-engine.mjs --platform <key> --binary <path> --version <x.y.z> [--out <binaries dir>]");
  process.exit(2);
}
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(values.version)) {
  console.error("version must be semver");
  process.exit(2);
}
const dir = path.join(path.resolve(values.out ?? path.join(cli, "binaries")), values.platform);
if (existsSync(dir)) {
  console.error(`refusing to overwrite ${dir}`);
  process.exit(1);
}
mkdirSync(path.join(dir, "bin"), { recursive: true });
const target = path.join(dir, "bin", exe);
copyFileSync(values.binary, target);
chmodSync(target, 0o755);
const sha256 = createHash("sha256").update(readFileSync(target)).digest("hex");
writeFileSync(
  path.join(dir, "engine-manifest.json"),
  `${JSON.stringify({ schema: "agentguard.engine-manifest.v1", body: { package: "ai-defender", version: values.version, platform: values.platform, binary: `bin/${exe}`, sha256, engine_protocol_version: 1 }, key_id: "", signature: "" }, null, 2)}\n`,
);
console.log(`staged ${values.platform} engine ${values.version} in ${dir} (sha256 ${sha256}); now sign engine-manifest.json`);
