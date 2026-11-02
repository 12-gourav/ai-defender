// Verify staged engines exactly as the installed CLI will: manifest signature against
// release-keys.json, platform, package, protocol and binary SHA-256. Requires `npm run build`.
//
// Usage:
//   node scripts/verify-engine-package.mjs --all                         # every engine in binaries/
//   node scripts/verify-engine-package.mjs --dir binaries/linux-x64 --platform linux-x64 [--keys <file>]
import { readdirSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

const here = path.dirname(new URL(import.meta.url).pathname);
const cli = path.join(here, "..");
const { verifyEnginePackage, loadReleaseKeys } = await import(path.join(cli, "build", "src", "services", "installer.js"));
const { allTargets } = await import(path.join(cli, "build", "src", "services", "platform.js"));

const { values } = parseArgs({ options: { all: { type: "boolean" }, dir: { type: "string" }, platform: { type: "string" }, keys: { type: "string" } }, strict: true });
const keys = loadReleaseKeys(path.resolve(values.keys ?? path.join(cli, "release-keys.json")));
if (keys.length === 0) {
  console.error("release-keys.json has no release key: provision the public key before releasing");
  process.exit(1);
}
let jobs;
if (values.all) {
  let present = [];
  try {
    present = readdirSync(path.join(cli, "binaries"));
  } catch {
    present = [];
  }
  jobs = present.map((key) => ({ dir: path.join(cli, "binaries", key), target: allTargets().find((t) => t.key === key), key }));
  if (jobs.length === 0) {
    console.error("no engines are staged in binaries/");
    process.exit(1);
  }
} else {
  jobs = [{ dir: values.dir, target: allTargets().find((t) => t.key === values.platform), key: values.platform }];
}
let failed = false;
for (const job of jobs) {
  if (!job.dir || !job.target) {
    console.error(`unknown platform ${job.key ?? ""} (usage: --all, or --dir <dir> --platform <key>)`);
    failed = true;
    continue;
  }
  try {
    const verified = verifyEnginePackage(path.resolve(job.dir), job.target, keys);
    console.log(`verified ${job.key} ${verified.version} ${verified.sha256}`);
  } catch (e) {
    console.error(`${job.key}: verification failed: ${e instanceof Error ? e.message : String(e)}`);
    failed = true;
  }
}
process.exit(failed ? 1 : 0);
