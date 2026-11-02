// Run the compiled CLI tests with Node's test runner. Node before 21 does not expand globs in
// `node --test`, so the files are listed here. Run after `npm run build`.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";

const root = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "build", "test");
const files = readdirSync(root, { recursive: true })
  .map(String)
  .filter((f) => f.endsWith(".test.js"))
  .sort()
  .map((f) => path.join(root, f));
if (files.length === 0) {
  console.error(`no compiled tests in ${root}`);
  process.exit(1);
}
const r = spawnSync(process.execPath, ["--test", "--test-reporter=spec", ...files], { stdio: "inherit" });
process.exit(r.status ?? 1);
