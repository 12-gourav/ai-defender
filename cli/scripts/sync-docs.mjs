// Copy the repository's README.md, SECURITY.md and LICENSE into the npm package directory, so
// the npm landing page and the repository page are the same document. Run by `prepack` and
// `pack:check`; check-package.mjs fails if the copies drift.
// Usage: node scripts/sync-docs.mjs
import { copyFileSync } from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
const cli = path.join(root, "cli");
for (const file of ["README.md", "SECURITY.md", "LICENSE"]) {
  copyFileSync(path.join(root, file), path.join(cli, file));
}
console.log("synced README.md, SECURITY.md, LICENSE into cli/");
