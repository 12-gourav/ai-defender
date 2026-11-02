// Minimal lint beyond the strict TypeScript compiler: forbid `any`, stray console use and
// non-null `as any` escapes in CLI sources. Usage: node scripts/lint.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "src");
const files = (function walk(dir) {
  return readdirSync(dir).flatMap((n) => {
    const f = path.join(dir, n);
    return statSync(f).isDirectory() ? walk(f) : f.endsWith(".ts") ? [f] : [];
  });
})(root);
const rules = [
  [/:\s*any\b|as any\b|<any>/, "explicit any"],
  [/\bconsole\.(log|error|warn|info)\(/, "console output (use Output)"],
  [/\bdebugger\b/, "debugger statement"],
  [/@ts-ignore|@ts-nocheck/, "type-check suppression"],
];
let failed = 0;
for (const file of files) {
  readFileSync(file, "utf8").split("\n").forEach((line, i) => {
    for (const [pattern, message] of rules) {
      if (pattern.test(line)) {
        console.error(`${path.relative(process.cwd(), file)}:${i + 1}: ${message}`);
        failed += 1;
      }
    }
  });
}
if (failed > 0) process.exit(1);
console.log(`lint: ${files.length} files clean`);
