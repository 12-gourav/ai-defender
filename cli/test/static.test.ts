/**
 * Structural guarantees about the CLI's own source.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { REPO } from "./helpers.js";

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? sources(full) : full.endsWith(".ts") ? [full] : [];
  });
}

const files = sources(path.join(REPO, "cli", "src"));

test("the CLI never writes files: every write goes through the engine", () => {
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /\b(writeFile|appendFile|createWriteStream|rmSync|rm\(|unlink|rename|mkdir|copyFile|chmod|symlink)\w*\(/, file);
  }
});

test("the CLI never invokes a shell", () => {
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /shell:\s*true/, file);
    assert.doesNotMatch(text, /\b(exec|execSync|execFileSync|spawnSync)\(/, file);
  }
});

test("the CLI has no way to produce an authorization decision", () => {
  // Engine-returned decisions may be compared for display; the CLI must never construct one,
  // and the engine protocol it speaks has no evaluate command.
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /decision\s*[:=]\s*["'](ALLOW|DENY|REQUIRE_APPROVAL)["']/, file);
    assert.doesNotMatch(text, /return\s+["'](ALLOW|REQUIRE_APPROVAL)["']/, file);
    assert.doesNotMatch(text, /["']evaluate["']/, file);
  }
});

test("secrets are never read from the environment or the command line", () => {
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /AGENTGUARD_PASSPHRASE|--passphrase["' ]/, file);
  }
});

test("approval cannot be automated, and the CLI never acts for an agent", () => {
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    if (text.includes('"approval.approve"')) {
      assert.match(text, /requireHumanAtTerminal\(ctx\);[\s\S]*"approval\.approve"/, `${file}: approve must pass the human-at-terminal gate first`);
      for (const flag of ["yes", "json", "passphraseFile", "nonInteractive"]) {
        assert.match(text, new RegExp(`ctx\\.flags\\.${flag}[^\\n]*throw refuse`), `${file}: --${flag} must be refused for approval`);
      }
    }
    assert.doesNotMatch(text, /"(approval\.request|authorization\.validate|authorization\.consume)"/, file);
    assert.doesNotMatch(text, /["']--agent["']/, file);
  }
});

test("the CLI has no network access: scans and secrets never leave the machine", () => {
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    assert.doesNotMatch(text, /\bfetch\(|from "node:(http|https|net|dgram|tls|http2)"|require\("(http|https|net)"\)|XMLHttpRequest|WebSocket/, file);
  }
});
