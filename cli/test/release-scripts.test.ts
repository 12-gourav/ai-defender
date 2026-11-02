import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { verifyEnginePackage } from "../src/services/installer.js";
import { detectPlatform } from "../src/services/platform.js";
import { REPO, tempDir } from "./helpers.js";

const SCRIPTS = path.join(REPO, "cli", "scripts");

test("release scripts stage an engine the CLI verifies, and an unsigned engine fails", () => {
  const work = tempDir("agentguard-release-");
  const binary = path.join(work, "agentguard-engine");
  writeFileSync(binary, "#!/bin/sh\necho engine\n");
  chmodSync(binary, 0o755);
  const binaries = path.join(work, "binaries");
  const out = path.join(binaries, "linux-x64");
  execFileSync("node", [path.join(SCRIPTS, "stage-engine.mjs"), "--platform", "linux-x64", "--binary", binary, "--version", "0.2.0", "--out", binaries]);
  const target = detectPlatform("linux", "x64")!;
  const { privateKey } = generateKeyPairSync("ed25519");
  const keyFile = path.join(work, "release.pem");
  writeFileSync(keyFile, privateKey.export({ format: "pem", type: "pkcs8" }));
  const pub = JSON.parse(execFileSync("node", [path.join(SCRIPTS, "sign-engine-manifest.mjs"), "--print-public-key", "--key", keyFile], { encoding: "utf8" })) as { publicKey: string };
  assert.throws(() => verifyEnginePackage(out, target, [{ publicKey: pub.publicKey }]), /unknown key/);
  execFileSync("node", [path.join(SCRIPTS, "sign-engine-manifest.mjs"), "--manifest", path.join(out, "engine-manifest.json"), "--key", keyFile]);
  const verified = verifyEnginePackage(out, target, [{ publicKey: pub.publicKey }]);
  assert.equal(path.basename(verified.binary), "agentguard-engine");
  assert.equal(verified.version, "0.2.0");
  assert.throws(() => execFileSync("node", [path.join(SCRIPTS, "stage-engine.mjs"), "--platform", "linux-x64", "--binary", binary, "--version", "0.2.0", "--out", binaries], { stdio: "pipe" }));
});
