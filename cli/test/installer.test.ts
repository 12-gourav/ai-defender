import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, cpSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { MANIFEST_PACKAGE, manifestMessage, releaseKeyId, resolveEngine, verifyEnginePackage, type ManifestBody, type ReleaseKey } from "../src/services/installer.js";
import { detectPlatform } from "../src/services/platform.js";
import { CliError } from "../src/utils/errors.js";
import { ExitCode } from "../src/utils/exit-codes.js";
import { tempDir } from "./helpers.js";

const target = detectPlatform("linux", "x64")!;

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url").toString("hex");
  return { privateKey, release: { publicKey: raw } as ReleaseKey };
}

function packageWith(opts: { binary?: string; bodyOverride?: Partial<ManifestBody>; signWith?: ReturnType<typeof keypair>; tamperAfterSign?: (b: ManifestBody) => void } = {}) {
  const k = opts.signWith ?? keypair();
  const dir = tempDir("agentguard-pkg-");
  mkdirSync(path.join(dir, "bin"));
  const content = opts.binary ?? "#!/bin/sh\necho engine\n";
  writeFileSync(path.join(dir, "bin", "agentguard-engine"), content);
  chmodSync(path.join(dir, "bin", "agentguard-engine"), 0o755);
  const body: ManifestBody = {
    package: MANIFEST_PACKAGE,
    version: "0.1.0",
    platform: "linux-x64",
    binary: "bin/agentguard-engine",
    sha256: createHash("sha256").update(content).digest("hex"),
    engine_protocol_version: 1,
    ...opts.bodyOverride,
  };
  const signature = sign(null, manifestMessage(body), k.privateKey).toString("base64");
  opts.tamperAfterSign?.(body);
  writeFileSync(path.join(dir, "engine-manifest.json"), JSON.stringify({ schema: "agentguard.engine-manifest.v1", body, key_id: releaseKeyId(k.release.publicKey), signature }));
  return { dir, keys: [k.release] };
}

const rejects = (fn: () => unknown, pattern: RegExp) =>
  assert.throws(fn, (e: unknown) => e instanceof CliError && e.exitCode === ExitCode.EngineUnavailable && pattern.test(e.message));

test("a correctly signed engine package verifies", () => {
  const { dir, keys } = packageWith();
  const result = verifyEnginePackage(dir, target, keys);
  assert.equal(path.basename(result.binary), "agentguard-engine");
  assert.equal(result.version, "0.1.0");
});

test("tampered binaries, manifests and signatures are rejected", () => {
  const a = packageWith();
  writeFileSync(path.join(a.dir, "bin", "agentguard-engine"), "#!/bin/sh\necho evil\n");
  rejects(() => verifyEnginePackage(a.dir, target, a.keys), /checksum/);

  const b = packageWith({ tamperAfterSign: (body) => { body.version = "9.9.9"; } });
  rejects(() => verifyEnginePackage(b.dir, target, b.keys), /signature is invalid/);

  const c = packageWith();
  rejects(() => verifyEnginePackage(c.dir, target, [keypair().release]), /unknown key/);
  rejects(() => verifyEnginePackage(c.dir, target, []), /no release signing key/);

  const d = packageWith({ bodyOverride: { platform: "darwin-arm64" } });
  rejects(() => verifyEnginePackage(d.dir, target, d.keys), /not linux-x64/);

  const e = packageWith({ bodyOverride: { engine_protocol_version: 2 } });
  rejects(() => verifyEnginePackage(e.dir, target, e.keys), /protocol 2/);

  const f = packageWith();
  writeFileSync(path.join(f.dir, "engine-manifest.json"), "{not json");
  rejects(() => verifyEnginePackage(f.dir, target, f.keys), /missing or unreadable/);
});

test("binary paths cannot escape the package, directly or through symlinks", () => {
  const k = keypair();
  const outside = tempDir("agentguard-outside-");
  writeFileSync(path.join(outside, "agentguard-engine"), "#!/bin/sh\n");
  const a = packageWith({ signWith: k, bodyOverride: { binary: `../../../../${outside}/agentguard-engine` } });
  rejects(() => verifyEnginePackage(a.dir, target, a.keys), /escapes|missing/);

  // A manifest naming a symlink that points outside the package.
  writeFileSync(path.join(outside, "agentguard-engine"), "#!/bin/sh\necho engine\n");
  const c = packageWith({ signWith: k, bodyOverride: { binary: "bin/link" } });
  symlinkSync(path.join(outside, "agentguard-engine"), path.join(c.dir, "bin", "link"));
  rejects(() => verifyEnginePackage(c.dir, target, c.keys), /escapes/);
});

test("a manifest naming another package is rejected", () => {
  const a = packageWith({ bodyOverride: { package: "ai-defender-engine-linux-x64" } });
  rejects(() => verifyEnginePackage(a.dir, target, a.keys), /not linux-x64/);
});

test("engine resolution: unsupported platforms, missing engines, bundled engines and the development override", () => {
  const base = { env: {}, trustedKeys: [] as ReleaseKey[], platformLabel: "x" };
  rejects(() => resolveEngine({ ...base, target: undefined }), /does not support this platform/);
  rejects(() => resolveEngine({ ...base, target: detectPlatform("win32", "x64") }), /not available for win32-x64/);
  const root = tempDir("agentguard-root-");
  rejects(() => resolveEngine({ ...base, target, packageRoot: root }), /does not include an engine for linux-x64/);
  const { dir, keys } = packageWith();
  cpSync(dir, path.join(root, "binaries", "linux-x64"), { recursive: true });
  rejects(() => resolveEngine({ ...base, target, packageRoot: root }), /could not be verified/);
  const bundled = resolveEngine({ ...base, target, packageRoot: root, trustedKeys: keys });
  assert.equal(bundled.verified, true);
  assert.equal(bundled.path, path.join(root, "binaries", "linux-x64", "bin", "agentguard-engine"));

  const engine = path.join(dir, "bin", "agentguard-engine");
  rejects(() => resolveEngine({ ...base, target, env: { AGENTGUARD_DEV_ENGINE: engine } }), /refusing to run an unverified engine/);
  rejects(() => resolveEngine({ ...base, target, env: { AGENTGUARD_DEV_ENGINE: "relative/engine", AGENTGUARD_ALLOW_UNVERIFIED_ENGINE: "1" } }), /absolute/);
  rejects(() => resolveEngine({ ...base, target, env: { AGENTGUARD_DEV_ENGINE: "/nonexistent/engine", AGENTGUARD_ALLOW_UNVERIFIED_ENGINE: "1" } }), /executable/);
  const dev = resolveEngine({ ...base, target, env: { AGENTGUARD_DEV_ENGINE: engine, AGENTGUARD_ALLOW_UNVERIFIED_ENGINE: "1" } });
  assert.deepEqual(dev, { path: engine, verified: false, source: "development" });
});
