/**
 * Locating and verifying the Rust engine binary.
 *
 * Release path: the `ai-defender` package carries each released platform's engine under
 * `binaries/<platform>/` (`bin/agentguard-engine` and a signed `engine-manifest.json`). Before
 * every use the CLI checks the manifest's Ed25519 signature against the public keys shipped
 * beside it (`release-keys.json`), the platform, the protocol and the binary's SHA-256. Any
 * failure is fatal: there is no fallback to another binary.
 *
 * Development path: `AGENTGUARD_DEV_ENGINE=/abs/path/agentguard-engine` together with
 * `AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1`. Both are required; the engine is then reported as
 * unverified everywhere and is never presented as a verified installation.
 */

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { fileURLToPath } from "node:url";
import { constants, accessSync, existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

import { CliError } from "../utils/errors.js";
import { ExitCode } from "../utils/exit-codes.js";
import type { PlatformTarget } from "./platform.js";

export const ENGINE_PROTOCOL_VERSION = 1;
const MANIFEST_SCHEMA = "agentguard.engine-manifest.v1";
const MANIFEST_DOMAIN = "agentguard.engine-manifest.v1\u0000";
const KEY_ID_DOMAIN = "agentguard.release-key-id.v1\u0000";
const MAX_BINARY_BYTES = 256 * 1024 * 1024;
/** `package` field of every engine manifest: the package that carries the engines. */
export const MANIFEST_PACKAGE = "ai-defender";
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export interface ReleaseKey {
  /** 32-byte Ed25519 public key, hex. */
  publicKey: string;
  label?: string;
}

export interface EngineLocation {
  path: string;
  verified: boolean;
  source: "release" | "development";
  version?: string;
  /** SHA-256 of the verified binary (release engines only). */
  sha256?: string;
}

export interface ManifestBody {
  package: string;
  version: string;
  platform: string;
  binary: string;
  sha256: string;
  engine_protocol_version: number;
}

export interface EngineManifest {
  schema: string;
  body: ManifestBody;
  key_id: string;
  signature: string;
}

function unavailable(message: string, recovery?: string): CliError {
  return new CliError("engine-unavailable", message, ExitCode.EngineUnavailable, recovery);
}

/** Canonical JSON: object keys sorted, no whitespace. Used for the signed manifest body. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`);
  return `{${entries.join(",")}}`;
}

/** Key identifier of a release key: first 16 bytes of a domain-separated SHA-256, hex. */
export function releaseKeyId(publicKeyHex: string): string {
  return createHash("sha256")
    .update(KEY_ID_DOMAIN)
    .update(Buffer.from(publicKeyHex, "hex"))
    .digest("hex")
    .slice(0, 32);
}

/** The bytes a manifest signature covers. */
export function manifestMessage(body: ManifestBody): Buffer {
  return Buffer.concat([Buffer.from(MANIFEST_DOMAIN, "utf8"), Buffer.from(canonicalJson(body), "utf8")]);
}

function publicKeyObject(hex: string) {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw unavailable("a release key in release-keys.json is malformed");
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(hex, "hex").toString("base64url") },
    format: "jwk",
  });
}

function isManifest(value: unknown): value is EngineManifest {
  if (typeof value !== "object" || value === null) return false;
  const m = value as Record<string, unknown>;
  const b = m["body"] as Record<string, unknown> | undefined;
  return (
    Object.keys(m).sort().join(",") === "body,key_id,schema,signature" &&
    typeof m["schema"] === "string" &&
    typeof m["key_id"] === "string" &&
    typeof m["signature"] === "string" &&
    typeof b === "object" &&
    b !== null &&
    Object.keys(b).sort().join(",") === "binary,engine_protocol_version,package,platform,sha256,version" &&
    typeof b["package"] === "string" &&
    typeof b["version"] === "string" &&
    typeof b["platform"] === "string" &&
    typeof b["binary"] === "string" &&
    typeof b["sha256"] === "string" &&
    typeof b["engine_protocol_version"] === "number"
  );
}

/**
 * Verify an engine directory: manifest structure, signature by a trusted key, target platform,
 * protocol version, binary location (inside the directory, no symlink escape) and SHA-256.
 * Returns the binary path. Throws on any failure.
 */
export function verifyEnginePackage(
  packageDir: string,
  target: PlatformTarget,
  trustedKeys: ReleaseKey[],
): { binary: string; version: string; sha256: string } {
  const fail = (why: string) =>
    unavailable(`the AI Defender engine could not be verified: ${why}`, "reinstall ai-defender; never run an engine that fails verification");
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(path.join(packageDir, "engine-manifest.json"), "utf8"));
  } catch {
    throw fail("engine-manifest.json is missing or unreadable");
  }
  if (!isManifest(manifest) || manifest.schema !== MANIFEST_SCHEMA) {
    throw fail("engine-manifest.json is malformed");
  }
  if (trustedKeys.length === 0) {
    throw fail("no release signing key is provisioned in this build of the CLI");
  }
  const key = trustedKeys.find((k) => releaseKeyId(k.publicKey) === manifest.key_id);
  if (!key) {
    throw fail("the manifest is signed by an unknown key");
  }
  let signatureOk = false;
  try {
    signatureOk = verifySignature(
      null,
      manifestMessage(manifest.body),
      publicKeyObject(key.publicKey),
      Buffer.from(manifest.signature, "base64"),
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    throw fail("the manifest signature is invalid");
  }
  const body = manifest.body;
  if (body.platform !== target.key || body.package !== MANIFEST_PACKAGE) {
    throw fail(`the engine is for ${body.platform} (${body.package}), not ${target.key}`);
  }
  if (body.engine_protocol_version !== ENGINE_PROTOCOL_VERSION) {
    throw fail(`engine protocol ${body.engine_protocol_version} is not supported (expected ${ENGINE_PROTOCOL_VERSION})`);
  }
  const realDir = realpathSync(packageDir);
  const candidate = path.resolve(realDir, body.binary);
  let binary: string;
  try {
    binary = realpathSync(candidate);
  } catch {
    throw fail("the engine binary is missing");
  }
  if (!binary.startsWith(realDir + path.sep) || path.basename(binary) !== target.binaryName) {
    throw fail("the engine binary path escapes its directory");
  }
  const stats = statSync(binary);
  if (!stats.isFile() || stats.size > MAX_BINARY_BYTES) {
    throw fail("the engine binary is not a regular file of plausible size");
  }
  const digest = createHash("sha256").update(readFileSync(binary)).digest("hex");
  if (digest !== body.sha256.toLowerCase()) {
    throw fail("the engine binary does not match its signed checksum");
  }
  return { binary, version: body.version, sha256: digest };
}

/** Load the public release keys shipped with the CLI. */
export function loadReleaseKeys(file: string): ReleaseKey[] {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { schema?: unknown; keys?: unknown };
    if (parsed.schema !== "agentguard.release-keys.v1" || !Array.isArray(parsed.keys)) return [];
    return parsed.keys.filter(
      (k): k is ReleaseKey => typeof k === "object" && k !== null && typeof (k as ReleaseKey).publicKey === "string",
    );
  } catch {
    return [];
  }
}

export interface ResolveOptions {
  env: Record<string, string | undefined>;
  target: PlatformTarget | undefined;
  platformLabel: string;
  trustedKeys: ReleaseKey[];
  /** Root of the installed package (the directory holding `binaries/`); defaults to this package. */
  packageRoot?: string;
}

function developmentEngine(env: Record<string, string | undefined>): EngineLocation | undefined {
  const dev = env["AGENTGUARD_DEV_ENGINE"];
  if (dev === undefined || dev === "") return undefined;
  if (env["AGENTGUARD_ALLOW_UNVERIFIED_ENGINE"] !== "1") {
    throw unavailable(
      "AGENTGUARD_DEV_ENGINE is set but AGENTGUARD_ALLOW_UNVERIFIED_ENGINE=1 is not; refusing to run an unverified engine",
      "unset AGENTGUARD_DEV_ENGINE, or set both variables for local development",
    );
  }
  if (!path.isAbsolute(dev)) {
    throw unavailable("AGENTGUARD_DEV_ENGINE must be an absolute path");
  }
  try {
    const stats = statSync(dev);
    if (!stats.isFile()) throw new Error("not a file");
    accessSync(dev, constants.X_OK);
  } catch {
    throw unavailable("AGENTGUARD_DEV_ENGINE does not name an executable file");
  }
  return { path: dev, verified: false, source: "development" };
}

/** Find the engine for this platform. Throws a `CliError` (exit 3) when there is none. */
export function resolveEngine(options: ResolveOptions): EngineLocation {
  const dev = developmentEngine(options.env);
  if (dev) return dev;
  const target = options.target;
  if (!target) {
    throw unavailable(
      `AI Defender does not support this platform (${options.platformLabel})`,
      "see the supported platforms in the README",
    );
  }
  if (target.status === "unsupported") {
    throw unavailable(`the AI Defender engine is not available for ${target.key}: ${target.note ?? ""}`);
  }
  const dir = path.join(options.packageRoot ?? PACKAGE_ROOT, target.bundleDir);
  if (!existsSync(path.join(dir, "engine-manifest.json"))) {
    throw unavailable(
      `this build of ai-defender does not include an engine for ${target.key}`,
      `upgrade with \`npm install -g ai-defender@latest\`; if the platform is still missing it is not released yet (for local development see README "Building from source")`,
    );
  }
  const { binary, version, sha256 } = verifyEnginePackage(dir, target, options.trustedKeys);
  return { path: binary, verified: true, source: "release", version, sha256 };
}
