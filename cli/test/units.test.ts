import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { validateResponse } from "../src/services/engine.js";
import { shouldColor } from "../src/services/output.js";
import { allTargets, detectPlatform } from "../src/services/platform.js";
import { ExitCode, exitCodeForEngineError, ENGINE_ERROR_CODES } from "../src/utils/exit-codes.js";
import { accountName, sanitize } from "../src/utils/sanitize.js";
import { CliError } from "../src/utils/errors.js";
import { cli, sandbox, tempDir } from "./helpers.js";

test("platform detection maps OS/CPU to engine packages", () => {
  assert.equal(detectPlatform("linux", "x64")?.bundleDir, "binaries/linux-x64");
  assert.equal(detectPlatform("darwin", "arm64")?.rustTarget, "aarch64-apple-darwin");
  assert.equal(detectPlatform("win32", "x64")?.binaryName, "agentguard-engine.exe");
  assert.equal(detectPlatform("win32", "x64")?.status, "unsupported");
  assert.equal(detectPlatform("linux", "x64")?.status, "validated");
  for (const [os, arch] of [["freebsd", "x64"], ["win32", "arm64"], ["linux", "ia32"], ["linux", "__proto__"], ["constructor", ""]]) {
    assert.equal(detectPlatform(os!, arch!), undefined, `${os}-${arch}`);
  }
  assert.equal(allTargets().length, 5);
});

test("engine response validation accepts only well-formed, matching responses", () => {
  const ok = { protocol_version: 1, request_id: "r", success: true, data: { a: 1 }, error: null };
  assert.deepEqual(validateResponse(ok, "r", 0), { success: true, data: { a: 1 } });
  const err = { protocol_version: 1, request_id: "r", success: false, data: null, error: { code: "not-registered", message: "m" } };
  assert.equal(validateResponse(err, "r", 1).success, false);
  const bad: Array<[unknown, number | null]> = [
    [null, 0],
    [[], 0],
    [{ ...ok, protocol_version: 2 }, 0],
    [{ ...ok, request_id: "other" }, 0],
    [{ ...ok, decision: "ALLOW" }, 0],
    [{ ...ok, error: { code: "x", message: "y" } }, 0],
    [{ ...ok, data: null }, 0],
    [{ ...ok, data: [1] }, 0],
    [ok, 1],
    [{ ...err, error: { code: "made-up", message: "m" } }, 1],
    [{ ...err, error: { code: "not-registered", message: "m", extra: true } }, 1],
    [{ ...err, data: {} }, 1],
    [err, 0],
    [{ ...ok, success: "true" }, 0],
  ];
  for (const [value, exit] of bad) {
    assert.throws(() => validateResponse(value, "r", exit), (e: unknown) => e instanceof CliError && e.exitCode === ExitCode.EngineProtocol, JSON.stringify(value));
  }
});

test("every engine error code maps to a documented exit code", () => {
  for (const code of ENGINE_ERROR_CODES) {
    assert.ok([1, 4, 5, 6, 7, 125].includes(exitCodeForEngineError(code)), code);
  }
  assert.equal(exitCodeForEngineError("authorization-required"), ExitCode.ActionRequired);
  assert.equal(exitCodeForEngineError("integrity-failure"), ExitCode.CheckFailed);
  assert.equal(exitCodeForEngineError("unsupported-protocol"), ExitCode.EngineProtocol);
  assert.equal(exitCodeForEngineError("outcome-unrecorded"), ExitCode.Indeterminate, "a run whose outcome was not recorded is never a success");
});

test("terminal output is sanitized and colour is opt-out", () => {
  assert.equal(sanitize("ok\u001b[2J\u001b]0;title\u0007 path\u0000\u009b"), "ok path");
  assert.equal(sanitize("line\nnext\tcol"), "line\nnext\tcol");
  assert.equal(shouldColor({ noColor: true }, {}, true), false);
  assert.equal(shouldColor({ noColor: false }, { NO_COLOR: "1" }, true), false);
  assert.equal(shouldColor({ noColor: false }, {}, false), false);
  assert.equal(shouldColor({ noColor: false }, {}, true), true);
  assert.equal(shouldColor({ noColor: false }, { FORCE_COLOR: "1" }, false), true);
  assert.equal(shouldColor({ noColor: false }, { TERM: "dumb" }, true), false);
  assert.equal(accountName("dev user;rm -rf /"), "devuserrm-rf");
  assert.equal(accountName(""), "user");
});

test("command parsing: usage errors and help", async () => {
  const cwd = tempDir();
  const env = { PATH: process.env["PATH"] };
  assert.equal((await cli([], { env, cwd })).code, ExitCode.Usage);
  assert.equal((await cli(["--help"], { env, cwd })).code, ExitCode.Ok);
  assert.match((await cli(["--help"], { env, cwd })).stdout, /ai-defender init/);
  assert.equal((await cli(["frobnicate"], { env, cwd })).code, ExitCode.Usage);
  assert.equal((await cli(["status", "--bogus"], { env, cwd })).code, ExitCode.Usage);
  assert.equal((await cli(["policy"], { env, cwd })).code, ExitCode.Usage);
  assert.equal((await cli(["project", "delete"], { env, cwd })).code, ExitCode.Usage);
  assert.equal((await cli(["status", "extra"], { env, cwd })).code, ExitCode.Usage);
});

test("the package is ai-defender, with agentguard kept as an alias of the same entry point", async () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { name: string; bin: Record<string, string> };
  assert.equal(pkg.name, "ai-defender");
  assert.deepEqual(Object.keys(pkg.bin).sort(), ["agentguard", "ai-defender"]);
  assert.equal(pkg.bin["agentguard"], pkg.bin["ai-defender"]);
  const help = (await cli(["--help"], { env: sandbox().env, cwd: tempDir() })).stdout;
  assert.match(help, /^AI Defender/);
  assert.match(help, /`agentguard` is the earlier name/);
});
