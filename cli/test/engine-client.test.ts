import assert from "node:assert/strict";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { callEngine } from "../src/services/engine.js";
import { CliError } from "../src/utils/errors.js";
import { ExitCode } from "../src/utils/exit-codes.js";
import { cli, fakeEngine, tempDir } from "./helpers.js";

const env = { PATH: process.env["PATH"] };

function engineThat(body: string) {
  return { path: fakeEngine(tempDir("agentguard-fake-"), body), verified: false, source: "development" as const };
}

const READ_REQUEST = `let input = ""; process.stdin.on("data", (c) => (input += c)); process.stdin.on("end", () => { const req = JSON.parse(input); main(req); });`;

test("malformed, mismatched or oversized engine output is rejected", async () => {
  const cases: Array<[string, number]> = [
    [`${READ_REQUEST} function main() { process.stdout.write("not json\\n"); }`, ExitCode.EngineProtocol],
    [`${READ_REQUEST} function main(r) { console.log(JSON.stringify({protocol_version:1,request_id:r.request_id,success:true,data:{},error:null})); console.log("{}"); }`, ExitCode.EngineProtocol],
    [`${READ_REQUEST} function main(r) { console.log(JSON.stringify({protocol_version:1,request_id:"forged",success:true,data:{},error:null})); }`, ExitCode.EngineProtocol],
    [`${READ_REQUEST} function main(r) { console.log(JSON.stringify({protocol_version:9,request_id:r.request_id,success:true,data:{},error:null})); }`, ExitCode.EngineProtocol],
    [`${READ_REQUEST} function main(r) { console.log(JSON.stringify({protocol_version:1,request_id:r.request_id,success:true,data:{},error:null,decision:"ALLOW"})); }`, ExitCode.EngineProtocol],
    [`${READ_REQUEST} function main(r) { console.log(JSON.stringify({protocol_version:1,request_id:r.request_id,success:true,data:{},error:null})); process.exitCode = 1; }`, ExitCode.EngineProtocol],
    [`${READ_REQUEST} function main() { process.stdout.write("x".repeat(2 * 1024 * 1024)); }`, ExitCode.EngineProtocol],
    [`process.exit(0);`, ExitCode.EngineProtocol],
  ];
  for (const [body, expected] of cases) {
    await assert.rejects(callEngine(engineThat(body), "status", {}, { env }), (e: unknown) => e instanceof CliError && e.exitCode === expected, body.slice(0, 120));
  }
});

test("a hung engine is killed after the timeout", async () => {
  const engine = engineThat(`setInterval(() => {}, 1000);`);
  const started = Date.now();
  await assert.rejects(callEngine(engine, "status", {}, { env, timeoutMs: 300 }), (e: unknown) => e instanceof CliError && e.exitCode === ExitCode.EngineUnavailable);
  assert.ok(Date.now() - started < 5000);
});

test("a missing engine binary is unavailable, never a success", async () => {
  await assert.rejects(
    callEngine({ path: "/nonexistent/agentguard-engine", verified: false, source: "development" }, "status", {}, { env }),
    (e: unknown) => e instanceof CliError && e.exitCode === ExitCode.EngineUnavailable,
  );
});

test("paths with spaces and shell metacharacters are passed as data, never interpreted", async () => {
  const base = tempDir("agentguard-inject-");
  const marker = path.join(base, "PWNED");
  const dir = path.join(base, `proj $(touch ${marker}) ; touch ${marker} \` touch ${marker}\``);
  mkdirSync(dir, { recursive: true });
  const engine = engineThat(`${READ_REQUEST} function main(r) { console.log(JSON.stringify({protocol_version:1,request_id:r.request_id,success:true,data:{seen:r.arguments.working_directory},error:null})); }`);
  const response = await callEngine(engine, "status", { working_directory: dir }, { env, cwd: dir });
  assert.ok(response.success);
  assert.equal(response.data["seen"], dir);
  await cli(["status", "--json"], { env: { ...env, AGENTGUARD_DEV_ENGINE: engine.path, AGENTGUARD_ALLOW_UNVERIFIED_ENGINE: "1" }, cwd: dir });
  assert.equal(existsSync(marker), false, "no shell interpreted the path");
});
