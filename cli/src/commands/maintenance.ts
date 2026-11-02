/**
 * `doctor`, `repair` and `update`.
 *
 * - `doctor` runs every diagnostic AI Defender has: engine verification and protocol, trusted
 *   state and project checks (`check`), prerequisites (Node.js, Git, agent CLIs), and the
 *   health of each installed integration. Exit 5 if anything fails.
 * - `repair` fixes installation problems only: it re-points degraded or outdated agent hooks at
 *   a fresh verified engine copy. It never repairs trusted state (a failed integrity check is
 *   reported, not accepted) and never changes policy.
 * - `update` reports installed versions and how to upgrade. npm performs the upgrade; the CLI
 *   has no network access and never downloads anything itself.
 */

import type { Context } from "../cli.js";
import { cliVersion } from "../cli.js";
import { ENGINE_PROTOCOL_VERSION } from "../services/installer.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { CliError, usageError } from "../utils/errors.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;
type Status = "pass" | "warn" | "fail" | "skip";

interface Item {
  id: string;
  title: string;
  status: Status;
  detail: string;
}

function nodeMajor(version: string): number {
  return Number(version.replace(/^v/, "").split(".")[0]);
}

export async function doctor(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender doctor");
  const items: Item[] = [];
  const engine = ctx.engine();
  items.push(
    engine.verified
      ? { id: "engine", title: "Engine binary", status: "pass", detail: `verified release ${engine.version ?? ""} at ${engine.path}` }
      : { id: "engine", title: "Engine binary", status: "warn", detail: `UNVERIFIED development build at ${engine.path}` },
  );
  const version = await ctx.call("version", {});
  const protocolOk = version["engine_protocol_version"] === ENGINE_PROTOCOL_VERSION;
  items.push({ id: "protocol", title: "Engine protocol", status: protocolOk ? "pass" : "fail", detail: `engine ${String(version["engine_version"])}, protocol ${String(version["engine_protocol_version"])}` });
  items.push({
    id: "versions",
    title: "CLI and engine versions",
    status: version["engine_version"] === cliVersion() ? "pass" : "warn",
    detail: `CLI ${cliVersion()}, engine ${String(version["engine_version"])}`,
  });
  items.push({ id: "node", title: "Node.js", status: nodeMajor(process.version) >= 18 ? "pass" : "fail", detail: process.version });
  const pre = await ctx.call("prerequisites", {});
  items.push({ id: "git", title: "Git", status: pre["git"] ? "pass" : "warn", detail: pre["git"] ? String(pre["git"]) : "not found: Git operations, staged scans and managed Git are unavailable" });
  for (const [id, name] of [["claude", "Claude Code"], ["codex", "Codex"]] as const) {
    const v = at(pre, `agents.${id}`);
    items.push({ id, title: name, status: v ? "pass" : "skip", detail: v ? String(v) : "not installed" });
  }
  const check = await ctx.call("check", { working_directory: ctx.cwd });
  for (const c of (Array.isArray(check["checks"]) ? check["checks"] : []) as Json[]) {
    items.push({ id: String(c["id"]), title: String(c["title"]), status: String(c["status"]) as Status, detail: String(c["detail"]) });
  }
  const integrations = await ctx.call("integrations.status", {});
  for (const i of (Array.isArray(integrations["integrations"]) ? integrations["integrations"] : []) as Json[]) {
    const state = String(i["state"]);
    const status: Status = state === "installed" ? (at(i, "compatibility.state") === "degraded" ? "warn" : "pass") : state === "not-installed" ? "skip" : "fail";
    const detail = state === "installed" && at(i, "compatibility.state") === "degraded" ? `installed; ${String(at(i, "compatibility.detail"))}` : state === "outdated" ? "hooks run an older engine: run `ai-defender repair`" : state;
    items.push({ id: `integration-${String(i["provider"])}`, title: `${String(i["name"])} integration`, status, detail });
  }
  const failed = items.some((i) => i.status === "fail");
  if (ctx.flags.json) {
    ctx.emitJson("doctor", !failed, { data: { ok: !failed, checks: items } });
    return failed ? ExitCode.CheckFailed : ExitCode.Ok;
  }
  ctx.out.title();
  ctx.out.heading("AI Defender doctor");
  for (const i of items) ctx.out.check(i.status, i.title, i.detail);
  ctx.out.line();
  if (failed) ctx.out.note("Installation problems can often be fixed with `ai-defender repair`. Trusted-state failures cannot: see `ai-defender check`.");
  return failed ? ExitCode.CheckFailed : ExitCode.Ok;
}

export async function repair(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender repair");
  const status = await ctx.call("status", { working_directory: ctx.cwd });
  if (at(status, "trust_store.state") === "integrity-failure") {
    throw new CliError(
      "integrity-failure",
      `trusted state failed verification (${String(at(status, "trust_store.detail"))}); repair never accepts modified trusted state`,
      ExitCode.CheckFailed,
      "see docs/TRUST_MODEL.md section 6 (recovery)",
    );
  }
  await ctx.confirm("Re-point degraded or outdated agent hooks at a fresh verified engine copy? Other settings and hooks are kept and backed up.", "repairing AI Defender");
  const sha = ctx.engine().sha256;
  const data = await ctx.call("integrations.repair", { confirm: true, ...(sha ? { engine_sha256: sha } : {}) });
  if (ctx.flags.json) {
    ctx.emitJson("repair", true, { data });
    return ExitCode.Ok;
  }
  ctx.out.title();
  ctx.out.heading("Repair");
  for (const a of (Array.isArray(data["actions"]) ? data["actions"] : []) as Json[]) {
    const action = String(a["action"]);
    ctx.out.check(action === "reinstalled" ? "pass" : "skip", `${String(a["provider"])} integration`, action === "reinstalled" ? `reinstalled (was ${String(a["previous_state"])})` : action === "none" ? "healthy, nothing to do" : String(a["detail"] ?? action));
  }
  ctx.out.line();
  ctx.out.note("Run `ai-defender integrations verify` to confirm.");
  return ExitCode.Ok;
}

export async function update(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender update");
  const version = await ctx.call("version", {});
  const data = {
    cli_version: cliVersion(),
    engine_version: version["engine_version"],
    engine_protocol_version: version["engine_protocol_version"],
    engine_verified: ctx.engine().verified,
    upgrade: ["npm install -g ai-defender@latest", "ai-defender repair", "ai-defender doctor"],
    downloads: false,
  };
  if (ctx.flags.json) {
    ctx.emitJson("update", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.field("CLI version", data.cli_version);
  out.field("Engine version", `${String(data.engine_version)} (protocol ${String(data.engine_protocol_version)})`);
  out.field("Engine verified", data.engine_verified ? "yes" : "no (development build)", data.engine_verified ? "ok" : "warn");
  out.line();
  out.line("  AI Defender is updated by npm; this command does not download anything. To upgrade:");
  for (const step of data.upgrade) out.line(`    ${step}`);
  out.note("  Upgrades keep your signing keys, trusted policy, project registry, approvals and audit history; `repair` re-points agent hooks at the new engine.");
  return ExitCode.Ok;
}
