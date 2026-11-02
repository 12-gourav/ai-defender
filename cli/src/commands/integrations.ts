/**
 * Agent hook integrations (Claude Code, OpenAI Codex). The engine edits the providers' hook
 * configuration, keeps backups and records health checks; this file displays its answers and
 * forwards a human's explicit confirmation (and, for removal, the signing key passphrase).
 */

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

const USAGE =
  "usage: ai-defender integrations [list] | status [claude|codex] | install claude|codex | uninstall claude|codex | verify [claude|codex] | coverage [claude|codex]";

const STATE_TONE: Record<string, Tone> = { installed: "ok", degraded: "bad", "not-installed": "muted", unavailable: "warn" };
const COVERAGE_TONE: Record<string, Tone> = { protected: "ok", observed: "info", unsupported: "muted", bypassable: "warn" };

function str(v: unknown): string {
  return v === undefined || v === null ? "—" : String(v);
}

function list(v: unknown): Json[] {
  return Array.isArray(v) ? (v as Json[]) : [];
}

function provider(arg: string | undefined, required: boolean): string | undefined {
  if (arg === undefined) {
    if (required) throw usageError(USAGE);
    return undefined;
  }
  if (arg !== "claude" && arg !== "codex") throw usageError(USAGE);
  return arg;
}

async function showList(ctx: Context): Promise<ExitCodeValue> {
  const data = await ctx.call("integrations.list", {});
  if (ctx.flags.json) {
    ctx.emitJson("integrations", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.heading("Agent integrations");
  for (const i of list(data["integrations"])) {
    out.line(`  ${out.paint(str(i["provider"]).padEnd(8), "info")} ${str(i["name"])}`);
    out.line(`           events: ${list(i["events"]).map((e) => `${str(e["name"])} (${str(e["capability"])})`).join(", ")}`);
    out.note(`           documentation verified ${str(i["documentation_verified"])}: ${str(i["documentation"])}`);
  }
  out.line();
  out.note("Install with `ai-defender integrations install claude|codex`; see what is covered with `ai-defender integrations coverage`.");
  return ExitCode.Ok;
}

async function showStatus(ctx: Context, p: string | undefined): Promise<ExitCodeValue> {
  const data = await ctx.call("integrations.status", p ? { provider: p } : {});
  if (ctx.flags.json) {
    ctx.emitJson("integrations status", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  for (const i of list(data["integrations"])) {
    const state = str(i["state"]);
    out.heading(str(i["name"]));
    out.field("State", state, STATE_TONE[state] ?? "plain");
    out.field("Configuration", i["config_path"] ?? i["config_error"]);
    out.field("Events", list(at(i, "installed.events")).join(", ") || "none");
    out.field("Other hooks kept", at(i, "installed.other_handlers"));
    out.field("Fails closed", at(i, "installed.fails_closed") === true ? "yes" : "no", at(i, "installed.fails_closed") === true ? "ok" : "bad");
    out.field("Hook executable", at(i, "engine.configured"));
    const problems = list(at(i, "engine.problems")) as unknown as string[];
    if (problems.length > 0) out.field("Executable problems", problems.join("; "), "bad");
    out.field("Engine unchanged", at(i, "engine.sha256_matches_install") === true ? "yes" : "no", at(i, "engine.sha256_matches_install") === true ? "ok" : "warn");
    out.field("Provider version", i["provider_version"] ?? "not found");
    const compat = str(at(i, "compatibility.state"));
    out.field("Compatibility", compat, compat === "compatible" ? "ok" : compat === "degraded" ? "bad" : "warn");
    if (at(i, "compatibility.detail")) out.note(`    ${str(at(i, "compatibility.detail"))}`);
    const health = i["last_health_check"] as Json | null | undefined;
    out.field("Last health check", health ? `${str(health["at"])} (${health["passed"] === true ? "passed" : "FAILED"})` : "never", health?.["passed"] === true ? "ok" : "warn");
    out.field("Enforcement", i["enforcement"]);
    out.note(`    ${str(i["notes"])}`);
    out.line();
  }
  out.note(str(data["statement"]));
  return ExitCode.Ok;
}

async function showCoverage(ctx: Context, p: string | undefined): Promise<ExitCodeValue> {
  const data = await ctx.call("integrations.coverage", p ? { provider: p } : {});
  if (ctx.flags.json) {
    ctx.emitJson("integrations coverage", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  for (const c of list(data["coverage"])) {
    out.heading(`${str(c["name"])} coverage`);
    for (const r of list(c["rows"])) {
      const status = str(r["status"]);
      out.line(`  ${out.paint(status.toUpperCase().padEnd(12), COVERAGE_TONE[status] ?? "plain")} ${str(r["subject"])}`);
      out.note(`               ${str(r["detail"])}`);
    }
    out.line();
  }
  out.note(str(data["statement"]));
  return ExitCode.Ok;
}

async function install(ctx: Context, p: string): Promise<ExitCodeValue> {
  await ctx.confirm(
    `Add AI Defender's hooks to your ${p === "claude" ? "Claude Code" : "Codex"} configuration? Your existing settings and hooks are kept and backed up.`,
    `installing the ${p} integration`,
  );
  const sha = ctx.engine().sha256;
  const data = await ctx.call("integrations.install", { provider: p, confirm: true, ...(sha ? { engine_sha256: sha } : {}) });
  if (ctx.flags.json) {
    ctx.emitJson("integrations install", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.line(out.paint(data["changed"] === true ? `Installed the ${p} integration.` : `The ${p} integration was already installed; nothing changed.`, "ok"));
  out.field("Configuration", data["config_path"]);
  if (data["backup"]) out.field("Backup", data["backup"], "muted");
  const compat = str(at(data, "compatibility.state"));
  out.field("Compatibility", compat, compat === "compatible" ? "ok" : compat === "degraded" ? "bad" : "warn");
  if (at(data, "compatibility.detail")) out.warn(str(at(data, "compatibility.detail")));
  for (const w of (Array.isArray(data["warnings"]) ? data["warnings"] : []) as string[]) out.warn(w);
  out.line();
  out.line(`  Next: ${str(data["next"])}`);
  return ExitCode.Ok;
}

async function uninstall(ctx: Context, p: string): Promise<ExitCodeValue> {
  await ctx.confirm(`Remove AI Defender's hooks from your ${p} configuration? Its tool calls will no longer be checked.`, `removing the ${p} integration`);
  const passphrase = await ctx.passphrase(false);
  const data = await ctx.call("integrations.uninstall", { provider: p, confirm: true, requested_by: ctx.requestedBy, ...passphrase });
  if (ctx.flags.json) {
    ctx.emitJson("integrations uninstall", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.line(data["changed"] === true ? `Removed ${str(data["handlers_removed"])} AI Defender hook entr(ies); other hooks and settings were kept.` : "No AI Defender hook entries were present.");
  if (data["backup"]) out.field("Backup", data["backup"], "muted");
  out.warn(`${p} tool calls are no longer checked by AI Defender.`);
  return ExitCode.Ok;
}

async function verify(ctx: Context, p: string | undefined): Promise<ExitCodeValue> {
  const data = await ctx.call("integrations.verify", { ...(p ? { provider: p } : {}), working_directory: ctx.cwd });
  const results = list(data["results"]);
  const failed = results.some((r) => r["passed"] !== true);
  if (ctx.flags.json) {
    ctx.emitJson("integrations verify", true, { data });
    return failed ? ExitCode.CheckFailed : ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  for (const r of results) {
    out.heading(`Verify ${str(r["provider"])}`);
    for (const c of list(r["checks"])) out.check(c["passed"] === true ? "pass" : "fail", str(c["id"]), str(c["detail"]));
    out.line();
  }
  out.note(str(data["statement"]));
  return failed ? ExitCode.CheckFailed : ExitCode.Ok;
}

export async function integrations(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, arg, ...rest] = args;
  if (rest.length > 0) throw usageError(USAGE);
  switch (sub) {
    case undefined:
    case "list":
      if (arg !== undefined) throw usageError(USAGE);
      return showList(ctx);
    case "status":
      return showStatus(ctx, provider(arg, false));
    case "coverage":
      return showCoverage(ctx, provider(arg, false));
    case "install":
      return install(ctx, provider(arg, true) as string);
    case "uninstall":
      return uninstall(ctx, provider(arg, true) as string);
    case "verify":
      return verify(ctx, provider(arg, false));
    default:
      throw usageError(USAGE);
  }
}
