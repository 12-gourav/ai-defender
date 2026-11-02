/**
 * `ai-defender history`: recent security events from the engine's hash-chained audit log.
 * The engine reads and filters the log; events were redacted when they were recorded.
 */

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { sanitize } from "../utils/sanitize.js";
import { usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";

type Json = Record<string, unknown>;

const DECISION_TONE: Record<string, Tone> = { allow: "ok", deny: "bad", "requires-approval": "warn" };

export async function history(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender history [--blocked | --approvals] [--limit N]");
  if (ctx.flags.blocked && ctx.flags.approvals) throw usageError("give either --blocked or --approvals");
  const filter = ctx.flags.blocked ? "blocked" : ctx.flags.approvals ? "approvals" : "all";
  const limit = ctx.flags.limit === undefined ? 30 : Number(ctx.flags.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw usageError("--limit must be a whole number from 1 to 500");
  const data = await ctx.call("history.list", { filter, limit });
  if (ctx.flags.json) {
    ctx.emitJson("history", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  if (data["available"] !== true) {
    out.note(String(data["detail"] ?? "no security history is available"));
    return ExitCode.Ok;
  }
  const events = Array.isArray(data["events"]) ? (data["events"] as Json[]) : [];
  const title = { all: "Recent security events", blocked: "Recent blocked operations", approvals: "Recent approval activity" }[filter];
  out.heading(`${title} (${events.length}, newest first)`);
  if (events.length === 0) out.note("  None recorded.");
  for (const e of events) {
    const decision = typeof e["decision"] === "string" ? e["decision"] : "";
    const time = String(e["timestamp"] ?? "").replace(/\.\d+Z$/, "Z");
    out.line(`  ${out.paint(sanitize(time), "muted")}  ${String(e["kind"]).padEnd(32)} ${decision ? out.paint(decision.toUpperCase().padEnd(18), DECISION_TONE[decision] ?? "plain") : "".padEnd(18)} ${sanitize(String(e["resource"] ?? "")).slice(0, 70)}`);
    const why = String(e["reason"] ?? "");
    if (why && decision === "deny") out.note(`      ${why.slice(0, 160)}`);
  }
  if (data["truncated_to_recent_bytes"] === true) out.note("Only the most recent 8 MiB of the audit log were read.");
  return ExitCode.Ok;
}
