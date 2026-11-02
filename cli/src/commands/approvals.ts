/**
 * Human approval commands. The engine owns every approval state and transition; this file only
 * displays engine data and forwards a human's explicit decision.
 *
 * Approving is deliberately the hardest path in the CLI: it needs a real interactive terminal,
 * the typed word "approve" after the exact operation is shown, and the signing key passphrase
 * typed at a hidden prompt. `--yes`, `--json`, `--non-interactive` and `--passphrase-file` are
 * refused for it, because each can be supplied by a process that is not a human at a terminal.
 */

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { CliError, usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

const RISK_TONE: Record<string, Tone> = { low: "ok", medium: "warn", high: "bad", critical: "bad" };
const STATUS_TONE: Record<string, Tone> = {
  pending: "warn",
  approved: "warn",
  rejected: "muted",
  expired: "muted",
  cancelled: "muted",
  consumed: "muted",
};

function str(value: unknown): string {
  return value === undefined || value === null ? "—" : String(value);
}

/** "in 4m 12s", "expired", from engine timestamps. */
export function relative(expiresAt: unknown, now: unknown): string {
  const end = Date.parse(str(expiresAt));
  const start = Date.parse(str(now));
  if (Number.isNaN(end) || Number.isNaN(start)) return str(expiresAt);
  const seconds = Math.floor((end - start) / 1000);
  if (seconds <= 0) return "expired";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `in ${m}m ${s}s` : `in ${s}s`;
}

function projectName(approval: Json): string {
  const root = str(at(approval, "project.root"));
  return root.split("/").filter(Boolean).at(-1) ?? root;
}

function requireId(args: string[], usage: string): string {
  const [id, ...rest] = args;
  if (id === undefined || rest.length > 0) throw usageError(usage);
  return id;
}

async function list(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender approvals [list] [--json]");
  const data = await ctx.call("approval.list", { include_closed: true });
  if (ctx.flags.json) {
    ctx.emitJson("approvals", true, { data });
    return ExitCode.Ok;
  }
  const approvals = Array.isArray(data["approvals"]) ? (data["approvals"] as Json[]) : [];
  const out = ctx.out;
  out.title();
  const pending = approvals.filter((a) => a["status"] === "pending").length;
  out.heading(`Approval requests (${pending} pending, ${approvals.length} total)`);
  if (approvals.length === 0) out.note("  No approval requests.");
  for (const a of approvals) {
    const status = str(a["status"]);
    out.line();
    out.line(`  ${out.paint(str(a["approval_id"]), "info")}  ${out.paint(status.toUpperCase(), STATUS_TONE[status] ?? "plain")}`);
    out.field("Operation", `${str(at(a, "operation.label"))}: ${str(at(a, "operation.target"))}`, "plain", 14);
    out.field("Project", projectName(a), "plain", 14);
    out.field("Agent", at(a, "agent.name"), "plain", 14);
    out.field("Risk", str(a["risk"]).toUpperCase(), RISK_TONE[str(a["risk"])] ?? "plain", 14);
    out.field("Requested", a["created_at"], "muted", 14);
    out.field("Expires", status === "pending" ? `${str(a["expires_at"])} (${relative(a["expires_at"], data["now"])})` : a["expires_at"], "muted", 14);
  }
  if (Number(data["unreadable"]) > 0) out.warn(`${String(data["unreadable"])} approval record(s) could not be read and are ignored`);
  if (pending > 0) {
    out.line();
    out.note("Review one with `ai-defender approve <id>` or `ai-defender reject <id>`.");
  }
  return ExitCode.Ok;
}

function review(ctx: Context, approval: Json, now: unknown): void {
  const out = ctx.out;
  const risk = str(approval["risk"]);
  out.line(out.paint("AI Defender — Approval Required", "bad"));
  out.line();
  const block = (label: string, value: unknown, tone: Tone = "plain") => {
    out.line(`${label}:`);
    out.line(`  ${out.paint(sanitizeLine(value), tone)}`);
    out.line();
  };
  block("Requested operation", at(approval, "operation.label"));
  block("Repository", `${projectName(approval)} (${str(at(approval, "project.root"))})`);
  block("Target", at(approval, "operation.target"));
  if (at(approval, "operation.target_truncated") === true) {
    out.warn("the target is longer than shown; reject unless you can verify the full operation");
  }
  block("Agent", at(approval, "agent.name"));
  block("Risk", risk.charAt(0).toUpperCase() + risk.slice(1), RISK_TONE[risk] ?? "plain");
  block("Reason", at(approval, "operation.impact"));
  block("Why approval is required", `policy: ${str(approval["reason"])}`);
  block("Approval scope", "One exact operation, once");
  block("Expiration", `${str(approval["expires_at"])} (${relative(approval["expires_at"], now)})`);
  out.field("Approval ID", approval["approval_id"], "muted", 18);
  out.field("Operation digest", approval["operation_digest"], "muted", 18);
  out.field("Policy rule", approval["rule"], "muted", 18);
  out.line();
}

function sanitizeLine(value: unknown): string {
  return str(value).replace(/\s*\n\s*/g, " ");
}

async function show(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const id = requireId(args, "usage: ai-defender approvals show <approval-id>");
  const data = await ctx.call("approval.show", { approval_id: id });
  if (ctx.flags.json) {
    ctx.emitJson("approvals show", true, { data });
    return ExitCode.Ok;
  }
  const approval = (data["approval"] ?? {}) as Json;
  ctx.out.title();
  review(ctx, approval, data["now"]);
  const status = str(approval["status"]);
  ctx.out.field("Status", status.toUpperCase(), STATUS_TONE[status] ?? "plain", 18);
  ctx.out.field("Decided by", approval["decided_by"], "plain", 18);
  ctx.out.field("Grant", at(approval, "grant.grant_id"), "muted", 18);
  ctx.out.field("Grant state", at(approval, "grant.state"), "muted", 18);
  ctx.out.field("Closed", at(approval, "closure.reason_code"), "muted", 18);
  return ExitCode.Ok;
}

/** Refuse every input that a non-human process could supply in place of a human decision. */
function requireHumanAtTerminal(ctx: Context): void {
  const refuse = (what: string) =>
    new CliError(
      "human-approval-required",
      `${what} cannot approve an operation; approval needs a human at an interactive terminal`,
      ExitCode.ActionRequired,
      "run `ai-defender approve <id>` yourself in a terminal, or reject it with `ai-defender reject <id>`",
    );
  if (ctx.flags.yes) throw refuse("--yes");
  if (ctx.flags.json) throw refuse("--json");
  if (ctx.flags.passphraseFile !== undefined) throw refuse("--passphrase-file");
  if (ctx.flags.nonInteractive) throw refuse("--non-interactive");
  if (!ctx.io.prompter.interactive) throw refuse("a session without a terminal");
}

const QUESTION: Record<string, string> = {
  git: "This operation will act on a Git repository.",
  terminal: "This operation will run a shell command with your permissions.",
  filesystem: "This operation will change files.",
};

export async function approve(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const id = requireId(args, "usage: ai-defender approve <approval-id>");
  requireHumanAtTerminal(ctx);
  const data = await ctx.call("approval.show", { approval_id: id });
  const approval = (data["approval"] ?? {}) as Json;
  const status = str(approval["status"]);
  if (status !== "pending") {
    throw new CliError("not-pending", `approval ${str(approval["approval_id"])} is ${status}; only pending requests can be decided`, ExitCode.Failure);
  }
  ctx.out.title();
  review(ctx, approval, data["now"]);
  const impact = str(at(approval, "operation.impact"));
  const lead = impact !== "—" ? impact : (QUESTION[str(at(approval, "operation.category"))] ?? "This operation needs your approval.");
  ctx.out.line(`${lead} Approve this exact operation?`);
  const answer = (await ctx.io.prompter.ask('Type "approve" to approve, "reject" to reject, or press Enter to decide later: ')).trim().toLowerCase();
  const fullId = str(approval["approval_id"]);
  if (answer === "reject") return decideReject(ctx, fullId);
  if (answer !== "approve") {
    throw new CliError("cancelled", "no decision recorded; the request is still pending", ExitCode.Failure);
  }
  const passphrase = await ctx.passphrase(false);
  const result = await ctx.call("approval.approve", {
    approval_id: fullId,
    operation_digest: approval["operation_digest"],
    requested_by: ctx.requestedBy,
    confirm: true,
    ...passphrase,
  });
  const after = (result["approval"] ?? {}) as Json;
  ctx.out.line();
  ctx.out.line(ctx.out.paint("APPROVED: one exact operation, once.", "warn"));
  ctx.out.field("Grant", at(after, "grant.grant_id"), "plain", 14);
  ctx.out.field("Valid until", at(after, "grant.expires_at"), "warn", 14);
  ctx.out.note("The agent can now perform exactly the operation shown above, one time. Any change to it needs a new approval.");
  ctx.out.note(`Revoke it before use with \`ai-defender approvals revoke ${fullId}\`.`);
  return ExitCode.Ok;
}

async function decideReject(ctx: Context, id: string): Promise<ExitCodeValue> {
  const data = await ctx.call("approval.reject", {
    approval_id: id,
    requested_by: ctx.requestedBy,
    confirm: true,
    ...(ctx.flags.reason !== undefined ? { reason: ctx.flags.reason } : {}),
  });
  if (ctx.flags.json) {
    ctx.emitJson("reject", true, { data });
    return ExitCode.Ok;
  }
  ctx.out.line(ctx.out.paint(`Rejected approval ${id}. The operation was not authorized.`, "plain"));
  return ExitCode.Ok;
}

export async function reject(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const id = requireId(args, "usage: ai-defender reject <approval-id> [--reason TEXT]");
  const data = await ctx.call("approval.show", { approval_id: id });
  const approval = (data["approval"] ?? {}) as Json;
  const fullId = str(approval["approval_id"]);
  await ctx.confirm(`Reject ${str(at(approval, "operation.label"))} (${str(at(approval, "operation.target"))}) requested by ${str(at(approval, "agent.name"))}?`, "rejecting an approval request");
  return decideReject(ctx, fullId);
}

async function withdraw(ctx: Context, args: string[], action: "cancel" | "revoke"): Promise<ExitCodeValue> {
  const id = requireId(args, `usage: ai-defender approvals ${action} <approval-id>`);
  const data = await ctx.call("approval.show", { approval_id: id });
  const approval = (data["approval"] ?? {}) as Json;
  const fullId = str(approval["approval_id"]);
  const what = `${str(at(approval, "operation.label"))} (${str(at(approval, "operation.target"))})`;
  if (action === "cancel") {
    await ctx.confirm(`Cancel the pending request for ${what}?`, "cancelling an approval request");
  } else {
    await ctx.confirm(`Revoke the unused grant for ${what}?`, "revoking an authorization");
  }
  const result = await ctx.call(action === "cancel" ? "approval.cancel" : "authorization.revoke", {
    approval_id: fullId,
    requested_by: ctx.requestedBy,
    confirm: true,
  });
  if (ctx.flags.json) {
    ctx.emitJson(`approvals ${action}`, true, { data: result });
    return ExitCode.Ok;
  }
  ctx.out.line(action === "cancel" ? `Cancelled approval request ${fullId}.` : `Revoked the grant for approval ${fullId}. It can no longer authorize anything.`);
  return ExitCode.Ok;
}

export async function approvals(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, ...rest] = args;
  switch (sub) {
    case undefined:
    case "list":
      return list(ctx, rest);
    case "show":
      return show(ctx, rest);
    case "cancel":
      return withdraw(ctx, rest, "cancel");
    case "revoke":
      return withdraw(ctx, rest, "revoke");
    default:
      throw usageError("usage: ai-defender approvals [list|show <id>|cancel <id>|revoke <id>]");
  }
}
