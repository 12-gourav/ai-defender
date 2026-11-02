import type { Context } from "../cli.js";
import { usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

async function list(ctx: Context): Promise<ExitCodeValue> {
  const data = await ctx.call("project.list", {});
  const projects = Array.isArray(data["projects"]) ? (data["projects"] as Json[]) : [];
  if (ctx.flags.json) {
    ctx.emitJson("project list", true, { data });
    return ExitCode.Ok;
  }
  ctx.out.title();
  ctx.out.heading(`Registered projects (${projects.length})`);
  for (const p of projects) {
    const trusted = p["status"] === "trusted";
    const intact = p["directory_matches"] === true;
    const label = !trusted ? "revoked" : intact ? "trusted" : "directory replaced";
    ctx.out.field(label, p["root"], trusted && intact ? "ok" : "bad", 22);
  }
  return ExitCode.Ok;
}

async function inspect(ctx: Context): Promise<ExitCodeValue> {
  const data = await ctx.call("project.inspect", { working_directory: ctx.cwd });
  if (ctx.flags.json) {
    ctx.emitJson("project inspect", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.heading("Project registration");
  out.field("Root", at(data, "registration.root"));
  out.field("Project ID", at(data, "registration.id"), "muted");
  out.field("Trust status", at(data, "registration.status"), at(data, "registration.status") === "trusted" ? "ok" : "bad");
  out.field("Directory intact", at(data, "registration.directory_matches") === true ? "yes" : "NO", at(data, "registration.directory_matches") === true ? "ok" : "bad");
  out.field("Approved policy", at(data, "registration.approved_policy") ?? "none");
  out.field("Approved by", at(data, "approved_by") ?? "—");
  out.field("Configuration", at(data, "config.state"));
  out.field("Configuration drift", at(data, "policy_drift") === true ? "yes (not applied until approved)" : "no", at(data, "policy_drift") === true ? "warn" : "plain");
  const rules = Array.isArray(data["approved_rules"]) ? (data["approved_rules"] as Json[]) : [];
  out.line();
  out.heading(`Approved restrictions (${rules.length})`);
  for (const r of rules) out.field(String(r["decision"]), `${String(r["id"])} — ${String(r["reason"])}`);
  return ExitCode.Ok;
}

async function change(ctx: Context, action: "trust" | "revoke"): Promise<ExitCodeValue> {
  const before = await ctx.call("status", { working_directory: ctx.cwd });
  const root = String(at(before, "project.root"));
  if (action === "revoke") {
    if (at(before, "project.registration.state") !== "registered") {
      throw usageError("the current directory is not inside a trusted, registered project");
    }
    await ctx.confirm(`Revoke AI Defender trust for ${root}? Requests from it will be treated as unregistered.`, "revoking project trust");
  } else {
    await ctx.confirm(`Trust ${root} and approve its configured restrictions?`, "trusting a project");
  }
  const passphrase = await ctx.passphrase(false);
  const data = await ctx.call(`project.${action}`, {
    working_directory: ctx.cwd,
    confirm: true,
    requested_by: ctx.requestedBy,
    ...passphrase,
  });
  if (ctx.flags.json) {
    ctx.emitJson(`project ${action}`, true, { data });
  } else {
    ctx.out.title();
    ctx.out.field("Project", data["root"]);
    ctx.out.field("Status", action === "revoke" ? data["status"] : at(data, "registration.status"), action === "revoke" ? "warn" : "ok");
    if (action === "trust") ctx.out.field("Approved policy", at(data, "project_policy.approved") ?? "none");
  }
  return ExitCode.Ok;
}

export async function project(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, ...rest] = args;
  if (rest.length > 0) throw usageError("too many arguments");
  switch (sub) {
    case "list":
      return list(ctx);
    case "inspect":
      return inspect(ctx);
    case "trust":
      return change(ctx, "trust");
    case "revoke":
      return change(ctx, "revoke");
    default:
      throw usageError("usage: ai-defender project list|inspect|trust|revoke");
  }
}
