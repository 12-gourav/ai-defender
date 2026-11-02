/**
 * The global project registry: every project connected to AI Defender on this machine.
 *
 * The registry is signed trusted state owned by the engine. This file lists and displays it,
 * resolves a project reference (ID prefix, folder name or path) to its registered root, and
 * reuses the existing commands for changes: `projects add` is `init` in that directory, and
 * `projects revoke` is `project revoke` there (confirmation and passphrase).
 */

import path from "node:path";

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { sanitize } from "../utils/sanitize.js";
import { CliError, usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { init } from "./init.js";
import { project } from "./project.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

const USAGE = "usage: ai-defender projects [list] | inspect <project> | add [path] | revoke <project>   (<project>: ID prefix, folder name or path)";

export interface Registered {
  id: string;
  root: string;
  name: string;
  status: string;
  intact: boolean;
  registeredAt: number | undefined;
}

function registered(data: Json): Registered[] {
  const list = Array.isArray(data["projects"]) ? (data["projects"] as Json[]) : [];
  return list.map((p) => ({
    id: String(p["id"]),
    root: String(p["root"]),
    name: path.basename(String(p["root"])),
    status: String(p["status"]),
    intact: p["directory_matches"] === true,
    registeredAt: typeof p["registered_at"] === "number" ? p["registered_at"] : undefined,
  }));
}

/** Display state of a registration. */
export function projectState(p: Registered): { label: string; tone: Tone } {
  if (p.status !== "trusted") return { label: "Revoked", tone: "bad" };
  if (!p.intact) return { label: "Moved or replaced", tone: "bad" };
  return { label: "Verified", tone: "ok" };
}

export async function listRegistered(ctx: Context): Promise<Registered[]> {
  return registered(await ctx.call("project.list", {}));
}

/** Resolve a reference to exactly one registered project. */
export function resolveProject(projects: Registered[], ref: string, cwd: string): Registered {
  const asPath = path.resolve(cwd, ref);
  const matches = projects.filter(
    (p) => p.root === asPath || p.name === ref || (ref.length >= 6 && /^[0-9a-f]+$/.test(ref) && p.id.startsWith(ref)),
  );
  if (matches.length === 1 && matches[0]) return matches[0];
  if (matches.length === 0) throw new CliError("not-registered", `no registered project matches "${ref}"`, ExitCode.NotInitialized, "list them with `ai-defender projects list`");
  throw new CliError("ambiguous", `"${ref}" matches ${matches.length} projects; use a longer ID prefix or the full path`, ExitCode.Usage);
}

async function integrationLabel(ctx: Context): Promise<string> {
  const status = await ctx.callRaw("integrations.status", { probe: false });
  if (!status.success) return "unknown";
  const installed = (Array.isArray(status.data["integrations"]) ? (status.data["integrations"] as Json[]) : [])
    .filter((i) => i["state"] === "installed" || i["state"] === "outdated")
    .map((i) => (i["provider"] === "claude" ? "Claude" : "Codex"));
  return installed.length > 0 ? installed.join(", ") : "None";
}

async function list(ctx: Context): Promise<ExitCodeValue> {
  const projects = await listRegistered(ctx);
  const integration = await integrationLabel(ctx);
  const rows = await Promise.all(
    projects.map(async (p) => {
      const policy = p.status === "trusted" && p.intact ? await ctx.callRaw("policy.show", { working_directory: p.root }) : undefined;
      const profile = policy?.success ? String(at(policy.data, "profile.name") ?? "balanced") : "—";
      return { ...p, profile: profile.charAt(0).toUpperCase() + profile.slice(1), state: projectState(p) };
    }),
  );
  if (ctx.flags.json) {
    ctx.emitJson("projects list", true, { data: { projects: rows.map((r) => ({ id: r.id, name: r.name, root: r.root, status: r.state.label, profile: r.profile, integration })), total: rows.length } });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.line(out.paint("AI DEFENDER — REGISTERED PROJECTS", "info"));
  out.line();
  const header = `${"PROJECT".padEnd(22)} ${"ID".padEnd(10)} ${"SECURITY".padEnd(10)} ${"INTEGRATION".padEnd(16)} STATUS`;
  out.line(header);
  out.line("-".repeat(header.length + 8));
  for (const r of rows) {
    out.line(`${sanitize(r.name).slice(0, 22).padEnd(22)} ${r.id.slice(0, 8).padEnd(10)} ${r.profile.padEnd(10)} ${integration.padEnd(16)} ${out.paint(r.state.label, r.state.tone)}`);
  }
  out.line();
  out.line(`Total projects: ${rows.length}`);
  if (rows.length === 0) out.note("Register one with `ai-defender init` (or `ai-defender projects add <path>`).");
  out.note("Agent hooks are installed per user, so the integration applies to every registered project.");
  return ExitCode.Ok;
}

async function inspect(ctx: Context, ref: string): Promise<ExitCodeValue> {
  const p = resolveProject(await listRegistered(ctx), ref, ctx.cwd);
  const here = ctx.withCwd(p.root);
  if (ctx.flags.json) {
    const [details, policy, integrations] = await Promise.all([
      here.call("project.inspect", { working_directory: p.root }),
      here.callRaw("policy.show", { working_directory: p.root }),
      here.callRaw("integrations.status", { probe: false }),
    ]);
    ctx.emitJson("projects inspect", true, {
      data: { project: { ...p, state: projectState(p).label }, details, policy: policy.success ? policy.data : null, integrations: integrations.success ? integrations.data : null },
    });
    return ExitCode.Ok;
  }
  const code = await project(here, ["inspect"]);
  const out = ctx.out;
  out.line();
  out.heading("Security coverage");
  out.field("State", projectState(p).label, projectState(p).tone);
  out.field("Agent integrations", await integrationLabel(ctx));
  out.note("  Hooks enforce only the tools `ai-defender integrations coverage` lists as protected; other actions are not intercepted.");
  return code;
}

export async function projects(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, arg, ...rest] = args;
  if (rest.length > 0) throw usageError(USAGE);
  switch (sub) {
    case undefined:
    case "list":
      if (arg !== undefined) throw usageError(USAGE);
      return list(ctx);
    case "inspect":
      if (arg === undefined) throw usageError(USAGE);
      return inspect(ctx, arg);
    case "add":
      return init(arg === undefined ? ctx : ctx.withCwd(path.resolve(ctx.cwd, arg)), []);
    case "revoke": {
      if (arg === undefined) throw usageError(USAGE);
      const p = resolveProject(await listRegistered(ctx), arg, ctx.cwd);
      return project(ctx.withCwd(p.root), ["revoke"]);
    }
    default:
      throw usageError(USAGE);
  }
}
