/**
 * `ai-defender uninstall [--purge]`: the supported, password-protected removal.
 *
 * The engine checks the signing key passphrase, then removes AI Defender's agent hooks (other
 * settings and hooks are kept, with a backup) and its verified engine copies. The trust store
 * (signing keys, policy, registry, audit history) and project configurations are kept unless
 * --purge is given and confirmed by typing "purge". The CLI starts no process but the engine, so
 * removing the npm package itself is left to one printed `npm uninstall -g ai-defender`.
 *
 * `npm uninstall -g ai-defender` bypasses all of this: npm runs no script AI Defender could rely
 * on. The hooks then stay in place, and keep blocking, until removed with this command (after
 * reinstalling) or by editing the agent's settings file.
 */

import type { Context } from "../cli.js";
import { CliError, usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

function list(v: unknown): Json[] {
  return Array.isArray(v) ? (v as Json[]) : [];
}

const FINAL_STEP = "npm uninstall -g ai-defender";

export async function uninstall(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender uninstall [--purge]");
  const purge = ctx.flags.purge;
  const status = await ctx.call("status", { working_directory: ctx.cwd });
  const protectedStore = at(status, "trust_store.state") !== "uninitialized";
  const out = ctx.out;
  if (!ctx.flags.json) {
    out.title();
    out.heading("Uninstall AI Defender");
    out.line("  This will:");
    if (protectedStore) out.line("    • verify your AI Defender password");
    out.line("    • remove AI Defender's hooks from Claude Code and Codex (your other settings are kept and backed up)");
    out.line("    • remove AI Defender's verified engine copies");
    out.line(`    • then tell you the one command that removes the package itself (${FINAL_STEP})`);
    out.line();
    if (purge) {
      out.warn("--purge: your signing keys, trusted policy, project registry and audit history will be DELETED. This cannot be undone.");
    } else {
      out.line("  Kept (remove them later with --purge):");
      out.line("    • signing keys, trusted policy, project registry and audit history");
      out.line("    • hook configuration backups");
    }
    out.line("  Always kept: each project's .agentguard/ configuration (it lives in your repositories).");
    out.line();
  }
  await ctx.confirm("Uninstall AI Defender from this machine?", "uninstalling AI Defender");
  let purgeConfirmation: string | undefined;
  if (purge) {
    if (ctx.interactive) {
      purgeConfirmation = (await ctx.io.prompter.ask('Type "purge" to delete your AI Defender keys and history: ')).trim();
      if (purgeConfirmation !== "purge") throw new CliError("cancelled", "cancelled; nothing was changed", ExitCode.Failure);
    } else if (ctx.flags.yes) {
      purgeConfirmation = "purge";
    }
  }
  const passphrase = protectedStore ? await ctx.passphrase(false) : {};
  const data = await ctx.call("system.uninstall", {
    confirm: true,
    requested_by: ctx.requestedBy,
    purge,
    ...(purgeConfirmation ? { purge_confirmation: purgeConfirmation } : {}),
    ...passphrase,
  });
  if (ctx.flags.json) {
    ctx.emitJson("uninstall", true, { data: { ...data, next: FINAL_STEP } });
    return ExitCode.Ok;
  }
  out.heading("Result");
  for (const i of list(data["integrations"])) {
    const removed = Number(i["handlers_removed"] ?? 0);
    out.check("pass", `${String(i["provider"])} hooks`, removed > 0 ? `removed (backup: ${String(i["backup"])})` : "none installed");
  }
  out.check("pass", "Engine copies", data["engine_copies_removed"] === true ? "removed" : "none present");
  out.check(
    data["trust_store_deleted"] === true ? "pass" : "skip",
    "Trust store",
    data["trust_store_deleted"] === true ? `deleted (${String(data["trust_store"])})` : `kept at ${String(data["trust_store"])}`,
  );
  const projects = Array.isArray(data["project_configurations"]) ? (data["project_configurations"] as string[]) : [];
  if (projects.length > 0) {
    out.line();
    out.note("Project configurations left in place (delete them yourself if you no longer want them):");
    for (const p of projects) out.note(`  ${p}`);
  }
  out.line();
  out.line(out.paint("AI Defender's hooks and engine copies are removed; nothing is enforced any more.", "ok"));
  out.line("  To remove the command itself, run (with the npm that installed it):");
  out.line(`    ${FINAL_STEP}`);
  return ExitCode.Ok;
}
