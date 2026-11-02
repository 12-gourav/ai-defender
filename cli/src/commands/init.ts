import type { Context } from "../cli.js";
import { CliError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { engineError } from "../cli.js";
import { at } from "./status.js";

/**
 * `init`: detect the project, show what will happen, ask for confirmation, then let the engine
 * create configuration, set up trust on first use, register, approve restrictions and validate.
 * Every write is done by the engine; the CLI never writes project or trusted files itself.
 */
export async function init(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw new CliError("usage", "init takes no arguments", ExitCode.Usage);
  const profile = ctx.flags.profile ?? "balanced";
  const before = await ctx.call("status", { working_directory: ctx.cwd });
  const trust = String(at(before, "trust_store.state"));
  const registration = String(at(before, "project.registration.state"));
  const config = String(at(before, "project.config.state"));
  if (trust === "integrity-failure") {
    throw new CliError("integrity-failure", `trusted state failed verification: ${String(at(before, "trust_store.detail"))}`, ExitCode.CheckFailed, "see docs/TRUST_MODEL.md section 6 (recovery)");
  }
  if (config === "invalid" || config === "ambiguous") {
    throw new CliError("invalid-configuration", String(at(before, "project.config.error")), ExitCode.Failure, "fix the project configuration first");
  }
  if (registration === "revoked") {
    throw new CliError("project-revoked", "this project's trust was revoked", ExitCode.Failure, "re-trust it deliberately with `ai-defender project trust`");
  }
  const creatingTrust = trust === "uninitialized";
  const registering = registration !== "registered";
  if (!ctx.flags.json) {
    const out = ctx.out;
    out.title();
    out.heading("Initialize AI Defender");
    out.field("Project root", at(before, "project.root"));
    out.field("Project kind", at(before, "project.kind") ?? "unknown", "muted");
    out.field("Trust store", creatingTrust ? "will be created (new signing keys)" : "existing", creatingTrust ? "warn" : "plain");
    out.field("Configuration", config === "valid" ? `keep ${String(at(before, "project.config.path"))}` : "create .agentguard/config.yaml");
    out.field("Registration", registering ? "register this project" : "already registered");
    out.field("Expected profile", profile);
    out.line();
  }
  await ctx.confirm("Initialize AI Defender for this project?", "initialization");
  let secret: Record<string, string> = {};
  if (creatingTrust || registering) secret = await ctx.passphrase(creatingTrust);
  const request = (extra: Record<string, string>) => ({
    working_directory: ctx.cwd,
    confirm: true,
    setup_trust: creatingTrust,
    requested_by: ctx.requestedBy,
    profile,
    ...(ctx.flags.name !== undefined ? { name: ctx.flags.name } : {}),
    ...extra,
  });
  let response = await ctx.callRaw("project.init", request(secret));
  if (!response.success && response.error.code === "authorization-required" && Object.keys(secret).length === 0) {
    // Changed restrictions need approval with the signing key.
    secret = await ctx.passphrase(false);
    response = await ctx.callRaw("project.init", request(secret));
  }
  if (!response.success) throw engineError(response.error);
  const data = response.data;
  if (ctx.flags.json) {
    ctx.emitJson("init", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.heading("Result");
  out.field("Project", data["root"]);
  out.field("Registration", at(data, "registration.created") === true ? "registered" : "already registered", "ok");
  out.field("Configuration", at(data, "config.path"));
  out.field("Security profile", at(data, "profile.effective"));
  if (at(data, "profile.matches") === false) out.warn(`the project expects profile ${String(at(data, "profile.requested"))}, but the global policy selects ${String(at(data, "profile.effective"))}`);
  out.field("Enforcement", "Not active (no agent integration yet)", "warn");
  if (at(data, "trust_store.created") === true) {
    out.line();
    out.warn(`New signing keys were created in ${String(at(data, "trust_store.path"))}/signing. Back them up, and keep the passphrase safe: without them trusted policy cannot be changed. Consider moving root.key offline.`);
  }
  out.line();
  out.heading("Next steps");
  for (const step of Array.isArray(data["next_steps"]) ? data["next_steps"] : []) out.note(`  • ${String(step)}`);
  return ExitCode.Ok;
}
