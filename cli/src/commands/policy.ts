import type { Context } from "../cli.js";
import { sanitize } from "../utils/sanitize.js";
import { usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";

type Json = Record<string, unknown>;

/** One-line summary of a rule's matcher, from the engine's serialised rule. */
function describeMatch(match: unknown): string {
  if (typeof match !== "object" || match === null) return "";
  return Object.entries(match as Json)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" ");
}

function rules(value: unknown): Json[] {
  return Array.isArray(value) ? value.filter((r): r is Json => typeof r === "object" && r !== null) : [];
}

/** `policy show`: displays the policy exactly as the engine computed and verified it. */
/** `policy validate`: the project configuration in this directory, and the trusted policy. */
async function validate(ctx: Context): Promise<ExitCodeValue> {
  const [config, status] = await Promise.all([
    ctx.call("config.validate", { working_directory: ctx.cwd }),
    ctx.call("status", { working_directory: ctx.cwd }),
  ]);
  const trusted = (status["policy"] ?? {}) as Json;
  const configValid = config["valid"] === true || config["config"] === "absent" || (config["config"] as Json | undefined)?.["state"] === "absent";
  const trustedOk = trusted["state"] === "verified";
  const ok = configValid && trustedOk;
  if (ctx.flags.json) {
    ctx.emitJson("policy validate", ok, { data: { ok, project_config: config, trusted_policy: trusted } });
    return ok ? ExitCode.Ok : ExitCode.CheckFailed;
  }
  const out = ctx.out;
  out.title();
  out.heading("Policy validation");
  out.check(trustedOk ? "pass" : "fail", "Trusted policy (signed)", String(trusted["state"] ?? "unavailable"));
  out.check(configValid ? "pass" : "fail", "Project configuration", sanitize(JSON.stringify(config["config"] ?? null)));
  out.note("Project configuration only takes effect after `ai-defender project trust`; it can add restrictions, never weaken the baseline.");
  return ok ? ExitCode.Ok : ExitCode.CheckFailed;
}

export async function policy(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args[0] === "validate" && args.length === 1) return validate(ctx);
  if (args[0] !== "show" || args.length > 1) throw usageError("usage: ai-defender policy show | validate");
  const data = await ctx.call("policy.show", { working_directory: ctx.cwd });
  if (ctx.flags.json) {
    ctx.emitJson("policy show", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  const layers = (data["layers"] ?? {}) as Json;
  const profile = (data["profile"] ?? {}) as Json;
  out.title();
  out.heading("Effective Policy");
  out.field("Version", data["version"], "muted");
  out.field("Integrity", data["integrity"] === "verified" ? "Verified" : String(data["integrity"]), data["integrity"] === "verified" ? "ok" : "bad");
  out.field("Security profile", `${String(profile["name"])} (${String(profile["version"])})`);
  const project = data["project"] as Json | null;
  out.field("Project", project ? project["root"] : "none (global layers only)");
  out.line();
  out.heading("Profile settings");
  for (const [k, v] of Object.entries((profile["settings"] ?? {}) as Json)) out.field(k, v);
  const section = (title: string, list: Json[], empty: string) => {
    out.line();
    out.heading(`${title} (${list.length})`);
    if (list.length === 0) out.note(`  ${empty}`);
    for (const r of list) {
      const decision = String(r["decision"]);
      const tone = decision === "DENY" ? "bad" : decision === "ALLOW" ? "ok" : "warn";
      out.line(`  ${out.paint(decision.padEnd(16), tone)} ${sanitize(String(r["id"]))}`);
      out.note(`  ${"".padEnd(16)} ${describeMatch(r["match"])} — ${sanitize(String(r["reason"]))}`);
    }
  };
  section("Mandatory baseline (floors)", rules(layers["mandatory"]), "none");
  section("Organization/user policy", rules(layers["global"]), "no rules: the profile and defaults apply");
  section("Project policy (floors, restrictions only)", rules(layers["project"]), "no approved project restrictions");
  section("Profile rules", rules(layers["profile"]), "none");
  out.line();
  out.heading("Precedence");
  for (const p of Array.isArray(data["precedence"]) ? data["precedence"] : []) out.note(`  • ${String(p)}`);
  out.heading("Defaults");
  for (const d of Array.isArray(data["defaults"]) ? data["defaults"] : []) out.note(`  • ${String(d)}`);
  return ExitCode.Ok;
}
