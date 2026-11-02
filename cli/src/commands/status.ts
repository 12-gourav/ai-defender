import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { CliError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";

type Json = Record<string, unknown>;

/** Read a nested value by a dotted path. */
export function at(value: unknown, dotted: string): unknown {
  return dotted.split(".").reduce<unknown>((acc, key) => (acc !== null && typeof acc === "object" ? (acc as Json)[key] : undefined), value);
}

const TRUST: Record<string, [string, Tone]> = {
  verified: ["Yes (trusted state verified)", "ok"],
  uninitialized: ["No — run `ai-defender init`", "warn"],
  "integrity-failure": ["INTEGRITY FAILURE", "bad"],
};
const REGISTRATION: Record<string, [string, Tone]> = {
  registered: ["Yes", "ok"],
  unregistered: ["No", "warn"],
  revoked: ["Revoked", "bad"],
  "identity-mismatch": ["Directory replaced since registration", "bad"],
  unknown: ["Unknown (trusted state unavailable)", "muted"],
};

export async function status(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw new CliError("usage", "status takes no arguments", ExitCode.Usage);
  let data: Json;
  try {
    data = await ctx.call("status", { working_directory: ctx.cwd });
  } catch (e) {
    if (e instanceof CliError && e.exitCode === ExitCode.EngineUnavailable && !ctx.flags.json) {
      ctx.out.title();
      ctx.out.heading("Installation");
      ctx.out.field("CLI", `installed (${ctx.version})`, "ok");
      ctx.out.field("Engine", "unavailable", "bad");
    }
    throw e;
  }
  if (ctx.flags.json) {
    const engine = ctx.engineIfLocated();
    ctx.emitJson("status", true, { data: { ...data, cli: { version: ctx.version, engine_verified: engine?.verified ?? false } } });
    return ExitCode.Ok;
  }
  render(ctx, data);
  return ExitCode.Ok;
}

function render(ctx: Context, data: Json): void {
  const out = ctx.out;
  const engine = ctx.engineIfLocated();
  out.title();
  out.heading("Installation");
  out.field("CLI", `installed (${ctx.version})`, "ok");
  out.field("Engine", `available (${String(at(data, "engine.version"))})`, "ok");
  out.field("Engine build", engine?.verified ? "verified release" : "UNVERIFIED development build", engine?.verified ? "ok" : "warn");
  if (ctx.flags.verbose && engine) out.field("Engine path", engine.path, "muted");
  out.line();
  out.heading("Security Status");
  const trust = TRUST[String(at(data, "trust_store.state"))] ?? ["unknown", "muted"];
  out.field("Initialized", trust[0], trust[1]);
  const registration = REGISTRATION[String(at(data, "project.registration.state"))] ?? ["unknown", "muted"];
  out.field("Project registered", registration[0], registration[1]);
  const policyState = String(at(data, "policy.state"));
  out.field("Policy integrity", policyState === "verified" ? "Verified" : policyState === "integrity-failure" ? "FAILED" : "Unavailable", policyState === "verified" ? "ok" : policyState === "integrity-failure" ? "bad" : "muted");
  out.field("Security profile", at(data, "policy.profile") ?? "—");
  const version = at(data, "policy.version");
  out.field("Policy version", typeof version === "string" ? version.slice(0, 12) : "—", "muted");
  const audit = String(at(data, "audit.state"));
  out.field("Audit storage", audit === "available" ? `available (${String(at(data, "audit.records"))} records)` : audit, audit === "available" ? "ok" : audit === "chain-broken" ? "bad" : "muted");
  out.field("Integration", "Not configured", "warn");
  out.field("Enforcement", "Not active", "warn");
  out.line();
  out.heading("Project");
  out.field("Root", at(data, "project.root"));
  out.field("Kind", at(data, "project.kind") ?? "unknown", "muted");
  const config = String(at(data, "project.config.state"));
  out.field("Configuration", config === "valid" ? at(data, "project.config.path") : config, config === "valid" ? "plain" : config === "absent" ? "warn" : "bad");
  if (at(data, "project.policy_drift") === true) out.field("Approved policy", "configuration differs (not applied)", "warn");
  if (at(data, "trust_store.state") === "integrity-failure") out.error(String(at(data, "trust_store.detail")), "see docs/TRUST_MODEL.md section 6 (recovery)");
  out.line();
  out.note(String(at(data, "enforcement.detail")));
}
