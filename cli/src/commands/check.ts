import type { Context } from "../cli.js";
import { CliError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";

interface CheckItem {
  id: string;
  title: string;
  status: "pass" | "warn" | "fail" | "skip";
  detail: string;
  recovery?: string | null;
}

function isCheck(v: unknown): v is CheckItem {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  return typeof c["id"] === "string" && typeof c["title"] === "string" && typeof c["detail"] === "string" && ["pass", "warn", "fail", "skip"].includes(String(c["status"]));
}

/** Diagnostics. Read-only; never runs project scripts. Exit 5 if any check fails. */
export async function check(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw new CliError("usage", "check takes no arguments", ExitCode.Usage);
  const data = await ctx.call("check", { working_directory: ctx.cwd });
  const engineChecks = Array.isArray(data["checks"]) ? data["checks"] : [];
  if (!engineChecks.every(isCheck)) {
    throw new CliError("engine-protocol", "the engine returned malformed diagnostics", ExitCode.EngineProtocol);
  }
  const engine = ctx.engine();
  const cliChecks: CheckItem[] = [
    engine.verified
      ? { id: "engine-verified", title: "Engine binary verified", status: "pass", detail: "signed release manifest and checksum" }
      : { id: "engine-verified", title: "Engine binary verified", status: "warn", detail: "UNVERIFIED development build (AGENTGUARD_DEV_ENGINE)" },
  ];
  const checks: CheckItem[] = [...cliChecks, ...engineChecks];
  const failed = checks.some((c) => c.status === "fail");
  if (ctx.flags.json) {
    ctx.emitJson("check", !failed, { data: { ok: !failed, checks } });
  } else {
    ctx.out.title();
    ctx.out.heading("Diagnostics");
    for (const c of checks) ctx.out.check(c.status, c.title, c.detail);
    ctx.out.line();
    const count = (s: string) => checks.filter((c) => c.status === s).length;
    ctx.out.line(`  ${count("pass")} passed, ${count("warn")} warnings, ${count("fail")} failed, ${count("skip")} skipped`);
    for (const c of checks.filter((x) => x.status === "fail" && x.recovery)) ctx.out.note(`  ${c.title}: ${String(c.recovery)}`);
  }
  return failed ? ExitCode.CheckFailed : ExitCode.Ok;
}
