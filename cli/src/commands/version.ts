import type { Context } from "../cli.js";
import { ENGINE_PROTOCOL_VERSION } from "../services/installer.js";
import { CliError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";

export async function version(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw new CliError("usage", "version takes no arguments", ExitCode.Usage);
  let engine: Record<string, unknown> | undefined;
  let engineError: CliError | undefined;
  try {
    engine = await ctx.call("version", {});
  } catch (e) {
    if (!(e instanceof CliError)) throw e;
    engineError = e;
  }
  const located = ctx.engineIfLocated();
  if (ctx.flags.json) {
    ctx.emitJson("version", engineError === undefined, {
      data: { cli_version: ctx.version, cli_engine_protocol: ENGINE_PROTOCOL_VERSION, engine: engine ?? null },
      ...(engineError ? { error: { code: engineError.code, message: engineError.message } } : {}),
    });
  } else {
    const out = ctx.out;
    out.field("CLI", ctx.version);
    out.field("Engine", engine ? String(engine["engine_version"]) : "unavailable", engine ? "plain" : "bad");
    out.field("Engine protocol", `CLI ${ENGINE_PROTOCOL_VERSION}${engine ? `, engine ${String(engine["engine_protocol_version"])}` : ""}`);
    if (engine) out.field("Authorization protocol", engine["authorization_protocol"]);
    if (located) out.field("Engine build", located.verified ? "verified release" : "UNVERIFIED development build", located.verified ? "ok" : "warn");
    if (engine && engine["engine_version"] !== ctx.version) out.note("The CLI and engine versions differ.");
    if (engineError) out.error(engineError.message, engineError.recovery);
  }
  return engineError ? engineError.exitCode : ExitCode.Ok;
}
