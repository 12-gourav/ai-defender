/**
 * Managed execution: `ai-defender run`, `ai-defender git`, `ai-defender execution`.
 *
 * The engine classifies, evaluates, asks for approval, runs, verifies and records. This file
 * forwards the command as an argument vector (or, with --shell, as a script for the engine's
 * strict shell parser), displays the engine's answer, and, in an interactive terminal, waits
 * while a human approves the exact operation with `ai-defender approve` in another terminal.
 * It never decides whether a command may run and never runs one itself.
 */

import { randomUUID } from "node:crypto";

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { sanitize } from "../utils/sanitize.js";
import { CliError, usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

const RUN_USAGE =
  "usage: ai-defender run [--shell sh|bash] [--timeout SECONDS] [--env-profile minimal|development] [--approval ID] [--no-wait] [--] COMMAND [ARGS...]";

export interface RunOptions {
  shell: "sh" | "bash" | undefined;
  timeout: number | undefined;
  envProfile: string | undefined;
  approval: string | undefined;
  noWait: boolean;
  command: string[];
}

/** Parse `run` options up to the first word of the command (or `--`). */
export function parseRunArgs(args: string[]): RunOptions {
  const o: RunOptions = { shell: undefined, timeout: undefined, envProfile: undefined, approval: undefined, noWait: false, command: [] };
  let i = 0;
  const value = (flag: string): string => {
    const v = args[i + 1];
    if (v === undefined) throw usageError(`${flag} needs a value\n${RUN_USAGE}`);
    i += 2;
    return v;
  };
  while (i < args.length) {
    const a = args[i] as string;
    if (a === "--") {
      i += 1;
      break;
    }
    if (a === "-h" || a === "--help") throw usageError(RUN_USAGE);
    if (a === "--shell") {
      const v = value(a);
      if (v !== "sh" && v !== "bash") throw usageError(`--shell must be sh or bash\n${RUN_USAGE}`);
      o.shell = v;
    } else if (a === "--timeout") {
      const v = Number(value(a));
      if (!Number.isInteger(v) || v < 1 || v > 3600) throw usageError("--timeout must be a whole number of seconds from 1 to 3600");
      o.timeout = v;
    } else if (a === "--env-profile") {
      o.envProfile = value(a);
    } else if (a === "--approval") {
      o.approval = value(a);
    } else if (a === "--no-wait") {
      o.noWait = true;
      i += 1;
    } else {
      break;
    }
  }
  o.command = args.slice(i);
  if (o.command.length === 0) throw usageError(RUN_USAGE);
  return o;
}

function str(value: unknown): string {
  return value === undefined || value === null ? "—" : String(value);
}

/** Exit status for an executed command: its own code, 124 for a time-out, 125 if unknown. */
function executedExit(data: Json): ExitCodeValue | number {
  const termination = (at(data, "result.termination") ?? {}) as Json;
  switch (termination["state"]) {
    case "exited":
      return Number(termination["code"]);
    case "signaled":
      return 128 + Number(termination["signal"]);
    case "timed-out":
      return ExitCode.TimedOut;
    case "spawn-failed":
      return ExitCode.Denied;
    default:
      return ExitCode.Indeterminate;
  }
}

const DECISION_TONE: Record<string, Tone> = { ALLOW: "ok", REQUIRE_APPROVAL: "warn", DENY: "bad" };

function describePlan(ctx: Context, data: Json): void {
  const out = ctx.out;
  out.field("Command", at(data, "plan.command"));
  out.field("Mode", at(data, "plan.mode"));
  out.field("Category", at(data, "plan.category"));
  out.field("Executable", at(data, "plan.executable.path"));
  const repo = at(data, "plan.git.repository") as Json | null | undefined;
  if (repo) {
    out.field("Repository", `${str(repo["id"])} on ${str(repo["branch"] ?? "(detached)")} at ${str(repo["head"]).slice(0, 12)}`);
    const hooks = repo["hooks"] as string[] | undefined;
    if (hooks && hooks.length > 0) out.field("Hooks that run", hooks.join(", "), "warn");
  }
  const push = at(data, "plan.git.push") as Json | null | undefined;
  if (push) {
    out.field(
      "Push",
      `${str(push["source"] ?? "(delete)")} → ${str(push["remote"])} ${str(push["destination"])} (${str(push["remote_url"])}), ${str(push["commits"])} commit(s)${push["forced"] === true ? ", FORCED" : ""}`,
      push["forced"] === true ? "bad" : "plain",
    );
  }
  const scan = at(data, "plan.git.secret_scan") as Json | null | undefined;
  if (scan) {
    const n = Number(scan["detections"]);
    out.field("Secret scan", `${n} detection(s) in ${str(scan["lines"])} added line(s)${scan["incomplete"] === true ? " (INCOMPLETE)" : ""}`, n > 0 ? "bad" : scan["incomplete"] === true ? "warn" : "ok");
  }
  out.field("Environment", `${str(at(data, "plan.environment.profile"))} (${str(at(data, "plan.environment.withheld"))} variable(s) withheld)`, "muted");
  const decision = str(at(data, "decision.decision"));
  out.field("Decision", `${decision} (${str(at(data, "decision.rule"))})`, DECISION_TONE[decision] ?? "plain");
  out.field("Reason", at(data, "decision.reason"));
}

function enforcementNote(ctx: Context): void {
  ctx.out.note("Managed execution controls only commands run through `ai-defender run`; commands an agent runs directly are not intercepted.");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Poll the approval until a human decides; returns its final status. */
async function waitForApproval(ctx: Context, id: string, token: string): Promise<string> {
  let interrupted = false;
  const onSignal = (): void => {
    interrupted = true;
  };
  process.once("SIGINT", onSignal);
  try {
    for (;;) {
      if (interrupted) {
        await ctx.callRaw("approval.cancel", { approval_id: id, claim_token: token });
        return "cancelled-by-requester";
      }
      const shown = await ctx.callRaw("approval.show", { approval_id: id });
      if (!shown.success) return "unavailable";
      const status = str(at(shown.data, "approval.status"));
      if (status !== "pending") return status;
      await sleep(1500);
    }
  } finally {
    process.removeListener("SIGINT", onSignal);
  }
}

async function submit(ctx: Context, o: RunOptions, key: string, approval?: { id: string; token: string }): Promise<Json> {
  const args: Json = { working_directory: ctx.cwd, idempotency_key: key };
  if (o.shell !== undefined) args["shell"] = { interpreter: o.shell, script: o.command.join(" ") };
  else args["argv"] = o.command;
  if (o.timeout !== undefined) args["timeout_seconds"] = o.timeout;
  if (o.envProfile !== undefined) args["environment_profile"] = o.envProfile;
  if (approval) args["approval"] = { approval_id: approval.id, claim_token: approval.token };
  return ctx.callLong("execution.run", args, ((o.timeout ?? 3600) + 120) * 1000);
}

function printExecuted(ctx: Context, data: Json): ExitCodeValue | number {
  const stdout = typeof data["stdout"] === "string" ? data["stdout"] : "";
  const stderr = typeof data["stderr"] === "string" ? data["stderr"] : "";
  if (stdout) ctx.io.stdout.write(sanitize(stdout));
  if (stderr) ctx.io.stderr.write(sanitize(stderr));
  const code = executedExit(data);
  const state = str(data["state"]);
  const truncated = at(data, "result.stdout_truncated") === true || at(data, "result.stderr_truncated") === true;
  const verification = at(data, "verification") as Json | undefined;
  const parts = [`ai-defender: ${state}`, `exit ${code}`, `execution ${str(data["execution_id"])}`];
  if (truncated) parts.push("output truncated");
  ctx.out.warnLine(parts.join(" · "), state === "completed" ? "muted" : "warn");
  if (verification && verification["status"] === "mismatch") ctx.out.warn(`verification failed: ${str(verification["detail"])}`);
  return code;
}

/** `ai-defender run`. */
export async function run(ctx: Context, args: string[]): Promise<ExitCodeValue | number> {
  const o = parseRunArgs(args);
  const key = randomUUID();
  let claim: { id: string; token: string } | undefined;
  if (o.approval !== undefined) {
    const token = ctx.io.env["AGENTGUARD_CLAIM_TOKEN"];
    if (!token) {
      throw new CliError("authorization-required", "--approval needs the request's claim token in AGENTGUARD_CLAIM_TOKEN", ExitCode.ActionRequired);
    }
    claim = { id: o.approval, token };
  }
  let data = await submit(ctx, o, key, claim);
  const outcome = str(data["outcome"]);
  if (outcome === "approval-required" && ctx.interactive && !o.noWait && !ctx.flags.json) {
    const id = str(at(data, "approval.approval_id"));
    const token = str(at(data, "approval.claim_token"));
    ctx.out.title();
    ctx.out.heading("Approval required");
    describePlan(ctx, data);
    ctx.out.line();
    ctx.out.line(`  Approve it in another terminal:  ${ctx.out.paint(`ai-defender approve ${id}`, "info")}`);
    ctx.out.note("  Waiting for a decision (Ctrl-C cancels the request)…");
    const status = await waitForApproval(ctx, id, token);
    if (status !== "approved") {
      throw new CliError("approval-not-granted", `the approval request was not approved (${status}); nothing was run`, ExitCode.ActionRequired);
    }
    data = await submit(ctx, o, key, { id, token });
  }
  return report(ctx, data);
}

function report(ctx: Context, data: Json): ExitCodeValue | number {
  const outcome = str(data["outcome"]);
  if (ctx.flags.json) {
    ctx.emitJson("run", true, { data });
    switch (outcome) {
      case "executed":
        return executedExit(data);
      case "denied":
        return ExitCode.Denied;
      case "refused":
        return ExitCode.Unsupported;
      default:
        return ExitCode.ActionRequired;
    }
  }
  const out = ctx.out;
  switch (outcome) {
    case "executed":
      return printExecuted(ctx, data);
    case "denied":
      out.title();
      out.heading("Denied");
      describePlan(ctx, data);
      enforcementNote(ctx);
      return ExitCode.Denied;
    case "refused":
      out.error(`not run: ${str(at(data, "refusal.reason"))}`, `(${str(at(data, "refusal.code"))})`);
      return ExitCode.Unsupported;
    case "context-changed":
      out.error(
        `not run: ${str(data["reason"])}`,
        `changed: ${((data["changed"] as string[] | undefined) ?? []).join(", ")}`,
      );
      return ExitCode.ActionRequired;
    case "approval-required": {
      const id = str(at(data, "approval.approval_id"));
      out.title();
      out.heading("Approval required (not run)");
      describePlan(ctx, data);
      out.line();
      out.line(`  A human must approve it:  ai-defender approve ${id}`);
      out.line(`  Then run it with the request's claim token:`);
      out.line(`    AGENTGUARD_CLAIM_TOKEN=${str(at(data, "approval.claim_token"))} ai-defender run --approval ${id} -- ${(at(data, "plan.command") as string | undefined) ?? ""}`);
      out.note("  The claim token identifies this request; it does not authorize anything without the human approval.");
      return ExitCode.ActionRequired;
    }
    default:
      throw new CliError("engine-protocol", `unexpected execution outcome: ${outcome}`, ExitCode.EngineProtocol);
  }
}

/** `ai-defender git status|inspect`. */
export async function git(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, ...rest] = args;
  if ((sub !== "status" && sub !== "inspect") || rest.length > 0) throw usageError("usage: ai-defender git status | inspect");
  const data = await ctx.call(sub === "status" ? "git.status" : "git.inspect", { working_directory: ctx.cwd });
  if (ctx.flags.json) {
    ctx.emitJson(`git ${sub}`, true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  const repo = (sub === "inspect" ? data["repository"] : data) as Json;
  out.heading(sub === "inspect" ? "Repository" : "Repository status");
  if (sub === "inspect") {
    out.field("Identity", repo["repository_id"]);
    out.field("Root", repo["root"]);
    out.field("Git directory", repo["git_dir"], "muted");
    out.field("Inside project", repo["inside_project"]);
  }
  out.field("Branch", repo["branch"] ?? "(detached)");
  out.field("HEAD", repo["head"] ?? "(no commits)");
  out.field("Staged changes", repo["staged_total"]);
  const status = repo["status"] as Json | null | undefined;
  if (status) {
    out.field("Working tree", `${str(status["total"])} change(s)`, Number(status["total"]) > 0 ? "warn" : "ok");
    for (const e of ((status["entries"] as Json[] | undefined) ?? []).slice(0, 50)) out.line(`    ${str(e["status"]).padEnd(3)} ${str(e["path"])}`);
  } else {
    out.field("Working tree", `not inspected: ${str(repo["status_skipped"])}`, "warn");
  }
  if (sub === "inspect") {
    out.line();
    out.heading("Remotes (credentials removed)");
    const remotes = (repo["remotes"] as Json[] | undefined) ?? [];
    if (remotes.length === 0) out.note("  none");
    for (const r of remotes) out.line(`  ${str(r["name"]).padEnd(12)} ${str(r["url"])}  ${out.paint(str(r["identity"]), "muted")}`);
    const hooks = (repo["hooks"] as string[] | undefined) ?? [];
    out.field("Hooks", hooks.length > 0 ? hooks.join(", ") : "none");
  }
  if (data["registered_project"] !== true) out.note("This directory is not inside a registered project.");
  return ExitCode.Ok;
}

const STATE_TONE: Record<string, Tone> = {
  completed: "ok",
  failed: "bad",
  "timed-out": "bad",
  indeterminate: "warn",
  interrupted: "warn",
  denied: "bad",
  refused: "bad",
  "context-changed": "warn",
  "awaiting-approval": "warn",
  started: "warn",
};

/** `ai-defender execution history|inspect`. */
export async function execution(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, ...rest] = args;
  if (sub === "history" && rest.length === 0) {
    const data = await ctx.call("execution.history", {});
    if (ctx.flags.json) {
      ctx.emitJson("execution history", true, { data });
      return ExitCode.Ok;
    }
    const out = ctx.out;
    out.title();
    const list = (data["executions"] as Json[] | undefined) ?? [];
    out.heading(`Managed executions (${list.length} most recent)`);
    if (list.length === 0) out.note("  none");
    for (const e of list) {
      const state = str(e["state"]);
      out.line(`  ${out.paint(str(e["execution_id"]), "info")}  ${out.paint(state.padEnd(17), STATE_TONE[state] ?? "plain")} ${sanitize(str(e["created_at"]))}  ${sanitize(str(e["command"]))}`);
    }
    if (Number(data["unreadable"]) > 0) out.warn(`${str(data["unreadable"])} record(s) could not be read`);
    enforcementNote(ctx);
    return ExitCode.Ok;
  }
  if (sub === "inspect" && rest.length === 1) {
    const data = await ctx.call("execution.inspect", { execution_id: rest[0] });
    if (ctx.flags.json) {
      ctx.emitJson("execution inspect", true, { data });
      return ExitCode.Ok;
    }
    const e = (data["execution"] ?? {}) as Json;
    const out = ctx.out;
    out.title();
    out.heading(`Execution ${str(e["execution_id"])}`);
    const state = str(e["state"]);
    out.field("State", state, STATE_TONE[state] ?? "plain");
    if (e["state_note"]) out.field("Note", e["state_note"], "warn");
    out.field("Command", e["command"]);
    out.field("Working directory", e["working_directory"]);
    out.field("Invocation", e["invocation"]);
    out.field("Decision", `${str(at(e, "decision.decision"))} (${str(at(e, "decision.rule"))})`);
    out.field("Operation digest", e["operation_digest"], "muted");
    if (e["approval_id"]) out.field("Approval", e["approval_id"]);
    out.field("Created", e["created_at"], "muted");
    out.field("Finished", e["finished_at"], "muted");
    const termination = at(e, "result.termination") as Json | undefined;
    if (termination) out.field("Result", `${str(termination["state"])}${termination["code"] !== undefined ? ` (exit ${str(termination["code"])})` : ""}, ${str(at(e, "result.duration_ms"))} ms`);
    if (e["verification"]) out.field("Verification", str(at(e, "verification.status")));
    if (e["refusal"]) out.field("Refused", `${str(at(e, "refusal.reason"))} (${str(at(e, "refusal.code"))})`, "bad");
    const stdout = str(at(e, "output.stdout"));
    if (stdout !== "—" && stdout !== "") {
      out.line();
      out.heading("Output (redacted excerpt)");
      ctx.io.stdout.write(sanitize(stdout.endsWith("\n") ? stdout : `${stdout}\n`));
    }
    return ExitCode.Ok;
  }
  throw usageError("usage: ai-defender execution history | inspect <execution-id>");
}
