/**
 * Argument parsing, the shared command context, and dispatch. `run` is the testable entry
 * point: it takes all process state as parameters and returns an exit code.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { approvals, approve, reject } from "./commands/approvals.js";
import { check } from "./commands/check.js";
import { dashboard } from "./commands/dashboard.js";
import { history } from "./commands/history.js";
import { doctor, repair, update } from "./commands/maintenance.js";
import { uninstall } from "./commands/uninstall.js";
import { projects } from "./commands/projects.js";
import { execution, git, run as runCommand } from "./commands/execution.js";
import { help } from "./commands/help.js";
import { init } from "./commands/init.js";
import { integrations } from "./commands/integrations.js";
import { policy } from "./commands/policy.js";
import { project } from "./commands/project.js";
import { secrets } from "./commands/secrets.js";
import { status } from "./commands/status.js";
import { version } from "./commands/version.js";
import { callEngine, type EngineResponse } from "./services/engine.js";
import { loadReleaseKeys, resolveEngine, type EngineLocation } from "./services/installer.js";
import { Output, shouldColor, type Writer } from "./services/output.js";
import { detectPlatform } from "./services/platform.js";
import { NotInteractiveError, type Prompter } from "./ui/prompt.js";
import { CliError, usageError } from "./utils/errors.js";
import { ExitCode, exitCodeForEngineError, type ExitCodeValue } from "./utils/exit-codes.js";

export interface Flags {
  json: boolean;
  noColor: boolean;
  nonInteractive: boolean;
  yes: boolean;
  verbose: boolean;
  passphraseFile: string | undefined;
  profile: string | undefined;
  name: string | undefined;
  reason: string | undefined;
  staged: boolean;
  exclude: string[];
  noDefaultExclusions: boolean;
  blocked: boolean;
  approvals: boolean;
  limit: string | undefined;
  purge: boolean;
}

export interface Io {
  stdout: Writer & { isTTY?: boolean };
  stderr: Writer;
  env: Record<string, string | undefined>;
  cwd: string;
  platform: string;
  arch: string;
  user: string;
  prompter: Prompter;
  /** Root of the installed package; tests point it at a staged copy. */
  packageRoot?: string;
}

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The CLI's own version, from its package.json. */
export function cliVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(path.join(PACKAGE_ROOT, "package.json"), "utf8")) as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

/** Everything a command needs. */
export class Context {
  readonly flags: Flags;
  readonly io: Io;
  readonly out: Output;
  readonly version: string;
  private located: EngineLocation | undefined;

  constructor(flags: Flags, io: Io, out: Output) {
    this.flags = flags;
    this.io = io;
    this.out = out;
    this.version = cliVersion();
  }

  get cwd(): string {
    return this.io.cwd;
  }

  get interactive(): boolean {
    return !this.flags.nonInteractive && this.io.prompter.interactive;
  }

  /** The same invocation acting in another directory (for commands about other projects). */
  withCwd(cwd: string): Context {
    return new Context(this.flags, { ...this.io, cwd }, this.out);
  }

  /** The engine, located and verified once per invocation. */
  engine(): EngineLocation {
    if (!this.located) {
      this.located = resolveEngine({
        env: this.io.env,
        target: detectPlatform(this.io.platform, this.io.arch),
        platformLabel: `${this.io.platform}-${this.io.arch}`,
        trustedKeys: loadReleaseKeys(path.join(PACKAGE_ROOT, "release-keys.json")),
        ...(this.io.packageRoot ? { packageRoot: this.io.packageRoot } : {}),
      });
    }
    return this.located;
  }

  /** The located engine, if it was located without error. */
  engineIfLocated(): EngineLocation | undefined {
    return this.located;
  }

  /** Send a command; return the validated response, success or error. */
  callRaw(command: string, args: Record<string, unknown>): Promise<EngineResponse> {
    return callEngine(this.engine(), command, args, { env: this.io.env });
  }

  /** Like `call`, for commands that run for a long time (managed execution). */
  async callLong(command: string, args: Record<string, unknown>, timeoutMs: number): Promise<Record<string, unknown>> {
    const response = await callEngine(this.engine(), command, args, { env: this.io.env, timeoutMs });
    if (response.success) return response.data;
    throw engineError(response.error);
  }

  /** Send a command; return its data or throw the engine's error as a `CliError`. */
  async call(command: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await this.callRaw(command, args);
    if (response.success) return response.data;
    throw engineError(response.error);
  }

  /** Ask for confirmation, or require `--yes` when not interactive. Declining is a failure. */
  async confirm(question: string, nonInteractiveHint: string): Promise<void> {
    if (this.flags.yes) return;
    if (!this.interactive) {
      throw new CliError("confirmation-required", `${nonInteractiveHint} requires confirmation`, ExitCode.ActionRequired, "re-run with --yes to confirm explicitly");
    }
    if (!(await this.io.prompter.confirm(question))) {
      throw new CliError("cancelled", "cancelled; nothing was changed", ExitCode.Failure);
    }
  }

  /**
   * The signing key passphrase as request arguments: a private file passed to the engine
   * (`--passphrase-file`), or a hidden prompt. Never from an environment variable or a
   * command-line argument, which other processes can read.
   */
  async passphrase(creating: boolean): Promise<Record<string, string>> {
    if (this.flags.passphraseFile !== undefined) {
      return { passphrase_file: path.resolve(this.cwd, this.flags.passphraseFile) };
    }
    if (!this.interactive) {
      throw new CliError(
        "authorization-required",
        "this operation needs the AI Defender signing key passphrase",
        ExitCode.ActionRequired,
        "run it in an interactive terminal, or pass --passphrase-file <private file>",
      );
    }
    try {
      if (!creating) return { passphrase: await this.io.prompter.secret("Signing key passphrase: ") };
      this.out.note("Choose a passphrase for the new AI Defender signing keys (at least 12 characters).");
      this.out.note("It protects every change to trusted policy. It cannot be recovered if lost.");
      const first = await this.io.prompter.secret("New passphrase: ");
      if ([...first].length < 12) {
        throw new CliError("weak-passphrase", "the passphrase must be at least 12 characters", ExitCode.Failure);
      }
      const second = await this.io.prompter.secret("Repeat passphrase: ");
      if (first !== second) throw new CliError("passphrase-mismatch", "the passphrases do not match", ExitCode.Failure);
      return { passphrase: first };
    } catch (e) {
      if (e instanceof CliError) throw e;
      if (e instanceof NotInteractiveError) throw e;
      throw new CliError("cancelled", "cancelled; nothing was changed", ExitCode.Failure);
    }
  }

  /** Attribution name sent with changes. */
  get requestedBy(): string {
    return this.io.user;
  }

  /** Emit the JSON envelope. */
  emitJson(command: string, ok: boolean, payload: { data?: unknown; error?: unknown }): void {
    const engine = this.located ? { path: this.located.path, verified: this.located.verified, source: this.located.source } : null;
    this.out.json({ ok, command, cli_version: this.version, engine, ...payload });
  }
}

export function engineError(error: { code: Parameters<typeof exitCodeForEngineError>[0]; message: string; recovery?: string }): CliError {
  return new CliError(error.code, error.message, exitCodeForEngineError(error.code), error.recovery);
}

function parseFlags(argv: string[]): { flags: Flags; positionals: string[]; help: boolean; version: boolean } {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "V" },
        json: { type: "boolean" },
        "no-color": { type: "boolean" },
        "non-interactive": { type: "boolean" },
        yes: { type: "boolean", short: "y" },
        verbose: { type: "boolean", short: "v" },
        "passphrase-file": { type: "string" },
        profile: { type: "string" },
        name: { type: "string" },
        reason: { type: "string" },
        staged: { type: "boolean" },
        exclude: { type: "string", multiple: true },
        "no-default-exclusions": { type: "boolean" },
        blocked: { type: "boolean" },
        approvals: { type: "boolean" },
        limit: { type: "string" },
        purge: { type: "boolean" },
      },
    });
  } catch (e) {
    throw usageError(e instanceof Error ? e.message : "invalid arguments");
  }
  const v = parsed.values;
  return {
    flags: {
      json: v.json === true,
      noColor: v["no-color"] === true,
      nonInteractive: v["non-interactive"] === true,
      yes: v.yes === true,
      verbose: v.verbose === true,
      passphraseFile: v["passphrase-file"],
      profile: v.profile,
      name: v.name,
      reason: v.reason,
      staged: v.staged === true,
      exclude: v.exclude ?? [],
      noDefaultExclusions: v["no-default-exclusions"] === true,
      blocked: v.blocked === true,
      approvals: v.approvals === true,
      limit: v.limit,
      purge: v.purge === true,
    },
    positionals: parsed.positionals,
    help: v.help === true,
    version: v.version === true,
  };
}

type Handler = (ctx: Context, args: string[]) => Promise<ExitCodeValue | number>;

const COMMANDS: Record<string, Handler> = {
  approvals: (ctx, args) => approvals(ctx, args),
  approve: (ctx, args) => approve(ctx, args),
  reject: (ctx, args) => reject(ctx, args),
  init: (ctx, args) => init(ctx, args),
  integrations: (ctx, args) => integrations(ctx, args),
  status: (ctx, args) => status(ctx, args),
  check: (ctx, args) => check(ctx, args),
  dashboard: (ctx, args) => dashboard(ctx, args),
  doctor: (ctx, args) => doctor(ctx, args),
  history: (ctx, args) => history(ctx, args),
  projects: (ctx, args) => projects(ctx, args),
  repair: (ctx, args) => repair(ctx, args),
  update: (ctx, args) => update(ctx, args),
  uninstall: (ctx, args) => uninstall(ctx, args),
  execution: (ctx, args) => execution(ctx, args),
  git: (ctx, args) => git(ctx, args),
  run: (ctx, args) => runCommand(ctx, args),
  policy: (ctx, args) => policy(ctx, args),
  project: (ctx, args) => project(ctx, args),
  secrets: (ctx, args) => secrets(ctx, args),
  version: (ctx, args) => version(ctx, args),
};

const VALUE_FLAGS = new Set(["--passphrase-file", "--profile", "--name", "--reason", "--exclude", "--limit"]);

/**
 * Split `ai-defender [global options] run <command...>`: everything after `run` belongs to the
 * command being run (its flags are not AI Defender's), so it is kept out of option parsing.
 */
export function splitRun(argv: string[]): { global: string[]; command: string[] | undefined } {
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] as string;
    if (a === "--") break;
    if (VALUE_FLAGS.has(a)) {
      i += 1;
      continue;
    }
    if (a.startsWith("-")) continue;
    return a === "run" ? { global: argv.slice(0, i), command: argv.slice(i + 1) } : { global: argv, command: undefined };
  }
  return { global: argv, command: undefined };
}

/** Run the CLI. Never throws; returns the process exit code. */
export async function run(argv: string[], io: Io): Promise<number> {
  let parsed;
  const fallback = new Output(io.stdout, io.stderr, { color: false, json: false });
  const split = splitRun(argv);
  try {
    parsed = parseFlags(split.global);
  } catch (e) {
    const err = e as CliError;
    fallback.error(err.message, err.recovery);
    return err.exitCode;
  }
  const { flags } = parsed;
  const positionals = split.command !== undefined ? ["run", ...split.command] : parsed.positionals;
  const out = new Output(io.stdout, io.stderr, {
    color: shouldColor({ noColor: flags.noColor }, io.env, Boolean(io.stdout.isTTY)) && !flags.json,
    json: flags.json,
  });
  const ctx = new Context(flags, io, out);
  const [command, ...rest] = positionals;
  if (parsed.version) return version(ctx, []);
  if (parsed.help || command === undefined || command === "help") {
    help(out);
    return command === undefined && !parsed.help ? ExitCode.Usage : ExitCode.Ok;
  }
  const handler = Object.prototype.hasOwnProperty.call(COMMANDS, command) ? COMMANDS[command] : undefined;
  try {
    if (!handler) throw usageError(`unknown command: ${command}`);
    return await handler(ctx, rest);
  } catch (e) {
    const err =
      e instanceof CliError
        ? e
        : e instanceof NotInteractiveError
          ? new CliError("not-interactive", "this command needs an interactive terminal", ExitCode.ActionRequired)
          : new CliError("internal", "unexpected error", ExitCode.Failure);
    if (flags.json) {
      ctx.emitJson(command ?? "", false, { error: { code: err.code, message: err.message, recovery: err.recovery ?? null } });
    } else {
      out.error(err.message, err.recovery);
    }
    return err.exitCode;
  }
}
