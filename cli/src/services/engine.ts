/**
 * Talking to the Rust engine: one process per request, JSON over stdin/stdout.
 *
 * The binary is started with an argument vector (never a shell), so no part of a path,
 * working directory or argument is interpreted by a shell. Output is bounded, the process is
 * killed on timeout, and every response is validated structurally before anything is read
 * from it. A malformed or incompatible response is an error, never a success.
 */

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

import { CliError } from "../utils/errors.js";
import { ENGINE_ERROR_CODES, ExitCode, type EngineErrorCode } from "../utils/exit-codes.js";
import { ENGINE_PROTOCOL_VERSION, type EngineLocation } from "./installer.js";

export const MAX_REQUEST_BYTES = 64 * 1024;
export const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
export const DEFAULT_TIMEOUT_MS = 30_000;
const KILL_GRACE_MS = 2_000;

export interface EngineErrorBody {
  code: EngineErrorCode;
  message: string;
  recovery?: string;
}

export type EngineResponse =
  | { success: true; data: Record<string, unknown> }
  | { success: false; error: EngineErrorBody };

export interface CallOptions {
  env: Record<string, string | undefined>;
  timeoutMs?: number;
  cwd?: string;
}

function protocolError(message: string): CliError {
  return new CliError(
    "engine-protocol",
    `the AI Defender engine returned an invalid response: ${message}`,
    ExitCode.EngineProtocol,
    "reinstall ai-defender so the CLI and engine versions match",
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate a decoded response. Exactly the protocol's keys, the expected protocol version and
 * request ID, and a consistent success/data/error triple; anything else is rejected.
 */
export function validateResponse(value: unknown, requestId: string, exitCode: number | null): EngineResponse {
  if (!isPlainObject(value)) throw protocolError("not a JSON object");
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "data,error,protocol_version,request_id,success") {
    throw protocolError("unexpected or missing fields");
  }
  if (value["protocol_version"] !== ENGINE_PROTOCOL_VERSION) {
    throw protocolError(`unsupported protocol version ${String(value["protocol_version"])}`);
  }
  if (value["request_id"] !== requestId) throw protocolError("request ID mismatch");
  const success = value["success"];
  if (success === true) {
    if (!isPlainObject(value["data"]) || value["error"] !== null) throw protocolError("inconsistent success response");
    if (exitCode !== 0) throw protocolError("success response with a failure exit status");
    return { success: true, data: value["data"] };
  }
  if (success === false) {
    const error = value["error"];
    if (value["data"] !== null || !isPlainObject(error)) throw protocolError("inconsistent error response");
    const errorKeys = Object.keys(error);
    const code = error["code"];
    const message = error["message"];
    const recovery = error["recovery"];
    if (
      !errorKeys.every((k) => k === "code" || k === "message" || k === "recovery") ||
      typeof code !== "string" ||
      !(ENGINE_ERROR_CODES as readonly string[]).includes(code) ||
      typeof message !== "string" ||
      (recovery !== undefined && typeof recovery !== "string")
    ) {
      throw protocolError("malformed error object");
    }
    if (exitCode === 0) throw protocolError("error response with a success exit status");
    const body: EngineErrorBody = { code: code as EngineErrorCode, message };
    if (typeof recovery === "string") body.recovery = recovery;
    return { success: false, error: body };
  }
  throw protocolError("missing success flag");
}

/** Send one command to the engine and return its validated response. */
export function callEngine(
  engine: EngineLocation,
  command: string,
  args: Record<string, unknown>,
  options: CallOptions,
): Promise<EngineResponse> {
  const requestId = randomUUID();
  const request = JSON.stringify({ protocol_version: ENGINE_PROTOCOL_VERSION, request_id: requestId, command, arguments: args });
  if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
    return Promise.reject(new CliError("request-too-large", "request too large", ExitCode.Usage));
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        fn();
      }
    };
    const child = spawn(engine.path, [], {
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      env: options.env as NodeJS.ProcessEnv,
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    });
    const stop = () => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), KILL_GRACE_MS).unref();
    };
    const timer = setTimeout(() => {
      stop();
      finish(() => reject(new CliError("engine-timeout", "the AI Defender engine did not respond in time", ExitCode.EngineUnavailable)));
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const out: Buffer[] = [];
    let outBytes = 0;
    let errBytes = 0;
    child.stdout.on("data", (chunk: Buffer) => {
      outBytes += chunk.length;
      if (outBytes > MAX_RESPONSE_BYTES) {
        stop();
        finish(() => reject(protocolError("response exceeds the size limit")));
        return;
      }
      out.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      errBytes += chunk.length;
      if (errBytes > MAX_STDERR_BYTES) stop();
    });
    child.on("error", (err: NodeJS.ErrnoException) => {
      finish(() =>
        reject(new CliError("engine-unavailable", `the AI Defender engine could not be started (${err.code ?? "error"})`, ExitCode.EngineUnavailable)),
      );
    });
    child.on("close", (code) => {
      finish(() => {
        const text = Buffer.concat(out).toString("utf8").trim();
        if (text.length === 0 || text.includes("\n")) {
          reject(protocolError("expected exactly one JSON line"));
          return;
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          reject(protocolError("not valid JSON"));
          return;
        }
        try {
          resolve(validateResponse(parsed, requestId, code));
        } catch (e) {
          reject(e);
        }
      });
    });
    child.stdin.on("error", () => {
      /* the close handler reports the outcome */
    });
    child.stdin.end(request);
  });
}
