/**
 * Process exit codes. Stable: scripts and CI may depend on them.
 */
export const ExitCode = {
  /** Success. */
  Ok: 0,
  /** The operation failed. */
  Failure: 1,
  /** Invalid command-line usage. */
  Usage: 2,
  /** The engine is missing, unverified, unsupported on this platform, or did not respond. */
  EngineUnavailable: 3,
  /** The engine answered with a malformed or incompatible response. */
  EngineProtocol: 4,
  /** A security check failed (integrity failure, failing diagnostics). */
  CheckFailed: 5,
  /** A required confirmation or authorization was not given (for example non-interactively). */
  ActionRequired: 6,
  /** AI Defender is not initialized, or the project is not registered. */
  NotInitialized: 7,
  /** `run`: policy denied the command; nothing was run. */
  Denied: 8,
  /** `run`: the command uses syntax or options managed execution does not support; nothing was run. */
  Unsupported: 9,
  /** `run`: the command exceeded its time limit and was terminated. */
  TimedOut: 124,
  /** `run`: the command's outcome could not be determined, or could not be recorded. */
  Indeterminate: 125,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

/** Error codes the engine may return (engine protocol v1). */
export const ENGINE_ERROR_CODES = [
  "invalid-request",
  "unsupported-protocol",
  "unknown-command",
  "trust-not-initialized",
  "integrity-failure",
  "not-registered",
  "project-revoked",
  "confirmation-required",
  "authorization-required",
  "authorization-failed",
  "invalid-configuration",
  "unsupported-project-root",
  "io-error",
  "identity-unavailable",
  "approval-not-found",
  "approval-conflict",
  "authorization-denied",
  "audit-unavailable",
  "execution-duplicate",
  "outcome-unrecorded",
  "internal-error",
] as const;

export type EngineErrorCode = (typeof ENGINE_ERROR_CODES)[number];

/** Map an engine error code to a CLI exit code. */
export function exitCodeForEngineError(code: EngineErrorCode): ExitCodeValue {
  switch (code) {
    case "invalid-request":
    case "unsupported-protocol":
    case "unknown-command":
      return ExitCode.EngineProtocol;
    case "trust-not-initialized":
    case "not-registered":
      return ExitCode.NotInitialized;
    case "integrity-failure":
    case "audit-unavailable":
      return ExitCode.CheckFailed;
    case "outcome-unrecorded":
      return ExitCode.Indeterminate;
    case "confirmation-required":
    case "authorization-required":
      return ExitCode.ActionRequired;
    case "project-revoked":
    case "authorization-failed":
    case "invalid-configuration":
    case "unsupported-project-root":
    case "io-error":
    case "identity-unavailable":
    case "approval-not-found":
    case "approval-conflict":
    case "authorization-denied":
    case "execution-duplicate":
    case "internal-error":
      return ExitCode.Failure;
  }
}
