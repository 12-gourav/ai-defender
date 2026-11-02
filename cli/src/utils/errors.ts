import { ExitCode, type ExitCodeValue } from "./exit-codes.js";

/** An error presented to the user with an exit code and an optional recovery hint. */
export class CliError extends Error {
  readonly exitCode: ExitCodeValue;
  readonly recovery: string | undefined;
  readonly code: string;

  constructor(code: string, message: string, exitCode: ExitCodeValue, recovery?: string) {
    super(message);
    this.name = "CliError";
    this.code = code;
    this.exitCode = exitCode;
    this.recovery = recovery;
  }
}

/** Invalid command-line usage. */
export function usageError(message: string): CliError {
  return new CliError("usage", message, ExitCode.Usage, "run `ai-defender --help` for usage");
}
