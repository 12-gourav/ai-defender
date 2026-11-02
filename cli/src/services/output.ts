/**
 * Terminal output: headings, aligned fields, status markers, colour when the terminal supports
 * it. Every string that originates outside the CLI (engine data, paths, messages) passes
 * through `sanitize` before it is printed.
 */

import { sanitize } from "../utils/sanitize.js";

export type Tone = "ok" | "warn" | "bad" | "muted" | "info" | "plain";

export interface Writer {
  write(text: string): void;
}

export interface OutputOptions {
  color: boolean;
  json: boolean;
}

const CODES: Record<Tone, [string, string]> = {
  ok: ["\u001b[32m", "\u001b[39m"],
  warn: ["\u001b[33m", "\u001b[39m"],
  bad: ["\u001b[31m", "\u001b[39m"],
  muted: ["\u001b[2m", "\u001b[22m"],
  info: ["\u001b[36m", "\u001b[39m"],
  plain: ["", ""],
};

/** Decide whether to colour output. `--no-color` and `NO_COLOR` always win. */
export function shouldColor(flags: { noColor: boolean }, env: Record<string, string | undefined>, isTTY: boolean): boolean {
  if (flags.noColor) return false;
  if (env["NO_COLOR"] !== undefined && env["NO_COLOR"] !== "") return false;
  if (env["FORCE_COLOR"] !== undefined && env["FORCE_COLOR"] !== "0" && env["FORCE_COLOR"] !== "") return true;
  if (env["TERM"] === "dumb") return false;
  return isTTY;
}

export class Output {
  readonly options: OutputOptions;
  private readonly out: Writer;
  private readonly err: Writer;

  constructor(out: Writer, err: Writer, options: OutputOptions) {
    this.out = out;
    this.err = err;
    this.options = options;
  }

  paint(text: string, tone: Tone): string {
    const [open, close] = CODES[tone];
    return this.options.color && tone !== "plain" ? `${open}${text}${close}` : text;
  }

  line(text = ""): void {
    this.out.write(`${text}\n`);
  }

  heading(text: string): void {
    this.line(this.paint(text, "info"));
  }

  title(): void {
    this.line(this.paint("AI Defender", "info"));
    this.line();
  }

  /** `label: value`, aligned; `value` is sanitized. */
  field(label: string, value: unknown, tone: Tone = "plain", width = 22): void {
    const text = sanitize(value === undefined || value === null ? "—" : String(value));
    this.line(`  ${`${label}:`.padEnd(Math.max(width, label.length + 2))}${this.paint(text, tone)}`);
  }

  /** A checklist row. */
  check(status: "pass" | "warn" | "fail" | "skip", title: string, detail?: string): void {
    const marks = { pass: ["PASS", "ok"], warn: ["WARN", "warn"], fail: ["FAIL", "bad"], skip: ["SKIP", "muted"] } as const;
    const [mark, tone] = marks[status];
    const suffix = detail ? this.paint(`  ${sanitize(detail)}`, "muted") : "";
    this.line(`  ${this.paint(mark, tone)}  ${sanitize(title)}${suffix}`);
  }

  note(text: string): void {
    this.line(this.paint(sanitize(text), "muted"));
  }

  /** A status line on standard error (keeps standard output for a command's own output). */
  warnLine(text: string, tone: Tone = "plain"): void {
    this.err.write(`${this.paint(sanitize(text), tone)}\n`);
  }

  warn(text: string): void {
    this.err.write(`${this.paint("warning:", "warn")} ${sanitize(text)}\n`);
  }

  error(text: string, recovery?: string): void {
    this.err.write(`${this.paint("error:", "bad")} ${sanitize(text)}\n`);
    if (recovery) this.err.write(`  ${this.paint("→", "muted")} ${sanitize(recovery)}\n`);
  }

  /** Machine-readable output: one JSON document. */
  json(value: unknown): void {
    this.out.write(`${JSON.stringify(value, null, 2)}\n`);
  }
}
