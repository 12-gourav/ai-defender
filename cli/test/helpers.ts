import { chmodSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { run, type Io } from "../src/cli.js";
import type { Prompter } from "../src/ui/prompt.js";

export class Memory {
  text = "";
  isTTY = false;
  write(chunk: string): void {
    this.text += chunk;
  }
}

/** A prompter that answers from a script, or refuses (non-interactive). */
export class ScriptedPrompter implements Prompter {
  readonly asked: string[] = [];
  constructor(readonly interactive: boolean, private readonly answers: Array<string | boolean> = []) {}
  confirm(question: string): Promise<boolean> {
    this.asked.push(question);
    return Promise.resolve(Boolean(this.answers.shift()));
  }
  ask(question: string): Promise<string> {
    this.asked.push(question);
    return Promise.resolve(String(this.answers.shift() ?? ""));
  }
  secret(question: string): Promise<string> {
    this.asked.push(question);
    return Promise.resolve(String(this.answers.shift() ?? ""));
  }
}

export const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..", "..");
export const ENGINE = process.env["AGENTGUARD_TEST_ENGINE"] ?? path.join(REPO, "target", "debug", "agentguard-engine");

export function tempDir(prefix = "agentguard-cli-"): string {
  return realpathSync(mkdtempSync(path.join(os.tmpdir(), prefix)));
}

export interface Sandbox {
  home: string;
  env: Record<string, string | undefined>;
}

/** Isolated HOME/XDG directories and the development engine. */
export function sandbox(engine = ENGINE): Sandbox {
  const home = tempDir("agentguard-home-");
  return {
    home,
    env: {
      PATH: process.env["PATH"],
      HOME: home,
      XDG_CONFIG_HOME: path.join(home, ".config"),
      XDG_STATE_HOME: path.join(home, ".state"),
      AGENTGUARD_DEV_ENGINE: engine,
      AGENTGUARD_ALLOW_UNVERIFIED_ENGINE: "1",
      NO_COLOR: "1",
    },
  };
}

export interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

export async function cli(argv: string[], options: { env: Record<string, string | undefined>; cwd: string; prompter?: Prompter; extra?: Partial<Io> }): Promise<Result> {
  const stdout = new Memory();
  const stderr = new Memory();
  const code = await run(argv, {
    stdout,
    stderr,
    env: options.env,
    cwd: options.cwd,
    platform: "linux",
    arch: "x64",
    user: "tester",
    prompter: options.prompter ?? new ScriptedPrompter(false),
    ...options.extra,
  });
  return { code, stdout: stdout.text, stderr: stderr.text };
}

/** Write an executable Node script that acts as a fake engine. */
export function fakeEngine(dir: string, body: string): string {
  const file = path.join(dir, "fake-engine.mjs");
  writeFileSync(file, `#!/usr/bin/env node\n${body}\n`);
  chmodSync(file, 0o755);
  return file;
}
