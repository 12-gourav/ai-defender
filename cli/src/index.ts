#!/usr/bin/env node
/**
 * `ai-defender` entry point.
 */

import os from "node:os";

import { run } from "./cli.js";
import { TerminalPrompter } from "./ui/prompt.js";
import { accountName } from "./utils/sanitize.js";

const argv = process.argv.slice(2);
let user = "user";
try {
  user = accountName(os.userInfo().username);
} catch {
  /* keep the default */
}

const code = await run(argv, {
  stdout: process.stdout,
  stderr: process.stderr,
  env: process.env,
  cwd: process.cwd(),
  platform: process.platform,
  arch: process.arch,
  user,
  prompter: new TerminalPrompter(process.stdin, process.stdout, argv.includes("--non-interactive")),
});
process.exitCode = code;
