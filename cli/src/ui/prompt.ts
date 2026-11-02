/**
 * Interactive prompts. Every prompt requires a terminal on both stdin and stdout; without one
 * the caller must fall back to explicit flags (`--yes`, `--passphrase-file`), never to a
 * default "yes".
 */

import { createInterface } from "node:readline";

export interface Prompter {
  /** Whether prompts can be shown. */
  readonly interactive: boolean;
  /** Ask a yes/no question; the default answer is no. */
  confirm(question: string): Promise<boolean>;
  /** Ask for a typed answer; there is no default. */
  ask(question: string): Promise<string>;
  /** Ask for a secret without echoing it. */
  secret(question: string): Promise<string>;
}

export class NotInteractiveError extends Error {
  constructor() {
    super("no interactive terminal");
  }
}

/** Prompts on the process's terminal. */
export class TerminalPrompter implements Prompter {
  readonly interactive: boolean;

  constructor(private readonly input: NodeJS.ReadStream, private readonly output: NodeJS.WriteStream, disabled: boolean) {
    this.interactive = !disabled && Boolean(input.isTTY) && Boolean(output.isTTY);
  }

  confirm(question: string): Promise<boolean> {
    if (!this.interactive) return Promise.reject(new NotInteractiveError());
    const rl = createInterface({ input: this.input, output: this.output });
    return new Promise((resolve) => {
      rl.question(`${question} [y/N] `, (answer) => {
        rl.close();
        resolve(/^(y|yes)$/i.test(answer.trim()));
      });
    });
  }

  ask(question: string): Promise<string> {
    if (!this.interactive) return Promise.reject(new NotInteractiveError());
    const rl = createInterface({ input: this.input, output: this.output });
    return new Promise((resolve) => {
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  secret(question: string): Promise<string> {
    if (!this.interactive) return Promise.reject(new NotInteractiveError());
    const input = this.input;
    const output = this.output;
    return new Promise((resolve, reject) => {
      let value = "";
      output.write(question);
      const wasRaw = input.isRaw;
      input.setRawMode(true);
      input.resume();
      const done = (fn: () => void) => {
        input.setRawMode(wasRaw);
        input.pause();
        input.removeListener("data", onData);
        output.write("\n");
        fn();
      };
      const onData = (chunk: Buffer) => {
        for (const ch of chunk.toString("utf8")) {
          if (ch === "\r" || ch === "\n") {
            done(() => resolve(value));
            return;
          }
          if (ch === "\u0003" || ch === "\u0004") {
            done(() => reject(new Error("cancelled")));
            return;
          }
          if (ch === "\u007f" || ch === "\b") {
            value = [...value].slice(0, -1).join("");
          } else if (ch >= " ") {
            value += ch;
          }
        }
      };
      input.on("data", onData);
    });
  }
}
