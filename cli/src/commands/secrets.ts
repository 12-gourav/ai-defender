/**
 * Secret scanning commands. The Rust engine scans, redacts and records; this file only
 * displays its results. Nothing is uploaded, no file is changed, nothing is rotated.
 */

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

const SEVERITY_TONE: Record<string, Tone> = { critical: "bad", high: "bad", medium: "warn", low: "muted" };

function list(value: unknown): Json[] {
  return Array.isArray(value) ? (value as Json[]) : [];
}

async function scan(ctx: Context, paths: string[]): Promise<ExitCodeValue> {
  const data = await ctx.call("secrets.scan", {
    working_directory: ctx.cwd,
    paths,
    staged: ctx.flags.staged,
    exclude: ctx.flags.exclude,
    no_default_exclusions: ctx.flags.noDefaultExclusions,
  });
  const report = (data["report"] ?? {}) as Json;
  const findings = list(report["findings"]);
  const complete = report["complete"] === true;
  const code = findings.length > 0 ? ExitCode.CheckFailed : ExitCode.Ok;
  if (ctx.flags.json) {
    ctx.emitJson("secrets scan", true, { data });
    return code;
  }
  const out = ctx.out;
  out.title();
  out.heading(`Secret scan: ${String(data["root"])}${ctx.flags.staged ? " (staged changes)" : ""}`);
  out.field("Files scanned", `${String(report["files_scanned"])} (${String(report["bytes_scanned"])} bytes)`);
  out.field("Findings", findings.length, findings.length > 0 ? "bad" : "ok");
  for (const f of findings) {
    const severity = String(f["severity"]);
    out.line(
      `  ${out.paint(String(f["id"]), "muted")}  ${out.paint(severity.toUpperCase().padEnd(8), SEVERITY_TONE[severity] ?? "plain")} ${String(f["detector"]).padEnd(28)} ${String(f["path"])}:${String(f["line"])}:${String(f["column"])}  ${String(f["preview"])}`,
    );
  }
  if (report["findings_truncated"] === true) out.warn("more findings exist than were recorded; fix these and scan again");
  const excluded = list(report["excluded"]);
  const excludedTotal = Number(report["excluded_total"] ?? 0);
  if (excludedTotal > 0) {
    out.line();
    out.heading(`Excluded: ${excludedTotal} (not scanned and not checked; never reported as clean)`);
    for (const e of excluded.slice(0, 20)) out.line(`  ${String(e["path"])}  ${out.paint(`(${String(e["rule"])})`, "muted")}`);
    if (excludedTotal > 20) out.note(`  … and ${excludedTotal - 20} more (see --json)`);
  }
  const skipped = list(report["skipped"]);
  const skippedTotal = Number(report["skipped_total"] ?? 0);
  if (skippedTotal > 0) {
    out.line();
    out.heading(`Skipped: ${skippedTotal} (not scanned)`);
    for (const s of skipped.slice(0, 20)) out.line(`  ${String(s["path"])}  ${out.paint(`(${String(s["reason"])})`, "warn")}`);
    if (skippedTotal > 20) out.note(`  … and ${skippedTotal - 20} more (see --json)`);
  }
  out.line();
  if (findings.length > 0) {
    out.line(out.paint(`${findings.length} potential secret(s) found. Explain one with \`ai-defender secrets explain <id>\`.`, "bad"));
  } else if (complete) {
    out.line(out.paint("No secrets detected in the scanned files.", "ok"));
  } else {
    out.line(out.paint("No secrets detected in the files that were scanned, but the scan is INCOMPLETE: see the skipped files above.", "warn"));
  }
  out.note("Pattern detection finds common credential formats; it cannot prove that a file contains no secrets.");
  if (data["recorded"] !== true) out.note("Results were not recorded (AI Defender is not initialised here), so `secrets explain` is unavailable.");
  return code;
}

async function status(ctx: Context): Promise<ExitCodeValue> {
  const data = await ctx.call("secrets.status", { working_directory: ctx.cwd });
  if (ctx.flags.json) {
    ctx.emitJson("secrets status", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.heading("Secret detection");
  out.field("Engine", at(data, "engine.state"), "ok");
  out.field("Detectors", list(at(data, "engine.detectors")).length);
  out.field("Categories", (at(data, "engine.categories") as unknown[] | undefined)?.join(", "));
  out.field("Project root", data["root"]);
  out.line();
  out.heading("Policy");
  const policyState = String(at(data, "policy.state"));
  out.field("Policy", policyState, policyState === "verified" ? "ok" : "warn");
  out.field("Read sensitive files", at(data, "policy.sensitive_read"));
  out.field("Modify sensitive files", at(data, "policy.sensitive_write"));
  out.field("Delete sensitive files", at(data, "policy.sensitive_delete"));
  out.field("Read files with secrets", at(data, "policy.source_with_secrets"));
  out.field("Protected patterns", list(data["protected_patterns"]).length);
  out.field("Mandatory protections", (at(data, "policy.mandatory") as unknown[] | undefined)?.length);
  out.line();
  out.heading("Scanning");
  out.field("Default exclusions", (at(data, "exclusions.default_dirs") as unknown[] | undefined)?.join(", "));
  const configured = (at(data, "exclusions.configured") as unknown[] | undefined) ?? [];
  out.field("Configured exclusions", configured.length > 0 ? configured.join(", ") : "none");
  const last = data["last_scan"] as Json | null;
  if (!last) {
    out.field("Last scan", "none recorded");
  } else {
    out.field("Last scan", `${String(last["scanned_at"])} (${String(last["scope"])})`);
    out.field("Last result", `${String(last["findings"])} finding(s), ${last["complete"] === true ? "complete" : "INCOMPLETE"}`, Number(last["findings"]) > 0 ? "bad" : last["complete"] === true ? "ok" : "warn");
  }
  return ExitCode.Ok;
}

async function explain(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [id, ...rest] = args;
  if (id === undefined || rest.length > 0) throw usageError("usage: ai-defender secrets explain <finding-id>");
  const data = await ctx.call("secrets.explain", { working_directory: ctx.cwd, finding_id: id });
  if (ctx.flags.json) {
    ctx.emitJson("secrets explain", true, { data });
    return ExitCode.Ok;
  }
  const f = (data["finding"] ?? {}) as Json;
  const out = ctx.out;
  out.title();
  out.heading(`Finding ${String(f["id"])}`);
  out.field("Detector", f["detector"]);
  out.field("What it matches", data["detector_description"]);
  out.field("Category", f["category"]);
  out.field("Severity", String(f["severity"]).toUpperCase(), SEVERITY_TONE[String(f["severity"])] ?? "plain");
  out.field("Location", `${String(f["path"])}:${String(f["line"])}:${String(f["column"])}`);
  out.field("Value", `${String(f["preview"])} (never stored or shown)`);
  out.field("Scanned at", data["scanned_at"], "muted");
  out.line();
  out.heading("What to do");
  out.line(`  ${String(data["guidance"])}`);
  out.line();
  out.heading("If this is not a secret");
  out.line(`  ${String(data["false_positive"])}`);
  return ExitCode.Ok;
}

async function preview(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [file, ...rest] = args;
  if (file === undefined || rest.length > 0) throw usageError("usage: ai-defender secrets preview <.env file>");
  const data = await ctx.call("secrets.preview", { working_directory: ctx.cwd, path: file });
  if (ctx.flags.json) {
    ctx.emitJson("secrets preview", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  out.title();
  out.heading(`Configuration keys in ${String(data["path"])} (values are never shown)`);
  for (const k of list(data["keys"])) out.field(String(k["key"]), String(k["state"]), k["state"] === "set" ? "plain" : "muted", 28);
  return ExitCode.Ok;
}

export async function secrets(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  const [sub, ...rest] = args;
  switch (sub) {
    case "scan":
      return scan(ctx, rest);
    case "status":
      if (rest.length > 0) throw usageError("usage: ai-defender secrets status");
      return status(ctx);
    case "explain":
      return explain(ctx, rest);
    case "preview":
      return preview(ctx, rest);
    default:
      throw usageError("usage: ai-defender secrets scan [PATH...] [--staged] [--exclude GLOB] | status | explain <finding-id> | preview <.env file>");
  }
}
