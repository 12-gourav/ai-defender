/**
 * `ai-defender dashboard`: one screen of the machine's security state, built only from engine
 * data (status, registry, approvals, history, integrations). Read-only: it makes no decisions.
 * Data that could not be read is shown as unavailable, never as zero.
 */

import type { Context } from "../cli.js";
import type { Tone } from "../services/output.js";
import { sanitize } from "../utils/sanitize.js";
import { usageError } from "../utils/errors.js";
import { ExitCode, type ExitCodeValue } from "../utils/exit-codes.js";
import { projectState, type Registered } from "./projects.js";
import { at } from "./status.js";

type Json = Record<string, unknown>;

export async function dashboard(ctx: Context, args: string[]): Promise<ExitCodeValue> {
  if (args.length > 0) throw usageError("usage: ai-defender dashboard");
  const engine = ctx.engine();
  const [status, version, registry, approvals, blocked, integrations] = await Promise.all([
    ctx.callRaw("status", { working_directory: ctx.cwd }),
    ctx.callRaw("version", {}),
    ctx.callRaw("project.list", {}),
    ctx.callRaw("approval.list", { include_closed: false }),
    ctx.callRaw("history.list", { filter: "blocked", limit: 5 }),
    ctx.callRaw("integrations.status", { probe: false }),
  ]);
  const projects: Registered[] = registry.success
    ? ((registry.data["projects"] as Json[] | undefined) ?? []).map((p) => ({
        id: String(p["id"]),
        root: String(p["root"]),
        name: String(p["root"]).split("/").filter(Boolean).at(-1) ?? "",
        status: String(p["status"]),
        intact: p["directory_matches"] === true,
        registeredAt: undefined,
      }))
    : [];
  const pending = approvals.success ? ((approvals.data["approvals"] as Json[] | undefined) ?? []).filter((a) => a["status"] === "pending") : undefined;
  const providers = integrations.success ? ((integrations.data["integrations"] as Json[] | undefined) ?? []) : undefined;
  const data = {
    engine: { path: engine.path, verified: engine.verified, version: version.success ? version.data["engine_version"] : null },
    trust: status.success ? at(status.data, "trust_store.state") : null,
    policy: status.success ? at(status.data, "policy.state") : null,
    projects: registry.success ? { total: projects.length, verified: projects.filter((p) => projectState(p).label === "Verified").length, attention: projects.filter((p) => projectState(p).label !== "Verified").map((p) => p.name) } : null,
    pending_approvals: pending ? pending.length : null,
    recent_blocked: blocked.success && blocked.data["available"] === true ? blocked.data["events"] : null,
    integrations: providers ? providers.map((i) => ({ provider: i["provider"], state: i["state"], compatibility: at(i, "compatibility.state") })) : null,
  };
  if (ctx.flags.json) {
    ctx.emitJson("dashboard", true, { data });
    return ExitCode.Ok;
  }
  const out = ctx.out;
  const na = out.paint("unavailable", "warn");
  out.line(out.paint("AI DEFENDER — DASHBOARD", "info"));
  out.line();
  out.heading("Global status");
  out.field("CLI version", ctx.version);
  out.field("Engine", `${String(data.engine.version ?? "unknown")} ${data.engine.verified ? "(verified)" : "(UNVERIFIED development build)"}`, data.engine.verified ? "ok" : "warn");
  out.field("Trusted state", data.trust ?? "unavailable", data.trust === "verified" ? "ok" : "bad");
  out.field("Global policy", data.policy ?? "unavailable", data.policy === "verified" ? "ok" : "warn");
  out.line();
  out.heading("Projects");
  if (!data.projects) out.field("Registered", na);
  else {
    out.field("Registered", data.projects.total);
    out.field("Verified", data.projects.verified, "ok");
    out.field("Needing attention", data.projects.attention.length > 0 ? data.projects.attention.join(", ") : "none", data.projects.attention.length > 0 ? "bad" : "ok");
  }
  out.line();
  out.heading("Security activity");
  out.field("Pending approvals", data.pending_approvals ?? "unavailable", data.pending_approvals ? "warn" : "plain");
  const recent = data.recent_blocked as Json[] | null;
  if (!recent) out.field("Recent blocked", na);
  else if (recent.length === 0) out.field("Recent blocked", "none recorded");
  else for (const e of recent) out.line(`    ${out.paint(sanitize(String(e["timestamp"] ?? "")).replace(/\.\d+Z$/, "Z"), "muted")}  ${sanitize(String(e["resource"] ?? "")).slice(0, 60)}`);
  out.line();
  out.heading("Agent integrations");
  if (!data.integrations) out.field("Integrations", na);
  else
    for (const i of data.integrations) {
      const state = String(i.state);
      const tone: Tone = state === "installed" ? (i.compatibility === "degraded" ? "warn" : "ok") : state === "not-installed" ? "muted" : "bad";
      const mode = state === "installed" ? (i.compatibility === "degraded" ? "enforcing (fails open on hook failure)" : "enforcing (pre-execution hooks)") : state;
      out.field(i.provider === "claude" ? "Claude Code" : "Codex", mode, tone);
    }
  out.line();
  out.note(`Details: \`ai-defender projects list\`, \`ai-defender approvals\`, \`ai-defender history --blocked\`, \`ai-defender integrations status\`. Hooks cover only the tools \`ai-defender integrations coverage\` lists.`);
  return ExitCode.Ok;
}
