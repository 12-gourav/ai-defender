/**
 * Make text safe to print to a terminal: remove ANSI escape sequences and C0/C1 control
 * characters (except newline and tab), so a crafted path or message cannot move the cursor,
 * rewrite earlier output or inject terminal commands.
 */
export function sanitize(text: string): string {
  return redactSecrets(text)
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\u001b[\]PX^_][\s\S]*?(?:\u0007|\u001b\\)/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");
}

/**
 * Defence in depth for terminal output. The engine never returns secret values; this masks
 * the most recognisable credential shapes in case one ever reaches the CLI (for example in a
 * path or an operating-system error message). It keeps only a public provider prefix.
 */
export function redactSecrets(text: string): string {
  return text
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g, "[PRIVATE KEY ****REDACTED]")
    .replace(/\b(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abposr]-|sk_live_|sk_test_|rk_live_|rk_test_|sk-ant-|npm_|AKIA|ASIA)[A-Za-z0-9_\-]{12,}/g, "$1****REDACTED")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)[^\s@/]+@/gi, "$1****REDACTED@");
}

/** A short, safe account name for attribution (the engine validates it again). */
export function accountName(raw: string | undefined): string {
  const cleaned = (raw ?? "").replace(/[^A-Za-z0-9._@:+-]/g, "").slice(0, 64);
  return cleaned.length > 0 ? cleaned : "user";
}
