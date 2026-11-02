//! `agentguard validate`: structural validation of the policy file.

use agentguard_common::config::{self, Severity, Validate};
use agentguard_common::{AgentGuardError, ExitCode};
use clap::Args;
use serde::Serialize;

use crate::commands::locate_policy;
use crate::output;
use crate::Context;

/// Arguments for `validate`.
#[derive(Debug, Args, Default)]
pub struct ValidateArgs {
    /// Treat warnings as errors.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Serialize)]
struct ValidateOutput<'a> {
    policy_path: &'a std::path::Path,
    version: u32,
    mode: String,
    sections: Vec<&'static str>,
    problems: &'a [config::Problem],
    ok: bool,
    scope: &'static str,
}

const SCOPE: &str =
    "structural (Phase 1); section semantics are validated by the policy engine from Phase 2";

/// Run `validate`.
pub fn run(ctx: &Context, args: &ValidateArgs) -> Result<ExitCode, AgentGuardError> {
    let found = locate_policy(ctx)?;
    let parsed = config::load(&found.policy_path)?;
    let report = parsed.validate();
    let failing = report.has_errors() || (args.strict && !report.warnings().is_empty());
    let out = ValidateOutput {
        policy_path: &found.policy_path,
        version: parsed.version(),
        mode: parsed.mode().to_string(),
        sections: parsed.present_sections(),
        problems: &report.problems,
        ok: !failing,
        scope: SCOPE,
    };
    if ctx.json {
        output::json(&out);
    } else {
        output::line(&format!("Policy:  {}", found.policy_path.display()));
        output::line(&format!("Version: {}   Mode: {}", out.version, out.mode));
        output::line(&format!(
            "Sections: {}",
            if out.sections.is_empty() {
                "(none)".to_owned()
            } else {
                out.sections.join(", ")
            }
        ));
        for p in &report.problems {
            let tag = match p.severity {
                Severity::Error => "ERROR",
                Severity::Warning => "WARN ",
            };
            output::line(&format!("  {tag} `{}`: {}", p.path, p.message));
        }
        output::line(&format!(
            "Result: {}",
            if failing { "INVALID" } else { "valid" }
        ));
        output::line(&format!("Scope:  {SCOPE}"));
    }
    Ok(if failing {
        ExitCode::ValidationFailed
    } else {
        ExitCode::Success
    })
}
