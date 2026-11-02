//! `agentguard inspect`: show what AgentGuard resolved about this project and host.

use std::path::PathBuf;

use agentguard_common::config::{self, Validate};
use agentguard_common::paths::AppPaths;
use agentguard_common::{AgentGuardError, ExitCode};
use clap::Args;
use serde::Serialize;

use crate::commands::locate_policy;
use crate::output::{self, Table};
use crate::Context;

/// Arguments for `inspect`.
#[derive(Debug, Args, Default)]
pub struct InspectArgs {}

#[derive(Debug, Serialize)]
struct InspectOutput {
    policy_path: PathBuf,
    project_root: PathBuf,
    git_root: Option<PathBuf>,
    version: u32,
    mode: String,
    sections_present: Vec<&'static str>,
    structural_errors: usize,
    structural_warnings: usize,
    state_dir: PathBuf,
    config_dir: PathBuf,
    runtime_dir: Option<PathBuf>,
    not_implemented: Vec<&'static str>,
}

fn opt_path(p: Option<&PathBuf>) -> String {
    p.map_or_else(|| "(none)".to_owned(), |p| p.display().to_string())
}

/// Run `inspect`.
pub fn run(ctx: &Context, _args: &InspectArgs) -> Result<ExitCode, AgentGuardError> {
    let found = locate_policy(ctx)?;
    let parsed = config::load(&found.policy_path)?;
    let report = parsed.validate();
    let paths = AppPaths::from_env()?;
    let out = InspectOutput {
        policy_path: found.policy_path,
        project_root: found.project_root,
        git_root: found.git_root,
        version: parsed.version(),
        mode: parsed.mode().to_string(),
        sections_present: parsed.present_sections(),
        structural_errors: report.errors().len(),
        structural_warnings: report.warnings().len(),
        state_dir: paths.state_dir,
        config_dir: paths.config_dir,
        runtime_dir: paths.runtime_dir,
        not_implemented: vec![
            "effective policy and precedence (Phase 2)",
            "agent capability and integration tier reporting (Phase 10)",
        ],
    };
    if ctx.json {
        output::json(&out);
        return Ok(ExitCode::Success);
    }
    let sections = if out.sections_present.is_empty() {
        "(none)".to_owned()
    } else {
        out.sections_present.join(", ")
    };
    let mut t = Table::new();
    t.row("Policy file", out.policy_path.display().to_string())
        .row("Project root", out.project_root.display().to_string())
        .row("Git root", opt_path(out.git_root.as_ref()))
        .row("Format version", out.version.to_string())
        .row("Mode", out.mode.clone())
        .row("Sections present", sections)
        .row(
            "Structural check",
            format!(
                "{} error(s), {} warning(s)",
                out.structural_errors, out.structural_warnings
            ),
        )
        .row("State dir", out.state_dir.display().to_string())
        .row("Config dir", out.config_dir.display().to_string())
        .row("Runtime dir", opt_path(out.runtime_dir.as_ref()));
    t.print();
    output::line("");
    output::line("Not implemented yet:");
    for item in &out.not_implemented {
        output::line(&format!("  - {item}"));
    }
    Ok(ExitCode::Success)
}
