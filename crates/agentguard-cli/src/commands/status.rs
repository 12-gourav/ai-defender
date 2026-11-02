//! `agentguard status`: what AgentGuard knows about this host and project right now.
//!
//! Session, approval and audit reporting belong to the security controller (Phase 3). This
//! command reports the state directory and policy, and says plainly what it cannot yet show.

use std::fs;

use agentguard_common::config::{self, Validate};
use agentguard_common::paths::AppPaths;
use agentguard_common::{AgentGuardError, ExitCode};
use clap::Args;
use serde::Serialize;

use crate::commands::locate_policy;
use crate::output::{self, Table};
use crate::Context;

/// Arguments for `status`.
#[derive(Debug, Args, Default)]
pub struct StatusArgs {}

#[derive(Debug, Serialize)]
struct StatusOutput {
    state_dir: std::path::PathBuf,
    state_dir_exists: bool,
    sessions_recorded: usize,
    policy: Option<PolicyStatus>,
    not_implemented: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct PolicyStatus {
    path: std::path::PathBuf,
    mode: String,
    structurally_valid: bool,
}

/// Run `status`.
pub fn run(ctx: &Context, _args: &StatusArgs) -> Result<ExitCode, AgentGuardError> {
    let paths = AppPaths::from_env()?;
    let state_dir_exists = paths.state_dir.is_dir();
    let sessions_recorded = fs::read_dir(paths.sessions_dir()).map_or(0, Iterator::count);
    let policy = match locate_policy(ctx) {
        Ok(found) => match config::load(&found.policy_path) {
            Ok(parsed) => Some(PolicyStatus {
                path: found.policy_path,
                mode: parsed.mode().to_string(),
                structurally_valid: !parsed.validate().has_errors(),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "policy file could not be parsed");
                Some(PolicyStatus {
                    path: found.policy_path,
                    mode: "(unparseable)".to_owned(),
                    structurally_valid: false,
                })
            }
        },
        Err(_) => None,
    };
    let out = StatusOutput {
        state_dir: paths.state_dir.clone(),
        state_dir_exists,
        sessions_recorded,
        policy,
        not_implemented: vec![
            "live sessions (security controller, Phase 3)",
            "pending approvals (approval engine, Phase 6)",
            "recent violations (audit queries, Phase 3)",
        ],
    };
    if ctx.json {
        output::json(&out);
        return Ok(ExitCode::Success);
    }
    let mut t = Table::new();
    t.row(
        "State dir",
        format!(
            "{} ({})",
            out.state_dir.display(),
            if out.state_dir_exists {
                "exists"
            } else {
                "not created"
            }
        ),
    )
    .row("Sessions recorded", out.sessions_recorded.to_string());
    match &out.policy {
        Some(p) => {
            t.row("Policy", p.path.display().to_string())
                .row("Mode", p.mode.clone())
                .row(
                    "Structurally valid",
                    if p.structurally_valid { "yes" } else { "no" },
                );
        }
        None => {
            t.row("Policy", "(none found; run `agentguard init`)");
        }
    }
    t.print();
    output::line("");
    output::line("Not available yet:");
    for item in &out.not_implemented {
        output::line(&format!("  - {item}"));
    }
    Ok(ExitCode::Success)
}
