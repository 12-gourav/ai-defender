//! `agentguard init`: write a starter policy file.

use std::fs;
use std::path::{Path, PathBuf};

use agentguard_common::config::{self, Validate, POLICY_FILE_NAME};
use agentguard_common::{AgentGuardError, ExitCode};
use clap::Args;

use crate::output;
use crate::Context;

/// The embedded template. Kept in `templates/` at the workspace root so documentation and the
/// binary cannot drift apart.
pub const TEMPLATE: &str = include_str!("../../../../templates/agent-security.v1.yml");

/// Arguments for `init`.
#[derive(Debug, Args, Default)]
pub struct InitArgs {
    /// Directory in which to create the policy file (default: current directory).
    #[arg(long, value_name = "DIR")]
    pub path: Option<PathBuf>,
}

/// Write the template to `dir`, refusing to overwrite. Returns the written path.
pub fn write_template(dir: &Path) -> Result<PathBuf, AgentGuardError> {
    let target = dir.join(POLICY_FILE_NAME);
    if target.exists() {
        return Err(AgentGuardError::AlreadyExists { path: target });
    }
    // The template must pass our own parser before it is offered to anyone.
    let parsed = config::parse_str(&target, TEMPLATE)?;
    if parsed.validate().has_errors() {
        return Err(AgentGuardError::Preflight(
            "embedded policy template failed validation; this is a build defect".to_owned(),
        ));
    }
    fs::write(&target, TEMPLATE)
        .map_err(|e| AgentGuardError::io(format!("writing {}", target.display()), e))?;
    Ok(target)
}

/// Run `init`.
pub fn run(ctx: &Context, args: &InitArgs) -> Result<ExitCode, AgentGuardError> {
    let dir = match &args.path {
        Some(p) => p.clone(),
        None => std::env::current_dir()
            .map_err(|e| AgentGuardError::io("reading the current directory", e))?,
    };
    if !dir.is_dir() {
        return Err(AgentGuardError::io(
            format!("opening directory {}", dir.display()),
            std::io::Error::new(std::io::ErrorKind::NotFound, "not a directory"),
        ));
    }
    let written = write_template(&dir)?;
    tracing::info!(path = %written.display(), "wrote policy template");
    if ctx.json {
        output::json(&serde_json::json!({ "written": written }));
    } else {
        output::line(&format!("Created {}", written.display()));
        output::line("Edit the file to match your project, then run `agentguard validate`.");
        output::line(
            "Phase 1 note: only the top-level structure is validated; section semantics arrive with the policy engine.",
        );
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_valid_v1() {
        let parsed = config::parse_str(Path::new("template"), TEMPLATE).unwrap();
        assert_eq!(parsed.version(), 1);
        assert!(!parsed.validate().has_errors());
    }

    #[test]
    fn write_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let first = write_template(dir.path()).unwrap();
        assert!(first.is_file());
        assert!(matches!(
            write_template(dir.path()),
            Err(AgentGuardError::AlreadyExists { .. })
        ));
        assert_eq!(fs::read_to_string(first).unwrap(), TEMPLATE);
    }
}
