//! One module per command. Each exposes `Args` and `run(&Context, &Args)`.

pub mod doctor;
pub mod init;
pub mod inspect;
pub mod status;
pub mod validate;

use std::path::{Path, PathBuf};

use agentguard_common::config::{self, Discovered};
use agentguard_common::AgentGuardError;

use crate::Context;

/// Resolve the policy file: explicit `--config` or discovery from the current directory.
pub(crate) fn locate_policy(ctx: &Context) -> Result<Discovered, AgentGuardError> {
    let Some(path) = &ctx.config else {
        let cwd = std::env::current_dir()
            .map_err(|e| AgentGuardError::io("reading the current directory", e))?;
        return Ok(config::discover(&cwd)?);
    };
    let policy_path = absolute(path);
    if !policy_path.is_file() {
        return Err(AgentGuardError::io(
            format!("opening policy file {}", policy_path.display()),
            std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        ));
    }
    let project_root = policy_path
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
    let git_root = config::discovery::find_git_root(&project_root);
    Ok(Discovered {
        policy_path,
        project_root,
        git_root,
    })
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |c| c.join(path))
    }
}
