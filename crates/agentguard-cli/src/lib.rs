//! Command-line interface for AgentGuard.
//!
//! The binary is a thin layer: parse arguments, initialise redacting logging, dispatch to one
//! command module, map the result to an exit code. Commands that belong to later phases are
//! registered here only when they can do something honest; a command that exists but is not
//! yet functional says so and exits with [`ExitCode::NotImplemented`].

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod commands;
pub mod output;

use std::path::PathBuf;

use agentguard_common::logging::{self, LogFormat, LogOptions};
use agentguard_common::{AgentGuardError, ExitCode};
use clap::{Parser, Subcommand, ValueEnum};

/// Log output format flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum LogFormatArg {
    /// Human-readable.
    #[default]
    Pretty,
    /// JSON lines.
    Json,
}

impl From<LogFormatArg> for LogFormat {
    fn from(value: LogFormatArg) -> Self {
        match value {
            LogFormatArg::Pretty => LogFormat::Pretty,
            LogFormatArg::Json => LogFormat::Json,
        }
    }
}

/// AgentGuard: developer-controlled security boundaries for AI coding agents.
#[derive(Debug, Parser)]
#[command(
    name = "agentguard",
    version,
    about,
    long_about = "AgentGuard runs AI coding agents inside an isolated environment under one \
                  project policy and brokers every sensitive operation through typed human \
                  approvals. The developer owns the permissions; the agent performs the work; \
                  AgentGuard enforces the boundaries."
)]
pub struct Cli {
    /// Increase log verbosity (-v info, -vv debug, -vvv trace). AGENTGUARD_LOG overrides.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Log output format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormatArg::Pretty)]
    pub log_format: LogFormatArg,

    /// Path to the policy file. Default: discover `.agent-security.yml` from the current
    /// directory upwards.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text where a command supports it.
    #[arg(long, global = true)]
    pub json: bool,

    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a starter `.agent-security.yml` in a project.
    Init(commands::init::InitArgs),
    /// Check the policy file for structural problems.
    Validate(commands::validate::ValidateArgs),
    /// Show the resolved policy, project and state locations.
    Inspect(commands::inspect::InspectArgs),
    /// Check this host for the capabilities AgentGuard needs.
    Doctor(commands::doctor::DoctorArgs),
    /// Show AgentGuard's state on this host.
    Status(commands::status::StatusArgs),
}

/// Shared context passed to every command.
#[derive(Debug, Clone)]
pub struct Context {
    /// Explicit policy path, if given.
    pub config: Option<PathBuf>,
    /// Whether to print JSON.
    pub json: bool,
}

/// Run a parsed command line. Logging is initialised here exactly once.
pub fn run(cli: Cli) -> Result<ExitCode, AgentGuardError> {
    logging::init(LogOptions {
        verbosity: cli.verbose,
        format: cli.log_format.into(),
    })?;
    let ctx = Context {
        config: cli.config,
        json: cli.json,
    };
    dispatch(&ctx, cli.command)
}

/// Dispatch without touching global logging (used by in-process tests).
pub fn dispatch(ctx: &Context, command: Command) -> Result<ExitCode, AgentGuardError> {
    match command {
        Command::Init(args) => commands::init::run(ctx, &args),
        Command::Validate(args) => commands::validate::run(ctx, &args),
        Command::Inspect(args) => commands::inspect::run(ctx, &args),
        Command::Doctor(args) => commands::doctor::run(ctx, &args),
        Command::Status(args) => commands::status::run(ctx, &args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_phase1_command_is_registered() {
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(clap::Command::get_name).collect();
        for expected in ["init", "validate", "inspect", "doctor", "status"] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }
}
