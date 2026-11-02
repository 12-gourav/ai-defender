//! `agentguard` entry point.

#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::process::ExitCode as ProcessExitCode;

use agentguard_cli::{run, Cli};
use clap::Parser;

fn main() -> ProcessExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code.into(),
        Err(err) => {
            eprintln!("error: {}", err.user_message());
            err.exit_code().into()
        }
    }
}
