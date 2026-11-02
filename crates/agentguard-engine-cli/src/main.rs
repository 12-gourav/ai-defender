//! `agentguard-engine`: reads one JSON request from standard input, writes one JSON response
//! to standard output, exits with 0 on success, 1 on a command error, 2 on a protocol error.
//!
//! Usage (normally invoked by the npm CLI, never through a shell):
//!   echo '{"protocol_version":1,"request_id":"r1","command":"version"}' | agentguard-engine
//!
//! An agent integration launches it as `agentguard-engine --agent <kind>` (from hook settings
//! that AgentGuard's guard protects); commands then act for that agent and `approval.approve`
//! is refused. Agent hooks run `agentguard-engine hook <provider> <event>`, which reads the
//! provider's own payload and writes the provider's response (see `agentguard_hooks`).

#![allow(clippy::print_stdout)]

use std::io::{Read, Write};
use std::process::ExitCode;

use agentguard_core::AgentKind;
use agentguard_engine::TrustedInvocation;
use agentguard_engine_cli::protocol::{EngineError, ErrorCode, Response, MAX_REQUEST_BYTES};
use agentguard_engine_cli::{handle, Environment};

fn invocation() -> Result<Option<TrustedInvocation>, EngineError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bad = || {
        EngineError::new(
            ErrorCode::InvalidRequest,
            "usage: agentguard-engine [--agent <kind>]",
        )
    };
    match args.as_slice() {
        [] => Ok(None),
        [flag, kind] if flag == "--agent" => kind
            .parse::<AgentKind>()
            .map(|agent| Some(TrustedInvocation { agent }))
            .map_err(|_| bad()),
        _ => Err(bad()),
    }
}

/// `agentguard-engine hook <provider> <event>`: the provider's payload on stdin, its response
/// on stdout. Any failure is a block (see `agentguard_hooks::respond`).
fn hook(provider: &str, event: &str) -> ExitCode {
    agentguard_exec::harden_current_process();
    let mut input = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(u64::try_from(agentguard_hooks::input::MAX_PAYLOAD_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut input);
    let agent =
        agentguard_hooks::Provider::parse(provider).map(|p| TrustedInvocation { agent: p.agent() });
    let response = match (read, Environment::from_process(agent)) {
        (Ok(_), Ok(env)) => {
            agentguard_engine_cli::integrations::run_hook(&env, provider, event, &input)
        }
        _ => agentguard_hooks::HookResponse {
            stdout: None,
            stderr: Some(
                "AI Defender could not start its engine environment; the operation is blocked"
                    .to_owned(),
            ),
            exit_code: agentguard_hooks::respond::BLOCK_EXIT,
            verdict: None,
        },
    };
    if let Some(s) = &response.stderr {
        let _ = writeln!(std::io::stderr().lock(), "{s}");
    }
    if let Some(s) = &response.stdout {
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{s}").and_then(|()| out.flush()).is_err() {
            return ExitCode::from(agentguard_hooks::respond::BLOCK_EXIT);
        }
    }
    ExitCode::from(response.exit_code)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let [mode, provider, event] = argv.as_slice() {
        if mode == "hook" {
            return hook(provider, event);
        }
    }
    let mut input = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(u64::try_from(MAX_REQUEST_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut input);
    // Before anything can run: no core dumps, no privilege gain through set-user-ID programs
    // (Linux), and termination signals delivered through a descriptor so a managed process
    // group is terminated rather than orphaned when the engine is interrupted.
    agentguard_exec::harden_current_process();
    let response = match (read, invocation().and_then(Environment::from_process)) {
        (Err(_), _) => Response::failed(
            None,
            EngineError::new(ErrorCode::InvalidRequest, "could not read the request").0,
        ),
        (Ok(_), Err(e)) => Response::failed(None, e.0),
        (Ok(_), Ok(mut env)) => {
            env.signals = agentguard_exec::Signals::capture();
            handle(&input, &env)
        }
    };
    let code = response.exit_code();
    let body = serde_json::to_string(&response).unwrap_or_else(|_| {
        "{\"protocol_version\":1,\"request_id\":null,\"success\":false,\"data\":null,\"error\":{\"code\":\"internal-error\",\"message\":\"response could not be encoded\"}}".to_owned()
    });
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{body}").and_then(|()| out.flush()).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(code)
}
