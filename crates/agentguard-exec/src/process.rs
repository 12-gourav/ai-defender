//! The process runner. Private to this crate: the only caller is the executor, after
//! authorization (see [`crate::executor::Permit`]).
//!
//! - The program is started by absolute path with an argument vector; no shell is involved
//!   unless the plan is a shell-mode script, in which case the interpreter is the program.
//! - The environment is exactly the one built for the plan; standard input is `/dev/null`, so
//!   nothing can wait for a password, an editor or a pager.
//! - Standard output and error are read concurrently and kept up to a limit; the rest is
//!   counted and discarded, so a noisy process cannot exhaust memory or block on a full pipe.
//! - On Linux the process runs in its own process group. When the time limit passes, or the
//!   engine is interrupted, the group receives `SIGTERM`, then `SIGKILL` after a grace period.
//!   Processes left in the group after the main process exits are killed too. Elsewhere the
//!   process shares the engine's group and only the main process is signalled.
//! - An outcome that cannot be determined is reported as indeterminate, never as success or
//!   failure.

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;
use serde::Serialize;

/// Grace period between `SIGTERM` and `SIGKILL`.
const KILL_GRACE: Duration = Duration::from_secs(2);
/// How long output is drained after the main process exits before leftovers are killed.
const DRAIN_AFTER_EXIT: Duration = Duration::from_millis(300);

/// What to run.
pub(crate) struct Spawn<'a> {
    pub program: &'a Path,
    pub arg0: &'a str,
    pub args: &'a [String],
    pub cwd: &'a Path,
    pub env: &'a [(String, String)],
    pub timeout: Duration,
    pub capture_limit: usize,
    pub signals: Option<&'a Signals>,
}

/// Captured output of one stream.
#[derive(Debug, Clone, Default)]
pub(crate) struct Captured {
    pub bytes: Vec<u8>,
    pub total: u64,
}

impl Captured {
    fn push(&mut self, chunk: &[u8], limit: usize) {
        self.total += chunk.len() as u64;
        let room = limit.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
    }

    pub(crate) fn truncated(&self) -> bool {
        self.total > self.bytes.len() as u64
    }
}

/// How the process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub(crate) enum Termination {
    /// Exited with a status code.
    Exited {
        /// The code.
        code: i32,
    },
    /// Killed by a signal it did not expect from AgentGuard.
    Signaled {
        /// The signal number.
        signal: i32,
    },
    /// Exceeded the time limit and was terminated.
    TimedOut,
    /// The engine was interrupted and terminated the process.
    Interrupted,
    /// The program could not be started.
    SpawnFailed,
    /// The outcome could not be determined.
    Indeterminate,
}

pub(crate) struct ProcessResult {
    pub termination: Termination,
    pub stdout: Captured,
    pub stderr: Captured,
    pub duration: Duration,
}

/// Termination signals delivered to the engine, readable without a signal handler.
pub struct Signals {
    #[cfg(target_os = "linux")]
    fd: nix::sys::signalfd::SignalFd,
}

impl Signals {
    /// Block `SIGINT`, `SIGTERM` and `SIGHUP` on the calling thread and receive them through a
    /// descriptor instead. The engine binary calls this once; child processes start with an
    /// empty signal mask (the standard library resets it). `None` where unsupported.
    #[must_use]
    pub fn capture() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::SigSet;
            use nix::sys::signalfd::{SfdFlags, SignalFd};
            let mut set = SigSet::empty();
            set.add(Signal::SIGINT);
            set.add(Signal::SIGTERM);
            set.add(Signal::SIGHUP);
            set.thread_block().ok()?;
            let fd =
                SignalFd::with_flags(&set, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC).ok()?;
            Some(Self { fd })
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    fn pending(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.fd.read_signal(), Ok(Some(_)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

/// Harden the engine process before it runs anything: no core dumps (they could contain
/// secrets) and, on Linux, `no_new_privs`, so no descendant can gain privileges through a
/// set-user-ID program. Both are inherited by every child. Called by the engine binary only.
pub fn harden_current_process() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    #[cfg(target_os = "linux")]
    {
        let _ = nix::sys::prctl::set_no_new_privs();
    }
}

const ISOLATE_GROUP: bool = cfg!(target_os = "linux");

fn signal(child: &Child, sig: Signal) {
    let Ok(raw) = i32::try_from(child.id()) else {
        return;
    };
    let pid = Pid::from_raw(raw);
    if ISOLATE_GROUP {
        let _ = killpg(pid, sig);
    } else {
        let _ = kill(pid, sig);
    }
}

fn terminate(child: &mut Child) -> Option<std::process::ExitStatus> {
    signal(child, Signal::SIGTERM);
    let until = Instant::now() + KILL_GRACE;
    while Instant::now() < until {
        if let Ok(Some(status)) = child.try_wait() {
            signal(child, Signal::SIGKILL);
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    signal(child, Signal::SIGKILL);
    wait_bounded(child, Duration::from_secs(5))
}

fn wait_bounded(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
            _ => return None,
        }
    }
}

// Managed execution is the one place AgentGuard starts host processes (see clippy.toml).
#[allow(clippy::disallowed_methods)]
fn command(spec: &Spawn<'_>) -> Command {
    let mut cmd = Command::new(spec.program);
    cmd.arg0(spec.arg0)
        .args(spec.args)
        .current_dir(spec.cwd)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if ISOLATE_GROUP {
        cmd.process_group(0);
    }
    cmd
}

/// Run `spec` to completion, time limit or interruption.
// The read loop is one state machine; splitting it would separate the invariants it keeps.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(spec: &Spawn<'_>) -> ProcessResult {
    let start = Instant::now();
    let Ok(mut child) = command(spec).spawn() else {
        return ProcessResult {
            termination: Termination::SpawnFailed,
            stdout: Captured::default(),
            stderr: Captured::default(),
            duration: start.elapsed(),
        };
    };
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let mut stdout = Captured::default();
    let mut stderr = Captured::default();
    let deadline = start + spec.timeout;
    let mut exit: Option<(std::process::ExitStatus, Instant)> = None;
    let mut forced: Option<Termination> = None;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if out.is_none() && err.is_none() && exit.is_some() {
            break;
        }
        // Poll the open pipes (and the signal descriptor) for up to 100 ms.
        let mut ready = [false; 3];
        {
            let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(3);
            let mut which = Vec::with_capacity(3);
            if let Some(o) = &out {
                fds.push(PollFd::new(o.as_fd(), PollFlags::POLLIN));
                which.push(0);
            }
            if let Some(e) = &err {
                fds.push(PollFd::new(e.as_fd(), PollFlags::POLLIN));
                which.push(1);
            }
            #[cfg(target_os = "linux")]
            if let Some(s) = spec.signals {
                fds.push(PollFd::new(s.fd.as_fd(), PollFlags::POLLIN));
                which.push(2);
            }
            if fds.is_empty() {
                std::thread::sleep(Duration::from_millis(20));
            } else if poll(&mut fds, PollTimeout::from(100u8)).is_ok() {
                for (fd, w) in fds.iter().zip(which) {
                    if fd.revents().is_some_and(|r| !r.is_empty()) {
                        if let Some(slot) = ready.get_mut(w) {
                            *slot = true;
                        }
                    }
                }
            }
        }
        if ready[0] {
            if let Some(o) = out.as_mut() {
                match o.read(&mut buf) {
                    Ok(0) | Err(_) => out = None,
                    Ok(n) => stdout.push(buf.get(..n).unwrap_or_default(), spec.capture_limit),
                }
            }
        }
        if ready[1] {
            if let Some(e) = err.as_mut() {
                match e.read(&mut buf) {
                    Ok(0) | Err(_) => err = None,
                    Ok(n) => stderr.push(buf.get(..n).unwrap_or_default(), spec.capture_limit),
                }
            }
        }
        if ready[2] && spec.signals.is_some_and(Signals::pending) && exit.is_none() {
            forced = Some(Termination::Interrupted);
            match terminate(&mut child) {
                Some(status) => exit = Some((status, Instant::now())),
                None => break,
            }
        }
        if exit.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => exit = Some((status, Instant::now())),
                Ok(None) => {}
                Err(_) => break,
            }
        }
        if exit.is_none() && Instant::now() >= deadline {
            forced = Some(Termination::TimedOut);
            match terminate(&mut child) {
                Some(status) => exit = Some((status, Instant::now())),
                None => break,
            }
        }
        if let Some((_, at)) = exit {
            if at.elapsed() >= DRAIN_AFTER_EXIT && (out.is_some() || err.is_some()) {
                // Something left in the group still holds the pipes open.
                signal(&child, Signal::SIGKILL);
                out = None;
                err = None;
            }
        }
    }
    if ISOLATE_GROUP {
        signal(&child, Signal::SIGKILL);
    }
    let termination =
        match (forced, exit) {
            (Some(f), _) => f,
            (None, Some((status, _))) => match (status.code(), status.signal()) {
                (Some(code), _) => Termination::Exited { code },
                (None, Some(signal)) => Termination::Signaled { signal },
                _ => Termination::Indeterminate,
            },
            (None, None) => {
                match wait_bounded(&mut child, Duration::from_secs(1)) {
                    Some(status) => status.code().map_or(Termination::Indeterminate, |code| {
                        Termination::Exited { code }
                    }),
                    None => Termination::Indeterminate,
                }
            }
        };
    ProcessResult {
        termination,
        stdout,
        stderr,
        duration: start.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, timeout: Duration, limit: usize) -> ProcessResult {
        let path = crate::environment::trusted_path(None, Path::new("/nonexistent-project"));
        let program = crate::validation::resolve("sh", Path::new("/"), &path).unwrap();
        let args = vec!["-c".to_owned(), script.to_owned()];
        let env = vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())];
        run(&Spawn {
            program: &program.path,
            arg0: "sh",
            args: &args,
            cwd: Path::new("/"),
            env: &env,
            timeout,
            capture_limit: limit,
            signals: None,
        })
    }

    #[test]
    fn exit_codes_and_streams() {
        let r = sh(
            "echo out; echo err >&2; exit 3",
            Duration::from_secs(10),
            1024,
        );
        assert_eq!(r.termination, Termination::Exited { code: 3 });
        assert_eq!(r.stdout.bytes, b"out\n");
        assert_eq!(r.stderr.bytes, b"err\n");
    }

    #[test]
    fn output_is_bounded() {
        let r = sh(
            "i=0; while [ $i -lt 2000 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done",
            Duration::from_secs(20),
            1000,
        );
        assert_eq!(r.termination, Termination::Exited { code: 0 });
        assert_eq!(r.stdout.bytes.len(), 1000);
        assert_eq!(r.stdout.total, 2000 * 41);
        assert!(r.stdout.truncated());
    }

    #[test]
    fn timeouts_terminate_the_whole_group() {
        let r = sh(
            "sleep 30 & sleep 30; echo never",
            Duration::from_millis(500),
            1024,
        );
        assert_eq!(r.termination, Termination::TimedOut);
        assert!(r.duration < Duration::from_secs(10), "{:?}", r.duration);
        assert!(!String::from_utf8_lossy(&r.stdout.bytes).contains("never"));
    }

    #[test]
    fn leftover_background_processes_do_not_hold_the_run_open() {
        let r = sh("sleep 30 & echo started", Duration::from_secs(20), 1024);
        assert_eq!(r.termination, Termination::Exited { code: 0 });
        assert!(r.duration < Duration::from_secs(10), "{:?}", r.duration);
    }

    #[test]
    fn environment_is_exactly_the_given_one() {
        let r = sh("env", Duration::from_secs(10), 4096);
        let text = String::from_utf8_lossy(&r.stdout.bytes).into_owned();
        assert!(text.contains("PATH=/usr/bin:/bin"));
        assert!(!text.contains("HOME="), "{text}");
    }
}
