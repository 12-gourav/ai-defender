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
//!   Processes left in the group after the main process exits are killed too. On macOS the
//!   process shares the engine's group and only the main process is signalled.
//! - On Windows the process starts suspended inside a Job Object it cannot leave, so the time
//!   limit, and the kill of leftovers after it exits, reach everything it started. There is no
//!   graceful stop: the job is terminated. The job dies with the engine, so an interrupted
//!   engine leaves nothing running.
//! - An outcome that cannot be determined is reported as indeterminate, never as success or
//!   failure.

use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
#[cfg(unix)]
use nix::sys::signal::{kill, killpg, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use serde::Serialize;

/// Grace period between `SIGTERM` and `SIGKILL`.
#[cfg(unix)]
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
    /// Killed by a signal it did not expect from AgentGuard (Unix).
    #[cfg_attr(windows, allow(dead_code))]
    Signaled {
        /// The signal number.
        signal: i32,
    },
    /// Exceeded the time limit and was terminated.
    TimedOut,
    /// The engine was interrupted and terminated the process (Unix; on Windows the job dies
    /// with the engine).
    #[cfg_attr(windows, allow(dead_code))]
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

    #[cfg(unix)]
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
    #[cfg(unix)]
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    #[cfg(target_os = "linux")]
    {
        let _ = nix::sys::prctl::set_no_new_privs();
    }
}

#[cfg(unix)]
const ISOLATE_GROUP: bool = cfg!(target_os = "linux");

#[cfg(unix)]
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

#[cfg(unix)]
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
    #[cfg(unix)]
    cmd.arg0(spec.arg0);
    cmd.args(spec.args)
        .current_dir(spec.cwd)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    if ISOLATE_GROUP {
        cmd.process_group(0);
    }
    cmd
}

fn spawn_failed(start: Instant) -> ProcessResult {
    ProcessResult {
        termination: Termination::SpawnFailed,
        stdout: Captured::default(),
        stderr: Captured::default(),
        duration: start.elapsed(),
    }
}

/// Run `spec` to completion or time limit.
#[cfg(windows)]
pub(crate) fn run(spec: &Spawn<'_>) -> ProcessResult {
    use std::sync::mpsc::{channel, RecvTimeoutError};

    // Windows starts the program by path with no separate argv[0], and has no termination
    // signals to watch: the job dies with the engine.
    let _ = (spec.arg0, spec.signals);
    let start = Instant::now();
    let Ok(job) = agentguard_platform::Job::new() else {
        return spawn_failed(start);
    };
    let Ok(mut child) = job.spawn(&mut command(spec)) else {
        return spawn_failed(start);
    };
    // Windows cannot poll pipes: one thread per stream forwards what it reads. A thread ends at
    // end of file or once nobody receives; it is never joined, so a pipe held open cannot hold
    // the run open.
    let (tx, rx) = channel::<(usize, Option<Vec<u8>>)>();
    let streams: [Option<Box<dyn Read + Send>>; 2] = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    let mut open = 0usize;
    for (which, stream) in streams.into_iter().enumerate() {
        let Some(mut stream) = stream else { continue };
        let tx = tx.clone();
        open += 1;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let chunk = match stream.read(&mut buf) {
                    Ok(0) | Err(_) => None,
                    Ok(n) => Some(buf.get(..n).unwrap_or_default().to_vec()),
                };
                let done = chunk.is_none();
                if tx.send((which, chunk)).is_err() || done {
                    break;
                }
            }
        });
    }
    drop(tx);
    let mut stdout = Captured::default();
    let mut stderr = Captured::default();
    let deadline = start + spec.timeout;
    let mut exit: Option<(std::process::ExitStatus, Instant)> = None;
    let mut timed_out = false;
    loop {
        if open == 0 && exit.is_some() {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((0, Some(chunk))) => stdout.push(&chunk, spec.capture_limit),
            Ok((_, Some(chunk))) => stderr.push(&chunk, spec.capture_limit),
            Ok((_, None)) => open = open.saturating_sub(1),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => open = 0,
        }
        if exit.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => exit = Some((status, Instant::now())),
                Ok(None) => {}
                Err(_) => break,
            }
        }
        if exit.is_none() && Instant::now() >= deadline {
            timed_out = true;
            job.terminate();
            match wait_bounded(&mut child, Duration::from_secs(5)) {
                Some(status) => exit = Some((status, Instant::now())),
                None => break,
            }
        }
        if let Some((_, at)) = exit {
            if at.elapsed() >= DRAIN_AFTER_EXIT && open > 0 {
                // Something left in the job still holds the pipes open.
                job.terminate();
                break;
            }
        }
    }
    job.terminate();
    let termination = if timed_out {
        Termination::TimedOut
    } else {
        let status = exit
            .map(|(status, _)| status)
            .or_else(|| wait_bounded(&mut child, Duration::from_secs(1)));
        status
            .and_then(|s| s.code())
            .map_or(Termination::Indeterminate, |code| Termination::Exited {
                code,
            })
    };
    ProcessResult {
        termination,
        stdout,
        stderr,
        duration: start.elapsed(),
    }
}

/// Run `spec` to completion, time limit or interruption.
// The read loop is one state machine; splitting it would separate the invariants it keeps.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub(crate) fn run(spec: &Spawn<'_>) -> ProcessResult {
    let start = Instant::now();
    let Ok(mut child) = command(spec).spawn() else {
        return spawn_failed(start);
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn cmd(script: &str, timeout: Duration, limit: usize) -> ProcessResult {
        let path = crate::environment::trusted_path(None, Path::new(r"C:\nonexistent-project"));
        let program = crate::validation::resolve("cmd", Path::new(r"C:\"), &path).unwrap();
        let args = vec!["/d".to_owned(), "/c".to_owned(), script.to_owned()];
        let env = vec![("SystemRoot".to_owned(), r"C:\Windows".to_owned())];
        run(&Spawn {
            program: &program.path,
            arg0: "cmd",
            args: &args,
            cwd: Path::new(r"C:\"),
            env: &env,
            timeout,
            capture_limit: limit,
            signals: None,
        })
    }

    #[test]
    fn exit_codes_and_streams() {
        let r = cmd(
            "echo out& echo err 1>&2& exit /b 3",
            Duration::from_secs(10),
            1024,
        );
        assert_eq!(r.termination, Termination::Exited { code: 3 });
        assert_eq!(String::from_utf8_lossy(&r.stdout.bytes).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&r.stderr.bytes).trim(), "err");
    }

    #[test]
    fn timeouts_terminate_the_whole_job() {
        let r = cmd(
            "ping -n 30 127.0.0.1 >nul & echo never",
            Duration::from_millis(500),
            1024,
        );
        assert_eq!(r.termination, Termination::TimedOut);
        assert!(r.duration < Duration::from_secs(10), "{:?}", r.duration);
        assert!(!String::from_utf8_lossy(&r.stdout.bytes).contains("never"));
    }

    #[test]
    fn leftover_background_processes_do_not_hold_the_run_open() {
        let r = cmd(
            "start /b ping -n 30 127.0.0.1 & echo started",
            Duration::from_secs(20),
            1024,
        );
        assert_eq!(r.termination, Termination::Exited { code: 0 });
        assert!(r.duration < Duration::from_secs(10), "{:?}", r.duration);
    }

    #[test]
    fn environment_is_exactly_the_given_one() {
        let r = cmd("set", Duration::from_secs(10), 8192);
        let text = String::from_utf8_lossy(&r.stdout.bytes).into_owned();
        assert!(text.contains(r"SystemRoot=C:\Windows"), "{text}");
        assert!(
            !text.to_ascii_uppercase().contains("USERPROFILE="),
            "{text}"
        );
    }
}

#[cfg(all(test, unix))]
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
