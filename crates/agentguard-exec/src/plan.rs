//! Planning: from a validated request to exactly what would run, what policy evaluates, and
//! the state an approval is bound to. Nothing runs here except read-only Git inspection.

use std::path::Path;

use agentguard_engine::normalize::quote_argv;
use agentguard_engine::{analyze_command, CommandAnalysis, ExecutionBinding};
use agentguard_secrets::{DetectorSet, Evidence};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::command::{categorize, TerminalCategory};
use crate::environment::BuiltEnvironment;
use crate::git::{self, GitCommand, GitContext, GitKind, Plumbing, PushContext, ScanResult};
use crate::request::{CommandSpec, ShellKind};
use crate::shell;
use crate::validation::{resolve, ResolveError, ResolvedExecutable};

/// Longest command text policy can evaluate (the protocol's terminal command bound).
const MAX_POLICY_TEXT: usize = 8192;

/// Why a request is refused before policy is consulted. Nothing runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Stable reason code.
    pub code: &'static str,
    /// Why, for the caller.
    pub reason: String,
}

fn refuse(code: &'static str, reason: impl Into<String>) -> Refusal {
    Refusal {
        code,
        reason: reason.into(),
    }
}

impl From<ResolveError> for Refusal {
    fn from(e: ResolveError) -> Self {
        let code = match e {
            ResolveError::NotFound => "execution.not-found",
            ResolveError::NotExecutable => "execution.not-executable",
            ResolveError::Refused => "execution.refused-program",
            ResolveError::SetId => "execution.set-id-program",
        };
        refuse(code, e.to_string())
    }
}

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// An argument vector, no shell.
    Managed,
    /// A script in the supported subset, run by this interpreter.
    Shell(ShellKind),
}

impl Mode {
    /// Name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::Managed => "managed",
            Mode::Shell(ShellKind::Sh) => "shell:sh",
            Mode::Shell(ShellKind::Bash) => "shell:bash",
        }
    }
}

/// The Git part of a plan.
#[derive(Debug, Clone)]
pub struct GitPlan {
    /// The parsed command.
    pub command: GitCommand,
    /// Inspection runner.
    pub plumbing: Plumbing,
    /// Repository state now (`None` outside a repository; only read-only commands then).
    pub context: Option<GitContext>,
    /// What a push would send.
    pub push: Option<PushContext>,
    /// Refs the command names, resolved.
    pub refs: Vec<(String, String)>,
    /// Pre-execution secret scan (commits and pushes).
    pub scan: Option<ScanResult>,
}

/// Exactly what would run.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Mode.
    pub mode: Mode,
    /// The program executed (the interpreter in shell mode).
    pub program: ResolvedExecutable,
    /// `argv[0]` given to the process.
    pub arg0: String,
    /// Arguments after `argv[0]`.
    pub args: Vec<String>,
    /// Every program a shell script runs, resolved (empty in managed mode).
    pub script_programs: Vec<ResolvedExecutable>,
    /// The text policy evaluates (and, in shell mode, the script executed).
    pub policy_text: String,
    /// The engine's analysis of it.
    pub analysis: CommandAnalysis,
    /// Display category.
    pub category: TerminalCategory,
    /// Git handling.
    pub git: Option<GitPlan>,
}

/// Whether `exe` is Git itself: named `git` and installed outside the project in a trusted
/// directory, however it was named on the command line (`git`, `/usr/bin/git`, a symlink).
fn is_git(exe: &ResolvedExecutable, project_root: &Path) -> bool {
    exe.basename() == "git"
        && (!exe.explicit_path
            || exe
                .path
                .parent()
                .is_some_and(|d| crate::environment::is_trusted_dir(d, project_root)))
}

fn plan_git(
    argv: &[String],
    program: &ResolvedExecutable,
    cwd: &Path,
    project_root: &Path,
    env: &BuiltEnvironment,
    detectors: &DetectorSet,
) -> Result<GitPlan, Refusal> {
    let command =
        git::parse(argv).map_err(|e| refuse("execution.unsupported-git", e.to_string()))?;
    let home = env
        .vars
        .iter()
        .find(|(k, _)| k == "HOME")
        .map(|(_, v)| v.as_str());
    let plumbing = Plumbing::new(&program.path, cwd, &env.path, home);
    let context = GitContext::inspect(&plumbing, project_root, false);
    if command.kind != GitKind::ReadOnly {
        let Some(ctx) = &context else {
            return Err(refuse(
                "execution.not-a-repository",
                "this Git operation needs a repository, and the working directory is not inside one",
            ));
        };
        if !ctx.inside_project {
            return Err(refuse(
                "execution.repository-outside-project",
                "the repository's working tree or Git directory lies outside the registered project, so its changes cannot be bound to this project",
            ));
        }
    }
    let mut push = None;
    let mut scan = None;
    if let (Some(spec), Some(ctx)) = (&command.push, &context) {
        if ctx.remote(&spec.remote).is_none() {
            return Err(refuse(
                "execution.unknown-remote",
                format!(
                    "`{}` is not a configured remote of this repository",
                    spec.remote
                ),
            ));
        }
        let observed = git::push_context(&plumbing, spec);
        if spec.src.is_some() && observed.source_commit.is_none() {
            return Err(refuse(
                "execution.unknown-ref",
                "the branch to push does not resolve to a commit",
            ));
        }
        scan = Some(git::scan_push(&plumbing, spec, &observed, detectors));
        push = Some(observed);
    }
    if command.kind == GitKind::Commit {
        scan = Some(git::scan_staged(&plumbing, detectors));
    }
    let refs = if command.kind == GitKind::ReadOnly {
        Vec::new()
    } else {
        git::resolve_refs(&plumbing, &command.positionals)
    };
    Ok(GitPlan {
        command,
        plumbing,
        context,
        push,
        refs,
        scan,
    })
}

/// Build the plan for `spec` in `cwd`.
pub fn plan(
    spec: &CommandSpec,
    cwd: &Path,
    project_root: &Path,
    env: &BuiltEnvironment,
    detectors: &DetectorSet,
) -> Result<Plan, Refusal> {
    match spec {
        CommandSpec::Argv(argv) => {
            let requested = argv.first().map(String::as_str).unwrap_or_default();
            let program = resolve(requested, cwd, &env.path)?;
            let policy_text = quote_argv(argv);
            if policy_text.len() > MAX_POLICY_TEXT {
                return Err(refuse(
                    "execution.too-long",
                    "the command is longer than 8192 characters",
                ));
            }
            let git = if is_git(&program, project_root) {
                Some(plan_git(argv, &program, cwd, project_root, env, detectors)?)
            } else {
                None
            };
            let analysis = analyze_command(&policy_text);
            let category = categorize(&analysis, argv);
            Ok(Plan {
                mode: Mode::Managed,
                arg0: requested.to_owned(),
                args: argv.iter().skip(1).cloned().collect(),
                program,
                script_programs: Vec::new(),
                policy_text,
                analysis,
                category,
                git,
            })
        }
        CommandSpec::Shell {
            interpreter,
            script,
        } => {
            let parsed = shell::parse(script)
                .map_err(|e| refuse("execution.unsupported-shell-syntax", e.to_string()))?;
            let mut script_programs = Vec::new();
            for c in &parsed.commands {
                let name = c.argv.first().map(String::as_str).unwrap_or_default();
                let exe = resolve(name, cwd, &env.path)?;
                if is_git(&exe, project_root) {
                    let kind = git::parse(&c.argv)
                        .map_err(|e| refuse("execution.unsupported-git", e.to_string()))?
                        .kind;
                    if kind != GitKind::ReadOnly {
                        return Err(refuse(
                            "execution.git-change-in-shell",
                            "run Git changes in managed mode (without --shell) so the repository state can be bound to the approval",
                        ));
                    }
                }
                script_programs.push(exe);
            }
            let policy_text = parsed.render();
            if policy_text.len() > MAX_POLICY_TEXT {
                return Err(refuse(
                    "execution.too-long",
                    "the script is longer than 8192 characters",
                ));
            }
            let program = resolve(interpreter.program(), cwd, &env.path)?;
            let mut args = Vec::new();
            if *interpreter == ShellKind::Bash {
                args.extend(["--noprofile".to_owned(), "--norc".to_owned()]);
            }
            args.extend(["-c".to_owned(), policy_text.clone()]);
            let analysis = analyze_command(&policy_text);
            let first: Vec<String> = parsed
                .commands
                .first()
                .map(|c| c.argv.clone())
                .unwrap_or_default();
            let category = categorize(&analysis, &first);
            Ok(Plan {
                mode: Mode::Shell(*interpreter),
                arg0: interpreter.program().to_owned(),
                args,
                program,
                script_programs,
                policy_text,
                analysis,
                category,
                git: None,
            })
        }
    }
}

/// Repository facts an approval is bound to, observed now.
#[must_use]
pub fn git_facts(g: &GitPlan, project_root: &Path) -> Vec<(String, String)> {
    let mut facts = Vec::new();
    if g.command.kind == GitKind::ReadOnly {
        return facts;
    }
    let ctx = GitContext::inspect(&g.plumbing, project_root, false);
    let dash = || "-".to_owned();
    if let Some(c) = &ctx {
        facts.push(("git.repository".to_owned(), c.repository_id.clone()));
        facts.push(("git.head".to_owned(), c.head.clone().unwrap_or_else(dash)));
        facts.push((
            "git.branch".to_owned(),
            c.branch.clone().unwrap_or_else(dash),
        ));
        facts.push((
            "git.staged-tree".to_owned(),
            c.staged_tree
                .clone()
                .unwrap_or_else(|| "unmerged".to_owned()),
        ));
        if let Some(spec) = &g.command.push {
            let push = git::push_context(&g.plumbing, spec);
            facts.push(("git.push.remote".to_owned(), spec.remote.clone()));
            facts.push((
                "git.push.remote-url".to_owned(),
                c.remote(&spec.remote)
                    .map_or_else(dash, |r| r.identity.clone()),
            ));
            facts.push((
                "git.push.source".to_owned(),
                push.source_commit.unwrap_or_else(dash),
            ));
            facts.push(("git.push.destination".to_owned(), spec.dst.clone()));
            facts.push((
                "git.push.remote-tracking".to_owned(),
                push.remote_tracking.unwrap_or_else(dash),
            ));
            facts.push((
                "git.push.range".to_owned(),
                git::range_digest(&push.commits),
            ));
        }
    }
    for (arg, commit) in git::resolve_refs(&g.plumbing, &g.command.positionals) {
        facts.push((format!("git.ref.{arg}"), commit));
    }
    facts
}

fn argv_digest(plan: &Plan) -> String {
    let all: Vec<&str> = std::iter::once(plan.arg0.as_str())
        .chain(plan.args.iter().map(String::as_str))
        .collect();
    hex::encode(Sha256::digest(serde_json::to_vec(&all).unwrap_or_default()))
}

/// The execution binding: program identities, exact arguments, environment, time limit and
/// repository facts.
pub fn binding(
    plan: &Plan,
    env: &BuiltEnvironment,
    timeout_seconds: u64,
    git_facts: &[(String, String)],
) -> Result<ExecutionBinding, agentguard_engine::binding::BindingError> {
    let mut b = ExecutionBinding::new();
    b.insert("exec.mode", plan.mode.as_str())?;
    b.insert("exec.program", plan.program.path.to_string_lossy())?;
    b.insert("exec.program.identity", plan.program.identity.digest())?;
    b.insert("exec.argv", argv_digest(plan))?;
    b.insert(
        "exec.environment",
        format!(
            "{}:{}",
            env.profile.as_str(),
            hex::encode(Sha256::digest(env.passed.join("\n").as_bytes()))
        ),
    )?;
    b.insert("exec.timeout-seconds", timeout_seconds.to_string())?;
    for (i, p) in plan.script_programs.iter().enumerate() {
        b.insert(&format!("shell.{i}.program"), p.path.to_string_lossy())?;
        b.insert(&format!("shell.{i}.identity"), p.identity.digest())?;
    }
    for (k, v) in git_facts {
        b.insert(k, v.clone())?;
    }
    Ok(b)
}

/// Evidence from pre-execution scans.
#[must_use]
pub fn scan_evidence(plan: &Plan) -> Option<(Evidence, bool)> {
    plan.git
        .as_ref()
        .and_then(|g| g.scan)
        .map(|s| (s.evidence, s.incomplete))
}

/// A display view of the plan (redacted by the caller before it leaves the engine).
#[must_use]
pub fn view(plan: &Plan, env: &BuiltEnvironment, project_root: &Path) -> Value {
    let rel = |p: &Path| {
        p.strip_prefix(project_root)
            .map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
    };
    let git = plan.git.as_ref().map(|g| {
        let ctx = g.context.as_ref();
        json!({
            "subcommand": g.command.subcommand,
            "kind": g.command.kind,
            "repository": ctx.map(|c| json!({
                "id": c.repository_id,
                "root": rel(&c.root),
                "branch": c.branch,
                "head": c.head,
                "staged_tree": c.staged_tree,
                "staged": c.staged,
                "staged_total": c.staged_total,
                "hooks": c.hooks,
            })),
            "push": g.command.push.as_ref().map(|spec| json!({
                "remote": spec.remote,
                "remote_url": ctx.and_then(|c| c.remote(&spec.remote)).map(|r| r.url.clone()),
                "source": spec.src,
                "destination": spec.dst,
                "forced": spec.forced,
                "delete": spec.delete,
                "dry_run": spec.dry_run,
                "source_commit": g.push.as_ref().and_then(|p| p.source_commit.clone()),
                "remote_tracking": g.push.as_ref().and_then(|p| p.remote_tracking.clone()),
                "commits": g.push.as_ref().map(|p| p.commits.len()),
                "commits_truncated": g.push.as_ref().is_some_and(|p| p.commits_truncated),
            })),
            "refs": g.refs.iter().map(|(a, c)| json!({"name": a, "commit": c})).collect::<Vec<_>>(),
            "secret_scan": g.scan,
        })
    });
    json!({
        "mode": plan.mode.as_str(),
        "command": plan.policy_text,
        "category": plan.category,
        "class": plan.analysis.class,
        "confidence": plan.analysis.confidence,
        "executable": {
            "requested": plan.program.requested,
            "path": plan.program.path,
            "explicit_path": plan.program.explicit_path,
            "sha256": plan.program.identity.sha256,
        },
        "script_programs": plan.script_programs.iter().map(|p| p.path.clone()).collect::<Vec<_>>(),
        "environment": {
            "profile": env.profile,
            "passed": env.passed,
            "withheld": env.withheld,
        },
        "git": git,
    })
}
