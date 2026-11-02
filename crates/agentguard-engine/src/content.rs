//! Content evidence for a decision: detected secrets in what an operation would read, move,
//! write, send or commit.
//!
//! | operation | content inspected |
//! |---|---|
//! | read, copy, rename, archive, upload of a file | the source file (first 1 MiB) |
//! | the same on a directory | a bounded scan of the tree (500 files, 16 MiB) |
//! | write, append | the inline `content`, when the integration supplies it |
//! | terminal command | the command text |
//! | `git commit` (typed or terminal) | staged changes, through `.git/index` |
//!
//! Inspection is bounded and read-only. Anything it could not inspect (a truncated file, an
//! incomplete tree scan, staged content that differs from the working tree) makes the
//! evaluation uncertain; it is never treated as clean. Only counts and severities leave this
//! module.

use agentguard_core::action::{FileOp, GitOp};
use agentguard_core::{Action, NormalizedPath};
use agentguard_secrets::git_index::staged;
use agentguard_secrets::{
    inspect_file, inspect_text, scan, scan_files, DetectorSet, Evidence, ScanOptions,
};

use crate::normalize::CommandAnalysis;
use crate::resource::{kind_of_relative_text, ResourceKind};

/// Limits for directory and staged scans made during a decision.
fn decision_scan_options() -> ScanOptions {
    ScanOptions {
        max_files: 500,
        max_total_bytes: 16 * 1024 * 1024,
        max_file_bytes: 1024 * 1024,
        max_findings: 50,
        list_limit: 0,
        ..ScanOptions::default()
    }
}

/// What content inspection found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentEvidence {
    /// Detected secrets.
    pub evidence: Evidence,
    /// Something relevant could not be fully inspected.
    pub incomplete: bool,
    /// A directory involved contains a sensitive file by name (`.env`, keys, credentials).
    pub sensitive_file_in_tree: bool,
}

fn from_report(report: &agentguard_secrets::ScanReport) -> Evidence {
    let mut evidence = Evidence::default();
    for f in &report.findings {
        evidence.count += 1;
        evidence.max_severity = evidence.max_severity.max(Some(f.severity));
        evidence.private_key |= f.category == agentguard_secrets::SecretCategory::PrivateKey;
    }
    evidence
}

fn tree_has_sensitive_name(root: &std::path::Path) -> bool {
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 5000 {
                return false;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if meta.is_dir() {
                if !agentguard_secrets::scan::DEFAULT_EXCLUDED_DIRS.contains(&name.as_str()) {
                    stack.push(entry.path());
                }
            } else if kind_of_relative_text(&name).is_secret() {
                return true;
            }
        }
    }
    false
}

fn inspect_source(
    path: &NormalizedPath,
    kind: ResourceKind,
    detectors: &DetectorSet,
) -> ContentEvidence {
    let p = path.as_path();
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let report = scan(p, None, &decision_scan_options(), detectors);
            match report {
                Ok(r) => ContentEvidence {
                    evidence: from_report(&r),
                    incomplete: !r.complete,
                    sensitive_file_in_tree: tree_has_sensitive_name(p),
                },
                Err(_) => ContentEvidence {
                    incomplete: true,
                    ..ContentEvidence::default()
                },
            }
        }
        // Sensitive resources are already sensitive by name; their content is not read.
        Ok(m) if m.is_file() && !kind.is_secret() => {
            let i = inspect_file(p, detectors);
            ContentEvidence {
                evidence: i.evidence,
                incomplete: !i.inspected || i.truncated,
                sensitive_file_in_tree: false,
            }
        }
        _ => ContentEvidence::default(),
    }
}

fn inspect_staged(root: &NormalizedPath, detectors: &DetectorSet) -> ContentEvidence {
    match staged(root.as_path()) {
        Ok(s) => match scan_files(
            root.as_path(),
            &s.verified,
            &s.unverified,
            &decision_scan_options(),
            detectors,
        ) {
            Ok(r) => ContentEvidence {
                evidence: from_report(&r),
                incomplete: !r.complete,
                sensitive_file_in_tree: false,
            },
            Err(_) => ContentEvidence {
                incomplete: true,
                ..ContentEvidence::default()
            },
        },
        // No repository at the project root, a worktree, or an unreadable index: nothing staged
        // that AgentGuard can see, so the decision is uncertain rather than clean.
        Err(_) => ContentEvidence {
            incomplete: true,
            ..ContentEvidence::default()
        },
    }
}

/// Gather content evidence for `action`.
#[must_use]
pub fn gather(
    action: &Action,
    command: Option<&CommandAnalysis>,
    project_root: &NormalizedPath,
    source_kind: ResourceKind,
    detectors: &DetectorSet,
) -> ContentEvidence {
    match action {
        Action::Filesystem(a) => match a.op {
            FileOp::Write | FileOp::Append => {
                a.content
                    .as_ref()
                    .map_or_else(ContentEvidence::default, |c| ContentEvidence {
                        evidence: inspect_text(c.as_str(), detectors).evidence,
                        ..ContentEvidence::default()
                    })
            }
            FileOp::Read | FileOp::Copy | FileOp::Rename | FileOp::Archive | FileOp::Upload => {
                inspect_source(&a.path, source_kind, detectors)
            }
            _ => ContentEvidence::default(),
        },
        Action::Terminal(t) => {
            let mut e = ContentEvidence {
                evidence: inspect_text(t.command.as_str(), detectors).evidence,
                ..ContentEvidence::default()
            };
            let commit = command.is_some_and(|c| {
                c.executable.as_deref() == Some("git") && c.subcommand.as_deref() == Some("commit")
            });
            if commit {
                let s = inspect_staged(project_root, detectors);
                e.evidence.merge(&s.evidence);
                e.incomplete |= s.incomplete;
            }
            e
        }
        Action::Git(g) if g.op == GitOp::Commit => inspect_staged(project_root, detectors),
        _ => ContentEvidence::default(),
    }
}
