//! Bounded, local scanning of a directory tree or a list of files.
//!
//! - Symlinks are never followed (reported as skipped), so a scan cannot leave its root.
//! - Files are opened with `O_NOFOLLOW | O_NONBLOCK` and re-checked as regular files after
//!   opening, so a file swapped for a symlink or FIFO between listing and opening is skipped.
//! - Reads are streamed; one line is held at a time, at most `max_line_bytes` (longer lines are
//!   scanned in segments). Memory does not grow with file size.
//! - Every file that is excluded, skipped (too large, binary, symlink, limit) or unreadable is
//!   reported. An excluded or skipped file is never reported as clean.
//! - Nothing is uploaded and no process is run; the crate has no network code.

use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};

use regex::Regex;
use serde::Serialize;

use crate::detectors::DetectorSet;
use crate::finding::{finding_id, Finding};
use crate::inspect::{looks_binary, open_regular};
use crate::model::SecretCategory;
use crate::redact::{redacted_value, PRIVATE_KEY_MASK};

/// Directories excluded by default: dependencies, build output, caches, version control.
pub const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    "coverage",
    ".tox",
    ".gradle",
    ".terraform",
    ".cache",
];

/// Limits and exclusions.
#[derive(Debug, Clone, Serialize)]
pub struct ScanOptions {
    /// Files larger than this are skipped and reported.
    pub max_file_bytes: u64,
    /// At most this many files are scanned.
    pub max_files: u64,
    /// At most this many bytes are scanned in total.
    pub max_total_bytes: u64,
    /// At most this many findings are recorded.
    pub max_findings: usize,
    /// Lines longer than this are scanned in segments.
    pub max_line_bytes: usize,
    /// Whether [`DEFAULT_EXCLUDED_DIRS`] apply.
    pub default_exclusions: bool,
    /// Extra exclusions: glob patterns on root-relative paths (`docs/**`, `*.min.js`).
    pub exclude: Vec<String>,
    /// At most this many excluded or skipped paths are listed (all are counted).
    pub list_limit: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 2 * 1024 * 1024,
            max_files: 20_000,
            max_total_bytes: 256 * 1024 * 1024,
            max_findings: 1000,
            max_line_bytes: 64 * 1024,
            default_exclusions: true,
            exclude: Vec::new(),
            list_limit: 200,
        }
    }
}

/// Why a file was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// A symlink (never followed).
    Symlink,
    /// Larger than `max_file_bytes`.
    TooLarge,
    /// Looks binary.
    Binary,
    /// Not a regular file (FIFO, socket, device).
    NotRegularFile,
    /// Could not be opened or read.
    Unreadable,
    /// The file or byte limit was reached.
    LimitReached,
    /// Staged content differs from the working tree, so the staged version could not be read.
    StagedContentUnverified,
}

/// An excluded path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Excluded {
    /// Root-relative path.
    pub path: String,
    /// The rule that excluded it.
    pub rule: String,
}

/// A skipped path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// Root-relative path.
    pub path: String,
    /// Why.
    pub reason: SkipReason,
}

/// The result of a scan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanReport {
    /// Findings, in path and line order.
    pub findings: Vec<Finding>,
    /// Whether findings beyond `max_findings` were dropped.
    pub findings_truncated: bool,
    /// Files scanned.
    pub files_scanned: u64,
    /// Bytes scanned.
    pub bytes_scanned: u64,
    /// Excluded paths (up to `list_limit`).
    pub excluded: Vec<Excluded>,
    /// Number of excluded paths.
    pub excluded_total: u64,
    /// Skipped paths (up to `list_limit`).
    pub skipped: Vec<Skipped>,
    /// Number of skipped paths.
    pub skipped_total: u64,
    /// Whether every included file was scanned: nothing skipped, no limit hit, no findings
    /// dropped. Exclusions do not make a scan incomplete, but excluded files are listed and
    /// never reported as clean.
    pub complete: bool,
}

/// Why a scan could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// The root is not a readable directory.
    #[error("the scan root is not a readable directory")]
    Root,
    /// A requested path is absolute, contains `..`, or leaves the root through a symlink.
    #[error("the path {0} is outside the scan boundary")]
    OutsideBoundary(String),
    /// An exclusion pattern is invalid.
    #[error("invalid exclusion pattern")]
    InvalidExclusion,
}

/// Convert a path glob to an anchored regex: `**` crosses directories, `*` and `?` do not.
pub fn glob_regex(glob: &str) -> Result<Regex, ScanError> {
    if glob.is_empty() || glob.len() > 256 {
        return Err(ScanError::InvalidExclusion);
    }
    let mut re = String::from("^");
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    re.push_str("(?:.*/)?");
                } else {
                    re.push_str(".*");
                }
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            other => re.push_str(&regex::escape(&other.to_string())),
        }
    }
    re.push('$');
    Regex::new(&re).map_err(|_| ScanError::InvalidExclusion)
}

struct Scanner<'a> {
    root: PathBuf,
    options: &'a ScanOptions,
    set: &'a DetectorSet,
    exclude: Vec<(String, Regex)>,
    report: ScanReport,
    limited: bool,
}

fn relative(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

impl Scanner<'_> {
    fn exclude(&mut self, path: &str, rule: &str) {
        self.report.excluded_total += 1;
        if self.report.excluded.len() < self.options.list_limit {
            self.report.excluded.push(Excluded {
                path: path.to_owned(),
                rule: rule.to_owned(),
            });
        }
    }

    fn skip(&mut self, path: &str, reason: SkipReason) {
        self.report.skipped_total += 1;
        if self.report.skipped.len() < self.options.list_limit {
            self.report.skipped.push(Skipped {
                path: path.to_owned(),
                reason,
            });
        }
    }

    fn exclusion_for(&self, rel: &str, name: &str, is_dir: bool) -> Option<String> {
        if is_dir && self.options.default_exclusions && DEFAULT_EXCLUDED_DIRS.contains(&name) {
            return Some(format!("default:{name}"));
        }
        // Like .gitignore: a pattern without `/` matches the name at any depth.
        self.exclude
            .iter()
            .find(|(glob, re)| {
                re.is_match(rel)
                    || (is_dir && re.is_match(&format!("{rel}/")))
                    || (!glob.contains('/') && re.is_match(name))
            })
            .map(|(glob, _)| glob.clone())
    }

    fn walk(&mut self, start: PathBuf) {
        let mut queue: VecDeque<PathBuf> = VecDeque::from([start]);
        while let Some(dir) = queue.pop_front() {
            let Ok(entries) = fs::read_dir(self.root.join(&dir)) else {
                self.skip(&relative(&dir), SkipReason::Unreadable);
                continue;
            };
            let mut names: Vec<_> = entries
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect();
            names.sort();
            for name in names {
                let rel = dir.join(&name);
                let rel_text = relative(&rel);
                let name_text = name.to_string_lossy();
                let Ok(meta) = fs::symlink_metadata(self.root.join(&rel)) else {
                    self.skip(&rel_text, SkipReason::Unreadable);
                    continue;
                };
                let kind = meta.file_type();
                if kind.is_symlink() {
                    self.skip(&rel_text, SkipReason::Symlink);
                } else if kind.is_dir() {
                    match self.exclusion_for(&rel_text, &name_text, true) {
                        Some(rule) => self.exclude(&rel_text, &rule),
                        None => queue.push_back(rel),
                    }
                } else if !kind.is_file() {
                    self.skip(&rel_text, SkipReason::NotRegularFile);
                } else if let Some(rule) = self.exclusion_for(&rel_text, &name_text, false) {
                    self.exclude(&rel_text, &rule);
                } else {
                    self.scan_file(&rel);
                }
            }
        }
    }

    fn scan_file(&mut self, rel: &Path) {
        let rel_text = relative(rel);
        if self.limited || self.report.files_scanned >= self.options.max_files {
            self.limited = true;
            self.skip(&rel_text, SkipReason::LimitReached);
            return;
        }
        let file = match open_regular(&self.root.join(rel)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                self.skip(&rel_text, SkipReason::NotRegularFile);
                return;
            }
            Err(e) if e.raw_os_error() == Some(nix::libc::ELOOP) => {
                self.skip(&rel_text, SkipReason::Symlink);
                return;
            }
            Err(_) => {
                self.skip(&rel_text, SkipReason::Unreadable);
                return;
            }
        };
        let len = file.metadata().map_or(u64::MAX, |m| m.len());
        if len > self.options.max_file_bytes {
            self.skip(&rel_text, SkipReason::TooLarge);
            return;
        }
        if self.report.bytes_scanned.saturating_add(len) > self.options.max_total_bytes {
            self.limited = true;
            self.skip(&rel_text, SkipReason::LimitReached);
            return;
        }
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        match reader.fill_buf() {
            Ok(head) if looks_binary(head) => {
                self.skip(&rel_text, SkipReason::Binary);
                return;
            }
            Ok(_) => {}
            Err(_) => {
                self.skip(&rel_text, SkipReason::Unreadable);
                return;
            }
        }
        if self.stream(&mut reader, &rel_text).is_err() {
            self.skip(&rel_text, SkipReason::Unreadable);
            return;
        }
        self.report.files_scanned += 1;
        self.report.bytes_scanned += len;
    }

    /// Stream lines (bounded) through the detectors.
    fn stream(&mut self, reader: &mut impl BufRead, path: &str) -> std::io::Result<()> {
        let max = self.options.max_line_bytes.max(1024);
        let mut line: Vec<u8> = Vec::with_capacity(4096);
        let mut line_no: u64 = 1;
        let mut column_offset: u64 = 0;
        let mut in_key = false;
        loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if !line.is_empty() {
                    self.scan_segment(&line, path, line_no, column_offset, &mut in_key);
                }
                return Ok(());
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let wanted = newline.map_or(available.len(), |i| i + 1);
            let take = wanted.min(max - line.len());
            line.extend_from_slice(available.get(..take).unwrap_or(&[]));
            reader.consume(take);
            let ended = newline.is_some_and(|i| take == i + 1);
            if ended || line.len() >= max {
                self.scan_segment(&line, path, line_no, column_offset, &mut in_key);
                if ended {
                    line_no += 1;
                    column_offset = 0;
                } else {
                    column_offset += line.len() as u64;
                }
                line.clear();
            }
        }
    }

    fn scan_segment(
        &mut self,
        bytes: &[u8],
        path: &str,
        line_no: u64,
        column_offset: u64,
        in_key: &mut bool,
    ) {
        let text = String::from_utf8_lossy(bytes);
        let text = text.trim_end_matches(['\n', '\r']);
        if *in_key {
            *in_key = !(text.contains("-----END") && text.contains("PRIVATE KEY"));
            return;
        }
        for m in self.set.detect_line(text) {
            if m.category == SecretCategory::PrivateKey && !text.contains("-----END") {
                *in_key = true;
            }
            if self.report.findings.len() >= self.options.max_findings {
                self.report.findings_truncated = true;
                return;
            }
            // The value is sliced only to compute the redacted preview and dropped here.
            let preview = if m.category == SecretCategory::PrivateKey {
                PRIVATE_KEY_MASK.to_owned()
            } else {
                redacted_value(text.get(m.start..m.end).unwrap_or(""), m.public_prefix)
            };
            let column = column_offset + m.start as u64 + 1;
            self.report.findings.push(Finding {
                id: finding_id(path, line_no, column, &m.detector),
                detector: m.detector,
                category: m.category,
                severity: m.severity,
                path: path.to_owned(),
                line: line_no,
                column,
                preview,
            });
        }
    }
}

/// Check that `rel` is a relative path inside `root` that does not pass through a symlink.
pub fn resolve_within(root: &Path, rel: &str) -> Result<PathBuf, ScanError> {
    let outside = || ScanError::OutsideBoundary(rel.to_owned());
    let path = Path::new(rel);
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(outside());
    }
    let clean: PathBuf = path
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .collect();
    let mut at = root.to_path_buf();
    let parts: Vec<_> = clean.components().collect();
    for (i, part) in parts.iter().enumerate() {
        at.push(part);
        let last = i + 1 == parts.len();
        match fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() => return Err(outside()),
            Ok(m) if !last && !m.is_dir() => return Err(outside()),
            Ok(_) => {}
            Err(_) if last => {}
            Err(_) => return Err(outside()),
        }
    }
    Ok(clean)
}

fn scanner<'a>(
    root: &Path,
    options: &'a ScanOptions,
    set: &'a DetectorSet,
) -> Result<Scanner<'a>, ScanError> {
    let root = fs::canonicalize(root).map_err(|_| ScanError::Root)?;
    if !root.is_dir() {
        return Err(ScanError::Root);
    }
    let exclude = options
        .exclude
        .iter()
        .map(|g| glob_regex(g).map(|re| (g.clone(), re)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Scanner {
        root,
        options,
        set,
        exclude,
        report: ScanReport::default(),
        limited: false,
    })
}

fn finish(mut s: Scanner<'_>) -> ScanReport {
    s.report
        .findings
        .sort_by(|a, b| (&a.path, a.line, a.column).cmp(&(&b.path, b.line, b.column)));
    s.report.complete = s.report.skipped_total == 0 && !s.limited && !s.report.findings_truncated;
    s.report
}

/// Scan the tree under `root`, or only `paths` (root-relative files or directories).
pub fn scan(
    root: &Path,
    paths: Option<&[String]>,
    options: &ScanOptions,
    set: &DetectorSet,
) -> Result<ScanReport, ScanError> {
    let mut s = scanner(root, options, set)?;
    match paths {
        None => s.walk(PathBuf::new()),
        Some(paths) => {
            let mut resolved = Vec::new();
            for rel in paths {
                resolved.push(resolve_within(&s.root, rel)?);
            }
            for rel in resolved {
                let text = relative(&rel);
                let full = s.root.join(&rel);
                match fs::symlink_metadata(&full) {
                    Ok(m) if m.is_dir() => s.walk(rel),
                    Ok(m) if m.is_file() => match s.exclusion_for(
                        &text,
                        &rel.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        false,
                    ) {
                        Some(rule) => s.exclude(&text, &rule),
                        None => s.scan_file(&rel),
                    },
                    Ok(_) => s.skip(&text, SkipReason::NotRegularFile),
                    Err(_) => s.skip(&text, SkipReason::Unreadable),
                }
            }
        }
    }
    Ok(finish(s))
}

/// Scan specific root-relative files, recording others as skipped with a given reason (used
/// for staged files whose staged content could not be verified).
pub fn scan_files(
    root: &Path,
    files: &[String],
    unverified: &[String],
    options: &ScanOptions,
    set: &DetectorSet,
) -> Result<ScanReport, ScanError> {
    let mut s = scanner(root, options, set)?;
    for rel in files {
        let clean = resolve_within(&s.root, rel)?;
        let text = relative(&clean);
        let name = clean
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match s.exclusion_for(&text, &name, false) {
            Some(rule) => s.exclude(&text, &rule),
            None => s.scan_file(&clean),
        }
    }
    for rel in unverified {
        s.skip(rel, SkipReason::StagedContentUnverified);
    }
    Ok(finish(s))
}
