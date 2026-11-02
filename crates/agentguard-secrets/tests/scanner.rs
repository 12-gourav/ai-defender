//! Scanner, redaction and staged-change tests against real temporary directories. Every
//! credential below is fake and nonfunctional.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    clippy::print_stderr,
    clippy::field_reassign_with_default,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::large_stack_arrays
)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use agentguard_secrets::detectors::BUILTIN;
use agentguard_secrets::git_index::staged;
use agentguard_secrets::{
    finding_id, redact, scan, scan_files, ScanError, ScanOptions, SkipReason,
};

const GITHUB: &str = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000";
const STRIPE: &str = "sk_live_FAKEfakeFAKEfake0000";
const PG_PASSWORD: &str = "Sup3rS3cretPw9";
const AWS: &str = "AKIAZZZZFAKEFAKE0001";
const KEY_BODY: &str = "MIIEFAKEFAKEFAKEFAKEFAKEKEYBODY";

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, "src/main.rs", "fn main() { println!(\"hello\"); }\n");
    write(
        r,
        ".env",
        &format!("DATABASE_URL=postgres://app:{PG_PASSWORD}@db:5432/app\nGITHUB_TOKEN={GITHUB}\n"),
    );
    write(
        r,
        "config/payments.yml",
        &format!("stripe:\n  key: {STRIPE}\n"),
    );
    write(r, "deploy/id_rsa", &format!("-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----\n"));
    write(r, "src/aws.py", &format!("AWS_KEY = \"{AWS}\"\n"));
    write(
        r,
        "node_modules/pkg/index.js",
        &format!("const t = '{GITHUB}';\n"),
    );
    write(
        r,
        "docs/readme.md",
        "Set API_KEY=your_api_key_here before running.\n",
    );
    dir
}

fn secrets() -> Vec<&'static str> {
    vec![&GITHUB[4..], &STRIPE[8..], PG_PASSWORD, &AWS[4..], KEY_BODY]
}

#[test]
fn finds_secrets_with_redacted_previews_only() {
    let p = project();
    let report = scan(p.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    let detectors: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.path.as_str(), f.detector.as_str()))
        .collect();
    for expected in [
        (".env", "connection-string-password"),
        (".env", "github-token"),
        ("config/payments.yml", "stripe-key"),
        ("deploy/id_rsa", "private-key"),
        ("src/aws.py", "aws-access-key-id"),
    ] {
        assert!(
            detectors.contains(&expected),
            "{expected:?} missing: {detectors:?}"
        );
    }
    assert!(
        !detectors.iter().any(|(p, _)| p.starts_with("docs/")),
        "placeholders are not findings"
    );
    let json = serde_json::to_string(&report).unwrap();
    for s in secrets() {
        assert!(!json.contains(s), "secret material in the report: {s}");
    }
    assert!(json.contains("ghp_****REDACTED") && json.contains("sk_live_****REDACTED"));
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.path == "deploy/id_rsa")
            .count(),
        1,
        "one finding per key block"
    );
}

#[test]
fn excluded_files_are_reported_as_excluded_never_clean() {
    let p = project();
    let mut options = ScanOptions::default();
    options.exclude = vec!["config/**".into(), "*.py".into()];
    let report = scan(p.path(), None, &options, &BUILTIN).unwrap();
    let excluded: Vec<_> = report
        .excluded
        .iter()
        .map(|e| (e.path.as_str(), e.rule.as_str()))
        .collect();
    assert!(
        excluded.contains(&("node_modules", "default:node_modules")),
        "{excluded:?}"
    );
    assert!(excluded.contains(&("config", "config/**")), "{excluded:?}");
    assert!(excluded.contains(&("src/aws.py", "*.py")), "{excluded:?}");
    assert!(
        !report.findings.iter().any(|f| f.path.starts_with("config/")
            || f.path.ends_with(".py")
            || f.path.starts_with("node_modules"))
    );
    assert_eq!(report.excluded_total as usize, report.excluded.len());
    // An explicitly requested excluded file is still reported as excluded.
    let r = scan(
        p.path(),
        Some(&["src/aws.py".to_owned()]),
        &options,
        &BUILTIN,
    )
    .unwrap();
    assert_eq!(r.findings.len(), 0);
    assert_eq!(r.excluded.len(), 1);
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed_and_paths_cannot_escape() {
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), "stolen.env", &format!("TOKEN={GITHUB}\n"));
    let p = project();
    std::os::unix::fs::symlink(outside.path().join("stolen.env"), p.path().join("link.env"))
        .unwrap();
    std::os::unix::fs::symlink(outside.path(), p.path().join("linkdir")).unwrap();
    let report = scan(p.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    assert!(
        !report.findings.iter().any(|f| f.path.starts_with("link")),
        "symlink targets are not read"
    );
    let skipped: Vec<_> = report
        .skipped
        .iter()
        .filter(|s| s.reason == SkipReason::Symlink)
        .map(|s| s.path.as_str())
        .collect();
    assert!(
        skipped.contains(&"link.env") && skipped.contains(&"linkdir"),
        "{skipped:?}"
    );
    assert!(
        !report.complete,
        "skipped symlinks make the scan incomplete"
    );

    for bad in [
        "../outside",
        "/etc/passwd",
        "src/../../x",
        "linkdir/stolen.env",
        "link.env",
    ] {
        assert!(
            matches!(
                scan(
                    p.path(),
                    Some(&[bad.to_owned()]),
                    &ScanOptions::default(),
                    &BUILTIN
                ),
                Err(ScanError::OutsideBoundary(_))
            ),
            "{bad}"
        );
    }
}

#[test]
fn binary_large_and_special_files_are_skipped_and_reported() {
    let p = project();
    let mut bin = vec![0u8; 4096];
    bin.extend_from_slice(GITHUB.as_bytes());
    fs::write(p.path().join("blob.bin"), &bin).unwrap();
    let big = p.path().join("big.log");
    let mut f = fs::File::create(&big).unwrap();
    for _ in 0..40 {
        f.write_all(&[b'a'; 64 * 1024]).unwrap();
    }
    f.write_all(GITHUB.as_bytes()).unwrap();
    #[cfg(unix)]
    nix::unistd::mkfifo(&p.path().join("pipe"), nix::sys::stat::Mode::S_IRWXU).unwrap();
    let mut options = ScanOptions::default();
    options.max_file_bytes = 1024 * 1024;
    let report = scan(p.path(), None, &options, &BUILTIN).unwrap();
    let reason = |name: &str| {
        report
            .skipped
            .iter()
            .find(|s| s.path == name)
            .map(|s| s.reason)
    };
    assert_eq!(reason("blob.bin"), Some(SkipReason::Binary));
    assert_eq!(reason("big.log"), Some(SkipReason::TooLarge));
    #[cfg(unix)]
    assert_eq!(reason("pipe"), Some(SkipReason::NotRegularFile));
    assert!(!report.complete);
}

#[test]
fn long_lines_are_scanned_in_bounded_segments() {
    let dir = tempfile::tempdir().unwrap();
    // One 1.5 MiB line with a token near the end: scanned in 64 KiB segments.
    let mut line = "x".repeat(1_500_000);
    line.push(' ');
    line.push_str(GITHUB);
    line.push('\n');
    fs::write(dir.path().join("minified.js"), &line).unwrap();
    let report = scan(dir.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert!(report.findings[0].column > 1_400_000);
}

#[test]
fn limits_mark_the_scan_incomplete() {
    let p = project();
    let mut options = ScanOptions::default();
    options.max_files = 2;
    options.max_findings = 1;
    let report = scan(p.path(), None, &options, &BUILTIN).unwrap();
    assert!(!report.complete);
    assert!(report
        .skipped
        .iter()
        .any(|s| s.reason == SkipReason::LimitReached));
    assert!(report.findings.len() <= 1);
}

#[test]
fn finding_metadata_cannot_recover_the_secret() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    write(a.path(), "x.env", &format!("T={GITHUB}\n"));
    write(
        b.path(),
        "x.env",
        "T=ghp_OTHERotherOTHERotherOTHERother999999\n",
    );
    let ra = scan(a.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    let rb = scan(b.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    // Same location and detector, different secrets: identical metadata.
    assert_eq!(ra.findings[0].id, rb.findings[0].id);
    assert_eq!(ra.findings[0].preview, rb.findings[0].preview);
    assert_eq!(ra.findings[0].id, finding_id("x.env", 1, 3, "github-token"));
    let text = serde_json::to_string(&ra.findings).unwrap();
    assert!(!text.contains(&GITHUB[4..]));
}

#[test]
fn the_crate_has_no_network_or_process_code() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(src).unwrap() {
        let text = fs::read_to_string(entry.unwrap().path()).unwrap();
        for forbidden in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process",
            "Command::new",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for net in ["reqwest", "hyper", "ureq", "tokio"] {
        assert!(!manifest.contains(net), "{net}");
    }
}

#[test]
fn redaction_property_fake_tokens_never_survive() {
    let tokens = [
        GITHUB,
        STRIPE,
        AWS,
        concat!("glpat", "-FAKEfakeFAKEfake0000"),
        "xoxb-0000000000-FAKEfakeFAKE",
        "sk-ant-api03-FAKEfakeFAKEfakeFAKE0000",
    ];
    let before_fillers = [
        "",
        " ",
        "=",
        "\"",
        "'",
        ":",
        "(",
        "x ",
        "Authorization: Bearer ",
        "export T=",
        "\t",
        ";",
    ];
    // A word character directly after a token makes it a different (invalid) token.
    let after_fillers = ["", " ", "\"", "'", ")", ",", ";", "\t", "\n"];
    for _ in 0..2000 {
        let token = tokens[fastrand::usize(..tokens.len())];
        let before = before_fillers[fastrand::usize(..before_fillers.len())];
        let after = after_fillers[fastrand::usize(..after_fillers.len())];
        let noise: String = (0..fastrand::usize(0..20))
            .map(|_| fastrand::alphanumeric())
            .collect();
        let text = format!("{noise} {before}{token}{after} {noise}");
        let out = redact(&text);
        let secret_part = &token[token.len() - 12..];
        assert!(!out.contains(secret_part), "{text:?} -> {out:?}");
    }
}

#[test]
fn random_bytes_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..60 {
        let len = fastrand::usize(0..20_000);
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                if fastrand::u8(..) < 4 {
                    b'\n'
                } else {
                    fastrand::u8(1..)
                }
            })
            .collect();
        fs::write(dir.path().join(format!("f{i}.txt")), bytes).unwrap();
    }
    let report = scan(dir.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    assert_eq!(report.files_scanned, 60);
}

#[test]
fn performance_two_thousand_files() {
    let dir = tempfile::tempdir().unwrap();
    let body = "fn handler(req: Request) -> Response {\n    let value = compute(req.id, 42);\n    Response::ok(value)\n}\n".repeat(40);
    for i in 0..2000 {
        write(dir.path(), &format!("src/m{}/f{i}.rs", i % 50), &body);
    }
    let start = Instant::now();
    let report = scan(dir.path(), None, &ScanOptions::default(), &BUILTIN).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(report.files_scanned, 2000);
    assert_eq!(report.findings.len(), 0);
    eprintln!(
        "scanned {} files, {} bytes in {elapsed:?}",
        report.files_scanned, report.bytes_scanned
    );
    assert!(elapsed.as_secs() < 15, "{elapsed:?}");
}

fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// Real Git as the oracle for the index reader. Skipped (with a message) when git is absent.
#[test]
fn staged_changes_from_a_real_repository() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("git not installed; staged test skipped");
        return;
    }
    for version in ["2", "3", "4"] {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        git(r, &["init", "-q"]);
        git(r, &["config", "index.version", version]);
        write(r, "docs/old.md", "old\n");
        write(r, "src/lib.rs", "pub fn a() {}\n");
        git(r, &["add", "."]);
        git(r, &["commit", "-qm", "init"]);
        write(
            r,
            "src/config.rs",
            &format!("const T: &str = \"{GITHUB}\";\n"),
        );
        write(r, "src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
        git(r, &["add", "src"]);
        // Staged, then modified again: the staged content cannot be verified from disk.
        write(r, "notes.txt", "draft\n");
        git(r, &["add", "notes.txt"]);
        write(r, "notes.txt", "draft changed after staging, longer\n");

        let s = staged(r).unwrap();
        assert!(
            s.verified.contains(&"src/config.rs".to_owned()),
            "v{version}: {s:?}"
        );
        assert!(
            s.verified.contains(&"src/lib.rs".to_owned()),
            "v{version}: {s:?}"
        );
        assert!(
            !s.verified.contains(&"docs/old.md".to_owned()),
            "unchanged directories are not candidates: {s:?}"
        );
        assert_eq!(s.unverified, ["notes.txt"], "v{version}");

        let report = scan_files(
            r,
            &s.verified,
            &s.unverified,
            &ScanOptions::default(),
            &BUILTIN,
        )
        .unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "src/config.rs");
        assert!(report
            .skipped
            .iter()
            .any(|k| k.path == "notes.txt" && k.reason == SkipReason::StagedContentUnverified));
        assert!(!report.complete);
    }
}
