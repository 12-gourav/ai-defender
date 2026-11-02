//! Redaction of detected secrets.
//!
//! A redacted value keeps only a public, provider-defined prefix when there is one
//! (`ghp_****REDACTED`, `sk_live_****REDACTED`) and nothing else: no suffix, no length, no
//! hash. A private key block is replaced as a whole.

use crate::detectors::{DetectorSet, BUILTIN};
use crate::model::Match;

/// The mask appended to a public prefix, or used alone.
pub const MASK: &str = "****REDACTED";

/// Replacement for a private key block.
pub const PRIVATE_KEY_MASK: &str = "[PRIVATE KEY ****REDACTED]";

/// The display form of a matched value.
#[must_use]
pub fn redacted_value(value: &str, public_prefix: usize) -> String {
    match value.get(..public_prefix) {
        Some(prefix) if public_prefix > 0 && public_prefix < value.len() => {
            format!("{prefix}{MASK}")
        }
        _ => MASK.to_owned(),
    }
}

/// Replace `matches` (sorted, non-overlapping, as returned by [`DetectorSet::detect_line`]) in
/// `line`.
#[must_use]
pub fn apply(line: &str, matches: &[Match]) -> String {
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    for m in matches {
        let (Some(before), Some(value)) = (line.get(at..m.start), line.get(m.start..m.end)) else {
            continue;
        };
        out.push_str(before);
        if m.category == crate::model::SecretCategory::PrivateKey {
            out.push_str(PRIVATE_KEY_MASK);
        } else {
            out.push_str(&redacted_value(value, m.public_prefix));
        }
        at = m.end;
    }
    out.push_str(line.get(at..).unwrap_or(""));
    out
}

/// Redact every detected secret in `text` with `set`. Lines inside a private key block are
/// dropped into the block's mask. Returns the text and the number of redactions.
#[must_use]
pub fn redact_with(text: &str, set: &DetectorSet) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut count = 0;
    let mut in_key = false;
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 && !in_key {
            out.push('\n');
        }
        if in_key {
            if line.contains("-----END") && line.contains("PRIVATE KEY") {
                in_key = false;
                out.push_str(
                    line.split("-----END")
                        .nth(1)
                        .and_then(|r| r.split("-----").nth(1))
                        .unwrap_or(""),
                );
            }
            continue;
        }
        let matches = set.detect_line(line);
        count += matches.len();
        let opens_block = matches
            .iter()
            .any(|m| m.category == crate::model::SecretCategory::PrivateKey)
            && !(line.contains("-----END") && line.contains("PRIVATE KEY"));
        if opens_block {
            let start = matches
                .iter()
                .find(|m| m.category == crate::model::SecretCategory::PrivateKey)
                .map_or(0, |m| m.start);
            out.push_str(line.get(..start).unwrap_or(""));
            out.push_str(PRIVATE_KEY_MASK);
            in_key = true;
        } else if line.contains("PRIVATE KEY-----") && line.contains("-----END") {
            // A whole block on one line (escaped newlines in JSON): drop everything after BEGIN.
            let start = line.find("-----BEGIN").unwrap_or(0);
            out.push_str(line.get(..start).unwrap_or(""));
            out.push_str(PRIVATE_KEY_MASK);
            out.push_str(line.rsplit("-----").next().unwrap_or(""));
        } else {
            out.push_str(&apply(line, &matches));
        }
    }
    (out, count)
}

/// Redact every detected secret in `text` with the built-in detectors.
#[must_use]
pub fn redact(text: &str) -> String {
    redact_with(text, &BUILTIN).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_only() {
        assert_eq!(redacted_value("ghp_abcdefghij", 4), "ghp_****REDACTED");
        assert_eq!(
            redacted_value("ghp_", 4),
            MASK,
            "a prefix equal to the value reveals nothing extra but is not shown either"
        );
        assert_eq!(redacted_value("hunter2hunter2", 0), MASK);
    }

    #[test]
    fn redacts_lines_and_key_blocks() {
        let text = "a=1\nGITHUB=ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000\n-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEFAKE\nFAKEFAKE==\n-----END RSA PRIVATE KEY-----\nurl=postgres://u:Sup3rS3cretPw@h/db\nend";
        let (out, n) = redact_with(text, &BUILTIN);
        assert!(
            !out.contains("FAKEfakeFAKE")
                && !out.contains("MIIEFAKE")
                && !out.contains("Sup3rS3cretPw"),
            "{out}"
        );
        assert!(out.contains("GITHUB=ghp_****REDACTED"), "{out}");
        assert!(out.contains(PRIVATE_KEY_MASK));
        assert!(out.contains("postgres://u:****REDACTED@h/db"), "{out}");
        assert!(out.starts_with("a=1\n") && out.ends_with("\nend"), "{out}");
        assert_eq!(n, 3);
        let json = r#"{"private_key": "-----BEGIN PRIVATE KEY-----\nMIIFAKE\n-----END PRIVATE KEY-----\n", "x": 1}"#;
        let out = redact(json);
        assert!(!out.contains("MIIFAKE"), "{out}");
    }
}
