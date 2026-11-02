//! Secret-safe access: what an agent can learn about configuration without receiving a value.
//!
//! An agent rarely needs a raw secret. It needs to know whether a setting exists, whether it is
//! set, and how to refer to it. [`SecretSource`] answers exactly that; no method returns a
//! value. [`SecretReference`] names a secret for a future broker that injects values at
//! execution time (environment injection, scoped credentials, provider integrations); no such
//! broker exists yet and nothing here resolves a reference to a value.
//!
//! Implemented locally: [`DotenvFile`] (`.env` format). A scanner cannot stop a model from
//! repeating what it has already received; these interfaces exist so it does not receive it.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::inspect::{looks_binary, open_regular, MAX_INSPECT_BYTES};

/// What a key's value looks like, without the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueState {
    /// A non-empty literal value is present.
    Set,
    /// The key is present with an empty value.
    Empty,
    /// The value refers to another variable or a secret manager (`${OTHER}`, `vault:...`).
    Reference,
}

/// One key of a configuration source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyStatus {
    /// The key name.
    pub key: String,
    /// What its value looks like.
    pub state: ValueState,
    /// 1-based line.
    pub line: u64,
}

/// A secret by name, never by value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretReference {
    /// Where it lives (a file path relative to the project, or a provider name).
    pub source: String,
    /// The key.
    pub key: String,
}

/// Why a source could not be described.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    /// Missing, not a regular file, a symlink, or unreadable.
    #[error("the configuration file could not be read as a regular file")]
    Unreadable,
    /// Binary or too large.
    #[error("the file is binary or larger than 1 MiB")]
    Unsupported,
}

/// A configuration source that can be described without revealing values.
pub trait SecretSource {
    /// Every key and the state of its value.
    fn describe(&self) -> Result<Vec<KeyStatus>, AccessError>;

    /// Whether `key` is present with a non-empty value.
    fn is_set(&self, key: &str) -> Result<bool, AccessError> {
        Ok(self
            .describe()?
            .iter()
            .any(|k| k.key == key && k.state != ValueState::Empty))
    }
}

/// A `.env`-format file: `KEY=value`, optional `export`, quotes, comments.
pub struct DotenvFile {
    path: PathBuf,
}

impl DotenvFile {
    /// A source for `path` (opened without following a final symlink).
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Describe `.env`-format text.
#[must_use]
pub fn describe_dotenv(text: &str) -> Vec<KeyStatus> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !valid_key(key) {
            continue;
        }
        let value = value.trim();
        let unquoted = value.trim_matches(|c| c == '"' || c == '\'');
        let state = if unquoted.is_empty() {
            ValueState::Empty
        } else if unquoted.starts_with("${")
            || unquoted.starts_with('$')
            || unquoted.starts_with("vault:")
            || unquoted.starts_with("op://")
        {
            ValueState::Reference
        } else {
            ValueState::Set
        };
        out.push(KeyStatus {
            key: key.to_owned(),
            state,
            line: i as u64 + 1,
        });
    }
    out
}

impl SecretSource for DotenvFile {
    fn describe(&self) -> Result<Vec<KeyStatus>, AccessError> {
        let file = open_regular(&self.path).map_err(|_| AccessError::Unreadable)?;
        if file.metadata().map_or(u64::MAX, |m| m.len()) > MAX_INSPECT_BYTES {
            return Err(AccessError::Unsupported);
        }
        let mut bytes = Vec::new();
        file.take(MAX_INSPECT_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|_| AccessError::Unreadable)?;
        if looks_binary(&bytes) {
            return Err(AccessError::Unsupported);
        }
        Ok(describe_dotenv(&String::from_utf8_lossy(&bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_keys_never_values() {
        let text = "# db\nDATABASE_URL=postgres://u:Sup3rS3cretPw9@h/db\nexport API_KEY=\"ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000\"\nEMPTY=\nOTHER=${API_KEY}\nnot a line\n";
        let keys = describe_dotenv(text);
        let summary: Vec<_> = keys.iter().map(|k| (k.key.as_str(), k.state)).collect();
        assert_eq!(
            summary,
            [
                ("DATABASE_URL", ValueState::Set),
                ("API_KEY", ValueState::Set),
                ("EMPTY", ValueState::Empty),
                ("OTHER", ValueState::Reference)
            ]
        );
        let json = serde_json::to_string(&keys).unwrap();
        assert!(!json.contains("Sup3rS3cretPw9") && !json.contains("FAKEfake"));
    }

    #[test]
    fn existence_checks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(&p, "A=1\nB=\n").unwrap();
        let src = DotenvFile::new(&p);
        assert!(src.is_set("A").unwrap());
        assert!(!src.is_set("B").unwrap());
        assert!(!src.is_set("C").unwrap());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&p, dir.path().join("link.env")).unwrap();
            assert_eq!(
                DotenvFile::new(&dir.path().join("link.env"))
                    .describe()
                    .unwrap_err(),
                AccessError::Unreadable
            );
        }
    }
}
