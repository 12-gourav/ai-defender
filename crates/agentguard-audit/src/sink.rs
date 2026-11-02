//! Audit sinks.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agentguard_platform::fs::{OpenNoFollow, UnixMode};

use crate::chain::{append, verify, ChainedRecord};
use crate::error::AuditError;
use crate::event::AuditEvent;

/// Destination for audit events. Implementations must be safe to share across threads and
/// must never persist an event outside the chain.
pub trait AuditSink: Send + Sync {
    /// Append `event`, returning the chained record that was stored.
    fn record(&self, event: AuditEvent) -> Result<ChainedRecord, AuditError>;

    /// All records in order.
    fn records(&self) -> Result<Vec<ChainedRecord>, AuditError>;

    /// Verify the stored chain.
    fn verify(&self) -> Result<(), AuditError> {
        verify(&self.records()?)
    }
}

/// In-memory sink for tests and short-lived commands.
#[derive(Debug, Default)]
pub struct MemorySink {
    records: Mutex<Vec<ChainedRecord>>,
}

impl MemorySink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSink for MemorySink {
    fn record(&self, event: AuditEvent) -> Result<ChainedRecord, AuditError> {
        let mut records = self.records.lock().map_err(|_| AuditError::Unavailable)?;
        let rec = append(records.last(), event)?;
        records.push(rec.clone());
        Ok(rec)
    }

    fn records(&self) -> Result<Vec<ChainedRecord>, AuditError> {
        self.records
            .lock()
            .map(|r| r.clone())
            .map_err(|_| AuditError::Unavailable)
    }
}

/// Largest single record line read back when continuing the chain.
const MAX_RECORD_LINE: u64 = 64 * 1024;

/// Append-only JSON Lines file, created private (mode `0600` on Unix; the directory's ACL on
/// Windows).
///
/// Safe across processes: each append takes an exclusive lock on the file and continues
/// from the record actually at the end of the file, so concurrent engine processes extend one
/// chain instead of forking it.
#[derive(Debug)]
pub struct JsonlSink {
    path: PathBuf,
    appending: Mutex<()>,
}

impl JsonlSink {
    /// Open or create the file at `path`. The existing chain is verified before anything is
    /// appended: continuing a tampered chain would make the new records vouch for it. A path
    /// that exists but is not a regular file (a symlink in particular) is refused.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let io = |action: &'static str, source: std::io::Error| AuditError::Io {
            path: path.to_path_buf(),
            action,
            source,
        };
        match fs::symlink_metadata(path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Err(AuditError::NotARegularFile {
                    path: path.to_path_buf(),
                });
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("inspect", e)),
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .unix_mode(0o600)
            .open(path)
            .map_err(|e| io("open", e))?;
        verify(&Self::read_all(path)?)?;
        Ok(Self {
            path: path.to_path_buf(),
            appending: Mutex::new(()),
        })
    }

    /// The file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_all(path: &Path) -> Result<Vec<ChainedRecord>, AuditError> {
        let file = fs::File::open(path).map_err(|source| AuditError::Io {
            path: path.to_path_buf(),
            action: "read",
            source,
        })?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|source| AuditError::Io {
                path: path.to_path_buf(),
                action: "read",
                source,
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: ChainedRecord =
                serde_json::from_str(&line).map_err(|_| AuditError::Malformed {
                    path: path.to_path_buf(),
                    line: idx + 1,
                })?;
            out.push(rec);
        }
        Ok(out)
    }

    /// The record at the end of `file`, if any.
    fn last_record(&self, file: &mut File) -> Result<Option<ChainedRecord>, AuditError> {
        let io = |action: &'static str| {
            let path = self.path.clone();
            move |source| AuditError::Io {
                path,
                action,
                source,
            }
        };
        let len = file.seek(SeekFrom::End(0)).map_err(io("read"))?;
        let start = len.saturating_sub(MAX_RECORD_LINE);
        file.seek(SeekFrom::Start(start)).map_err(io("read"))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).map_err(io("read"))?;
        let text = String::from_utf8_lossy(&tail);
        let mut lines = text.split('\n').filter(|l| !l.trim().is_empty());
        let Some(last) = lines.next_back() else {
            return Ok(None);
        };
        // A tail that starts mid-file must contain the start of its last line.
        let complete = start == 0 || lines.next_back().is_some();
        let malformed = || AuditError::Malformed {
            path: self.path.clone(),
            line: 0,
        };
        if !complete {
            return Err(malformed());
        }
        serde_json::from_str(last)
            .map(Some)
            .map_err(|_| malformed())
    }
}

impl AuditSink for JsonlSink {
    fn record(&self, event: AuditEvent) -> Result<ChainedRecord, AuditError> {
        let _appending = self.appending.lock().map_err(|_| AuditError::Unavailable)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .unix_mode(0o600)
            .open_no_follow(&self.path)
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                action: "open",
                source,
            })?;
        // Released when `file` is closed at the end of this call.
        file.lock().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            action: "lock",
            source,
        })?;
        let last = self.last_record(&mut file)?;
        let rec = append(last.as_ref(), event)?;
        let mut line = serde_json::to_string(&rec).map_err(AuditError::Serialise)?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                action: "write",
                source,
            })?;
        Ok(rec)
    }

    fn records(&self) -> Result<Vec<ChainedRecord>, AuditError> {
        Self::read_all(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEventKind;

    #[test]
    fn memory_sink_chains_and_verifies() {
        let sink = MemorySink::new();
        for i in 0..3 {
            sink.record(AuditEvent::new(
                AuditEventKind::HostCheck,
                &i.to_string(),
                "",
            ))
            .unwrap();
        }
        let recs = sink.records().unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[2].seq, 2);
        assert!(sink.verify().is_ok());
    }

    #[test]
    fn jsonl_sink_persists_with_private_mode_and_continues_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let sink = JsonlSink::open(&path).unwrap();
            sink.record(AuditEvent::new(AuditEventKind::SessionStarted, "s", ""))
                .unwrap();
            sink.record(AuditEvent::new(AuditEventKind::SessionEnded, "s", ""))
                .unwrap();
        }
        #[cfg(unix)]
        assert_eq!(
            agentguard_platform::fs::unix_mode(&fs::metadata(&path).unwrap()),
            Some(0o600)
        );

        let reopened = JsonlSink::open(&path).unwrap();
        let rec = reopened
            .record(AuditEvent::new(AuditEventKind::HostCheck, "h", ""))
            .unwrap();
        assert_eq!(rec.seq, 2);
        assert!(reopened.verify().is_ok());
        assert_eq!(reopened.records().unwrap().len(), 3);
    }

    #[test]
    fn jsonl_tamper_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlSink::open(&path).unwrap();
        sink.record(AuditEvent::new(AuditEventKind::HostCheck, "a", ""))
            .unwrap();
        sink.record(AuditEvent::new(AuditEventKind::HostCheck, "b", ""))
            .unwrap();
        let text = fs::read_to_string(&path).unwrap().replace("\"a\"", "\"z\"");
        fs::write(&path, text).unwrap();
        assert!(matches!(
            sink.verify(),
            Err(AuditError::ChainBroken { index: 0 })
        ));

        fs::write(&path, "not json\n").unwrap();
        assert!(matches!(
            JsonlSink::open(&path),
            Err(AuditError::Malformed { line: 1, .. })
        ));
    }

    // Regression: opening used to continue from the last record without verifying the
    // chain, so new records were silently chained onto a tampered history.
    #[test]
    fn jsonl_open_refuses_tampered_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let sink = JsonlSink::open(&path).unwrap();
            for r in ["a", "b", "c"] {
                sink.record(AuditEvent::new(AuditEventKind::HostCheck, r, ""))
                    .unwrap();
            }
        }
        let text = fs::read_to_string(&path).unwrap();
        let without_middle: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        fs::write(&path, without_middle.join("\n") + "\n").unwrap();
        assert!(matches!(
            JsonlSink::open(&path),
            Err(AuditError::ChainBroken { index: 1 })
        ));
    }

    #[test]
    fn concurrent_sinks_extend_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        JsonlSink::open(&path).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    // Separate sinks model separate processes: nothing is shared but the file.
                    let sink = JsonlSink::open(&path).unwrap();
                    for i in 0..10 {
                        sink.record(AuditEvent::new(
                            AuditEventKind::HostCheck,
                            &format!("{t}-{i}"),
                            "",
                        ))
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let sink = JsonlSink::open(&path).unwrap();
        let records = sink.records().unwrap();
        assert_eq!(records.len(), 80);
        assert!(sink.verify().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn jsonl_open_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.jsonl");
        fs::write(&target, "").unwrap();
        let link = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            JsonlSink::open(&link),
            Err(AuditError::NotARegularFile { .. })
        ));
    }
}
