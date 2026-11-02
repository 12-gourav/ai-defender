//! Reading staged changes from `.git/index` without running Git.
//!
//! Git stores staged content as compressed objects, which this crate does not decompress.
//! Instead it reads the (uncompressed) index:
//!
//! 1. The cache-tree extension (`TREE`) records which directories changed since the tree was
//!    last written (normally the last commit). Entries in a changed or new directory are the
//!    staged candidates; without the extension every entry is a candidate.
//! 2. For each candidate, the working-tree file's size and modification time are compared with
//!    the index entry, as Git itself does. When they match, the working-tree file is the
//!    staged content and is scanned. When they differ, the staged content is reported as
//!    unverified, never as clean.
//!
//! Supported: index versions 2, 3 and 4; SHA-1 and SHA-256 repositories; a `.git` directory at
//! the repository root. A `.git` file (linked worktrees, submodules) is not supported.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Largest index read.
pub const MAX_INDEX_BYTES: u64 = 128 * 1024 * 1024;

/// One index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Repository-relative path.
    pub path: String,
    /// File mode.
    pub mode: u32,
    /// Size (low 32 bits).
    pub size: u32,
    /// Modification time, seconds.
    pub mtime_s: u32,
    /// Modification time, nanoseconds.
    pub mtime_ns: u32,
    /// Merge stage (0 normally).
    pub stage: u8,
    /// Added with `git add -N` (no content staged).
    pub intent_to_add: bool,
    /// Marked skip-worktree.
    pub skip_worktree: bool,
}

/// A parsed index.
#[derive(Debug, Clone, Default)]
pub struct Index {
    /// Entries.
    pub entries: Vec<IndexEntry>,
    /// Directories with a valid cache-tree entry (unchanged since the tree was written).
    /// `None` when the index has no cache-tree extension.
    pub valid_dirs: Option<BTreeSet<String>>,
}

/// Why the index could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    /// No Git repository at the root.
    #[error("no Git repository (.git directory) at the project root")]
    NoRepository,
    /// `.git` is a file (worktree or submodule).
    #[error("linked worktrees and submodules (.git file) are not supported")]
    Unsupported,
    /// The index is missing (nothing staged yet) or unreadable.
    #[error("the Git index could not be read")]
    Unreadable,
    /// The index is malformed or of an unknown version.
    #[error("the Git index is malformed or of an unsupported version")]
    Malformed,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], IndexError> {
        let end = self.pos.checked_add(n).ok_or(IndexError::Malformed)?;
        let slice = self.data.get(self.pos..end).ok_or(IndexError::Malformed)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], IndexError> {
        self.take(N)?.try_into().map_err(|_| IndexError::Malformed)
    }

    fn u32(&mut self) -> Result<u32, IndexError> {
        self.array::<4>().map(u32::from_be_bytes)
    }

    fn u16(&mut self) -> Result<u16, IndexError> {
        self.array::<2>().map(u16::from_be_bytes)
    }

    fn until_nul(&mut self) -> Result<&'a [u8], IndexError> {
        let rest = self.data.get(self.pos..).ok_or(IndexError::Malformed)?;
        let n = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or(IndexError::Malformed)?;
        let s = self.take(n)?;
        self.pos += 1;
        Ok(s)
    }

    fn until(&mut self, byte: u8) -> Result<&'a [u8], IndexError> {
        let rest = self.data.get(self.pos..).ok_or(IndexError::Malformed)?;
        let n = rest
            .iter()
            .position(|b| *b == byte)
            .ok_or(IndexError::Malformed)?;
        let s = self.take(n)?;
        self.pos += 1;
        Ok(s)
    }

    /// Git's offset varint (used by index v4 path compression).
    fn varint(&mut self) -> Result<usize, IndexError> {
        let [mut byte] = self.array::<1>()?;
        let mut value = usize::from(byte & 0x7f);
        while byte & 0x80 != 0 {
            [byte] = self.array::<1>()?;
            value = value
                .checked_add(1)
                .and_then(|v| v.checked_shl(7))
                .ok_or(IndexError::Malformed)?
                | usize::from(byte & 0x7f);
        }
        Ok(value)
    }
}

/// Parse index bytes. `hash_len` is 20 (SHA-1) or 32 (SHA-256).
pub fn parse_index(data: &[u8], hash_len: usize) -> Result<Index, IndexError> {
    let mut r = Reader { data, pos: 0 };
    if r.take(4)? != b"DIRC" {
        return Err(IndexError::Malformed);
    }
    let version = r.u32()?;
    if !(2..=4).contains(&version) {
        return Err(IndexError::Malformed);
    }
    let count = r.u32()? as usize;
    if count > 4_000_000 {
        return Err(IndexError::Malformed);
    }
    let mut entries = Vec::with_capacity(count.min(100_000));
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let start = r.pos;
        r.take(8)?; // ctime
        let mtime_s = r.u32()?;
        let mtime_nanos = r.u32()?;
        r.take(8)?; // dev, ino
        let mode = r.u32()?;
        r.take(8)?; // uid, gid
        let size = r.u32()?;
        r.take(hash_len)?;
        let flags = r.u16()?;
        let extended = flags & 0x4000 != 0;
        let (mut skip_worktree, mut intent_to_add) = (false, false);
        if extended {
            if version < 3 {
                return Err(IndexError::Malformed);
            }
            let ext = r.u16()?;
            skip_worktree = ext & 0x4000 != 0;
            intent_to_add = ext & 0x2000 != 0;
        }
        let path = if version == 4 {
            let strip = r.varint()?;
            let keep = previous
                .len()
                .checked_sub(strip)
                .ok_or(IndexError::Malformed)?;
            let mut name = previous.get(..keep).ok_or(IndexError::Malformed)?.to_vec();
            name.extend_from_slice(r.until_nul()?);
            name
        } else {
            let name = r.until_nul()?.to_vec();
            // Entries are NUL-padded to a multiple of 8 bytes (one NUL already consumed).
            let len = r.pos - start;
            let padded = len.div_ceil(8) * 8;
            r.take(padded - len)?;
            name
        };
        previous.clone_from(&path);
        entries.push(IndexEntry {
            path: String::from_utf8(path).map_err(|_| IndexError::Malformed)?,
            mode,
            size,
            mtime_s,
            mtime_ns: mtime_nanos,
            stage: u8::try_from((flags >> 12) & 0x3).unwrap_or(0),
            intent_to_add,
            skip_worktree,
        });
    }
    let mut valid_dirs = None;
    let end = data
        .len()
        .checked_sub(hash_len)
        .ok_or(IndexError::Malformed)?;
    while r.pos + 8 <= end {
        let signature = r.take(4)?;
        let size = r.u32()? as usize;
        let body = r.take(size)?;
        if signature == b"TREE" {
            let mut valid = BTreeSet::new();
            let mut t = Reader { data: body, pos: 0 };
            while t.pos < body.len() {
                parse_tree(&mut t, "", hash_len, &mut valid, 0)?;
            }
            valid_dirs = Some(valid);
        }
    }
    Ok(Index {
        entries,
        valid_dirs,
    })
}

fn parse_tree(
    r: &mut Reader<'_>,
    parent: &str,
    hash_len: usize,
    valid: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), IndexError> {
    if depth > 4096 {
        return Err(IndexError::Malformed);
    }
    let name = std::str::from_utf8(r.until_nul()?).map_err(|_| IndexError::Malformed)?;
    let path = match (parent.is_empty(), name.is_empty()) {
        (_, true) => parent.to_owned(),
        (true, false) => name.to_owned(),
        (false, false) => format!("{parent}/{name}"),
    };
    let count: i64 = std::str::from_utf8(r.until(b' ')?)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(IndexError::Malformed)?;
    let subtrees: usize = std::str::from_utf8(r.until(b'\n')?)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(IndexError::Malformed)?;
    if count >= 0 {
        r.take(hash_len)?;
        valid.insert(path.clone());
    }
    for _ in 0..subtrees {
        parse_tree(r, &path, hash_len, valid, depth + 1)?;
    }
    Ok(())
}

/// Read and parse `<root>/.git/index`.
pub fn read_index(root: &Path) -> Result<Index, IndexError> {
    let git = root.join(".git");
    match fs::symlink_metadata(&git) {
        Ok(m) if m.is_dir() => {}
        Ok(m) if m.is_file() => return Err(IndexError::Unsupported),
        _ => return Err(IndexError::NoRepository),
    }
    let config = fs::read_to_string(git.join("config")).unwrap_or_default();
    let hash_len = if config
        .to_ascii_lowercase()
        .contains("objectformat = sha256")
    {
        32
    } else {
        20
    };
    let file =
        crate::inspect::open_regular(&git.join("index")).map_err(|_| IndexError::Unreadable)?;
    let mut data = Vec::new();
    file.take(MAX_INDEX_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| IndexError::Unreadable)?;
    if data.len() as u64 > MAX_INDEX_BYTES {
        return Err(IndexError::Malformed);
    }
    parse_index(&data, hash_len)
}

/// Staged files split into those whose working-tree copy is the staged content and those whose
/// staged content could not be verified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Staged {
    /// Working-tree file equals the staged content; scan it.
    pub verified: Vec<String>,
    /// Staged content differs from the working tree (or is a conflict); not scannable here.
    pub unverified: Vec<String>,
}

fn parent_dir(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// Staged candidates under `root`.
pub fn staged(root: &Path) -> Result<Staged, IndexError> {
    let index = read_index(root)?;
    let mut out = Staged::default();
    for e in &index.entries {
        let candidate = index
            .valid_dirs
            .as_ref()
            .is_none_or(|valid| !valid.contains(parent_dir(&e.path)));
        let gitlink = e.mode & 0o170_000 == 0o160_000;
        if !candidate || gitlink || e.intent_to_add || e.skip_worktree {
            continue;
        }
        let symlink = e.mode & 0o170_000 == 0o120_000;
        let matches = !symlink
            && e.stage == 0
            && fs::symlink_metadata(root.join(&e.path)).is_ok_and(|m| {
                let mtime = agentguard_platform::identity::mtime_ns(&m);
                m.is_file()
                    && u32::try_from(m.len() & 0xffff_ffff).ok() == Some(e.size)
                    && u32::try_from(mtime.div_euclid(1_000_000_000)).ok() == Some(e.mtime_s)
                    && (e.mtime_ns == 0
                        || u32::try_from(mtime.rem_euclid(1_000_000_000)).ok() == Some(e.mtime_ns))
            });
        if matches {
            out.verified.push(e.path.clone());
        } else {
            out.unverified.push(e.path.clone());
        }
    }
    out.verified.dedup();
    out.unverified.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, version: u32, prev: &str) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&[0; 8]);
        e.extend_from_slice(&7u32.to_be_bytes());
        e.extend_from_slice(&9u32.to_be_bytes());
        e.extend_from_slice(&[0; 8]);
        e.extend_from_slice(&0o100_644u32.to_be_bytes());
        e.extend_from_slice(&[0; 8]);
        e.extend_from_slice(&5u32.to_be_bytes());
        e.extend_from_slice(&[0xab; 20]);
        let len = u16::try_from(path.len()).unwrap();
        e.extend_from_slice(&len.to_be_bytes());
        if version == 4 {
            let common = prev
                .bytes()
                .zip(path.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            e.push(u8::try_from(prev.len() - common).unwrap());
            e.extend_from_slice(&path.as_bytes()[common..]);
            e.push(0);
        } else {
            e.extend_from_slice(path.as_bytes());
            e.push(0);
            while e.len() % 8 != 0 {
                e.push(0);
            }
        }
        e
    }

    fn index(version: u32, paths: &[&str], tree: Option<&[u8]>) -> Vec<u8> {
        let mut d = b"DIRC".to_vec();
        d.extend_from_slice(&version.to_be_bytes());
        d.extend_from_slice(&u32::try_from(paths.len()).unwrap().to_be_bytes());
        let mut prev = "";
        for p in paths {
            d.extend_from_slice(&entry(p, version, prev));
            prev = p;
        }
        if let Some(t) = tree {
            d.extend_from_slice(b"TREE");
            d.extend_from_slice(&u32::try_from(t.len()).unwrap().to_be_bytes());
            d.extend_from_slice(t);
        }
        d.extend_from_slice(&[0; 20]);
        d
    }

    #[test]
    fn parses_v2_v3_v4() {
        for v in [2, 3, 4] {
            let i =
                parse_index(&index(v, &["a.txt", "src/lib.rs", "src/main.rs"], None), 20).unwrap();
            let paths: Vec<_> = i.entries.iter().map(|e| e.path.as_str()).collect();
            assert_eq!(paths, ["a.txt", "src/lib.rs", "src/main.rs"], "v{v}");
            assert_eq!(i.entries[0].size, 5);
            assert!(i.valid_dirs.is_none());
        }
    }

    #[test]
    fn cache_tree_marks_changed_directories() {
        // root invalid (-1), 2 subtrees: src invalid, docs valid.
        let mut t = b"\0-1 2\n".to_vec();
        t.extend_from_slice(b"src\0-1 0\n");
        t.extend_from_slice(b"docs\x001 0\n");
        t.extend_from_slice(&[0xcd; 20]);
        let i = parse_index(&index(2, &["docs/a.md", "src/main.rs"], Some(&t)), 20).unwrap();
        let valid = i.valid_dirs.unwrap();
        assert!(valid.contains("docs") && !valid.contains("src") && !valid.contains(""));
    }

    #[test]
    fn malformed_input_is_rejected_not_panicked() {
        assert_eq!(parse_index(b"", 20).unwrap_err(), IndexError::Malformed);
        assert_eq!(
            parse_index(b"DIRC\0\0\0\x09\0\0\0\0", 20).unwrap_err(),
            IndexError::Malformed
        );
        let mut good = index(2, &["a"], None);
        good.truncate(30);
        assert_eq!(parse_index(&good, 20).unwrap_err(), IndexError::Malformed);
        for _ in 0..500 {
            let len = fastrand::usize(0..200);
            let mut junk: Vec<u8> = (0..len).map(|_| fastrand::u8(..)).collect();
            if fastrand::bool() && junk.len() > 4 {
                junk[..4].copy_from_slice(b"DIRC");
            }
            let _ = parse_index(&junk, 20);
        }
    }
}
