//! Codex `apply_patch` envelopes: which files a patch adds, updates, moves or deletes, and the
//! text it adds (for secret inspection).
//!
//! Codex reports file edits as the `apply_patch` tool with the patch in `tool_input.command`
//! (hooks reference). The envelope is:
//!
//! ```text
//! *** Begin Patch
//! *** Add File: <path>        followed by `+` lines
//! *** Update File: <path>     optionally `*** Move to: <path>`, then hunks (`@@`, ` `, `-`, `+`)
//! *** Delete File: <path>
//! *** End Patch
//! ```
//!
//! Anything that does not fit this grammar is rejected: a patch AgentGuard cannot read is never
//! treated as harmless.

/// What a patch does to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChange {
    /// Create a file with the added text.
    Add {
        /// Path as written in the patch.
        path: String,
        /// Added lines.
        content: String,
    },
    /// Change a file, optionally moving it.
    Update {
        /// Path as written.
        path: String,
        /// New path, for a move.
        move_to: Option<String>,
        /// Added lines.
        added: String,
    },
    /// Delete a file.
    Delete {
        /// Path as written.
        path: String,
    },
}

/// Most files one patch may touch before it is refused.
pub const MAX_FILES: usize = 64;

/// Why a patch was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the apply_patch input could not be parsed: {0}")]
pub struct PatchError(pub &'static str);

fn path_of(line: &str, prefix: &str) -> Result<String, PatchError> {
    let path = line.strip_prefix(prefix).unwrap_or_default().trim();
    if path.is_empty() || path.contains('\0') {
        return Err(PatchError("a file header has no path"));
    }
    Ok(path.to_owned())
}

/// Parse a patch.
pub fn parse(patch: &str) -> Result<Vec<FileChange>, PatchError> {
    let mut lines = patch.lines().map(|l| l.strip_suffix('\r').unwrap_or(l));
    let first = lines.by_ref().find(|l| !l.trim().is_empty());
    if first.map(str::trim) != Some("*** Begin Patch") {
        return Err(PatchError("missing `*** Begin Patch`"));
    }
    let mut changes: Vec<FileChange> = Vec::new();
    let mut ended = false;
    for line in lines {
        if ended {
            if line.trim().is_empty() {
                continue;
            }
            return Err(PatchError("content after `*** End Patch`"));
        }
        if line.trim() == "*** End Patch" {
            ended = true;
        } else if line.starts_with("*** Add File: ") {
            changes.push(FileChange::Add {
                path: path_of(line, "*** Add File: ")?,
                content: String::new(),
            });
        } else if line.starts_with("*** Update File: ") {
            changes.push(FileChange::Update {
                path: path_of(line, "*** Update File: ")?,
                move_to: None,
                added: String::new(),
            });
        } else if line.starts_with("*** Delete File: ") {
            changes.push(FileChange::Delete {
                path: path_of(line, "*** Delete File: ")?,
            });
        } else if line.starts_with("*** Move to: ") {
            match changes.last_mut() {
                Some(FileChange::Update { move_to, .. }) if move_to.is_none() => {
                    *move_to = Some(path_of(line, "*** Move to: ")?);
                }
                _ => return Err(PatchError("`*** Move to:` outside an update")),
            }
        } else if line == "*** End of File" {
            if !matches!(changes.last(), Some(FileChange::Update { .. })) {
                return Err(PatchError("`*** End of File` outside an update"));
            }
        } else if line.starts_with("***") {
            return Err(PatchError("an unknown `***` header"));
        } else {
            match changes.last_mut() {
                Some(FileChange::Add { content, .. }) => match line.strip_prefix('+') {
                    Some(text) => {
                        content.push_str(text);
                        content.push('\n');
                    }
                    None => return Err(PatchError("an added file has a line without `+`")),
                },
                Some(FileChange::Update { added, .. }) => {
                    if let Some(text) = line.strip_prefix('+') {
                        added.push_str(text);
                        added.push('\n');
                    } else if !(line.starts_with("@@")
                        || line.starts_with('-')
                        || line.starts_with(' ')
                        || line.is_empty())
                    {
                        return Err(PatchError("an update hunk has an unrecognised line"));
                    }
                }
                Some(FileChange::Delete { .. }) => {
                    return Err(PatchError("a deleted file has content"))
                }
                None => return Err(PatchError("content before the first file header")),
            }
        }
        if changes.len() > MAX_FILES {
            return Err(PatchError("the patch touches too many files"));
        }
    }
    if !ended {
        return Err(PatchError("missing `*** End Patch`"));
    }
    if changes.is_empty() {
        return Err(PatchError("the patch changes no file"));
    }
    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_change_kind() {
        let patch = "*** Begin Patch\n*** Add File: src/new.rs\n+fn main() {}\n*** Update File: src/lib.rs\n*** Move to: src/core.rs\n@@ fn x\n-old\n+new\n context\n*** End of File\n*** Delete File: old.txt\n*** End Patch\n";
        let changes = parse(patch).unwrap();
        assert_eq!(
            changes,
            [
                FileChange::Add {
                    path: "src/new.rs".into(),
                    content: "fn main() {}\n".into()
                },
                FileChange::Update {
                    path: "src/lib.rs".into(),
                    move_to: Some("src/core.rs".into()),
                    added: "new\n".into()
                },
                FileChange::Delete {
                    path: "old.txt".into()
                },
            ]
        );
    }

    #[test]
    fn anything_else_is_rejected() {
        for bad in [
            "",
            "rm -rf /",
            "*** Begin Patch\n*** Add File: a\n+x\n",
            "*** Begin Patch\n*** End Patch\n",
            "*** Begin Patch\n*** Frobnicate File: a\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: a\nno plus\n*** End Patch\n",
            "*** Begin Patch\n*** Delete File: a\n+x\n*** End Patch\n",
            "*** Begin Patch\n*** Move to: b\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: \n*** End Patch\n",
            "*** Begin Patch\n*** Update File: a\n?? weird\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch\nextra\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
