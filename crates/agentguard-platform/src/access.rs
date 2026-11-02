//! Who owns a file and who else can use it.

use std::fs::Metadata;
use std::io;
use std::path::Path;

/// The owner of a file, relative to the current process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The current user (on Windows also the token's default owner, which is Administrators in
    /// an elevated session).
    CurrentUser,
    /// The system: root; on Windows SYSTEM, Administrators or TrustedInstaller.
    System,
    /// Anyone else.
    Other,
}

/// Ownership and access of one file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// Who owns it.
    pub owner: Owner,
    /// Someone other than the owner and the system can modify it (Unix: group or other write
    /// bits; Windows: a write, delete or permission-changing allow ACE for another SID).
    pub others_can_write: bool,
    /// Someone other than the owner and the system has any access (Unix: any group or other
    /// bit; Windows: any applicable allow ACE for another SID).
    pub others_have_access: bool,
}

impl Access {
    /// Owned by the current user and inaccessible to anyone else but the system.
    pub fn is_private(&self) -> bool {
        self.owner == Owner::CurrentUser && !self.others_have_access
    }

    /// Owned by the current user or the system, and modifiable by no one else.
    pub fn is_protected(&self) -> bool {
        self.owner != Owner::Other && !self.others_can_write
    }
}

/// Ownership and access of `path`. `meta` must be the metadata of the same path (Unix reads
/// everything from it; Windows reads the security descriptor of `path`, following links).
pub fn of(path: &Path, meta: &Metadata) -> io::Result<Access> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        let uid = meta.uid();
        let owner = if uid == nix::unistd::Uid::current().as_raw() {
            Owner::CurrentUser
        } else if uid == 0 {
            Owner::System
        } else {
            Owner::Other
        };
        let mode = meta.mode();
        Ok(Access {
            owner,
            others_can_write: mode & 0o022 != 0,
            others_have_access: mode & 0o077 != 0,
        })
    }
    #[cfg(windows)]
    {
        let _ = meta;
        crate::windows::access(path)
    }
}

/// The current user's identifier for display and comparison: the uid on Unix, the user SID's
/// string form on Windows.
pub fn current_user_id() -> String {
    #[cfg(unix)]
    {
        nix::unistd::Uid::current().as_raw().to_string()
    }
    #[cfg(windows)]
    {
        crate::windows::current_user_sid().unwrap_or_else(|_| "unknown".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_created_by_the_user_are_theirs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        crate::fs::set_unix_mode(&file, 0o600).unwrap();
        let a = of(&file, &std::fs::metadata(&file).unwrap()).unwrap();
        assert_eq!(a.owner, Owner::CurrentUser);
        assert!(a.is_protected());
        #[cfg(unix)]
        {
            assert!(a.is_private());
            crate::fs::set_unix_mode(&file, 0o664).unwrap();
            let a = of(&file, &std::fs::metadata(&file).unwrap()).unwrap();
            assert!(a.others_can_write && !a.is_protected() && !a.is_private());
        }
        assert_ne!(current_user_id(), "");
    }
}
