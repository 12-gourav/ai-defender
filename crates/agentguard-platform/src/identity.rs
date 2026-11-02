//! Telling whether a path still names the same file.

use std::fs::Metadata;
use std::io;
use std::path::Path;

/// The filesystem's identity of a file: device and inode on Unix, volume serial number and
/// file index on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// Device (Unix) or volume serial number (Windows).
    pub device: u64,
    /// Inode (Unix) or file index (Windows).
    pub file: u64,
}

/// The identity of the file `path` resolves to (links are followed). Works for directories.
pub fn file_id(path: &Path) -> io::Result<FileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(FileId {
            device: meta.dev(),
            file: meta.ino(),
        })
    }
    #[cfg(windows)]
    {
        crate::windows::file_id(path)
    }
}

/// The inode generation, where the filesystem reports one (Linux: ext4, XFS, Btrfs and others
/// through `FS_IOC_GETVERSION`). It changes when an inode number is reused, so together with
/// [`FileId`] it tells a recreated file or directory from the original. `None` elsewhere: APFS
/// never reuses inode numbers, and NTFS file indexes carry their own sequence number.
pub fn generation(path: &Path) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        linux::generation(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use std::ffi::c_long;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use crate::fs::OpenNoFollow;

    nix::ioctl_read!(fs_ioc_getversion, b'v', 1, c_long);

    pub(super) fn generation(path: &Path) -> Option<u64> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open_no_follow_nonblocking(path)
            .ok()?;
        let mut value: c_long = 0;
        // SAFETY: the descriptor stays open for the call and `value` is a valid, initialised
        // out pointer of the ioctl's declared type (filesystems write a 32-bit generation into
        // its low bytes).
        unsafe { fs_ioc_getversion(file.as_raw_fd(), &raw mut value) }.ok()?;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(u64::from(value as u32))
    }
}

/// Modification time in nanoseconds since the Unix epoch (negative before it).
pub fn mtime_ns(meta: &Metadata) -> i128 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec())
    }
    #[cfg(windows)]
    {
        use std::time::UNIX_EPOCH;
        match meta.modified() {
            Ok(t) => match t.duration_since(UNIX_EPOCH) {
                Ok(d) => i128::try_from(d.as_nanos()).unwrap_or(i128::MAX),
                Err(e) => -i128::try_from(e.duration().as_nanos()).unwrap_or(i128::MAX),
            },
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_distinguishes_files() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        assert_eq!(file_id(&a).unwrap(), file_id(&a).unwrap());
        assert_ne!(file_id(&a).unwrap(), file_id(&b).unwrap());
        assert!(file_id(dir.path()).is_ok());
        assert!(mtime_ns(&std::fs::metadata(&a).unwrap()) > 0);
        assert_eq!(generation(&a), generation(&a));
    }
}
