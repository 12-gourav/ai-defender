//! Opening files without following a final link, and Unix permission modes that have no
//! Windows meaning (on Windows new files inherit the parent directory's ACL, which for the
//! user profile grants only the user, SYSTEM and Administrators).

use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// `std::fs::canonicalize` in the form the rest of AgentGuard compares: on Windows without
/// the `\\?\` prefix (`C:\dir`, `\\server\share\dir`), which the standard library adds and
/// stored project roots and the caller's paths do not have. A prefix comparison between the
/// two forms never matches, so mixing them makes "inside the project" checks silently false.
#[allow(clippy::disallowed_methods)]
pub fn canonicalize<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    #[cfg(windows)]
    {
        Ok(strip_verbatim(canonical))
    }
    #[cfg(not(windows))]
    {
        Ok(canonical)
    }
}

#[cfg(windows)]
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

/// Whether `path` is `base` or below it, component by component; case-insensitive on Windows,
/// as NTFS is. Both should come from [`canonicalize`].
pub fn path_starts_with(path: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        let fold = |c: std::path::Component<'_>| -> String {
            c.as_os_str()
                .to_string_lossy()
                .chars()
                .flat_map(char::to_uppercase)
                .collect()
        };
        let mut own = path.components();
        base.components()
            .all(|theirs| own.next().is_some_and(|mine| fold(mine) == fold(theirs)))
    }
    #[cfg(not(windows))]
    {
        path.starts_with(base)
    }
}

/// Open without following a symbolic link (or Windows reparse point) in the final component.
pub trait OpenNoFollow {
    /// Open `path`; a final link is refused with an error for which [`is_link_refusal`] holds.
    fn open_no_follow<P: AsRef<Path>>(&self, path: P) -> io::Result<File>;
    /// As [`OpenNoFollow::open_no_follow`], and never block on a FIFO or device (Unix
    /// `O_NONBLOCK`; Windows opens of such paths do not block).
    fn open_no_follow_nonblocking<P: AsRef<Path>>(&self, path: P) -> io::Result<File>;
}

#[cfg(unix)]
impl OpenNoFollow for OpenOptions {
    fn open_no_follow<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = self.clone();
        o.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
        o.open(path)
    }

    fn open_no_follow_nonblocking<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = self.clone();
        o.custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
        o.open(path)
    }
}

#[cfg(windows)]
impl OpenNoFollow for OpenOptions {
    fn open_no_follow<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        crate::windows::open_no_follow(self, path.as_ref())
    }

    fn open_no_follow_nonblocking<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        crate::windows::open_no_follow(self, path.as_ref())
    }
}

/// Whether `e` is the refusal produced when [`OpenNoFollow`] meets a link.
pub fn is_link_refusal(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(nix::libc::ELOOP)
    }
    #[cfg(windows)]
    {
        e.raw_os_error() == Some(crate::windows::LINK_REFUSED)
    }
}

/// Unix permission bits for files and directories created through these builders. Ignored on
/// Windows.
pub trait UnixMode {
    /// Set the mode used at creation.
    fn unix_mode(&mut self, mode: u32) -> &mut Self;
}

impl UnixMode for OpenOptions {
    #[cfg(unix)]
    fn unix_mode(&mut self, mode: u32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, mode)
    }

    #[cfg(windows)]
    fn unix_mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

impl UnixMode for DirBuilder {
    #[cfg(unix)]
    fn unix_mode(&mut self, mode: u32) -> &mut Self {
        std::os::unix::fs::DirBuilderExt::mode(self, mode)
    }

    #[cfg(windows)]
    fn unix_mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

/// Set Unix permission bits on an existing path. Does nothing on Windows.
pub fn set_unix_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// The Unix permission bits (`mode & 0o7777`), or `None` on Windows.
pub fn unix_mode(meta: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o7777)
    }
    #[cfg(windows)]
    {
        let _ = meta;
        None
    }
}

/// Whether a regular file can be executed directly: an execute bit on Unix, an `.exe` or
/// `.com` extension on Windows. Batch files are not directly executable: running them goes
/// through `cmd.exe`, whose argument parsing differs from the argument vector AgentGuard
/// evaluated.
pub fn is_executable(path: &Path, meta: &Metadata) -> bool {
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        let _ = path;
        unix_mode(meta).is_some_and(|m| m & 0o111 != 0)
    }
    #[cfg(windows)]
    {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("com"))
    }
}

/// Whether the file carries set-user-ID or set-group-ID bits. Always false on Windows, which
/// has no such mechanism.
pub fn has_privilege_bits(meta: &Metadata) -> bool {
    unix_mode(meta).is_some_and(|m| m & 0o6000 != 0)
}

/// File names to try for a program name: the name itself, and on Windows `<name>.exe` and
/// `<name>.com` when the name has no extension.
pub fn program_file_names(name: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        if Path::new(name).extension().is_none() {
            return vec![format!("{name}.exe"), format!("{name}.com")];
        }
    }
    vec![name.to_owned()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_files_open_and_links_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(OpenOptions::new().read(true).open_no_follow(&file).is_ok());
        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file, &link).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&file, &link).is_err() {
            // Creating symbolic links needs Developer Mode or a privilege; nothing to test.
            return;
        }
        let err = OpenOptions::new()
            .read(true)
            .open_no_follow(&link)
            .unwrap_err();
        assert!(is_link_refusal(&err), "{err:?}");
        let err = OpenOptions::new()
            .read(true)
            .open_no_follow_nonblocking(&link)
            .unwrap_err();
        assert!(is_link_refusal(&err), "{err:?}");
    }

    #[test]
    fn executables() {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) { "tool.exe" } else { "tool" };
        let tool = dir.path().join(name);
        std::fs::write(&tool, b"x").unwrap();
        set_unix_mode(&tool, 0o755).unwrap();
        assert!(is_executable(&tool, &std::fs::metadata(&tool).unwrap()));
        let script = dir.path().join("script.bat");
        std::fs::write(&script, b"x").unwrap();
        set_unix_mode(&script, 0o644).unwrap();
        assert!(!is_executable(
            &script,
            &std::fs::metadata(&script).unwrap()
        ));
        assert!(!is_executable(
            dir.path(),
            &std::fs::metadata(dir.path()).unwrap()
        ));
    }
}
