//! Operating-system primitives that AgentGuard's security checks are built on.
//!
//! Each function has one Unix and one Windows implementation with the same meaning:
//!
//! | Question | Unix | Windows |
//! |---|---|---|
//! | Is this final path component a link? | `O_NOFOLLOW` | `FILE_FLAG_OPEN_REPARSE_POINT`, then the handle's reparse attribute |
//! | Who owns it? | `st_uid` | the owner SID (the token user, or its default owner when elevated) |
//! | Can anyone else change or read it? | group/other mode bits | allow ACEs for any SID other than the owner and the system |
//! | Is it the same file as before? | device and inode | volume serial and file index |
//! | Can it be executed directly? | an execute bit | an `.exe` or `.com` extension |
//!
//! Nothing here decides policy: callers interpret the answers. Unknown or unreadable answers
//! are reported as errors, never as "safe".

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod access;
pub mod fs;
pub mod identity;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::Job;
