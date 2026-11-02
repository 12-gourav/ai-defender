//! Windows system calls. The only module in the workspace allowed to use `unsafe`: every block
//! states why it is sound, and every handle or allocation it obtains is released by a guard.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_STOPPED_ON_SYMLINK, ERROR_SUCCESS, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetTokenInformation, IsWellKnownSid,
    TokenOwner, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid,
    WinCreatorOwnerSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, OpenThread, ResumeThread, CREATE_NO_WINDOW,
    CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
};

use crate::access::{Access, Owner};
use crate::identity::FileId;

/// Raw OS error used for a refused link, so callers can recognise it.
#[allow(clippy::cast_possible_wrap)]
pub(crate) const LINK_REFUSED: i32 = ERROR_STOPPED_ON_SYMLINK as i32;

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`: allow ACEs whose SID
/// follows the mask. Other allow types (object, compound) are treated as granting everything.
const ALLOW_PLAIN: u8 = 0;
const ALLOW_CALLBACK: u8 = 9;
const ALLOW_OTHER: [u8; 3] = [4, 5, 11];

/// Rights that change content, names, attributes or permissions.
const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE
/// Rights that read or execute content, plus every write right.
const ANY_RIGHTS: u32 = WRITE_RIGHTS
    | 0x0000_0001 // FILE_READ_DATA / FILE_LIST_DIRECTORY
    | 0x0000_0008 // FILE_READ_EA
    | 0x0000_0020 // FILE_EXECUTE / FILE_TRAVERSE
    | 0x2000_0000 // GENERIC_EXECUTE
    | 0x8000_0000; // GENERIC_READ

/// `IsReparseTagNameSurrogate`: the reparse point names another file (symbolic link,
/// junction), as opposed to a filter's placeholder such as a OneDrive cloud file.
const NAME_SURROGATE: u32 = 0x2000_0000;

const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the guard owns a handle obtained from a successful call and closes it once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalGuard(HLOCAL);

impl Drop for LocalGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the memory was allocated by the system with LocalAlloc semantics (security
            // descriptors, SID strings) and is freed exactly once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn handle_file_id(file: &File) -> io::Result<FileId> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is a plain C struct; all-zero is a valid value.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: the handle belongs to `file`, which outlives the call; `info` is a valid out
    // pointer of the expected type.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(FileId {
        device: u64::from(info.dwVolumeSerialNumber),
        file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

fn reparse_tag(file: &File) -> io::Result<Option<u32>> {
    // SAFETY: FILE_ATTRIBUTE_TAG_INFO is a plain C struct; all-zero is a valid value.
    let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { zeroed() };
    // SAFETY: the handle belongs to `file`; the buffer is exactly one FILE_ATTRIBUTE_TAG_INFO,
    // as the information class requires.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut info).cast::<c_void>(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(u32::MAX),
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(info.ReparseTag))
}

/// Open `path` without following a final symbolic link or junction. Other reparse points
/// (cloud placeholders) are reopened normally and must be the same file.
pub(crate) fn open_no_follow(opts: &OpenOptions, path: &Path) -> io::Result<File> {
    let mut o = opts.clone();
    o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = o.open(path)?;
    match reparse_tag(&file)? {
        None => Ok(file),
        Some(tag) if tag & NAME_SURROGATE != 0 => Err(io::Error::from_raw_os_error(LINK_REFUSED)),
        Some(_) => {
            let reopened = opts.open(path)?;
            if handle_file_id(&reopened)? == handle_file_id(&file)? {
                Ok(reopened)
            } else {
                Err(io::Error::from_raw_os_error(LINK_REFUSED))
            }
        }
    }
}

/// Volume serial number and file index of the file `path` resolves to.
pub(crate) fn file_id(path: &Path) -> io::Result<FileId> {
    let file = OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    handle_file_id(&file)
}

/// The current process token's user SID and default owner SID.
struct TokenSids {
    // Backing storage for the variable-length TOKEN_USER and TOKEN_OWNER structures; `u64`
    // elements keep them aligned for the pointers they contain.
    user: Vec<u64>,
    owner: Vec<u64>,
}

fn token_information(token: HANDLE, class: i32) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 asks for the required size, written to `len`.
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &raw mut len);
    }
    if len == 0 {
        return Err(last_error());
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes and is 8-byte aligned; `len` is its size.
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr().cast::<c_void>(),
            len,
            &raw mut len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(buf)
}

impl TokenSids {
    fn current() -> io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing; `token` is a
        // valid out pointer and is closed by the guard.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
        if ok == 0 {
            return Err(last_error());
        }
        let _guard = HandleGuard(token);
        Ok(Self {
            user: token_information(token, TokenUser)?,
            owner: token_information(token, TokenOwner)?,
        })
    }

    fn user(&self) -> PSID {
        // SAFETY: `user` was filled by GetTokenInformation(TokenUser) and begins with an aligned
        // TOKEN_USER whose SID pointer points into the same buffer, alive as long as `self`.
        unsafe { (*self.user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn default_owner(&self) -> PSID {
        // SAFETY: as for `user`, with TOKEN_OWNER.
        unsafe { (*self.owner.as_ptr().cast::<TOKEN_OWNER>()).Owner }
    }

    fn is_me(&self, sid: PSID) -> bool {
        sid_eq(sid, self.user()) || sid_eq(sid, self.default_owner())
    }
}

fn sid_eq(a: PSID, b: PSID) -> bool {
    // SAFETY: both point to valid SIDs owned by live buffers for the duration of the call.
    !a.is_null() && !b.is_null() && unsafe { EqualSid(a, b) } != 0
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut out: *mut u16 = null_mut();
    // SAFETY: `sid` is valid; the system allocates the string, freed by the guard below.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut out) };
    if ok == 0 || out.is_null() {
        return Err(last_error());
    }
    let _guard = LocalGuard(out.cast::<c_void>());
    let mut len = 0usize;
    // SAFETY: the string is NUL-terminated; reading up to the terminator stays in bounds.
    while unsafe { *out.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` UTF-16 units precede the terminator in the system-allocated string.
    let units = unsafe { std::slice::from_raw_parts(out, len) };
    Ok(String::from_utf16_lossy(units))
}

fn is_system(sid: PSID) -> bool {
    // SAFETY: `sid` is a valid SID for the duration of the calls.
    let well_known = unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    };
    well_known || sid_string(sid).is_ok_and(|s| s == TRUSTED_INSTALLER)
}

fn is_placeholder(sid: PSID) -> bool {
    // SAFETY: `sid` is a valid SID for the duration of the calls.
    unsafe {
        IsWellKnownSid(sid, WinCreatorOwnerSid) != 0
            || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
    }
}

/// Owner and DACL of `path`.
pub(crate) fn access(path: &Path) -> io::Result<Access> {
    let name = wide(path);
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated UTF-16; the out pointers are valid. On success `owner`
    // and `dacl` point into `descriptor`, which the guard frees after their last use.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS {
        #[allow(clippy::cast_possible_wrap)]
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _descriptor = LocalGuard(descriptor);
    let me = TokenSids::current()?;
    let owner_kind = if me.is_me(owner) {
        Owner::CurrentUser
    } else if !owner.is_null() && is_system(owner) {
        Owner::System
    } else {
        Owner::Other
    };
    let (others_can_write, others_have_access) = if dacl.is_null() {
        // A NULL DACL grants everyone full access.
        (true, true)
    } else {
        scan_dacl(dacl, owner, &me)?
    };
    Ok(Access {
        owner: owner_kind,
        others_can_write,
        others_have_access,
    })
}

fn scan_dacl(dacl: *mut ACL, owner: PSID, me: &TokenSids) -> io::Result<(bool, bool)> {
    // SAFETY: ACL_SIZE_INFORMATION is a plain C struct; all-zero is a valid value.
    let mut size: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    // SAFETY: `dacl` points into a live security descriptor; the buffer matches the class.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut size).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let (mut write, mut any) = (false, false);
    for index in 0..size.AceCount {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `index` is below the ACL's ACE count; `ace` receives a pointer into the ACL.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
            return Err(last_error());
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = if header.AceType == ALLOW_PLAIN || header.AceType == ALLOW_CALLBACK {
            // Plain and callback allow ACEs share ACCESS_ALLOWED_ACE's layout: header, mask,
            // then the SID starting at `SidStart`.
            let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: `allowed` points to a live ACE of that layout inside the DACL; taking the
            // address of its `SidStart` field creates no reference.
            let sid: PSID = unsafe { (&raw mut (*allowed).SidStart).cast::<c_void>() };
            if sid_eq(sid, owner) || me.is_me(sid) || is_system(sid) || is_placeholder(sid) {
                continue;
            }
            // SAFETY: as above.
            unsafe { (*allowed).Mask }
        } else if ALLOW_OTHER.contains(&header.AceType) {
            u32::MAX
        } else {
            continue;
        };
        write |= mask & WRITE_RIGHTS != 0;
        any |= mask & ANY_RIGHTS != 0;
    }
    Ok((write, any))
}

/// The current user's SID as a string.
pub(crate) fn current_user_sid() -> io::Result<String> {
    sid_string(TokenSids::current()?.user())
}

/// A Windows Job Object that kills every process in it when terminated or dropped.
pub struct Job(HANDLE);

impl Job {
    /// A new job: processes in it die when the job is closed and cannot break away.
    pub fn new() -> io::Result<Self> {
        // SAFETY: null attributes and name create an anonymous job owned by this process.
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(last_error());
        }
        let job = Self(handle);
        // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a plain C struct; zero is valid.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        // SAFETY: the buffer is one JOBOBJECT_EXTENDED_LIMIT_INFORMATION, as the class requires.
        let ok = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast::<c_void>(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .unwrap_or(u32::MAX),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(job)
    }

    /// Start `command` suspended, place it in the job, then let it run, so it cannot start a
    /// process outside the job first. Without a console window.
    pub fn spawn(&self, command: &mut Command) -> io::Result<Child> {
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        let mut child = command.spawn()?;
        // SAFETY: both handles are valid: the job is owned by `self`, the process by `child`.
        let assigned =
            unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle().cast()) } != 0;
        if !assigned {
            let e = last_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        if let Err(e) = resume_threads(child.id()) {
            self.terminate();
            let _ = child.wait();
            return Err(e);
        }
        Ok(child)
    }

    /// Kill every process in the job.
    pub fn terminate(&self) {
        // SAFETY: the job handle is valid for the lifetime of `self`.
        unsafe {
            TerminateJobObject(self.0, 1);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by `self` and closed once; closing kills the job's
        // processes (KILL_ON_JOB_CLOSE).
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn resume_threads(pid: u32) -> io::Result<()> {
    // SAFETY: a thread snapshot of the whole system; the guard closes it.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Err(last_error());
    }
    let _snapshot = HandleGuard(snapshot);
    // SAFETY: THREADENTRY32 is a plain C struct; zero is valid once dwSize is set.
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = u32::try_from(size_of::<THREADENTRY32>()).unwrap_or(u32::MAX);
    let mut resumed = 0usize;
    // SAFETY: valid snapshot handle and entry with dwSize set.
    let mut more = unsafe { Thread32First(snapshot, &raw mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: opening a thread by id; a null result is handled.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !thread.is_null() {
                let _thread = HandleGuard(thread);
                // SAFETY: valid thread handle with THREAD_SUSPEND_RESUME access.
                if unsafe { ResumeThread(thread) } != u32::MAX {
                    resumed += 1;
                }
            }
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot, &raw mut entry) } != 0;
    }
    if resumed == 0 {
        Err(io::Error::other("the new process could not be resumed"))
    } else {
        Ok(())
    }
}
