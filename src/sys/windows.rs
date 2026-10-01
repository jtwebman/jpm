//! Windows: a directory link is a junction, which needs no privilege but must be absolute, and a
//! process cannot be replaced, only waited on.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn libc() -> Option<&'static str> {
    None
}

pub fn clone_dir(_src: &Path, _dst: &Path) -> io::Result<bool> {
    Ok(false)
}

pub fn symlink_dir(target: &str, at: &Path) -> io::Result<()> {
    let absolute = at.parent().unwrap_or(Path::new(".")).join(target);
    junction::create(normalize(&absolute), at)
}

/// Absolute, as a junction holds it: whether it was made from a relative target or an absolute
/// one (a link into the global store) is not recorded.
pub fn read_link(at: &Path) -> Option<String> {
    let target = junction::get_target(at).or_else(|_| std::fs::read_link(at)).ok()?;
    let target = if target.is_absolute() { target } else { normalize(&at.parent()?.join(target)) };
    Some(target.to_string_lossy().into_owned())
}

/// Compared resolved, and without case, as NTFS compares names: a project opened as
/// `c:\users\…` is the one linked as `C:\Users\…`.
pub fn links_to(at: &Path, target: &str) -> bool {
    let Some(have) = read_link(at) else { return false };
    let want = normalize(&at.parent().unwrap_or(Path::new(".")).join(target));
    have.to_lowercase() == want.to_string_lossy().to_lowercase()
}

/// `..` resolved without touching the disk: a junction target must be a clean absolute path.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[repr(C)]
struct CertContext {
    encoding: u32,
    encoded: *const u8,
    len: u32,
    info: *mut std::ffi::c_void,
    store: *mut std::ffi::c_void,
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CertOpenSystemStoreW(prov: usize, name: *const u16) -> *mut std::ffi::c_void;
    fn CertEnumCertificatesInStore(store: *mut std::ffi::c_void, prev: *const CertContext) -> *const CertContext;
    fn CertCloseStore(store: *mut std::ffi::c_void, flags: u32) -> i32;
}

/// The current user's `ROOT` store, which takes in the machine's and group policy's roots: where
/// a company installs the root of its TLS-inspecting proxy.
pub fn system_roots() -> Vec<Vec<u8>> {
    let name: Vec<u16> = "ROOT\0".encode_utf16().collect();
    let mut out = Vec::new();
    // SAFETY: the store is opened, walked (each call frees the context before it) and closed
    // here; each certificate's bytes are copied out while its context is live.
    unsafe {
        let store = CertOpenSystemStoreW(0, name.as_ptr());
        if store.is_null() {
            return out;
        }
        let mut cert = CertEnumCertificatesInStore(store, std::ptr::null());
        while !cert.is_null() {
            let c = &*cert;
            if !c.encoded.is_null() {
                out.push(std::slice::from_raw_parts(c.encoded, c.len as usize).to_vec());
            }
            cert = CertEnumCertificatesInStore(store, cert);
        }
        CertCloseStore(store, 0);
    }
    out
}

/// `BY_HANDLE_FILE_INFORMATION`. A `FILETIME` is two `u32`s, aligned as one: a `u64` here would
/// pad the struct and shift every field after it.
#[repr(C)]
#[derive(Default)]
struct ByHandleInfo {
    attributes: u32,
    created: [u32; 2],
    accessed: [u32; 2],
    written: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

/// `FILE_BASIC_INFO`.
#[repr(C)]
#[derive(Default)]
struct BasicInfo {
    created: i64,
    accessed: i64,
    written: i64,
    changed: i64,
    attributes: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(file: *mut std::ffi::c_void, info: *mut ByHandleInfo) -> i32;
    fn GetFileInformationByHandleEx(
        file: *mut std::ffi::c_void,
        class: i32,
        info: *mut std::ffi::c_void,
        size: u32,
    ) -> i32;
}

/// What `stat` gives unix and std does not give Windows: the change time (moved by any write,
/// and set back by no ordinary tool), the file's index on its volume, and its hardlink count.
pub struct FileInfo {
    pub changed: i64,
    pub index: u64,
    pub links: u32,
}

pub fn file_info(path: &Path) -> Option<FileInfo> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000; // directories open too
    let file = std::fs::OpenOptions::new().access_mode(0).custom_flags(BACKUP_SEMANTICS).open(path).ok()?;
    let (mut by, mut basic) = (ByHandleInfo::default(), BasicInfo::default());
    // SAFETY: the handle is live for both calls and each writes only the struct it is given.
    let ok = unsafe {
        GetFileInformationByHandle(file.as_raw_handle(), &mut by) != 0
            && GetFileInformationByHandleEx(
                file.as_raw_handle(),
                0,
                (&raw mut basic).cast(),
                size_of::<BasicInfo>() as u32,
            ) != 0
    };
    ok.then(|| FileInfo {
        changed: basic.changed,
        index: (u64::from(by.index_high) << 32) | u64::from(by.index_low),
        links: by.links,
    })
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
    fn GetExitCodeProcess(process: *mut std::ffi::c_void, code: *mut u32) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

/// Whether the process can still be writing. One that cannot be opened for another reason than
/// not existing (another user's) counts as alive: leaving a temp directory is the safe side.
pub fn alive(pid: u32) -> bool {
    const QUERY_LIMITED: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    const INVALID_PARAMETER: i32 = 87; // no such process
    // SAFETY: the handle is checked, used for one query and closed.
    unsafe {
        let process = OpenProcess(QUERY_LIMITED, 0, pid);
        if process.is_null() {
            return io::Error::last_os_error().raw_os_error() != Some(INVALID_PARAMETER);
        }
        let mut code = 0;
        let running = GetExitCodeProcess(process, &mut code) == 0 || code == STILL_ACTIVE;
        CloseHandle(process);
        running
    }
}

pub fn exec(command: &mut Command) -> io::Result<i32> {
    let _children = leave_interrupts_to_children();
    Ok(command.status()?.code().unwrap_or(1))
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
}

unsafe extern "system" fn handled(_event: u32) -> i32 {
    1
}

/// Ctrl+C reaches every process on the console. jpm waits for its child to act on it and exits
/// with the child's code, as `exec` does on unix, instead of leaving it running behind the prompt.
/// A handler, not the ignore flag, which children would inherit. Only while the returned value
/// lives: between children, Ctrl+C ends jpm itself (taking its progress line off first).
pub fn leave_interrupts_to_children() -> Interrupts {
    // SAFETY: registers a handler that only returns; it touches nothing.
    unsafe { SetConsoleCtrlHandler(Some(handled), 1) };
    Interrupts
}

pub struct Interrupts;

impl Drop for Interrupts {
    fn drop(&mut self) {
        // SAFETY: removes the handler registered with this value.
        unsafe { SetConsoleCtrlHandler(Some(handled), 0) };
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetConsoleMode(console: *mut std::ffi::c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(console: *mut std::ffi::c_void, mode: u32) -> i32;
}

/// A console takes escape sequences once asked to (Windows 10 and later); Windows Terminal
/// already does. Not a console (a pipe, mintty): false.
pub fn vt() -> bool {
    use std::os::windows::io::AsRawHandle;
    const VIRTUAL_TERMINAL_PROCESSING: u32 = 0x4;
    let console = std::io::stderr().as_raw_handle();
    let mut mode = 0;
    // SAFETY: stderr's handle, live for the process; each call reads or sets only its mode.
    unsafe {
        GetConsoleMode(console, &mut mode) != 0
            && (mode & VIRTUAL_TERMINAL_PROCESSING != 0
                || SetConsoleMode(console, mode | VIRTUAL_TERMINAL_PROCESSING) != 0)
    }
}

static UNDO: std::sync::Mutex<&str> = std::sync::Mutex::new("");

/// Runs on a thread of its own; not handled, so the default handler ends the process next.
unsafe extern "system" fn undo_then_exit(_event: u32) -> i32 {
    let text = *UNDO.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = io::Write::write_all(&mut io::stderr(), text.as_bytes());
    0
}

pub fn on_interrupt(undo: Option<&'static str>) {
    *UNDO.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = undo.unwrap_or("");
    // SAFETY: registers or removes a handler that only writes to stderr.
    unsafe { SetConsoleCtrlHandler(Some(undo_then_exit), i32::from(undo.is_some())) };
}

/// `UNICODE_STRING`.
#[repr(C)]
struct NtName {
    len: u16,
    max: u16,
    buf: *const u16,
}

/// `OBJECT_ATTRIBUTES`.
#[repr(C)]
struct ObjectAttributes {
    len: u32,
    root: *mut std::ffi::c_void,
    name: *const NtName,
    attributes: u32,
    security: *mut std::ffi::c_void,
    qos: *mut std::ffi::c_void,
}

/// `IO_STATUS_BLOCK`.
#[repr(C)]
struct IoStatus {
    status: usize,
    info: usize,
}

/// `FILE_LINK_INFORMATION` up to its name, which follows `name_len`.
#[repr(C)]
struct LinkInfo {
    replace: u8,
    root: *mut std::ffi::c_void,
    name_len: u32,
}

/// `FILE_ID_INFO`: the volume and the file's 128-bit id, which name a file on any file system.
#[repr(C)]
#[derive(Default, PartialEq, Eq)]
struct IdInfo {
    volume: u64,
    id: [u8; 16],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        handle: *mut *mut std::ffi::c_void,
        access: u32,
        attributes: *const ObjectAttributes,
        status: *mut IoStatus,
        size: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const std::ffi::c_void,
        ea_len: u32,
    ) -> i32;
    fn NtSetInformationFile(
        handle: *mut std::ffi::c_void,
        status: *mut IoStatus,
        info: *const std::ffi::c_void,
        len: u32,
        class: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_LIST_DIRECTORY: u32 = 0x1;
const FILE_ADD_FILE: u32 = 0x2;
const FILE_ADD_SUBDIRECTORY: u32 = 0x4;
const FILE_TRAVERSE: u32 = 0x20;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const SHARE_ALL: u32 = 0x7;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_OPEN_BY_FILE_ID: u32 = 0x2000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_LINK_INFORMATION: u32 = 11;
const FILE_ID_INFO: i32 = 18;

/// The access a `Dir` holds its directory with: enough to make, create and link in it.
const DIR_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE;
/// Enough to open and link what is in it.
const DIR_READ: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE;

/// An NTSTATUS as the Win32 error the same call through kernel32 would set, so `ErrorKind`s match.
fn nt_error(status: i32) -> io::Error {
    // SAFETY: a pure mapping from one code to another.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

/// `rel` under `root`, as `NtCreateFile` takes a name relative to a directory handle: `\`
/// between parts, never leaving it. Not case-sensitive, as Win32 opens are.
fn nt_open(
    root: &std::os::windows::io::OwnedHandle,
    rel: &[u16],
    access: u32,
    disposition: u32,
    options: u32,
) -> io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    let bytes = u16::try_from(rel.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidFilename))?;
    let name = NtName { len: bytes, max: bytes, buf: rel.as_ptr() };
    let attributes = ObjectAttributes {
        len: size_of::<ObjectAttributes>() as u32,
        root: root.as_raw_handle(),
        name: &name,
        attributes: OBJ_CASE_INSENSITIVE,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    let (mut handle, mut status) = (std::ptr::null_mut(), IoStatus { status: 0, info: 0 });
    // SAFETY: every pointer is to a live local; on success the handle is new and ours alone.
    let st = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if st < 0 {
        return Err(nt_error(st));
    }
    // SAFETY: `NtCreateFile` succeeded, so `handle` is an open handle nothing else owns.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) })
}

/// A relative path in NT's form; an absolute one, a drive or a stream would leave the directory.
fn nt_rel(rel: &str) -> io::Result<Vec<u16>> {
    if rel.is_empty() || rel.starts_with(['/', '\\']) || rel.contains(':') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{rel} is not a relative path")));
    }
    Ok(rel.encode_utf16().map(|c| if c == u16::from(b'/') { u16::from(b'\\') } else { c }).collect())
}

fn id_of(handle: &std::os::windows::io::OwnedHandle) -> Option<IdInfo> {
    use std::os::windows::io::AsRawHandle;
    let mut info = IdInfo::default();
    // SAFETY: a live handle, and a buffer the size the call is told.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FILE_ID_INFO,
            (&raw mut info).cast(),
            size_of::<IdInfo>() as u32,
        )
    };
    (ok != 0).then_some(info)
}

/// The directory `path` names, open, by its file id where the file system allows: what is named
/// relative to a handle opened by path is checked by the file system filters (Windows Defender
/// among them) from the whole path, one parent directory read at a time for every link, where
/// one opened by id has its name from the file system. A link took half the CPU. The id is
/// checked against the directory's own: a 64-bit index can name another file on ReFS.
fn open_dir(path: &Path) -> io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::fs::OpenOptionsExt;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000; // directories open too
    let open = |access| {
        std::fs::OpenOptions::new().access_mode(access).share_mode(SHARE_ALL).custom_flags(BACKUP_SEMANTICS).open(path)
    };
    // One that may only be read (a store on a read-only share) is still one to link out of.
    let (by_path, access) = match open(DIR_ACCESS) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => (open(DIR_READ)?, DIR_READ),
        other => (other?, DIR_ACCESS),
    };
    let by_path = std::os::windows::io::OwnedHandle::from(by_path);
    let mut by = ByHandleInfo::default();
    // SAFETY: a live handle, and the struct the call fills.
    let indexed =
        unsafe { GetFileInformationByHandle(std::os::windows::io::AsRawHandle::as_raw_handle(&by_path), &mut by) } != 0;
    let (Some(id), true) = (id_of(&by_path), indexed) else { return Ok(by_path) };
    let index = (u64::from(by.index_high) << 32) | u64::from(by.index_low);
    let index: Vec<u16> = index.to_ne_bytes().chunks(2).map(|b| u16::from_ne_bytes([b[0], b[1]])).collect();
    match nt_open(&by_path, &index, access, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID) {
        Ok(by_id) if id_of(&by_id).is_some_and(|other| other == id) => Ok(by_id),
        _ => Ok(by_path),
    }
}

/// A directory that what is made, created or linked is named relative to, held open, as the unix
/// `Dir` holds its fd: each call names only the path under it (see `open_dir`).
pub struct Dir {
    handle: std::os::windows::io::OwnedHandle,
}

impl Dir {
    pub fn open(path: &Path) -> io::Result<Self> {
        let handle = open_dir(path)?;
        Ok(Self { handle })
    }

    /// The directory `rel`, whose parent is there.
    pub fn mkdir(&self, rel: &str) -> io::Result<()> {
        let access = FILE_LIST_DIRECTORY | SYNCHRONIZE;
        nt_open(&self.handle, &nt_rel(rel)?, access, FILE_CREATE, FILE_DIRECTORY_FILE).map(drop)
    }

    /// `rel` as a hard link to `from`'s file `from_rel`, as `CreateHardLinkW` makes one: the file
    /// opened as itself (a reparse point too), its new name given relative to this directory.
    pub fn link(&self, from: &Dir, from_rel: &str, rel: &str) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        let access = FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
        let options = FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT;
        let file = nt_open(&from.handle, &nt_rel(from_rel)?, access, FILE_OPEN, options)?;
        let name = nt_rel(rel)?;
        let at = std::mem::offset_of!(LinkInfo, name_len) + size_of::<u32>();
        let mut info = vec![0u8; (at + name.len() * 2).max(size_of::<LinkInfo>())];
        let head = LinkInfo { replace: 0, root: self.handle.as_raw_handle(), name_len: (name.len() * 2) as u32 };
        // SAFETY: `info` is at least a `LinkInfo` long, written unaligned; the name follows its
        // length field, as `FILE_LINK_INFORMATION` lays it out.
        unsafe { std::ptr::write_unaligned(info.as_mut_ptr().cast::<LinkInfo>(), head) };
        for (i, c) in name.iter().enumerate() {
            info[at + i * 2..at + i * 2 + 2].copy_from_slice(&c.to_ne_bytes());
        }
        let mut status = IoStatus { status: 0, info: 0 };
        let len = u32::try_from(info.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidFilename))?;
        // SAFETY: a live handle, and a buffer of the length given that the call only reads.
        let st = unsafe {
            NtSetInformationFile(file.as_raw_handle(), &mut status, info.as_ptr().cast(), len, FILE_LINK_INFORMATION)
        };
        if st < 0 { Err(nt_error(st)) } else { Ok(()) }
    }

    /// The file `rel`, created (or emptied) for writing. The mode is unix's alone.
    pub fn create(&self, rel: &str, _mode: u32) -> io::Result<std::fs::File> {
        let file =
            nt_open(&self.handle, &nt_rel(rel)?, FILE_GENERIC_WRITE, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE)?;
        Ok(std::fs::File::from(file))
    }

    /// Whether `rel` is a directory, through a link as `Path::is_dir` goes.
    pub fn is_dir(&self, rel: &str) -> bool {
        let access = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        nt_rel(rel).is_ok_and(|rel| nt_open(&self.handle, &rel, access, FILE_OPEN, FILE_DIRECTORY_FILE).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_ctrl_c_to_children_only_while_they_run() {
        // Removing a handler that is not registered fails: that is how to see it is gone.
        let remove = || unsafe { SetConsoleCtrlHandler(Some(handled), 0) };
        let children = leave_interrupts_to_children();
        assert_ne!(remove(), 0, "registered while children run");
        unsafe { SetConsoleCtrlHandler(Some(handled), 1) };
        drop(children);
        assert_eq!(remove(), 0, "still registered: Ctrl+C would never end jpm again");
    }

    #[test]
    fn reads_file_identity_and_links() {
        assert_eq!(size_of::<ByHandleInfo>(), 52);
        assert_eq!(size_of::<BasicInfo>(), 40);
        let dir = std::env::temp_dir().join(format!("jpm-fileinfo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), "some bytes").unwrap();
        assert_eq!(file_info(&dir.join("a")).unwrap().links, 1);
        std::fs::hard_link(dir.join("a"), dir.join("b")).unwrap();
        let (a, b) = (file_info(&dir.join("a")).unwrap(), file_info(&dir.join("b")).unwrap());
        assert_eq!((a.links, b.links), (2, 2));
        assert_eq!(a.index, b.index);
        std::fs::write(dir.join("c"), "x").unwrap();
        assert_ne!(file_info(&dir.join("c")).unwrap().index, a.index);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn makes_creates_and_links_relative_to_a_held_directory() {
        use std::io::Write;
        assert_eq!(size_of::<IdInfo>(), 24);
        assert_eq!(
            std::mem::offset_of!(LinkInfo, name_len) + 4,
            if cfg!(target_pointer_width = "64") { 20 } else { 12 }
        );
        let root = std::env::temp_dir().join(format!("jpm-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("from")).unwrap();
        std::fs::create_dir_all(root.join("to")).unwrap();
        let (from, to) = (Dir::open(&root.join("from")).unwrap(), Dir::open(&root.join("to")).unwrap());
        // Made and created by the path under the directory, `/` between its parts.
        from.mkdir("lib").unwrap();
        assert_eq!(from.mkdir("lib").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(from.is_dir("lib") && !from.is_dir("lib/x.js") && !from.is_dir("none"));
        from.create("lib/x.js", 0o444).unwrap().write_all(b"x").unwrap();
        // Emptied when created again, as `File::create` does.
        from.create("lib/x.js", 0o444).unwrap().write_all(b"y").unwrap();
        assert_eq!(std::fs::read(root.join("from/lib/x.js")).unwrap(), b"y");
        // Linked under another name in another directory: one file.
        to.mkdir("dist").unwrap();
        to.link(&from, "lib/x.js", "dist/x.js").unwrap();
        assert_eq!(file_info(&root.join("to/dist/x.js")).unwrap().links, 2);
        assert_eq!(std::fs::read(root.join("to/dist/x.js")).unwrap(), b"y");
        assert_eq!(to.link(&from, "lib/x.js", "dist/x.js").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(to.link(&from, "lib/none.js", "dist/none.js").unwrap_err().kind(), io::ErrorKind::NotFound);
        // Names are compared without case, as NTFS compares them through Win32.
        assert!(to.is_dir("DIST"));
        // Nothing outside the directory is named through it.
        for bad in ["", "/abs", "\\abs", "C:x", "C:\\x", "a:stream", "../x"] {
            assert!(to.create(bad, 0o644).is_err(), "{bad:?}");
        }
        assert!(!root.join("x").exists());
        assert!(Dir::open(&root.join("none")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
