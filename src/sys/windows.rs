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
    fn GetFileInformationByHandleEx(file: *mut std::ffi::c_void, class: i32, info: *mut BasicInfo, size: u32) -> i32;
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
            && GetFileInformationByHandleEx(file.as_raw_handle(), 0, &mut basic, size_of::<BasicInfo>() as u32) != 0
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

/// A directory that what is made, created or linked is named relative to (see the unix `Dir`,
/// which holds it open). Here each call joins the path whole: Windows has no `*at` calls.
pub struct Dir {
    path: PathBuf,
}

impl Dir {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_dir() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{} is not a directory", path.display())));
        }
        let verbatim = std::env::var_os("JPM_VERBATIM").is_some();
        let path = if verbatim && path.is_absolute() && !path.to_string_lossy().starts_with(r"\\") {
            PathBuf::from(format!(r"\\?\{}", normalize(path).display()))
        } else {
            path.to_path_buf()
        };
        Ok(Self { path })
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.path.join(rel.replace('/', "\\"))
    }

    pub fn mkdir(&self, rel: &str) -> io::Result<()> {
        std::fs::create_dir(self.at(rel))
    }

    pub fn link(&self, from: &Dir, from_rel: &str, rel: &str) -> io::Result<()> {
        std::fs::hard_link(from.at(from_rel), self.at(rel))
    }

    pub fn create(&self, rel: &str, _mode: u32) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(self.at(rel))
    }

    pub fn is_dir(&self, rel: &str) -> bool {
        self.at(rel).is_dir()
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
}
