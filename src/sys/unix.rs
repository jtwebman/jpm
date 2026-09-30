//! What Linux and macOS share.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

pub fn symlink_dir(target: &str, at: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

pub fn read_link(at: &Path) -> Option<String> {
    std::fs::read_link(at).ok().map(|p| p.to_string_lossy().into_owned())
}

pub fn links_to(at: &Path, target: &str) -> bool {
    read_link(at).as_deref() == Some(target)
}

pub fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return true };
    // SAFETY: signal 0 only asks whether the process exists; nothing is sent.
    let found = unsafe { libc::kill(pid, 0) } == 0;
    found || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Replaces this process, so signals and the exit code are the command's own.
pub fn exec(command: &mut Command) -> io::Result<i32> {
    Err(command.exec())
}

/// Nothing to hold: unix delivers Ctrl+C to the whole process group.
pub struct Interrupts;

pub fn leave_interrupts_to_children() -> Interrupts {
    Interrupts
}

/// A terminal takes escape sequences as they are.
pub fn vt() -> bool {
    true
}

static UNDO: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static UNDO_LEN: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupted(signal: libc::c_int) {
    let text = UNDO.load(Ordering::SeqCst);
    // SAFETY: `write` and `raise` are async-signal-safe; the text is 'static.
    unsafe {
        if !text.is_null() {
            libc::write(2, text.cast(), UNDO_LEN.load(Ordering::SeqCst));
        }
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

/// `Some(text)`: Ctrl+C writes it to stderr, then ends the process as it would have. `None`
/// puts Ctrl+C back as it was. A process that ignores Ctrl+C goes on ignoring it.
pub fn on_interrupt(undo: Option<&'static str>) {
    let handler = interrupted as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only reads the statics set before it is installed.
    unsafe {
        match undo {
            Some(text) => {
                UNDO_LEN.store(text.len(), Ordering::SeqCst);
                UNDO.store(text.as_ptr().cast_mut(), Ordering::SeqCst);
                if libc::signal(libc::SIGINT, handler) == libc::SIG_IGN {
                    libc::signal(libc::SIGINT, libc::SIG_IGN);
                } else {
                    ARMED.store(true, Ordering::SeqCst);
                }
            }
            None if ARMED.swap(false, Ordering::SeqCst) => {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
            }
            None => {}
        }
    }
}

#[allow(dead_code)] // used by unix targets that have no faster copy
pub fn clone_dir(_src: &Path, _dst: &Path) -> io::Result<bool> {
    Ok(false)
}

/// A directory held open: what is made, created or linked under it is named by a path relative
/// to it, so each call walks that path alone, not the whole absolute one again. Thousands of
/// files go into each install's entries, under paths a dozen directories deep.
pub struct Dir {
    fd: std::os::fd::OwnedFd,
}

impl Dir {
    pub fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file =
            std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC).open(path)?;
        Ok(Self { fd: file.into() })
    }

    /// The directory `rel`, whose parent is there.
    pub fn mkdir(&self, rel: &str) -> io::Result<()> {
        // SAFETY: a valid fd and a NUL-terminated path that outlives the call.
        with_rel(rel, |p| unsafe { libc::mkdirat(self.raw(), p, 0o777) })
    }

    /// `rel` as a hard link to `from`'s file `from_rel`.
    pub fn link(&self, from: &Dir, from_rel: &str, rel: &str) -> io::Result<()> {
        let mut linked = Ok(());
        with_rel(from_rel, |old| {
            // SAFETY: valid fds and NUL-terminated paths that outlive the call; no flags, so a
            // symlink is linked as itself, as `std::fs::hard_link` does.
            linked = with_rel(rel, |new| unsafe { libc::linkat(from.raw(), old, self.raw(), new, 0) });
            0
        })?;
        linked
    }

    /// The file `rel`, created (or emptied) for writing, with this mode if it is new.
    pub fn create(&self, rel: &str, mode: u32) -> io::Result<std::fs::File> {
        use std::os::fd::FromRawFd;
        let mut fd = -1;
        with_rel(rel, |p| {
            let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC;
            // SAFETY: a valid fd and a NUL-terminated path that outlives the call.
            fd = unsafe { libc::openat(self.raw(), p, flags, mode as libc::c_uint) };
            fd
        })?;
        // SAFETY: `openat` returned a new fd that nothing else owns.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// Whether `rel` is a directory, through a symlink as `Path::is_dir` goes.
    pub fn is_dir(&self, rel: &str) -> bool {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid fd, a NUL-terminated path that outlives the call, and room for a stat.
        let found = with_rel(rel, |p| unsafe { libc::fstatat(self.raw(), p, st.as_mut_ptr(), 0) }).is_ok();
        // SAFETY: `fstatat` succeeded, so it filled `st`.
        found && unsafe { st.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn raw(&self) -> libc::c_int {
        use std::os::fd::AsRawFd;
        self.fd.as_raw_fd()
    }
}

/// `f` over `rel` as a C string, from the stack when it is short; its `-1` as the OS error. An
/// absolute path would leave the directory, so none is taken.
fn with_rel(rel: &str, f: impl FnOnce(*const libc::c_char) -> libc::c_int) -> io::Result<()> {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a relative path: {rel:?}")));
    }
    let mut stack = [0u8; 256];
    let owned;
    let p = if rel.len() < stack.len() {
        stack[..rel.len()].copy_from_slice(rel.as_bytes());
        stack.as_ptr()
    } else {
        owned = std::ffi::CString::new(rel)?;
        owned.as_ptr().cast()
    };
    if f(p.cast()) == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
