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
