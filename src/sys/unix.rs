//! What Linux and macOS share.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

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

pub fn leave_interrupts_to_children() {}

#[allow(dead_code)] // used by unix targets that have no faster copy
pub fn clone_dir(_src: &Path, _dst: &Path) -> io::Result<bool> {
    Ok(false)
}
