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

pub fn alive(_pid: u32) -> bool {
    true // unknowable without more API; leaving a temp directory behind is the safe side
}

pub fn exec(command: &mut Command) -> io::Result<i32> {
    Ok(command.status()?.code().unwrap_or(1))
}
