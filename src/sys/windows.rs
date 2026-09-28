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

/// A junction reads back absolute; given back relative to `at`'s directory, as it was made.
pub fn read_link(at: &Path) -> Option<String> {
    let target = junction::get_target(at).or_else(|_| std::fs::read_link(at)).ok()?;
    if !target.is_absolute() {
        return Some(target.to_string_lossy().into_owned());
    }
    let from = at.parent()?;
    Some(crate::util::relative(from, &target).to_string_lossy().into_owned())
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
