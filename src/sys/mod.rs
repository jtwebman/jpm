//! Everything that differs by operating system. Exactly one of the files below is compiled for a
//! target, and each provides the same functions, so the rest of the crate calls `sys::…` and
//! never asks which OS it is on.
//!
//! - `clone_dir(src, dst)`: copy a whole package directory in one step where the filesystem can
//!   (macOS `clonefile`); `Ok(false)` means "not here", and the caller links file by file.
//! - `symlink_dir(target, at)`: a link to a directory, `target` relative to `at`'s directory.
//! - `read_link(at)`: a link's target: as `symlink_dir` was given it on unix, absolute on
//!   Windows, where a junction keeps no other form.
//! - `links_to(at, target)`: whether the link at `at` leads where `symlink_dir(target, at)`
//!   would make it, whichever form `target` is in.
//! - `alive(pid)`: whether a process could still be writing under that pid.
//! - `libc()`: `glibc` or `musl` on Linux, `None` elsewhere.
//! - `system_roots()`: the certificates the OS trusts (DER): the Windows `ROOT` store, the Linux
//!   CA bundle; none on macOS, whose keychain is not read yet.
//! - `exec(command)`: run a command in place of this process, returning only on failure or,
//!   where a process cannot be replaced, with the command's exit code.
//! - `leave_interrupts_to_children()`: while the value it returns lives (around a child's wait),
//!   Ctrl+C is the children's to act on (Windows; unix delivers it to the whole process group).
//! - `vt()`: whether stderr takes escape sequences (turned on for a Windows console that can).
//! - `cap_malloc_arenas()`: glibc's malloc held to one arena per core (Linux; nothing elsewhere).
//! - `FOLDS_CASE`: whether `Foo.js` and `foo.js` are one file, as on a Mac's or Windows's
//!   disk by default.
//! - `on_interrupt(undo)`: Ctrl+C writes `undo` to stderr before ending the process as before;
//!   `None` stops that.

#[cfg(unix)]
mod unix;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests {
    #[test]
    fn knows_whether_a_process_is_alive() {
        assert!(super::alive(std::process::id()));
        let mut child = std::process::Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) { &["/c", "exit"][..] } else { &[][..] })
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(!super::alive(pid));
    }
}
#[cfg(windows)]
pub use windows::*;

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub use unix::{
    Dir, alive, clone_dir, exec, leave_interrupts_to_children, links_to, on_interrupt, read_link, symlink_dir, vt,
};
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub fn libc() -> Option<&'static str> {
    None
}
#[cfg(not(target_os = "linux"))]
pub fn cap_malloc_arenas() {}
#[cfg(all(unix, not(target_os = "linux")))]
pub fn system_roots() -> Vec<Vec<u8>> {
    Vec::new()
}

// ponytail: by OS, not by volume; a case-sensitive APFS volume keeps one of two case twins too.
pub const FOLDS_CASE: bool = cfg!(any(target_os = "macos", windows));

/// What a package's `os`, `cpu` and `libc` fields are matched against, in Node's spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub cpu: String,
    pub libc: Option<String>,
}

impl Platform {
    pub fn current() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            "windows" => "win32",
            other => other,
        };
        let cpu = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            "x86" => "ia32",
            "powerpc64" => "ppc64",
            "loongarch64" => "loong64",
            other => other,
        };
        Self { os: os.into(), cpu: cpu.into(), libc: libc().map(str::to_string) }
    }
}

impl Platform {
    /// `{"os","cpu","libc"}`, as the install state records it.
    pub fn to_value(&self) -> crate::json::Value {
        let mut o = crate::json::Object::new();
        o.insert("os", self.os.as_str().into());
        o.insert("cpu", self.cpu.as_str().into());
        if let Some(libc) = &self.libc {
            o.insert("libc", libc.as_str().into());
        }
        o.into()
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.os, self.cpu)?;
        if let Some(libc) = &self.libc {
            write!(f, "-{libc}")?;
        }
        Ok(())
    }
}
