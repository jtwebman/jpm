//! Everything that differs by operating system. Exactly one of the files below is compiled for a
//! target, and each provides the same functions, so the rest of the crate calls `sys::…` and
//! never asks which OS it is on.
//!
//! - `clone_dir(src, dst)`: copy a whole package directory in one step where the filesystem can
//!   (macOS `clonefile`); `Ok(false)` means "not here", and the caller links file by file.
//! - `symlink_dir(target, at)`: a link to a directory, `target` relative to `at`'s directory.
//! - `read_link(at)`: a link's target as `symlink_dir` was given it.
//! - `alive(pid)`: whether a process could still be writing under that pid.
//! - `libc()`: `glibc` or `musl` on Linux, `None` elsewhere.
//! - `exec(command)`: run a command in place of this process, returning only on failure or,
//!   where a process cannot be replaced, with the command's exit code.

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
#[cfg(windows)]
pub use windows::*;

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub use unix::{alive, clone_dir, exec, read_link, symlink_dir};
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub fn libc() -> Option<&'static str> {
    None
}

/// What a package's `os`, `cpu` and `libc` fields are matched against, in Node's spelling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Platform {
    pub os: String,
    pub cpu: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.os, self.cpu)?;
        if let Some(libc) = &self.libc {
            write!(f, "-{libc}")?;
        }
        Ok(())
    }
}
