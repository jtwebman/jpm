//! Linux: hardlinks file by file, and the C library read off the loader that is installed.

pub use super::unix::{alive, clone_dir, exec, links_to, read_link, symlink_dir};

/// musl's loader is `/lib/ld-musl-<arch>.so.1`; a system without one is glibc. Read off the
/// system, not this binary, which is static and would say musl on any machine.
pub fn libc() -> Option<&'static str> {
    let musl = std::fs::read_dir("/lib")
        .map(|dir| dir.flatten().any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-")))
        .unwrap_or(false);
    Some(if musl { "musl" } else { "glibc" })
}
