//! macOS: APFS copies a whole package directory with one `clonefile`, sharing its blocks.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub use super::unix::{alive, exec, leave_interrupts_to_children, links_to, read_link, symlink_dir};

/// `<sys/clonefile.h>`: do not follow a symlink at `src`. libc does not export it.
const CLONE_NOFOLLOW: u32 = 0x0001;

pub fn libc() -> Option<&'static str> {
    None
}

/// `Ok(false)` where the filesystem cannot clone (not APFS, another volume): link per file.
pub fn clone_dir(src: &Path, dst: &Path) -> io::Result<bool> {
    let from = CString::new(src.as_os_str().as_bytes())?;
    let to = CString::new(dst.as_os_str().as_bytes())?;
    // SAFETY: both are valid NUL-terminated paths that outlive the call.
    if unsafe { libc::clonefile(from.as_ptr(), to.as_ptr(), CLONE_NOFOLLOW) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOTSUP | libc::EXDEV) => Ok(false),
        _ => Err(error),
    }
}
