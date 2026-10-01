//! jpm's modules, compiled as a library for the fuzz targets (see build.rs), and what the
//! targets share.
#![allow(deprecated, dead_code, unused_imports, unused_variables, unused_mut, unexpected_cfgs, clippy::all)]

include!(concat!(env!("OUT_DIR"), "/modules.rs"));

/// A directory of its own for this process, emptied for each input: under /dev/shm where
/// there is one, so extracting writes to memory.
pub fn scratch(what: &str) -> std::path::PathBuf {
    let base = if std::path::Path::new("/dev/shm").is_dir() {
        std::path::PathBuf::from("/dev/shm")
    } else {
        std::env::temp_dir()
    };
    let dir = base.join(format!("jpm-fuzz-{what}-{}", std::process::id()));
    if dir.exists() {
        store::remove_tree(&dir);
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `data` as text, lossily: the parsers take `&str`, and a file read as UTF-8 fails before them.
pub fn text(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}
