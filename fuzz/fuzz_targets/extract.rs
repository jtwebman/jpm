//! A tarball as the store unpacks one, gzipped or not: into a directory of its own, and nothing
//! anywhere else. The first byte picks how: bit 0 gzips the rest first, so the tar layer is
//! reached through the decoder (clear hands the rest over as it is, gzip or plain tar); bit 1
//! writes each file with the store's suffix.
#![no_main]

use jpm::store;
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use std::path::Path;

/// Every entry under `dir`: a directory or a regular file, never a link.
fn walk(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let t = std::fs::symlink_metadata(e.path()).unwrap().file_type();
        assert!(!t.is_symlink(), "a link was made: {}", e.path().display());
        if t.is_dir() {
            walk(&e.path());
        } else {
            assert!(t.is_file(), "not a file: {}", e.path().display());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&how, rest)) = data.split_first() else { return };
    let bytes = if how & 1 == 1 {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(rest).unwrap();
        gz.finish().unwrap()
    } else {
        rest.to_vec()
    };
    let parent = jpm::scratch("extract");
    let dest = parent.join("pkg");
    let result = store::extract(&mut &bytes[..], &dest, how & 2 == 2);
    // Nothing beside the destination.
    let beside: Vec<_> = std::fs::read_dir(&parent).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(beside, vec![std::ffi::OsString::from("pkg")], "written outside the destination");
    walk(&dest);
    if let Ok(index) = result {
        for f in &index.files {
            assert!(jpm::tar::plain(&f.path), "unsafe path in the index: {:?}", f.path);
        }
    }
    store::remove_tree(&parent);
});
