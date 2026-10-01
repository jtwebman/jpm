//! A patch file (a project's `patches/*.patch`, cloned, so untrusted) applied to a package in a
//! directory of its own: nothing may be written beside it, and no link made.
#![no_main]

use jpm::{patch, store};
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fn walk(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let t = std::fs::symlink_metadata(e.path()).unwrap().file_type();
        assert!(!t.is_symlink(), "a link was made: {}", e.path().display());
        if t.is_dir() {
            walk(&e.path());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let parent = jpm::scratch("patch");
    let pkg = parent.join("pkg");
    std::fs::create_dir_all(pkg.join("lib")).unwrap();
    std::fs::write(pkg.join("index.js"), "a\nb\nc\n").unwrap();
    std::fs::write(pkg.join("lib/x.js"), "x\r\ny\r\n").unwrap();
    std::fs::write(pkg.join("package.json"), "{\"name\":\"p\",\"version\":\"1.0.0\"}\n").unwrap();
    let _ = patch::apply(&pkg, data, data.first().is_some_and(|b| b & 1 == 1));
    let beside: Vec<_> = std::fs::read_dir(&parent).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(beside, vec![std::ffi::OsString::from("pkg")], "written outside the package");
    walk(&pkg);
    store::remove_tree(&parent);
});
