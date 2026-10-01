//! The tar reader over arbitrary bytes: every path it hands out must be a plain relative one.
#![no_main]

use jpm::tar;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tar::read_entries(data, |path, _mode, size, body| {
        assert!(tar::plain(path), "unsafe path {path:?}");
        assert!(!path.starts_with('/'), "absolute path {path:?}");
        // Read some of each body, and leave the rest for the reader to skip.
        let mut buf = vec![0u8; size.min(4096) as usize];
        let _ = body.read(&mut buf);
        Ok(())
    });
});
