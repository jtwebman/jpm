//! Other managers' lockfiles, as `jpm import` and an install that finds one read them. The first
//! byte picks the file; the rest is `package.json`, a NUL, and the lockfile (`{}` and the whole
//! rest when there is no NUL).
#![no_main]

use jpm::foreign;
use jpm::project::RootManifest;
use libfuzzer_sys::fuzz_target;
use std::path::Path;

const FILES: [&str; 5] = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else { return };
    let file = FILES[which as usize % FILES.len()];
    let (manifest, lock) = match rest.iter().position(|b| *b == 0) {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (&b"{}"[..], rest),
    };
    let text = jpm::text(lock);
    let _ = foreign::prefer(file, &text);
    let Ok(manifest) = RootManifest::parse(&jpm::text(manifest), Path::new("/nonexistent/package.json")) else {
        return;
    };
    let _ = foreign::load(file, &text, &manifest, false, &|_| "https://registry.npmjs.org/".to_string());
});
