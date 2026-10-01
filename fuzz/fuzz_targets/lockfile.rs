//! jpm.lock: read and validated as `read_lockfile` does; one that is accepted must write back
//! out and read again.
#![no_main]

use jpm::lock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = jpm::text(data);
    let Ok(lock) = lock::parse_lockfile(&text, "jpm.lock") else { return };
    let _ = lock::tally(&lock);
    let _ = lock::recorded_keys(&lock);
    let _ = lock::content_hash(&lock);
    let _ = lock::from_lockfile(&lock, &|_| "https://registry.npmjs.org/".to_string());
    let written = lock::format_lockfile(&lock).expect("a validated lockfile formats");
    if let Err(e) = lock::parse_lockfile(&written, "jpm.lock") {
        panic!("jpm.lock written from an accepted one does not read back: {e}\n{written}");
    }
});
