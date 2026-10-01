//! A version's manifest, as the registry's full or abbreviated document gives it.
#![no_main]

use jpm::manifest::Manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Manifest::from_json(&jpm::text(data)) else { return };
    let _ = m.bins();
    let _ = m.integrity();
});
