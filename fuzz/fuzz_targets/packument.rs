//! A registry document: parsed, each version read, the release cutoff applied and a version
//! picked, as the resolver does. The input's first line is the range to pick with.
#![no_main]

use jpm::manifest::{Packument, parse_date};
use jpm::{registry, spec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|b| *b == b'\n').unwrap_or(0);
    let range = jpm::text(&data[..split]).into_owned();
    let Ok(doc) = Packument::parse(data[split..].to_vec()) else { return };
    let versions: Vec<String> = doc.versions().map(str::to_string).collect();
    for v in &versions {
        if let Some(m) = doc.version(v) {
            let _ = m.bins();
            let _ = m.integrity();
        }
    }
    for t in doc.time.values() {
        let _ = parse_date(t);
    }
    for r in [range.as_str(), "*", "latest"] {
        if let Ok(s) = spec::parse_dep("a", r) {
            let _ = registry::pick_manifest(&doc, &s);
            let cut = doc.copy().until(&doc.time.clone(), 1_600_000_000_000);
            let _ = registry::pick_manifest(&cut, &s);
        }
    }
});
