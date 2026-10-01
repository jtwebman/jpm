//! jpm's JSON: what parses must write out and read back the same, and skipping a document
//! must accept whatever parsing does.
#![no_main]

use jpm::json;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let parsed = json::parse(text);
    let skipped = json::Scan::new(text).span();
    let Ok(v) = parsed else { return };
    skipped.expect("a value that parses skips");
    // Numbers are written as JavaScript would (`2.5e3` as `2500`): what is written once must
    // read back and write the same.
    let out = json::to_string(&v);
    let back = json::parse(&out).unwrap_or_else(|e| panic!("written JSON does not parse: {e}\n{out}"));
    assert_eq!(json::to_string(&back), out, "round trip differs");
    let pretty = json::to_pretty(&v, "  ");
    let back = json::parse(&pretty).unwrap_or_else(|e| panic!("written JSON does not parse: {e}\n{pretty}"));
    assert_eq!(json::to_string(&back), out, "pretty round trip differs");
});
