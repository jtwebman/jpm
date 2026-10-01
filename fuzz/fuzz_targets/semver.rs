//! Versions and ranges: lines of the input, each tried as both, and every pair compared.
//! `AtMost` must pick what `max_satisfying("<=v")` picks.
#![no_main]

use jpm::semver;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = jpm::text(data);
    let lines: Vec<&str> = text.split('\n').take(8).collect();
    for l in &lines {
        let _ = semver::parse(l);
        let _ = semver::is_exact(l);
        let _ = semver::valid_range(l);
    }
    let at_most = semver::AtMost::new(lines.iter().copied());
    for a in &lines {
        for b in &lines {
            let _ = semver::satisfies(a, b);
            let _ = semver::satisfies_peer(a, b);
            let _ = semver::intersects(a, b);
            if let (Some(x), Some(y)) = (semver::parse(a), semver::parse(b)) {
                assert_eq!(x.cmp(&y), y.cmp(&x).reverse());
            }
        }
        let _ = semver::max_satisfying(lines.iter().copied(), a);
        let _ = semver::max_satisfying_peer(lines.iter().copied(), a);
        if semver::parse(a).is_some() {
            let want = semver::max_satisfying(lines.iter().copied(), &format!("<={a}"));
            assert_eq!(at_most.find(a), want, "<={a:?} over {lines:?}");
        }
    }
});
