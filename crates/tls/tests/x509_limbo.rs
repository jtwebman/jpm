//! x509-limbo (https://github.com/C2SP/x509-limbo): every server test case whose features
//! jpm-tls supports, against the expected result and against webpki.
//!
//! limbo.json is over 8 MB gzipped, so it is not in the repository. Fetch it and run:
//!
//!     curl -LO https://raw.githubusercontent.com/C2SP/x509-limbo/main/limbo.json
//!     LIMBO_JSON=limbo.json cargo test -p jpm-tls --release --test x509_limbo -- --ignored --nocapture
//!
//! or put it gzipped at tests/data/limbo.json.gz.

mod x509_util;

use std::collections::BTreeMap;
use std::io::Read;

use serde_json::Value;
use x509_util::*;

fn load() -> Value {
    let gz = format!("{}/tests/data/limbo.json.gz", env!("CARGO_MANIFEST_DIR"));
    let text = match std::fs::File::open(&gz) {
        Ok(f) => {
            let mut s = String::new();
            flate2::read::GzDecoder::new(f).read_to_string(&mut s).unwrap();
            s
        }
        Err(_) => {
            let path = std::env::var("LIMBO_JSON").expect("limbo.json: set LIMBO_JSON or add tests/data/limbo.json.gz");
            std::fs::read_to_string(path).unwrap()
        }
    };
    serde_json::from_str(&text).unwrap()
}

/// Seconds since the epoch for an RFC 3339 time in UTC, as limbo writes them.
fn epoch(s: &str) -> u64 {
    let n = |r: std::ops::Range<usize>| s[r].parse::<i64>().unwrap();
    let (y, m, d) = (n(0..4), n(5..7), n(8..10));
    // Fractions of a second are dropped.
    let zone = s[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    assert!(zone == "+00:00" || zone == "Z", "{s}");
    // Days from civil, after Howard Hinnant.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days * 86400 + n(11..13) * 3600 + n(14..16) * 60 + n(17..19)) as u64
}

/// Why a case is skipped, if it is.
fn skip(tc: &Value) -> Option<&'static str> {
    let features: Vec<&str> = tc["features"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
    if tc["validation_kind"] != "SERVER" {
        return Some("client validation");
    }
    if features.contains(&"has-crl") {
        return Some("revocation (not checked, as in rustls by default)");
    }
    if features.contains(&"has-mldsa") {
        return Some("ML-DSA");
    }
    if features.contains(&"max-chain-depth") || !tc["max_chain_depth"].is_null() {
        return Some("a configured maximum depth");
    }
    let eku = tc["extended_key_usage"].as_array().unwrap();
    if !eku.is_empty() && eku.iter().any(|e| e != "serverAuth") {
        return Some("an EKU other than serverAuth");
    }
    if !tc["key_usage"].as_array().unwrap().is_empty() {
        return Some("a required key usage");
    }
    if !tc["signature_algorithms"].as_array().unwrap().is_empty() {
        return Some("a restricted set of signature algorithms");
    }
    if tc["expected_peer_name"].is_null() {
        return Some("no peer name");
    }
    None
}

#[test]
#[ignore]
fn limbo() {
    let limbo = load();
    let cases = limbo["testcases"].as_array().unwrap();
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    let (mut pass, mut fail, mut webpki_fail, mut differ) = (0, 0, 0, 0);
    let mut failures = Vec::new();
    for tc in cases {
        let id = tc["id"].as_str().unwrap();
        if let Some(why) = skip(tc) {
            *skipped.entry(why).or_default() += 1;
            continue;
        }
        let leaf = pem_certs(tc["peer_certificate"].as_str().unwrap());
        let mut inters = Vec::new();
        for pem in tc["untrusted_intermediates"].as_array().unwrap() {
            inters.extend(pem_certs(pem.as_str().unwrap()));
        }
        let roots: Vec<Vec<u8>> =
            tc["trusted_certs"].as_array().unwrap().iter().flat_map(|p| pem_certs(p.as_str().unwrap())).collect();
        // Anchors as webpki makes them from certificates; one it cannot make is left out.
        let anchors: Vec<_> = roots
            .iter()
            .filter_map(|r| webpki::anchor_from_trusted_cert(&r[..].into()).ok().map(|a| a.to_owned()))
            .collect();
        let now = match tc["validation_time"].as_str() {
            Some(t) => epoch(t),
            None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        let name = tc["expected_peer_name"]["value"].as_str().unwrap();
        let mut chain: Vec<&[u8]> = vec![&leaf[0]];
        chain.extend(inters.iter().map(|c| &c[..]));
        let want = tc["expected_result"] == "SUCCESS";
        let ours = ours(&chain, name, now, &anchors);
        let theirs = theirs(&chain, name, now, &anchors);
        if ours.is_ok() != theirs.is_ok() {
            differ += 1;
            let why = difference(&chain, ours, &theirs, Allowed::None);
            eprintln!("DIFFERS from webpki: {id}: ours {ours:?}, webpki {theirs:?}, intentional: {why:?}");
            assert!(why.is_some(), "{id}");
        }
        if theirs.is_ok() != want {
            webpki_fail += 1;
        }
        if ours.is_ok() == want {
            pass += 1;
        } else {
            fail += 1;
            failures.push(format!("{id}: expected {}, ours {ours:?}, webpki {theirs:?}", tc["expected_result"]));
        }
    }
    for f in &failures {
        eprintln!("FAIL {f}");
    }
    eprintln!("limbo: {pass} pass, {fail} fail, {} skipped", skipped.values().sum::<usize>());
    for (why, n) in &skipped {
        eprintln!("  skipped {n}: {why}");
    }
    eprintln!("webpki fails {webpki_fail} of the same cases; jpm-tls and webpki differ on {differ}");
}
