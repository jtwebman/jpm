//! Helpers shared by the integration tests: Wycheproof files, hex, random bytes, timing.
#![allow(dead_code)]

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::io::Read;

/// A gzipped Wycheproof file from tests/data, e.g. `wycheproof("x25519_test")`.
pub fn wycheproof(name: &str) -> Value {
    let path = format!("{}/tests/data/{name}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let mut s = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()).read_to_string(&mut s).unwrap();
    serde_json::from_str(&s).unwrap()
}

/// Every (group, test) pair of a Wycheproof file.
pub fn cases(v: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    v["testGroups"].as_array().unwrap().iter().flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub fn random<const L: usize>() -> [u8; L] {
    let mut b = [0; L];
    SystemRandom::new().fill(&mut b).unwrap();
    b
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut b = vec![0; len];
    SystemRandom::new().fill(&mut b).unwrap();
    b
}

/// Rounds for the randomized tests: many in release builds, a few in slow debug builds.
pub fn rounds(release: usize) -> usize {
    if cfg!(debug_assertions) { release / 50 } else { release }
}

/// Microseconds per call of f, over iters calls.
pub fn time(iters: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..iters / 10 {
        f();
    }
    let start = std::time::Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_secs_f64() * 1e6 / iters as f64
}
