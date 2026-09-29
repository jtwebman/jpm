//! Every Wycheproof HMAC and HKDF case, valid and invalid (C2SP/wycheproof, testvectors_v1).

use jpm_crypto::ct_eq;
use jpm_crypto::hash::{Alg, hkdf_expand, hkdf_extract, hmac};
use serde_json::Value;
use std::io::Read;

const ALGS: [(Alg, &str); 4] =
    [(Alg::Sha1, "sha1"), (Alg::Sha256, "sha256"), (Alg::Sha384, "sha384"), (Alg::Sha512, "sha512")];

fn load(name: &str) -> Value {
    let path = format!("{}/tests/data/{name}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap()).read_to_string(&mut json).unwrap();
    serde_json::from_str(&json).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Runs every test in the file and returns how many ran.
fn each_test(file: &Value, mut f: impl FnMut(&Value, &Value)) -> usize {
    let mut n = 0;
    for group in file["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            f(group, test);
            n += 1;
        }
    }
    assert_eq!(n as u64, file["numberOfTests"].as_u64().unwrap());
    n
}

/// A tag is accepted when it equals the MAC cut to the group's tag size. Invalid cases carry
/// modified tags.
#[test]
fn wycheproof_hmac() {
    for (alg, name) in ALGS {
        let file = load(&format!("hmac_{name}_test"));
        let n = each_test(&file, |group, test| {
            let tag_len = group["tagSize"].as_u64().unwrap() as usize / 8;
            let (key, msg, tag) = (unhex(&test["key"]), unhex(&test["msg"]), unhex(&test["tag"]));
            let mac = hmac(alg, &key, &[&msg]);
            let ok = tag_len <= mac.len() && ct_eq(&mac[..tag_len], &tag);
            let valid = test["result"] == "valid";
            assert_eq!(ok, valid, "{name} tcId {} ({})", test["tcId"], test["comment"]);
        });
        assert!(n > 100, "{name}: {n} tests");
    }
}

/// HKDF-Extract then HKDF-Expand. The invalid cases ask for more than 255 digests, which
/// `hkdf_expand` refuses by panicking, so they are checked against that limit instead.
#[test]
fn wycheproof_hkdf() {
    for (alg, name) in ALGS {
        let file = load(&format!("hkdf_{name}_test"));
        let n = each_test(&file, |_, test| {
            let size = test["size"].as_u64().unwrap() as usize;
            let id = format!("{name} tcId {} ({})", test["tcId"], test["comment"]);
            if test["result"] != "valid" {
                assert!(size > 255 * alg.len(), "{id}");
                return;
            }
            let prk = hkdf_extract(alg, &unhex(&test["salt"]), &unhex(&test["ikm"]));
            let mut okm = vec![0; size];
            hkdf_expand(alg, &prk, &[&unhex(&test["info"])], &mut okm);
            assert_eq!(okm, unhex(&test["okm"]), "{id}");
        });
        assert!(n > 80, "{name}: {n} tests");
    }
}
