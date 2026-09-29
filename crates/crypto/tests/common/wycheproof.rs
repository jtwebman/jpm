//! Wycheproof AEAD test vectors (github.com/C2SP/wycheproof, testvectors_v1), stored gzipped in
//! tests/data. Shared by tests/aead.rs and the crate's unit tests, which also run them through the
//! portable AES code.

use std::io::Read;

pub struct Case {
    pub id: u64,
    pub key: Vec<u8>,
    pub iv: [u8; 12],
    pub aad: Vec<u8>,
    pub msg: Vec<u8>,
    pub ct: Vec<u8>,
    pub tag: [u8; 16],
    pub valid: bool,
}

/// The cases in `file` with a 12-byte IV, a 16-byte tag and a key of one of `key_bits`, and the
/// number of cases skipped.
pub fn load(file: &str, key_bits: &[u64]) -> (Vec<Case>, usize) {
    let path = format!("{}/tests/data/{file}", env!("CARGO_MANIFEST_DIR"));
    let mut json = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()).read_to_string(&mut json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let hex = |v: &serde_json::Value| -> Vec<u8> {
        let s = v.as_str().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let (mut cases, mut skipped) = (Vec::new(), 0);
    for g in v["testGroups"].as_array().unwrap() {
        let tests = g["tests"].as_array().unwrap();
        let fits = g["ivSize"] == 96 && g["tagSize"] == 128 && key_bits.contains(&g["keySize"].as_u64().unwrap());
        if !fits {
            skipped += tests.len();
            continue;
        }
        for t in tests {
            cases.push(Case {
                id: t["tcId"].as_u64().unwrap(),
                key: hex(&t["key"]),
                iv: hex(&t["iv"]).try_into().unwrap(),
                aad: hex(&t["aad"]),
                msg: hex(&t["msg"]),
                ct: hex(&t["ct"]),
                tag: hex(&t["tag"]).try_into().unwrap(),
                valid: t["result"] != "invalid",
            });
        }
    }
    (cases, skipped)
}

type Seal<K> = fn(&K, &[u8; 12], &[u8], &mut [u8]) -> [u8; 16];
type Open<K> = fn(&K, &[u8; 12], &[u8], &mut [u8], &[u8; 16]) -> bool;

/// Valid cases must seal to their ciphertext and tag and open back to the message; invalid ones
/// must not open.
pub fn run<K>(cases: &[Case], key: impl Fn(&[u8]) -> K, seal: Seal<K>, open: Open<K>) {
    for c in cases {
        let k = key(&c.key);
        if c.valid {
            let mut data = c.msg.clone();
            let tag = seal(&k, &c.iv, &c.aad, &mut data);
            assert_eq!((&data, &tag), (&c.ct, &c.tag), "case {} seal", c.id);
        }
        let mut data = c.ct.clone();
        let ok = open(&k, &c.iv, &c.aad, &mut data, &c.tag);
        assert_eq!(ok, c.valid, "case {} open", c.id);
        if ok {
            assert_eq!(data, c.msg, "case {} plaintext", c.id);
        }
    }
}
