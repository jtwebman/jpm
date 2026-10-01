//! OpenPGP as a runtime download is checked with it: a detached signature, the armored key
//! that made it and the signed SHASUMS document. The input is the signature and the key, each
//! after a two-byte big-endian length, then the document.
#![no_main]

use jpm::pgp;
use libfuzzer_sys::fuzz_target;

fn take(data: &[u8]) -> (&[u8], &[u8]) {
    if data.len() < 2 {
        return (data, &[]);
    }
    let n = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
    (&data[2..2 + n], &data[2 + n..])
}

fuzz_target!(|data: &[u8]| {
    let (sig, rest) = take(data);
    let (key, document) = take(rest);
    let primary = pgp::signer(sig).unwrap_or([0; 20]);
    let _ = pgp::verify(document, sig, &primary, key);
});
