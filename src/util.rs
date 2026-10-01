//! Small helpers shared across modules: base64, hashing, atomic writes, temp names.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use jpm_crypto::hash::{Alg, digest};

use crate::error::{Error, Result};

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode(bytes: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(table[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// An environment switch meant for jpm's own tests: a local server in place of GitHub or the
/// Node.js release keys, git over `file://`, a stand-in node version. Read only in a debug
/// build, which is what `cargo test` runs; a release build acts as though it were unset.
pub fn test_hook(name: &str) -> Option<String> {
    if cfg!(debug_assertions) { std::env::var(name).ok() } else { None }
}

pub fn to_base64(bytes: &[u8]) -> String {
    encode(bytes, STD, true)
}

/// Url-safe and unpadded: a hash that can be a file name.
pub fn to_base64_url(bytes: &[u8]) -> String {
    encode(bytes, URL, false)
}

/// Lenient like Node's Buffer: stops at the first `=`, skips junk, drops a dangling sextet.
pub fn from_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

/// 128 bits of sha256 as 22 characters of base64url: a short key for a subgraph or an input set.
pub fn short_hash(text: &str) -> String {
    to_base64_url(&digest(Alg::Sha256, text.as_bytes())[..16])
}

/// SHA-256 of `text`, all of it: 43 characters of base64url.
pub fn full_hash(text: &str) -> String {
    to_base64_url(&digest(Alg::Sha256, text.as_bytes()))
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    digest(Alg::Sha256, data.as_ref()).iter().map(|b| format!("{b:02x}")).collect()
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A name no other process or thread will pick: pid, a per-process random token and a counter.
/// A pid alone is not enough, since two containers sharing a store through a mount each have
/// their own pid namespace.
pub fn temp_suffix() -> String {
    format!("{}-{}-{}", std::process::id(), token(), SEQ.fetch_add(1, Ordering::Relaxed))
}

fn token() -> &'static str {
    use std::sync::OnceLock;
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let mut seed = [0u8; 6];
        jpm_crypto::rand::fill(&mut seed);
        to_base64_url(&seed)
    })
}

/// Write through a temp file and a rename, so a reader never sees half a file.
pub fn write_atomic(file: &Path, data: &[u8]) -> Result<()> {
    let temp = file.with_file_name(format!(
        ".{}.{}.tmp",
        file.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        temp_suffix()
    ));
    let written = (|| {
        let mut out = fs::File::create(&temp)?;
        out.write_all(data)?;
        drop(out);
        replace_file(&temp, file)
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&temp);
        Error::io(&e, format!("cannot write {}", file.display()))
    })
}

/// `rename` over a file. Windows refuses for a moment while another process holds the target,
/// so retry there; elsewhere the replace is atomic and never busy.
pub fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match fs::rename(from, to) {
            Err(e) if cfg!(windows) && attempt < 10 && e.kind() == std::io::ErrorKind::PermissionDenied => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(10 * attempt));
            }
            other => return other,
        }
    }
}

/// `to` spelled from `from`, both absolute: `../../x`. Nothing is read from the disk.
pub fn relative(from: &Path, to: &Path) -> std::path::PathBuf {
    let a: Vec<_> = from.components().collect();
    let b: Vec<_> = to.components().collect();
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut out = std::path::PathBuf::new();
    for _ in common..a.len() {
        out.push("..");
    }
    for part in &b[common..] {
        out.push(part);
    }
    out
}

/// Seconds since the epoch, as milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for n in 0..20 {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + 5) as u8).collect();
            assert_eq!(from_base64(&to_base64(&bytes)), bytes);
            assert_eq!(from_base64(&to_base64_url(&bytes)), bytes);
        }
        assert_eq!(to_base64(b"hello"), "aGVsbG8=");
        assert_eq!(to_base64_url(b"\xfb\xff"), "-_8");
    }

    #[test]
    fn short_hash_is_22_url_chars() {
        let h = short_hash("abc");
        assert_eq!(h.len(), 22);
        assert!(h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn spells_relative_paths() {
        let r = relative(Path::new("/a/b/c"), Path::new("/a/x/y"));
        assert_eq!(r, Path::new("../../x/y"));
        assert_eq!(relative(Path::new("/a"), Path::new("/a/b")), Path::new("b"));
    }

    #[test]
    fn hex_decodes() {
        assert_eq!(from_hex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("zz"), None);
    }
}
