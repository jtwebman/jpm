//! A minimal ustar/pax/GNU tar reader for npm tarballs: regular files only, paths hardened,
//! sizes bounded. Streams: each file's bytes go to the caller as they inflate.

use std::collections::BTreeMap;
use std::io::{self, Read};

use crate::error::{Error, Result};

const BLOCK: usize = 512;
/// Ceilings, so a 1 MB tarball cannot declare a 1 GB entry and exhaust the disk or memory.
const MAX_ENTRY: u64 = 512 * 1024 * 1024;
pub const MAX_ARCHIVE: u64 = 1024 * 1024 * 1024;

fn bad(message: impl Into<String>) -> Error {
    Error::new("EBADTAR", message)
}

/// Read every regular file, calling `each(path, mode, size, bytes)`. `each` must read exactly
/// `size` bytes, or the rest are skipped for it. The first path component is stripped.
pub fn read_entries(
    mut input: impl Read,
    mut each: impl FnMut(&str, u32, u64, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut global: BTreeMap<String, String> = BTreeMap::new();
    let mut next: BTreeMap<String, String> = BTreeMap::new();
    let mut long_name = String::new();
    let mut header = [0u8; BLOCK];
    loop {
        if !fill(&mut input, &mut header)? {
            return Ok(());
        }
        if header.iter().all(|b| *b == 0) {
            // Two zero blocks end the archive; a lone one is padding noise.
            if !fill(&mut input, &mut header)? || header.iter().all(|b| *b == 0) {
                return Ok(());
            }
        }
        let kind = header[156];
        let meta_kind = matches!(kind, b'x' | b'g' | b'L' | b'K');
        let pax_size =
            if meta_kind { None } else { next.get("size").or(global.get("size")).and_then(|s| s.parse::<u64>().ok()) };
        let size = pax_size.unwrap_or_else(|| num(&header[124..136]));
        if !checksum_ok(&header) {
            // The header is untrusted, but its size is the only way forward.
            skip(&mut input, padded(size))?;
            next.clear();
            long_name.clear();
            continue;
        }
        if size > MAX_ENTRY {
            return Err(bad(format!("Tar entry {} declares {size} bytes", name(&header))));
        }
        if meta_kind {
            let mut data = vec![0u8; size as usize];
            input.read_exact(&mut data).map_err(|_| bad("Unexpected end of tar archive"))?;
            skip(&mut input, padded(size) - size)?;
            match kind {
                b'x' => next.extend(parse_pax(&data)),
                b'g' => global.extend(parse_pax(&data)),
                b'L' => long_name = String::from_utf8_lossy(&data).trim_end_matches('\0').to_string(),
                _ => {} // `K` is a link target, and links are dropped anyway
            }
            continue;
        }
        let raw = next.get("path").or(global.get("path")).cloned().filter(|p| !p.is_empty());
        let raw = raw.unwrap_or_else(|| if long_name.is_empty() { name(&header) } else { long_name.clone() });
        next.clear();
        long_name.clear();
        // Regular files only: `1` and `2` are links, which npm refuses outright.
        let regular = matches!(kind, b'0' | 0 | b'7');
        let path = if regular { safe_path(&raw) } else { None };
        let mut body = (&mut input).take(size);
        if let Some(path) = path {
            each(&path, num(&header[100..108]) as u32, size, &mut body)?;
        }
        // Whatever `each` left, and the padding.
        io::copy(&mut body, &mut io::sink()).map_err(|e| bad(format!("Corrupt tarball: {e}")))?;
        if body.limit() > 0 {
            return Err(bad("Unexpected end of tar archive"));
        }
        skip(&mut input, padded(size) - size)?;
    }
}

/// A whole block, or `false` at a clean end.
fn fill(input: &mut impl Read, block: &mut [u8; BLOCK]) -> Result<bool> {
    let mut got = 0;
    while got < BLOCK {
        match input.read(&mut block[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(bad("Unexpected end of tar archive")),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(bad(format!("Corrupt tarball: {e}"))),
        }
    }
    Ok(true)
}

fn skip(input: &mut impl Read, n: u64) -> Result<()> {
    let copied = io::copy(&mut input.take(n), &mut io::sink()).map_err(|e| bad(format!("Corrupt tarball: {e}")))?;
    if copied < n {
        return Err(bad("Unexpected end of tar archive"));
    }
    Ok(())
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

/// Strip the first component and refuse traversal, absolute paths and drive letters.
pub fn safe_path(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.contains(['\0', '\n', '\r']) {
        return None;
    }
    let b = raw.as_bytes();
    if b.len() > 1 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return None;
    }
    let normalized = raw.replace('\\', "/");
    if normalized.starts_with('/') {
        return None;
    }
    let parts: Vec<&str> = normalized.split('/').collect();
    if parts.contains(&"..") {
        return None;
    }
    let kept: Vec<&str> = parts.into_iter().filter(|p| !p.is_empty() && *p != ".").collect();
    (kept.len() > 1).then(|| kept[1..].join("/"))
}

fn name(header: &[u8]) -> String {
    let cut = |b: &[u8]| String::from_utf8_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())]).into_owned();
    let base = cut(&header[0..100]);
    let prefix = cut(&header[345..500]);
    if prefix.is_empty() { base } else { format!("{prefix}/{base}") }
}

/// Octal, or base-256 for a value too large for the field.
fn num(field: &[u8]) -> u64 {
    if field[0] & 0x80 != 0 {
        return field[1..].iter().fold(0u64, |v, b| v.saturating_mul(256).saturating_add(u64::from(*b)));
    }
    let text: String = field.iter().filter(|b| **b != 0 && **b != b' ').map(|b| *b as char).collect();
    u64::from_str_radix(&text, 8).unwrap_or(0)
}

fn checksum_ok(header: &[u8; BLOCK]) -> bool {
    let expected = num(&header[148..156]);
    let (mut unsigned, mut signed) = (8 * 0x20u64, 8 * 0x20i64);
    for (i, &b) in header.iter().enumerate() {
        if (148..156).contains(&i) {
            continue;
        }
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    expected == unsigned || i64::try_from(expected).is_ok_and(|e| e == signed)
}

/// PAX records are `<byte length> <key>=<value>\n`, counted in bytes.
fn parse_pax(data: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut at = 0;
    while at < data.len() {
        let Some(space) = data[at..].iter().position(|b| *b == b' ').map(|p| p + at) else { break };
        let Some(len) = std::str::from_utf8(&data[at..space]).ok().and_then(|s| s.parse::<usize>().ok()) else { break };
        if len == 0 || at + len > data.len() || space + 1 > at + len {
            break;
        }
        let record = String::from_utf8_lossy(&data[space + 1..at + len]);
        let record = record.strip_suffix('\n').unwrap_or(&record);
        if let Some((k, v)) = record.split_once('=').filter(|(k, _)| !k.is_empty()) {
            out.insert(k.to_string(), v.to_string());
        }
        at += len;
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A ustar archive of `(path, mode, bytes)` entries, for tests across the crate.
    pub fn build(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, mode, data) in entries {
            let mut h = [0u8; BLOCK];
            h[..path.len()].copy_from_slice(path.as_bytes());
            h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
            h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
            h[156] = b'0';
            h[257..263].copy_from_slice(b"ustar\0");
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        }
        out.extend_from_slice(&[0; BLOCK * 2]);
        out
    }

    fn list(archive: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
        let mut out = Vec::new();
        read_entries(archive, |path, mode, _, r| {
            let mut data = Vec::new();
            r.read_to_end(&mut data).unwrap();
            out.push((path.to_string(), mode, data));
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn reads_files_and_strips_the_top() {
        let a = build(&[("package/index.js", 0o644, b"hi"), ("package/bin/cli", 0o755, b"#!")]);
        let got = list(&a);
        assert_eq!(got[0], ("index.js".into(), 0o644, b"hi".to_vec()));
        assert_eq!(got[1].0, "bin/cli");
    }

    #[test]
    fn refuses_traversal() {
        let a = build(&[
            ("package/../../etc/passwd", 0o644, b"x"),
            ("/abs", 0o644, b"x"),
            ("c:/x/y", 0o644, b"x"),
            ("package/ok", 0o644, b"y"),
        ]);
        assert_eq!(list(&a).into_iter().map(|e| e.0).collect::<Vec<_>>(), ["ok"]);
    }

    #[test]
    fn skips_bad_checksums_and_reads_pax() {
        let mut a = build(&[("package/a", 0o644, b"1")]);
        a[148] = b'7';
        assert!(list(&a).is_empty());
        let pax = b"29 path=package/long/name.js\n";
        let mut h = build(&[("PaxHeader", 0o644, pax)]);
        h[156] = b'x';
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h[..BLOCK].iter().map(|b| u32::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h.truncate(h.len() - BLOCK * 2);
        h.extend(build(&[("package/short", 0o644, b"z")]));
        assert_eq!(list(&h)[0].0, "long/name.js");
    }

    #[test]
    fn fails_on_truncation() {
        let a = build(&[("package/a", 0o644, b"hello")]);
        assert!(read_entries(&a[..BLOCK + 2], |_, _, _, _| Ok(())).is_err());
    }
}
