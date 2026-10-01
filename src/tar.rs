//! A minimal ustar/pax/GNU tar reader for npm tarballs: regular files only, paths hardened,
//! sizes bounded. Streams: each file's bytes go to the caller as they inflate.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read};

use crate::error::{Error, Result};

const BLOCK: usize = 512;
/// Ceilings, so a 1 MB tarball cannot declare a 1 GB entry and exhaust the disk or memory.
const MAX_ENTRY: u64 = 512 * 1024 * 1024;
pub const MAX_ARCHIVE: u64 = 1024 * 1024 * 1024;
/// A pax header, long name or package.json is read into memory whole.
pub const MAX_META: u64 = 1024 * 1024;
/// Files per package: far above any real one, far below what fills a disk with inodes.
const MAX_FILES: usize = 200_000;

fn bad(message: impl Into<String>) -> Error {
    Error::new("EBADTAR", message)
}

/// Read every regular file, calling `each(path, mode, size, bytes)`. `each` must read exactly
/// `size` bytes, or the rest are skipped for it. The first path component is stripped.
pub fn read_entries(input: impl Read, each: impl FnMut(&str, u32, u64, &mut dyn Read) -> Result<()>) -> Result<()> {
    read_limited(input, MAX_FILES, cfg!(windows), each)
}

/// `read_entries`, with its limit on files, and the check for short names Windows makes under
/// `short_names`.
fn read_limited(
    mut input: impl Read,
    max_files: usize,
    short_names: bool,
    mut each: impl FnMut(&str, u32, u64, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut files = 0;
    let mut names = ShortNames::default();
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
        // Before the checksum: a bad header's size is still what `padded` is given.
        if size > MAX_ENTRY {
            return Err(bad(format!("Tar entry {} declares {size} bytes", name(&header))));
        }
        if !checksum_ok(&header) {
            // The header is untrusted, but its size is the only way forward.
            skip(&mut input, padded(size))?;
            next.clear();
            long_name.clear();
            continue;
        }
        if meta_kind && size > MAX_META {
            return Err(bad(format!("Tar header entry of {size} bytes")));
        }
        if meta_kind {
            let mut data = vec![0u8; size as usize];
            input.read_exact(&mut data).map_err(|_| bad("Unexpected end of tar archive"))?;
            skip(&mut input, padded(size) - size)?;
            match kind {
                b'x' => next.extend(pax_fields(&data)),
                b'g' => global.extend(pax_fields(&data)),
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
        if let Some(path) = &path {
            if path.split('/').any(device) {
                return Err(bad(format!("Tarball entry {path} is a Windows device name")));
            }
            if short_names && let Some((short, long)) = names.add(path) {
                return Err(bad(format!("Tarball entry {short} may be the short name Windows gives {long}")));
            }
        }
        let mut body = (&mut input).take(size);
        if let Some(path) = path {
            files += 1;
            if files > max_files {
                return Err(bad(format!("Tarball has more than {max_files} files")));
            }
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

/// Strip the first component, then keep the path only when every part is a plain name.
pub fn safe_path(raw: &str) -> Option<String> {
    let normalized: std::borrow::Cow<'_, str> =
        if raw.contains('\\') { raw.replace('\\', "/").into() } else { raw.into() };
    if normalized.starts_with('/') || raw.contains(':') {
        return None;
    }
    // One string for the path, not a list of its parts joined into another.
    let mut path = String::with_capacity(normalized.len());
    for part in normalized.split('/').filter(|p| !p.is_empty() && *p != ".").skip(1) {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(part);
    }
    plain(&path).then_some(path)
}

/// A relative `/`-separated path that stays where it is joined on every OS: no empty, `.` or
/// `..` part, no NUL or line breaks, and no `:` (a drive letter or an alternate data stream on
/// Windows, where `C:/x` joined onto a directory replaces it). Windows also drops trailing dots
/// and spaces from a name, so a part may not end in one, or be only dots and spaces.
pub fn plain(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\0', '\n', '\r', ':', '\\'])
        && path.split('/').all(|p| !p.is_empty() && !p.ends_with(['.', ' ']) && p != "..")
}

/// A name Windows reads as a device whatever its extension, in any case, with spaces before the
/// dot or none: `con`, `NUL.js`, `com1 .txt`, `LPT¹`. Refused on every OS, so a package unpacks
/// the same everywhere: no real one has such a name.
pub fn device(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part).trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    let port = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT"));
    port.is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
}

/// Where Windows makes 8.3 names, a file can be opened by its short name: `PACKAG~1.JSO` is
/// `package.json`. An entry named as Windows may have named another in the same directory would
/// be written over it. Real packages ship names of that shape (rspack's `612~3.js` chunks), so
/// only a pair is refused: a short-shaped name and a long name it may be the short name of, in
/// either order, since the linker writes files in an order of its own.
#[derive(Default)]
struct ShortNames {
    /// Directories already looked at, lowercased: each part of a path is looked at once.
    seen: HashSet<String>,
    /// Paths named in the maps below.
    paths: Vec<String>,
    /// Long names by each short name Windows may give them (see `Long::keys`), and short-shaped
    /// names by theirs.
    longs: HashMap<u64, usize>,
    shorts: HashMap<u64, usize>,
    /// By directory: a long name and a short-shaped one in it, and one of each Windows may map
    /// past ASCII in its own way, which then pairs with any of the other kind there.
    dirs: HashMap<String, [Option<usize>; 4]>,
    hasher: std::hash::RandomState,
}

const LONG: usize = 0;
const SHORT: usize = 1;
/// Past these two, the same kinds past ASCII.
const ODD: usize = 2;

impl ShortNames {
    /// `path`'s parts added: the short-shaped path and the long one it may stand for, once there
    /// are both.
    fn add(&mut self, path: &str) -> Option<(String, String)> {
        // ASCII case only: its byte offsets are the path's.
        let lower = path.to_ascii_lowercase();
        let mut start = 0;
        for part in path.split('/') {
            let end = start + part.len();
            if end == path.len() || self.seen.insert(lower[..end].to_string()) {
                let dir = &lower[..start.saturating_sub(1)];
                if let Some(pair) = self.part(dir, part, &path[..end]) {
                    return Some(pair);
                }
            }
            start = end + 1;
        }
        None
    }

    /// One part of a path, `at`, in `dir`: the pair it makes, if it makes one.
    fn part(&mut self, dir: &str, part: &str, at: &str) -> Option<(String, String)> {
        let (keys, long, odd) = if let Some(s) = Short::parse(part) {
            (s.keys(), false, s.odd)
        } else {
            let l = Long::parse(part)?;
            (l.keys(), true, l.odd)
        };
        let (mine, theirs) = if long { (LONG, SHORT) } else { (SHORT, LONG) };
        let slots = self.dirs.get(dir).copied().unwrap_or_default();
        // One past ASCII pairs with any of the other kind in its directory, and one in ASCII
        // with any such of the other kind.
        let mut other = if odd { slots[theirs] } else { slots[theirs + ODD] };
        if other.is_none() && !odd {
            let found = if long { &self.shorts } else { &self.longs };
            other = keys.iter().find_map(|k| found.get(&self.key(dir, k)).copied());
        }
        if let Some(i) = other {
            let other = self.paths[i].clone();
            return Some(if long { (other, at.to_string()) } else { (at.to_string(), other) });
        }
        let i = self.paths.len();
        self.paths.push(at.to_string());
        let slots = self.dirs.entry(dir.to_string()).or_default();
        slots[mine].get_or_insert(i);
        if odd {
            slots[mine + ODD].get_or_insert(i);
        } else {
            for k in &keys {
                let key = self.key(dir, k);
                if long { &mut self.longs } else { &mut self.shorts }.entry(key).or_insert(i);
            }
        }
        None
    }

    fn key(&self, dir: &str, short: &str) -> u64 {
        use std::hash::BuildHasher as _;
        self.hasher.hash_one((dir, short))
    }
}

/// A name Windows makes no short name for, since it is one: up to eight characters, then at
/// most one dot and three more, of those 8.3 allows (and any past ASCII).
fn is_83(part: &str) -> bool {
    let (base, ext) = part.rsplit_once('.').unwrap_or((part, ""));
    let allowed = |c: char| !c.is_ascii() || c.is_ascii_alphanumeric() || "$%'-_@~`!(){}^#&".contains(c);
    !base.is_empty()
        && base.chars().count() <= 8
        && ext.chars().count() <= 3
        && base.chars().chain(ext.chars()).all(allowed)
}

/// A long name as Windows starts its short name: uppercased, without spaces, leading dots or
/// dots before the extension, `+,;=[]` as `_`. `odd` when what Windows keeps of it is past
/// ASCII, which it maps in ways of its own.
struct Long {
    base: Vec<char>,
    ext: String,
    odd: bool,
}

impl Long {
    fn parse(part: &str) -> Option<Self> {
        if is_83(part) {
            return None;
        }
        let name = part.trim_start_matches('.');
        let (base, ext) = name.rsplit_once('.').unwrap_or((name, ""));
        let short = |s: &str| -> Vec<char> {
            let each = |c: char| if "+,;=[]".contains(c) { '_' } else { c.to_ascii_uppercase() };
            s.chars().filter(|c| *c != '.' && *c != ' ').map(each).collect()
        };
        let (base, ext) = (short(base), short(ext));
        let ext: String = ext.into_iter().take(3).collect();
        let odd = !ext.is_ascii() || base.iter().take(6).any(|c| !c.is_ascii());
        Some(Self { base, ext, odd })
    }

    /// Each short name Windows may give it, without the digits after `~`: its first `7 - d`
    /// characters, or all of them when fewer, for a number of `d` digits; past four alike, its
    /// first two and four hex digits (`#` here).
    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = (1..=6)
            .map(|d: usize| {
                let base: String = self.base.iter().take(7 - d).collect();
                format!("{base}~{d}.{}", self.ext)
            })
            .collect();
        if self.base.len() >= 2 {
            keys.push(format!("{}{}#.{}", self.base[0], self.base[1], self.ext));
        }
        keys
    }
}

/// A name shaped as Windows makes a short one: 8.3, its first part a prefix, `~` and a number.
struct Short {
    prefix: String,
    digits: usize,
    ext: String,
    odd: bool,
}

impl Short {
    fn parse(part: &str) -> Option<Self> {
        if !is_83(part) {
            return None;
        }
        let (base, ext) = part.rsplit_once('.').unwrap_or((part, ""));
        let (prefix, n) = base.rsplit_once('~')?;
        // Windows counts from 1, so `612~0.js` is never one.
        if prefix.is_empty() || n.starts_with('0') || n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let odd = !part.is_ascii();
        Some(Self { prefix: prefix.to_ascii_uppercase(), digits: n.len(), ext: ext.to_ascii_uppercase(), odd })
    }

    /// The names `Long::keys` makes that this one may be.
    fn keys(&self) -> Vec<String> {
        let mut keys = vec![format!("{}~{}.{}", self.prefix, self.digits, self.ext)];
        let p = self.prefix.as_bytes();
        if self.digits == 1 && p.len() == 6 && p[2..].iter().all(u8::is_ascii_hexdigit) {
            keys.push(format!("{}#.{}", &self.prefix[..2], self.ext));
        }
        keys
    }
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
    // What `u64::from_str_radix` makes of the field with its NULs and spaces taken out, without
    // building that string for each of every header's three numbers: 0 for anything but octal
    // digits (one leading `+` aside), for nothing at all, and past u64.
    let mut digits = field.iter().filter(|b| **b != 0 && **b != b' ').peekable();
    if digits.peek() == Some(&&b'+') {
        digits.next();
    }
    let mut value = None::<u64>;
    for &b in digits {
        if !(b'0'..=b'7').contains(&b) {
            return 0;
        }
        let Some(v) = value.unwrap_or(0).checked_mul(8).and_then(|v| v.checked_add(u64::from(b - b'0'))) else {
            return 0;
        };
        value = Some(v);
    }
    value.unwrap_or(0)
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

/// The records of a pax header the reader uses. The rest are dropped as they are read: kept, a
/// run of headers, each with records of new keys, would hold gigabytes from a small gzipped
/// tarball, since `global` lasts the whole archive and `next` until a file comes.
fn pax_fields(data: &[u8]) -> impl Iterator<Item = (String, String)> {
    parse_pax(data).into_iter().filter(|(k, _)| matches!(k.as_str(), "path" | "size"))
}

/// PAX records are `<byte length> <key>=<value>\n`, counted in bytes.
fn parse_pax(data: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut at = 0;
    while at < data.len() {
        let Some(space) = data[at..].iter().position(|b| *b == b' ').map(|p| p + at) else { break };
        let Some(len) = std::str::from_utf8(&data[at..space]).ok().and_then(|s| s.parse::<usize>().ok()) else { break };
        if len == 0 || len > data.len() - at || space - at >= len {
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
    fn bounds_what_it_holds() {
        // A pax header over the cap is refused before it is read into memory.
        let mut pax = build(&[("package/x", 0o644, b"x")]);
        pax[156] = b'x';
        let big = format!("{:011o}\0", MAX_META + 1);
        pax[124..136].copy_from_slice(big.as_bytes());
        let sum: u32 =
            pax[..512].iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u32::from(*b) }).sum();
        pax[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(read_entries(pax.as_slice(), |_, _, _, _| Ok(())).unwrap_err().message.contains("header entry"));
        // So are more files than the limit.
        let four = build(&[
            ("package/a", 0o644, b""),
            ("package/b", 0o644, b""),
            ("package/c", 0o644, b""),
            ("package/d", 0o644, b""),
        ]);
        assert!(
            read_limited(four.as_slice(), 3, false, |_, _, _, _| Ok(()))
                .unwrap_err()
                .message
                .contains("more than 3 files")
        );
        assert!(read_limited(four.as_slice(), 4, false, |_, _, _, _| Ok(())).is_ok());
    }

    #[test]
    fn keeps_only_plain_paths() {
        for ok in ["package/index.js", "package/.github/x.yml", "package/a/b/c.d.ts", "../package/x"] {
            assert!(safe_path(ok).is_some(), "{ok}");
        }
        for bad in [
            "package/C:/Users/x",
            "package/C:x",
            "package/a/../b",
            "package\\a\\..\\..\\b",
            "/abs/x",
            "package/.../x",
            "package/x. ",
            "package/x.",
            "package/a:stream",
            "package/nul\0x",
            "package",
            "",
        ] {
            assert_eq!(safe_path(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn refuses_device_names() {
        for name in ["con", "CON", "nul.js", "Aux.d.ts", "com1", "COM9.txt", "lpt3.md", "prn ", "nul .js", "LPT¹"] {
            assert!(device(name), "{name}");
        }
        for name in
            ["console.js", "connect", "com10", "com0", "lpt", "auxiliary.js", "nul_", "con_.js", "x.con", "conx"]
        {
            assert!(!device(name), "{name}");
        }
        // On every OS: a package unpacks the same everywhere.
        for path in ["package/lib/aux.js", "package/CON/x.js", "package/x/Com1.txt"] {
            let a = build(&[("package/index.js", 0o644, b"x"), (path, 0o644, b"y")]);
            let e = read_entries(a.as_slice(), |_, _, _, _| Ok(())).unwrap_err();
            assert_eq!(e.code, "EBADTAR");
            assert!(e.message.contains(&path["package/".len()..]) && e.message.contains("device name"), "{e}");
        }
    }

    #[test]
    fn refuses_a_short_name_beside_the_long_one() {
        let pair = |a: &str, b: &str| {
            let mut names = ShortNames::default();
            names.add(a).or_else(|| names.add(b))
        };
        let both = |long: &str, short: &str| Some((short.to_string(), long.to_string()));
        // Either order, any case, in the same directory.
        assert_eq!(pair("package.json", "PACKAG~1.JSO"), both("package.json", "PACKAG~1.JSO"));
        assert_eq!(pair("packag~1.jso", "package.json"), both("package.json", "packag~1.jso"));
        assert_eq!(pair("lib/Package.json", "LIB/PACKAG~2.JSO"), both("lib/Package.json", "LIB/PACKAG~2.JSO"));
        assert_eq!(pair("a/node_modules/x.js", "a/NODE_M~1/y.js"), both("a/node_modules", "a/NODE_M~1"));
        assert_eq!(pair(".eslintrc.json", "ESLINT~1.JSO"), both(".eslintrc.json", "ESLINT~1.JSO"));
        assert_eq!(pair("a b+c.json", "ABC~1.JSO"), None);
        assert_eq!(pair("a b+c.json", "AB_C~1.JSO"), both("a b+c.json", "AB_C~1.JSO"));
        assert_eq!(pair("ab.longext", "AB~1.LON"), both("ab.longext", "AB~1.LON"));
        assert_eq!(pair("rslib-runtime~0.mjs", "rslib-~1.mjs"), both("rslib-runtime~0.mjs", "rslib-~1.mjs"));
        // Past nine, fewer of the name's characters; past four alike, two and a hash.
        assert_eq!(pair("package.json", "PACKA~12.JSO"), both("package.json", "PACKA~12.JSO"));
        assert_eq!(pair("package.json", "PA3F2C~1.JSO"), both("package.json", "PA3F2C~1.JSO"));
        // Past ASCII, Windows maps a name as it will: paired with any of the other kind.
        assert_eq!(pair("café-latte.js", "CAFELA~1.JS"), both("café-latte.js", "CAFELA~1.JS"));
        // Not what Windows would make for it: another directory, extension or prefix, a number
        // it never gives, or a long name that is already 8.3.
        for (a, b) in [
            ("package.json", "x/PACKAG~1.JSO"),
            ("package.json", "PACKAG~1.JS"),
            ("package.json", "PACK~1.JSO"),
            ("package.json", "PACKAG~0.JSO"),
            ("lazy-compilation.js", "l~3.js"),
            ("612.js", "612~3.js"),
            ("612~0.js", "612~3.js"),
            ("rslib-runtime~0.mjs", "RSLIB-~1.JS"),
        ] {
            assert_eq!(pair(a, b), None, "{a} {b}");
        }
        // Names real packages ship (rspack's chunks, next's), alone or beside others, unpack.
        let real = [
            "package/dist/612~0.js",
            "package/dist/612~3.js",
            "package/dist/l~0.js",
            "package/dist/l~3.js",
            "package/dist/1~184.cjs",
            "package/dist/0~795.js",
            "package/dist/index.js",
            "package/dist/lazy-compilation.js",
            "package/dist/rslib-runtime~0.mjs",
            "package/dist/chunks/turbopack-0xtlpa~_u2u~0.js",
        ];
        let a = build(&real.map(|p| (p, 0o644, b"x".as_slice())));
        assert_eq!(read_limited(a.as_slice(), MAX_FILES, true, |_, _, _, _| Ok(())).map_err(|e| e.message), Ok(()));
        // A pair is refused where Windows makes short names, and only there.
        let a = build(&[("package/package.json", 0o644, b"{}"), ("package/PACKAG~1.JSO", 0o644, b"x")]);
        let e = read_limited(a.as_slice(), MAX_FILES, true, |_, _, _, _| Ok(())).unwrap_err();
        assert_eq!(e.message, "Tarball entry PACKAG~1.JSO may be the short name Windows gives package.json");
        assert!(read_limited(a.as_slice(), MAX_FILES, false, |_, _, _, _| Ok(())).is_ok());
    }

    #[test]
    fn checks_short_names_in_linear_time() {
        // Many short-shaped names and many long ones in one directory, none a pair.
        let mut names = ShortNames::default();
        let start = std::time::Instant::now();
        for i in 0..50_000 {
            assert_eq!(names.add(&format!("dir/A{i:05}~1.JS")), None);
            assert_eq!(names.add(&format!("dir/b-long-name-{i}.js")), None);
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
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
    fn keeps_only_the_pax_records_it_reads() {
        let records = b"10 path=a\n8 size=\n12 mtime=12\n16 SCHILY.dev=1\n";
        assert_eq!(parse_pax(records).len(), 4);
        assert_eq!(
            pax_fields(records).collect::<Vec<_>>(),
            [("path".into(), "a".into()), ("size".into(), String::new())]
        );
        // Found while fuzzing: global headers of new keys, one after another, each kept every key
        // until the archive ended. Here 64 of them, then a file, which still reads.
        let mut a = Vec::new();
        for i in 0..64 {
            let records: String = (0..100).map(|j| format!("15 k{i:04}x{j:04}=\n")).collect();
            assert_eq!(parse_pax(records.as_bytes()).len(), 100);
            let mut h = build(&[("pax", 0o644, records.as_bytes())]);
            h[156] = b'g';
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h[..BLOCK].iter().map(|b| u32::from(*b)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            h.truncate(h.len() - BLOCK * 2);
            a.extend(h);
        }
        a.extend(build(&[("package/x", 0o644, b"x")]));
        assert_eq!(list(&a).into_iter().map(|e| e.0).collect::<Vec<_>>(), ["x"]);
    }

    #[test]
    fn refuses_sizes_that_overflow() {
        // A bad-checksum header declaring a base-256 size of u64::MAX.
        let mut a = build(&[("package/a", 0o644, b"1")]);
        a[124] = 0x80;
        a[125..136].fill(0xff);
        assert!(read_entries(a.as_slice(), |_, _, _, _| Ok(())).unwrap_err().message.contains("declares"));
        // A pax record whose length runs past the end of usize.
        assert!(parse_pax(b"3 018446744073709551615 x=y\n").is_empty());
        assert_eq!(parse_pax(b"3 06 a=b\n")["a"], "b");
    }

    #[test]
    fn fails_on_truncation() {
        let a = build(&[("package/a", 0o644, b"hello")]);
        assert!(read_entries(&a[..BLOCK + 2], |_, _, _, _| Ok(())).is_err());
    }

    #[test]
    fn reads_numbers_as_from_str_radix_did() {
        let old = |field: &[u8]| {
            let text: String = field.iter().filter(|b| **b != 0 && **b != b' ').map(|b| *b as char).collect();
            u64::from_str_radix(&text, 8).unwrap_or(0)
        };
        let fields: [&[u8]; 16] = [
            b"0000644\0",
            b"00000001750\0",
            b" 1750 \0\0\0\0\0",
            b"\0\0\0\0\0\0\0\0",
            b"        ",
            b"1 2 3\0",
            b"+17\0",
            b"++17",
            b"+",
            b"-17",
            b"0009",
            b"12a",
            b"7777777777777777777777",
            b"1777777777777777777777",
            b"2000000000000000000000",
            b"\x0077",
        ];
        for f in fields {
            assert_eq!(num(f), old(f), "{:?}", String::from_utf8_lossy(f));
        }
        // Base-256, for a size past what octal fits.
        assert_eq!(num(&[0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]), 1 << 32);
    }

    #[test]
    fn strips_the_first_part_as_it_did() {
        let old = |raw: &str| {
            let normalized = raw.replace('\\', "/");
            if normalized.starts_with('/') || raw.contains(':') {
                return None;
            }
            let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
            let path = parts.get(1..)?.join("/");
            plain(&path).then_some(path)
        };
        for raw in [
            "package/a.js",
            "package//lib/./a.js",
            "package\\lib\\a.js",
            "./package/a.js",
            "package",
            "package/",
            "/package/a.js",
            "package/../a.js",
            "package/a:b",
            "a/b/c/d.e",
            "package/lib/",
            "package/ x/y",
            "package/x./y",
            "",
            "package/\\/a",
        ] {
            assert_eq!(safe_path(raw), old(raw), "{raw:?}");
        }
    }
}
