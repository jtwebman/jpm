//! HPACK (RFC 7541), header compression for HTTP/2. The decoder is whole: the static and
//! dynamic tables, table size updates, and Huffman-coded strings. The encoder writes only what
//! a GET needs: static entries by index, everything else as a literal without indexing and
//! without Huffman coding, which section 5.2 leaves to the encoder.

use std::collections::VecDeque;

/// A header block the decoder refuses: a COMPRESSION_ERROR for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

type Result<T> = std::result::Result<T, Error>;

/// The static table (appendix A); index 1 is the first entry.
static STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// The table size both ends start with, and all this decoder allows (SETTINGS_HEADER_TABLE_SIZE
/// is left at its default).
pub const TABLE_SIZE: usize = 4096;

/// What an entry costs in the dynamic table besides its bytes (section 4.1).
const ENTRY_OVERHEAD: usize = 32;

/// A decoder for one connection's header blocks, in the order they arrive.
pub struct Decoder {
    /// Newest first: name and value in one buffer, and where the name ends.
    table: VecDeque<(Box<[u8]>, usize)>,
    size: usize,
    /// The size the encoder has set, at most `TABLE_SIZE`.
    max: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self { table: VecDeque::new(), size: 0, max: TABLE_SIZE }
    }
}

impl Decoder {
    /// The fields of one whole header block, names as sent. Refused past `max_list` bytes as
    /// SETTINGS_MAX_HEADER_LIST_SIZE counts them: each name and value, and 32 more per field.
    /// An error leaves the table unusable: the connection must end.
    pub fn decode(&mut self, block: &[u8], max_list: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut r = block;
        let mut out = Vec::new();
        let mut list = 0;
        while let Some(&b) = r.first() {
            let (name, value) = if b & 0x80 != 0 {
                let (n, v) = self.entry(int(&mut r, 7)?)?;
                (n.to_vec(), v.to_vec())
            } else if b & 0xe0 == 0x20 {
                // A size update, only before the first field (section 4.2).
                let size = int(&mut r, 5)?;
                if !out.is_empty() {
                    return Err(Error("hpack: table size update after a header field"));
                }
                if size > TABLE_SIZE {
                    return Err(Error("hpack: table size update above the limit"));
                }
                self.max = size;
                self.evict(0);
                continue;
            } else {
                // With incremental indexing (01), without (0000) or never indexed (0001).
                let index = b & 0x40 != 0;
                let i = int(&mut r, if index { 6 } else { 4 })?;
                let name = if i == 0 { string(&mut r)? } else { self.entry(i)?.0.to_vec() };
                let value = string(&mut r)?;
                if index {
                    self.insert(&name, &value);
                }
                (name, value)
            };
            list += name.len() + value.len() + ENTRY_OVERHEAD;
            if list > max_list {
                return Err(Error("hpack: header list too large"));
            }
            out.push((name, value));
        }
        Ok(out)
    }

    /// Entry `i` of the static table, then the dynamic one.
    fn entry(&self, i: usize) -> Result<(&[u8], &[u8])> {
        if let Some(&(n, v)) = i.checked_sub(1).and_then(|i| STATIC.get(i)) {
            return Ok((n.as_bytes(), v.as_bytes()));
        }
        let (b, split) = self.table.get(i.wrapping_sub(STATIC.len() + 1)).ok_or(Error("hpack: bad index"))?;
        Ok(b.split_at(*split))
    }

    /// Add an entry, evicting the oldest to make room; one larger than the table empties it
    /// (section 4.4).
    fn insert(&mut self, name: &[u8], value: &[u8]) {
        let size = name.len() + value.len() + ENTRY_OVERHEAD;
        self.evict(size);
        if size <= self.max {
            self.table.push_front(([name, value].concat().into_boxed_slice(), name.len()));
            self.size += size;
        }
    }

    /// Evict until `room` more bytes fit, or the table is empty.
    fn evict(&mut self, room: usize) {
        while self.size + room > self.max {
            let Some((b, _)) = self.table.pop_back() else { break };
            self.size -= b.len() + ENTRY_OVERHEAD;
        }
    }
}

/// An integer with an `n`-bit prefix (section 5.1). Values past 2^28 are refused: nothing in a
/// header block is that long.
fn int(r: &mut &[u8], n: u8) -> Result<usize> {
    let bad = Error("hpack: bad integer");
    let (&first, rest) = r.split_first().ok_or(bad)?;
    *r = rest;
    let mask = (1usize << n) - 1;
    let mut v = usize::from(first) & mask;
    if v < mask {
        return Ok(v);
    }
    for shift in (0..28).step_by(7) {
        let (&b, rest) = r.split_first().ok_or(bad)?;
        *r = rest;
        v += usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(bad)
}

/// A string literal (section 5.2), Huffman-decoded when its H bit is set.
fn string(r: &mut &[u8]) -> Result<Vec<u8>> {
    let huffman = r.first().is_some_and(|b| b & 0x80 != 0);
    let len = int(r, 7)?;
    if r.len() < len {
        return Err(Error("hpack: string past the end of the block"));
    }
    let (s, rest) = r.split_at(len);
    *r = rest;
    if huffman { huffman_decode(s) } else { Ok(s.to_vec()) }
}

/// The Huffman code of appendix B is canonical: each length's codes follow the last length's,
/// in symbol order. So these two tables are the whole code: how many codes each length from 0
/// to 30 has, and the symbols sorted by length, then value. EOS, the one 257th symbol, is the
/// last 30-bit code.
static COUNTS: [u8; 31] =
    [0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4];
static SYMBOLS: [u8; 256] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57, 61, 65, 95, 98, 100,
    102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
    82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119, 120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39,
    43, 124, 35, 62, 0, 36, 64, 91, 93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224,
    226, 153, 161, 167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156, 160,
    163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1, 135, 137, 138, 139, 140,
    141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191, 197, 231, 239,
    9, 142, 144, 145, 148, 159, 171, 206, 215, 225, 236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210,
    213, 218, 219, 238, 240, 242, 243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250,
    251, 252, 253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 127, 220, 249, 10, 13, 22,
];

/// Huffman-coded bytes, a bit at a time. The padding at the end must be under a byte and all
/// ones (section 5.2); EOS itself must not appear.
fn huffman_decode(src: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len() * 8 / 5);
    // The code read so far and its length; the first code of that length and its symbol's
    // index; and whether every bit so far is a one.
    let (mut code, mut len, mut first, mut index, mut ones) = (0usize, 0, 0usize, 0usize, true);
    for i in 0..src.len() * 8 {
        let bit = usize::from(src[i / 8] >> (7 - i % 8) & 1);
        code |= bit;
        len += 1;
        ones &= bit == 1;
        let count = usize::from(COUNTS[len]);
        if code < first + count {
            let sym = index + code - first;
            out.push(*SYMBOLS.get(sym).ok_or(Error("hpack: EOS in a Huffman string"))?);
            (code, len, first, index, ones) = (0, 0, 0, 0, true);
            continue;
        }
        if len == 30 {
            return Err(Error("hpack: bad Huffman code"));
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    if len > 7 || !ones {
        return Err(Error("hpack: bad Huffman padding"));
    }
    Ok(out)
}

/// Append one field to a header block: by index when the static table has it whole, else as a
/// literal without indexing, naming it by index when the static table has the name. A value
/// marked `sensitive` is sent never-indexed, so no intermediary keeps it in a table.
pub fn encode(out: &mut Vec<u8>, name: &str, value: &str, sensitive: bool) {
    if !sensitive && let Some(i) = STATIC.iter().position(|&e| e == (name, value)) {
        put_int(out, 0x80, 7, i + 1);
        return;
    }
    let flag = if sensitive { 0x10 } else { 0 };
    match STATIC.iter().position(|e| e.0 == name) {
        Some(i) => put_int(out, flag, 4, i + 1),
        None => {
            out.push(flag);
            put_str(out, name);
        }
    }
    put_str(out, value);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_int(out, 0, 7, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// `v` with an `n`-bit prefix, the bits above it `flags`.
fn put_int(out: &mut Vec<u8>, flags: u8, n: u8, mut v: usize) {
    let mask = (1usize << n) - 1;
    if v < mask {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | mask as u8);
    v -= mask;
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn fields(d: &mut Decoder, block: &str) -> Vec<(String, String)> {
        let got = d.decode(&hex(block), 1 << 20).unwrap();
        got.into_iter().map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap())).collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    /// The dynamic table, newest first, and its size.
    fn table(d: &Decoder) -> (Vec<(String, String)>, usize) {
        let t = d
            .table
            .iter()
            .map(|(b, i)| {
                let (n, v) = b.split_at(*i);
                (String::from_utf8(n.to_vec()).unwrap(), String::from_utf8(v.to_vec()).unwrap())
            })
            .collect();
        (t, d.size)
    }

    /// A test Huffman encoder, the codes rebuilt from the canonical tables.
    fn huffman_encode(s: &[u8]) -> Vec<u8> {
        let mut codes = [(0u32, 0u8); 257];
        let (mut code, mut k) = (0u32, 0);
        for len in 1..=30u8 {
            for _ in 0..COUNTS[usize::from(len)] {
                let sym = SYMBOLS.get(k).map_or(256, |&s| usize::from(s));
                codes[sym] = (code, len);
                code += 1;
                k += 1;
            }
            code <<= 1;
        }
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u64, 0);
        for &b in s {
            let (c, l) = codes[usize::from(b)];
            acc = acc << l | u64::from(c);
            bits += l;
            while bits >= 8 {
                out.push((acc >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push((acc << (8 - bits)) as u8 | (0xff >> bits));
        }
        out
    }

    #[test]
    fn integers() {
        // C.1: 10 and 1337 with 5-bit prefixes, 42 at an octet boundary.
        for (v, n, bytes) in [(10, 5, vec![0x0a]), (1337, 5, vec![0x1f, 0x9a, 0x0a]), (42, 8, vec![0x2a])] {
            let mut out = Vec::new();
            put_int(&mut out, 0, n, v);
            assert_eq!(out, bytes);
            assert_eq!(int(&mut &bytes[..], n).unwrap(), v);
        }
        // Too long, and cut short.
        assert!(int(&mut &[0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f][..], 5).is_err());
        assert!(int(&mut &[0x1f, 0x9a][..], 5).is_err());
        assert!(int(&mut &[][..], 5).is_err());
    }

    #[test]
    fn field_representations() {
        // C.2.1: literal with indexing.
        let mut d = Decoder::default();
        let got = fields(&mut d, "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572");
        assert_eq!(got, pairs(&[("custom-key", "custom-header")]));
        assert_eq!(table(&d), (pairs(&[("custom-key", "custom-header")]), 55));
        // C.2.2: without indexing.
        let mut d = Decoder::default();
        assert_eq!(fields(&mut d, "040c 2f73 616d 706c 652f 7061 7468"), pairs(&[(":path", "/sample/path")]));
        assert_eq!(table(&d), (vec![], 0));
        // C.2.3: never indexed.
        let mut d = Decoder::default();
        assert_eq!(fields(&mut d, "1008 7061 7373 776f 7264 0673 6563 7265 74"), pairs(&[("password", "secret")]));
        assert_eq!(table(&d), (vec![], 0));
        // C.2.4: indexed.
        let mut d = Decoder::default();
        assert_eq!(fields(&mut d, "82"), pairs(&[(":method", "GET")]));
    }

    /// C.3 (plain) and C.4 (Huffman): three requests on one connection.
    #[test]
    fn requests() {
        let blocks = [
            ("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d", "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"),
            ("8286 84be 5808 6e6f 2d63 6163 6865", "8286 84be 5886 a8eb 1064 9cbf"),
            (
                "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
                "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
            ),
        ];
        let want = [
            pairs(&[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]),
            pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ]),
            pairs(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ]),
        ];
        let tables = [
            (pairs(&[(":authority", "www.example.com")]), 57),
            (pairs(&[("cache-control", "no-cache"), (":authority", "www.example.com")]), 110),
            (
                pairs(&[
                    ("custom-key", "custom-value"),
                    ("cache-control", "no-cache"),
                    (":authority", "www.example.com"),
                ]),
                164,
            ),
        ];
        for huffman in [false, true] {
            let mut d = Decoder::default();
            for (i, (plain, coded)) in blocks.iter().enumerate() {
                assert_eq!(fields(&mut d, if huffman { coded } else { plain }), want[i], "{huffman} {i}");
                assert_eq!(table(&d), tables[i], "{huffman} {i}");
            }
        }
    }

    /// C.5 (plain) and C.6 (Huffman): three responses with a 256-byte table, so entries are
    /// evicted.
    #[test]
    fn responses_with_eviction() {
        let blocks = [
            (
                "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
                "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
            ),
            ("4803 3330 37c1 c0bf", "4883 640e ffc1 c0bf"),
            (
                "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31",
                "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            ),
        ];
        let date1 = "Mon, 21 Oct 2013 20:13:21 GMT";
        let date2 = "Mon, 21 Oct 2013 20:13:22 GMT";
        let url = "https://www.example.com";
        let cookie = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";
        let want = [
            pairs(&[(":status", "302"), ("cache-control", "private"), ("date", date1), ("location", url)]),
            pairs(&[(":status", "307"), ("cache-control", "private"), ("date", date1), ("location", url)]),
            pairs(&[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", date2),
                ("location", url),
                ("content-encoding", "gzip"),
                ("set-cookie", cookie),
            ]),
        ];
        let tables = [
            (pairs(&[("location", url), ("date", date1), ("cache-control", "private"), (":status", "302")]), 222),
            (pairs(&[(":status", "307"), ("location", url), ("date", date1), ("cache-control", "private")]), 222),
            (pairs(&[("set-cookie", cookie), ("content-encoding", "gzip"), ("date", date2)]), 215),
        ];
        for huffman in [false, true] {
            let mut d = Decoder::default();
            // The examples' encoder set the table to 256 bytes.
            d.decode(&[0x3f, 0xe1, 0x01], 1 << 20).unwrap();
            assert_eq!(d.max, 256);
            for (i, (plain, coded)) in blocks.iter().enumerate() {
                assert_eq!(fields(&mut d, if huffman { coded } else { plain }), want[i], "{huffman} {i}");
                assert_eq!(table(&d), tables[i], "{huffman} {i}");
            }
        }
    }

    #[test]
    fn huffman_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        let samples: [&[u8]; 6] = [b"", b"a", b"www.example.com", b"no-cache", &all, b"\xff\xfe\x00\x01 gzip, br"];
        for s in samples {
            assert_eq!(huffman_decode(&huffman_encode(s)).unwrap(), s);
        }
        for i in 0..2000u32 {
            let s: Vec<u8> = (0..i % 50).map(|j| (i.wrapping_mul(2654435761).rotate_left(j) >> 7) as u8).collect();
            assert_eq!(huffman_decode(&huffman_encode(&s)).unwrap(), s);
        }
        // "www.example.com" as C.4.1 codes it.
        assert_eq!(huffman_encode(b"www.example.com"), hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"));
    }

    #[test]
    fn refuses_bad_huffman() {
        // A whole byte of padding; padding with a zero; EOS spelled out.
        assert!(huffman_decode(&hex("1f ff")).is_err(), "'a' then eight padding bits");
        assert!(huffman_decode(&hex("1e")).is_err(), "'a' then padding 110");
        assert!(huffman_decode(&hex("ff ff ff fc")).is_err(), "EOS");
        assert_eq!(huffman_decode(&hex("1f")).unwrap(), b"a");
    }

    #[test]
    fn refuses_bad_blocks() {
        let mut d = Decoder::default();
        let e = |d: &mut Decoder, b: &[u8]| d.decode(b, 1 << 20).unwrap_err().0;
        // Index 0, and past both tables.
        assert_eq!(e(&mut d, &[0x80]), "hpack: bad index");
        assert_eq!(e(&mut d, &[0xbe]), "hpack: bad index");
        // A string longer than the block.
        assert_eq!(e(&mut d, &[0x00, 0x05, b'a']), "hpack: string past the end of the block");
        // A size update past the limit, and one after a field.
        assert_eq!(e(&mut d, &[0x3f, 0xe2, 0x1f]), "hpack: table size update above the limit");
        assert_eq!(e(&mut d, &[0x82, 0x20]), "hpack: table size update after a header field");
        // The header list limit counts 32 per field.
        assert!(d.decode(&[0x82], 32 + 10).is_ok());
        assert_eq!(d.decode(&[0x82], 32 + 9).unwrap_err().0, "hpack: header list too large");
    }

    #[test]
    fn bounds_the_table() {
        let mut d = Decoder::default();
        // An entry bigger than the table empties it; the table never passes its size.
        let big = "x".repeat(TABLE_SIZE);
        let mut block = vec![0x40];
        put_str(&mut block, "k");
        put_str(&mut block, &big);
        let mut small = vec![0x40];
        put_str(&mut small, "k");
        put_str(&mut small, "v");
        for _ in 0..200 {
            d.decode(&small, 1 << 20).unwrap();
            assert!(d.size <= TABLE_SIZE);
        }
        assert_eq!(d.table.len(), TABLE_SIZE / 34);
        d.decode(&block, 1 << 20).unwrap();
        assert_eq!(table(&d), (vec![], 0));
        // A size update of 0 empties it too.
        d.decode(&small, 1 << 20).unwrap();
        d.decode(&[0x20], 1 << 20).unwrap();
        assert_eq!(table(&d), (vec![], 0));
    }

    #[test]
    fn encodes_what_it_decodes() {
        let mut block = Vec::new();
        encode(&mut block, ":method", "GET", false);
        encode(&mut block, ":scheme", "https", false);
        encode(&mut block, ":path", "/@scope%2fname", false);
        encode(&mut block, ":authority", "registry.npmjs.org", false);
        encode(&mut block, "accept", "application/json", false);
        encode(&mut block, "npm-command", "install", false);
        encode(&mut block, "authorization", "Bearer secret", true);
        encode(&mut block, "x-long", &"v".repeat(300), false);
        assert_eq!(&block[..2], &[0x82, 0x87], "whole static entries by index");
        let mut d = Decoder::default();
        let got = d.decode(&block, 1 << 20).unwrap();
        let got: Vec<_> =
            got.into_iter().map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap())).collect();
        assert_eq!(got[6], ("authorization".to_string(), "Bearer secret".to_string()));
        assert_eq!(got[7].1.len(), 300);
        assert_eq!(got.len(), 8);
        // Nothing was indexed, on either side.
        assert_eq!(table(&d), (vec![], 0));
    }
}
