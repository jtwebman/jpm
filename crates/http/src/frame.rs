//! HTTP/2 frames (RFC 9113 section 4 and 6): the 9-byte header, and each frame type's payload
//! checked for what the RFC makes a connection error. Nothing here keeps state; the header
//! block assembly across CONTINUATION frames is `Block`.

use std::io::{self, Read};

pub const DATA: u8 = 0;
pub const HEADERS: u8 = 1;
pub const PRIORITY: u8 = 2;
pub const RST_STREAM: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const PUSH_PROMISE: u8 = 5;
pub const PING: u8 = 6;
pub const GOAWAY: u8 = 7;
pub const WINDOW_UPDATE: u8 = 8;
pub const CONTINUATION: u8 = 9;

pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;
pub const PADDED: u8 = 0x8;
pub const PRIORITY_FLAG: u8 = 0x20;

// Error codes (section 7).
pub const NO_ERROR: u32 = 0;
pub const PROTOCOL_ERROR: u32 = 1;
pub const INTERNAL_ERROR: u32 = 2;
pub const FLOW_CONTROL_ERROR: u32 = 3;
pub const FRAME_SIZE_ERROR: u32 = 6;
pub const REFUSED_STREAM: u32 = 7;
pub const CANCEL: u32 = 8;
pub const COMPRESSION_ERROR: u32 = 9;
pub const ENHANCE_YOUR_CALM: u32 = 11;

// Settings (section 6.5.2).
pub const HEADER_TABLE_SIZE: u16 = 1;
pub const ENABLE_PUSH: u16 = 2;
pub const MAX_CONCURRENT_STREAMS: u16 = 3;
pub const INITIAL_WINDOW_SIZE: u16 = 4;
pub const MAX_FRAME_SIZE: u16 = 5;
pub const MAX_HEADER_LIST_SIZE: u16 = 6;

/// The client's connection preface (section 3.4), before its first SETTINGS.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The largest frame payload either side may send until SETTINGS_MAX_FRAME_SIZE says more;
/// this client never says more.
pub const DEFAULT_MAX_FRAME: usize = 1 << 14;

/// The largest flow-control window (section 6.9.1).
pub const MAX_WINDOW: i64 = (1 << 31) - 1;

/// A connection error: the code for GOAWAY, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Violation {
    pub code: u32,
    pub why: &'static str,
}

pub const fn violation(code: u32, why: &'static str) -> Violation {
    Violation { code, why }
}

/// A frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub len: usize,
    pub typ: u8,
    pub flags: u8,
    pub stream: u32,
}

impl Head {
    pub fn parse(b: &[u8; 9]) -> Self {
        Self {
            len: usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]),
            typ: b[3],
            flags: b[4],
            // The reserved bit is ignored (section 4.1).
            stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&[self.typ, self.flags]);
        out.extend_from_slice(&self.stream.to_be_bytes());
    }
}

/// Append a whole frame.
pub fn put(out: &mut Vec<u8>, typ: u8, flags: u8, stream: u32, payload: &[u8]) {
    Head { len: payload.len(), typ, flags, stream }.write(out);
    out.extend_from_slice(payload);
}

/// The next frame's header, its payload in `buf`. A payload over `max` is FRAME_SIZE_ERROR
/// (section 4.2), reported before any of it is read. `Ok(None)` is a clean end between frames.
pub fn read(r: &mut dyn Read, max: usize, buf: &mut Vec<u8>) -> io::Result<Option<Result<Head, Violation>>> {
    let mut b = [0; 9];
    let mut got = 0;
    while got < 9 {
        match r.read(&mut b[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "http2: connection closed inside a frame"));
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let head = Head::parse(&b);
    if head.len > max {
        return Ok(Some(Err(violation(FRAME_SIZE_ERROR, "http2: frame larger than the maximum frame size"))));
    }
    buf.clear();
    buf.resize(head.len, 0);
    r.read_exact(buf).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => io::Error::new(e.kind(), "http2: connection closed inside a frame"),
        _ => e,
    })?;
    Ok(Some(Ok(head)))
}

/// A frame's payload, checked against its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `pad` bytes of padding came with it: flow control counts them too.
    Data {
        stream: u32,
        end: bool,
        data: &'a [u8],
        pad: usize,
    },
    Headers {
        stream: u32,
        end: bool,
        done: bool,
        block: &'a [u8],
    },
    Continuation {
        stream: u32,
        done: bool,
        block: &'a [u8],
    },
    Reset {
        stream: u32,
        code: u32,
    },
    Settings {
        ack: bool,
        params: &'a [u8],
    },
    Ping {
        ack: bool,
        data: [u8; 8],
    },
    GoAway {
        last: u32,
        code: u32,
    },
    WindowUpdate {
        stream: u32,
        increment: u32,
    },
    /// PRIORITY, and types this client does not know: ignored (sections 5.5 and 6.3).
    Ignored,
}

/// Check a frame received by a client that never enables push. Every violation is taken as a
/// connection error, as section 5.4 allows for the stream errors among them.
pub fn parse<'a>(h: &Head, p: &'a [u8]) -> Result<Frame<'a>, Violation> {
    let on_stream = matches!(h.typ, DATA | HEADERS | PRIORITY | RST_STREAM | PUSH_PROMISE | CONTINUATION);
    let on_connection = matches!(h.typ, SETTINGS | PING | GOAWAY);
    if on_stream && h.stream == 0 {
        return Err(violation(PROTOCOL_ERROR, "http2: a stream frame on stream 0"));
    }
    if on_connection && h.stream != 0 {
        return Err(violation(PROTOCOL_ERROR, "http2: a connection frame on a stream"));
    }
    let size = |ok: bool| if ok { Ok(()) } else { Err(violation(FRAME_SIZE_ERROR, "http2: bad frame length")) };
    let u32_at = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
    let (stream, flags) = (h.stream, h.flags);
    Ok(match h.typ {
        DATA => {
            let (data, pad) = unpad(flags, p)?;
            Frame::Data { stream, end: flags & END_STREAM != 0, data, pad }
        }
        HEADERS => {
            let (mut block, _) = unpad(flags, p)?;
            if flags & PRIORITY_FLAG != 0 {
                size(block.len() >= 5)?;
                block = &block[5..];
            }
            Frame::Headers { stream, end: flags & END_STREAM != 0, done: flags & END_HEADERS != 0, block }
        }
        CONTINUATION => Frame::Continuation { stream, done: flags & END_HEADERS != 0, block: p },
        PRIORITY => {
            size(p.len() == 5)?;
            Frame::Ignored
        }
        RST_STREAM => {
            size(p.len() == 4)?;
            Frame::Reset { stream, code: u32_at(0) }
        }
        SETTINGS => {
            let ack = flags & ACK != 0;
            size(if ack { p.is_empty() } else { p.len().is_multiple_of(6) })?;
            Frame::Settings { ack, params: p }
        }
        PUSH_PROMISE => return Err(violation(PROTOCOL_ERROR, "http2: PUSH_PROMISE with push disabled")),
        PING => {
            size(p.len() == 8)?;
            Frame::Ping { ack: flags & ACK != 0, data: p.try_into().unwrap() }
        }
        GOAWAY => {
            size(p.len() >= 8)?;
            Frame::GoAway { last: u32_at(0) & 0x7fff_ffff, code: u32_at(4) }
        }
        WINDOW_UPDATE => {
            size(p.len() == 4)?;
            let increment = u32_at(0) & 0x7fff_ffff;
            if increment == 0 {
                return Err(violation(PROTOCOL_ERROR, "http2: WINDOW_UPDATE of 0"));
            }
            Frame::WindowUpdate { stream, increment }
        }
        _ => Frame::Ignored,
    })
}

/// A padded payload's content and the padding's length with its length byte (section 6.1).
fn unpad(flags: u8, p: &[u8]) -> Result<(&[u8], usize), Violation> {
    if flags & PADDED == 0 {
        return Ok((p, 0));
    }
    let (&n, rest) = p.split_first().ok_or(violation(FRAME_SIZE_ERROR, "http2: bad frame length"))?;
    let n = usize::from(n);
    if n >= p.len() {
        return Err(violation(PROTOCOL_ERROR, "http2: padding longer than the frame"));
    }
    Ok((&rest[..rest.len() - n], n + 1))
}

/// The settings in a SETTINGS payload as `(id, value)`.
pub fn settings(params: &[u8]) -> impl Iterator<Item = (u16, u32)> + '_ {
    params
        .as_chunks::<6>()
        .0
        .iter()
        .map(|s| (u16::from_be_bytes([s[0], s[1]]), u32::from_be_bytes([s[2], s[3], s[4], s[5]])))
}

/// A header block assembled from HEADERS and the CONTINUATION frames after it (section 6.10),
/// bounded in bytes and in frames: an endless run of small or empty CONTINUATION frames is the
/// CONTINUATION flood of CVE-2024-27316 and its kin.
#[derive(Default)]
pub struct Block {
    /// The stream whose block is open, whether it ends the stream, and the frames it took.
    open: Option<(u32, bool, usize)>,
    bytes: Vec<u8>,
}

/// A whole header block: its stream, whether it ends the stream, and its bytes.
pub type Whole<'a> = (u32, bool, &'a [u8]);

impl Block {
    /// The most bytes one header block may take, compressed.
    pub const MAX_BYTES: usize = 64 * 1024;
    /// The most frames one header block may take, HEADERS included.
    pub const MAX_FRAMES: usize = 16;

    /// Whether a block is waiting for CONTINUATION: nothing else may come until it ends.
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Take a frame. A block is returned once whole.
    pub fn push<'a>(&'a mut self, f: &Frame<'a>) -> Result<Option<Whole<'a>>, Violation> {
        match (*f, self.open) {
            (Frame::Headers { stream, end, done: true, block }, None) => Ok(Some((stream, end, block))),
            (Frame::Headers { stream, end, done: false, block }, None) => {
                self.bytes.clear();
                self.add(block)?;
                self.open = Some((stream, end, 1));
                Ok(None)
            }
            (Frame::Continuation { stream, done, block }, Some((open, end, frames))) if stream == open => {
                if frames == Self::MAX_FRAMES {
                    return Err(violation(ENHANCE_YOUR_CALM, "http2: too many CONTINUATION frames"));
                }
                self.add(block)?;
                self.open = Some((open, end, frames + 1));
                if !done {
                    return Ok(None);
                }
                self.open = None;
                Ok(Some((stream, end, &self.bytes)))
            }
            (Frame::Continuation { .. }, _) => {
                Err(violation(PROTOCOL_ERROR, "http2: CONTINUATION without HEADERS before it"))
            }
            (_, Some(_)) => Err(violation(PROTOCOL_ERROR, "http2: a frame inside a header block")),
            (_, None) => Ok(None),
        }
    }

    fn add(&mut self, b: &[u8]) -> Result<(), Violation> {
        if self.bytes.len() + b.len() > Self::MAX_BYTES {
            return Err(violation(ENHANCE_YOUR_CALM, "http2: header block too large"));
        }
        self.bytes.extend_from_slice(b);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(typ: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, typ, flags, stream, payload);
        out
    }

    /// `bytes` read as frames and parsed: each frame, or the error that stopped the reading.
    fn parse_all(bytes: &[u8], max: usize) -> Result<Vec<String>, String> {
        let mut r = bytes;
        let mut buf = Vec::new();
        let mut out = Vec::new();
        loop {
            match read(&mut r, max, &mut buf) {
                Ok(None) => return Ok(out),
                Ok(Some(Ok(h))) => match parse(&h, &buf) {
                    Ok(f) => out.push(format!("{f:?}")),
                    Err(v) => return Err(format!("{} {}", v.code, v.why)),
                },
                Ok(Some(Err(v))) => return Err(format!("{} {}", v.code, v.why)),
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    #[test]
    fn heads_round_trip() {
        let h = Head { len: 0x12_3456, typ: 9, flags: 0xa5, stream: 0x7fff_fffe };
        let mut out = Vec::new();
        h.write(&mut out);
        assert_eq!(Head::parse(&out.clone().try_into().unwrap()), h);
        // The reserved bit is dropped.
        out[5] |= 0x80;
        assert_eq!(Head::parse(&out.try_into().unwrap()).stream, 0x7fff_fffe);
    }

    #[test]
    fn parses_each_type() {
        let mut all = Vec::new();
        all.extend(frame(DATA, END_STREAM, 1, b"abc"));
        all.extend(frame(DATA, PADDED, 3, b"\x02xyz\0\0"));
        all.extend(frame(HEADERS, END_HEADERS | PRIORITY_FLAG, 5, b"\0\0\0\x01\x10\x82"));
        all.extend(frame(RST_STREAM, 0, 5, &8u32.to_be_bytes()));
        all.extend(frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]));
        all.extend(frame(SETTINGS, ACK, 0, b""));
        all.extend(frame(PING, 0, 0, b"12345678"));
        all.extend(frame(GOAWAY, 0, 0, b"\x80\0\0\x07\0\0\0\0debug"));
        all.extend(frame(WINDOW_UPDATE, 0, 0, &[0x80, 0, 0, 9]));
        all.extend(frame(PRIORITY, 0, 1, &[0; 5]));
        all.extend(frame(0xfa, 0xff, 0, b"unknown"));
        let got = parse_all(&all, DEFAULT_MAX_FRAME).unwrap();
        assert_eq!(
            got,
            [
                "Data { stream: 1, end: true, data: [97, 98, 99], pad: 0 }",
                "Data { stream: 3, end: false, data: [120, 121, 122], pad: 3 }",
                "Headers { stream: 5, end: false, done: true, block: [130] }",
                "Reset { stream: 5, code: 8 }",
                "Settings { ack: false, params: [0, 3, 0, 0, 0, 100] }",
                "Settings { ack: true, params: [] }",
                "Ping { ack: false, data: [49, 50, 51, 52, 53, 54, 55, 56] }",
                "GoAway { last: 7, code: 0 }",
                "WindowUpdate { stream: 0, increment: 9 }",
                "Ignored",
                "Ignored",
            ]
        );
        assert_eq!(settings(&[0, 3, 0, 0, 0, 100, 0, 5, 0, 0, 0x40, 0]).collect::<Vec<_>>(), [(3, 100), (5, 16384)]);
    }

    #[test]
    fn refuses_malformed_frames() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            // Truncated: in the header, and in the payload.
            (frame(DATA, 0, 1, b"abc")[..5].to_vec(), "http2: connection closed inside a frame"),
            (frame(DATA, 0, 1, b"abc")[..11].to_vec(), "http2: connection closed inside a frame"),
            // Longer than the maximum frame size: refused before the payload is read.
            (
                frame(DATA, 0, 1, &[0; DEFAULT_MAX_FRAME + 1])[..9].to_vec(),
                "6 http2: frame larger than the maximum frame size",
            ),
            // Bad padding: as long as the frame, longer, and no room for its length.
            (frame(DATA, PADDED, 1, b"\x04abc"), "1 http2: padding longer than the frame"),
            (frame(HEADERS, PADDED, 1, b"\x09ab"), "1 http2: padding longer than the frame"),
            (frame(DATA, PADDED, 1, b""), "6 http2: bad frame length"),
            // Stream 0 where a stream is needed, and a stream where none may be.
            (frame(DATA, 0, 0, b"x"), "1 http2: a stream frame on stream 0"),
            (frame(HEADERS, END_HEADERS, 0, b"\x82"), "1 http2: a stream frame on stream 0"),
            (frame(CONTINUATION, 0, 0, b""), "1 http2: a stream frame on stream 0"),
            (frame(RST_STREAM, 0, 0, &[0; 4]), "1 http2: a stream frame on stream 0"),
            (frame(PRIORITY, 0, 0, &[0; 5]), "1 http2: a stream frame on stream 0"),
            (frame(SETTINGS, 0, 1, b""), "1 http2: a connection frame on a stream"),
            (frame(PING, 0, 3, &[0; 8]), "1 http2: a connection frame on a stream"),
            (frame(GOAWAY, 0, 1, &[0; 8]), "1 http2: a connection frame on a stream"),
            // Wrong lengths.
            (frame(SETTINGS, 0, 0, &[0; 5]), "6 http2: bad frame length"),
            (frame(SETTINGS, ACK, 0, &[0; 6]), "6 http2: bad frame length"),
            (frame(PING, 0, 0, &[0; 7]), "6 http2: bad frame length"),
            (frame(GOAWAY, 0, 0, &[0; 7]), "6 http2: bad frame length"),
            (frame(RST_STREAM, 0, 1, &[0; 5]), "6 http2: bad frame length"),
            (frame(WINDOW_UPDATE, 0, 1, &[0; 3]), "6 http2: bad frame length"),
            (frame(PRIORITY, 0, 1, &[0; 4]), "6 http2: bad frame length"),
            (frame(HEADERS, PRIORITY_FLAG, 1, &[0; 4]), "6 http2: bad frame length"),
            // A zero window increment, and push.
            (frame(WINDOW_UPDATE, 0, 0, &[0x80, 0, 0, 0]), "1 http2: WINDOW_UPDATE of 0"),
            (frame(PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2, 0x82]), "1 http2: PUSH_PROMISE with push disabled"),
        ];
        for (bytes, want) in cases {
            assert_eq!(parse_all(&bytes, DEFAULT_MAX_FRAME).unwrap_err(), want, "{bytes:?}");
        }
        // A frame of exactly the maximum size is fine.
        assert!(parse_all(&frame(DATA, 0, 1, &[0; DEFAULT_MAX_FRAME]), DEFAULT_MAX_FRAME).is_ok());
    }

    fn headers(stream: u32, done: bool, block: &[u8]) -> Frame<'_> {
        Frame::Headers { stream, end: true, done, block }
    }

    fn cont(stream: u32, done: bool, block: &[u8]) -> Frame<'_> {
        Frame::Continuation { stream, done, block }
    }

    #[test]
    fn assembles_header_blocks() {
        let mut b = Block::default();
        assert_eq!(b.push(&headers(1, true, b"ab")).unwrap(), Some((1, true, &b"ab"[..])));
        assert_eq!(b.push(&headers(3, false, b"ab")).unwrap(), None);
        assert!(b.is_open());
        assert_eq!(b.push(&cont(3, false, b"")).unwrap(), None);
        assert_eq!(b.push(&cont(3, true, b"cd")).unwrap(), Some((3, true, &b"abcd"[..])));
        assert!(!b.is_open());
        // Other frames pass through between blocks.
        assert_eq!(b.push(&Frame::Ignored).unwrap(), None);
    }

    #[test]
    fn refuses_bad_header_blocks() {
        let e = |frames: &[Frame]| {
            let mut b = Block::default();
            frames.iter().map(|f| b.push(f).map(|_| ())).collect::<Result<Vec<_>, _>>().unwrap_err().why
        };
        // CONTINUATION with no HEADERS before it, after a whole block, and on another stream.
        assert_eq!(e(&[cont(1, true, b"")]), "http2: CONTINUATION without HEADERS before it");
        assert_eq!(e(&[headers(1, true, b""), cont(1, true, b"")]), "http2: CONTINUATION without HEADERS before it");
        assert_eq!(e(&[headers(1, false, b""), cont(3, true, b"")]), "http2: CONTINUATION without HEADERS before it");
        // Another frame, or another HEADERS, inside a block.
        assert_eq!(e(&[headers(1, false, b""), Frame::Ignored]), "http2: a frame inside a header block");
        assert_eq!(e(&[headers(1, false, b""), headers(3, true, b"")]), "http2: a frame inside a header block");
        // A flood of empty CONTINUATION frames, and too many bytes.
        let mut flood = vec![headers(1, false, b"")];
        flood.extend((0..Block::MAX_FRAMES).map(|_| cont(1, false, b"")));
        assert_eq!(e(&flood), "http2: too many CONTINUATION frames");
        let big = vec![0; Block::MAX_BYTES / 4 + 1];
        let mut many = vec![headers(1, false, &big)];
        many.extend((0..4).map(|_| cont(1, false, &big)));
        assert_eq!(e(&many), "http2: header block too large");
    }
}
