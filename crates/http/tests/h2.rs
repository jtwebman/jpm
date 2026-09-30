//! HTTP/2 end to end: a small server built on this crate's own frames and HPACK, over TLS
//! (rustls, with ALPN) and over plain loopback sockets for the protocol cases. Every socket has
//! a timeout, so no test can hang.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use jpm_http::frame::{self, Head};
use jpm_http::{Conn, Got, Link, MAX_STREAMS, Pool, Request, hpack};

const TIMEOUT: Duration = Duration::from_secs(20);

/// The server's side of one connection.
struct Peer<S> {
    s: S,
    dec: hpack::Decoder,
    block: Vec<u8>,
    /// The client's windows for what the server sends: the connection's, and each stream's.
    conn_window: i64,
    initial: i64,
    windows: HashMap<u32, i64>,
    /// Frames other than requests, in order, as `(type, flags, stream, payload)`.
    seen: Vec<(u8, u8, u32, Vec<u8>)>,
    /// The frames the last request's header block took.
    frames: usize,
}

impl<S: Read + Write> Peer<S> {
    /// Read the client's preface, and send SETTINGS with `settings`.
    fn new(mut s: S, settings: &[(u16, u32)]) -> Self {
        let mut preface = [0; 24];
        s.read_exact(&mut preface).unwrap();
        assert_eq!(&preface[..], frame::PREFACE);
        let mut p = Self {
            s,
            dec: hpack::Decoder::default(),
            block: Vec::new(),
            conn_window: 65_535,
            initial: 65_535,
            windows: HashMap::new(),
            seen: Vec::new(),
            frames: 0,
        };
        let mut payload = Vec::new();
        for (id, v) in settings {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&v.to_be_bytes());
        }
        p.send(frame::SETTINGS, 0, 0, &payload);
        p
    }

    fn send(&mut self, typ: u8, flags: u8, stream: u32, payload: &[u8]) {
        let mut out = Vec::new();
        frame::put(&mut out, typ, flags, stream, payload);
        self.s.write_all(&out).unwrap();
        self.s.flush().unwrap();
    }

    /// The next frame, or `None` at the end of the connection.
    fn frame(&mut self) -> Option<(Head, Vec<u8>)> {
        let mut buf = Vec::new();
        match frame::read(&mut self.s, 1 << 24, &mut buf) {
            Ok(Some(Ok(h))) => Some((h, buf)),
            _ => None,
        }
    }

    /// Take one frame that is not a request's: settings and windows are noted, SETTINGS and
    /// PING answered.
    fn note(&mut self, h: Head, p: Vec<u8>) {
        match h.typ {
            frame::SETTINGS if h.flags & frame::ACK == 0 => {
                for (id, v) in frame::settings(&p) {
                    if id == frame::INITIAL_WINDOW_SIZE {
                        let delta = i64::from(v) - self.initial;
                        self.initial = i64::from(v);
                        self.windows.values_mut().for_each(|w| *w += delta);
                    }
                }
                self.send(frame::SETTINGS, frame::ACK, 0, &[]);
            }
            frame::WINDOW_UPDATE => {
                let n = i64::from(u32::from_be_bytes(p[..4].try_into().unwrap()));
                if h.stream == 0 {
                    self.conn_window += n;
                } else if let Some(w) = self.windows.get_mut(&h.stream) {
                    *w += n;
                }
            }
            _ => {}
        }
        self.seen.push((h.typ, h.flags, h.stream, p));
    }

    /// The next request: its stream and its fields, names and values as text.
    fn request(&mut self) -> Option<(u32, Vec<(String, String)>)> {
        loop {
            let (h, p) = self.frame()?;
            match h.typ {
                frame::HEADERS | frame::CONTINUATION => {
                    if h.typ == frame::HEADERS {
                        self.block.clear();
                        self.frames = 0;
                    }
                    self.block.extend_from_slice(&p);
                    self.frames += 1;
                    if h.flags & frame::END_HEADERS != 0 {
                        assert!(
                            h.typ == frame::CONTINUATION || h.flags & frame::END_STREAM != 0,
                            "a GET ends its stream"
                        );
                        let fields = self.dec.decode(&self.block, 1 << 20).unwrap();
                        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
                        self.windows.insert(h.stream, self.initial);
                        return Some((h.stream, fields.into_iter().map(|(n, v)| (text(n), text(v))).collect()));
                    }
                }
                _ => self.note(h, p),
            }
        }
    }

    /// Frames until one of type `typ`, noting the others.
    fn until(&mut self, typ: u8) -> Option<(Head, Vec<u8>)> {
        loop {
            let (h, p) = self.frame()?;
            if h.typ == typ {
                return Some((h, p));
            }
            self.note(h, p);
        }
    }

    fn head(&mut self, id: u32, status: u16, headers: &[(&str, &str)], end: bool) {
        let mut block = Vec::new();
        hpack::encode(&mut block, ":status", &status.to_string(), false);
        for (n, v) in headers {
            hpack::encode(&mut block, n, v, false);
        }
        let flags = frame::END_HEADERS | if end { frame::END_STREAM } else { 0 };
        self.send(frame::HEADERS, flags, id, &block);
    }

    /// `body` as DATA, within the client's windows: when they are spent, wait for its
    /// WINDOW_UPDATEs.
    fn data(&mut self, id: u32, body: &[u8], end: bool) {
        let mut rest = body;
        loop {
            let room = self.conn_window.min(self.windows[&id]).min(frame::DEFAULT_MAX_FRAME as i64);
            if room <= 0 {
                let (h, p) = self.frame().expect("the client gives window back");
                self.note(h, p);
                continue;
            }
            let n = rest.len().min(room as usize);
            let last = n == rest.len();
            self.send(frame::DATA, if end && last { frame::END_STREAM } else { 0 }, id, &rest[..n]);
            self.conn_window -= n as i64;
            *self.windows.get_mut(&id).unwrap() -= n as i64;
            rest = &rest[n..];
            if last {
                return;
            }
        }
    }

    fn respond(&mut self, id: u32, status: u16, body: &[u8]) {
        let len = body.len().to_string();
        self.head(id, status, &[("content-length", &len)], body.is_empty());
        if !body.is_empty() {
            self.data(id, body, true);
        }
    }

    /// The GOAWAY the client sent, if it sent one: its error code.
    fn goaway(&mut self) -> Option<u32> {
        let (_, p) = self.until(frame::GOAWAY)?;
        Some(u32::from_be_bytes(p[4..8].try_into().unwrap()))
    }
}

fn get<'a>(field: &'a [(String, String)], name: &str) -> Option<&'a str> {
    field.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// A loopback listener: each connection runs `serve` on a thread of its own, told which
/// connection it is.
fn listen(serve: impl Fn(TcpStream, usize) + Send + Sync + 'static) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let serve = Arc::new(serve);
    thread::spawn(move || {
        for (i, s) in l.incoming().enumerate() {
            let s = s.unwrap();
            s.set_read_timeout(Some(TIMEOUT)).unwrap();
            s.set_nodelay(true).unwrap();
            let serve = serve.clone();
            thread::spawn(move || serve(s, i));
        }
    });
    addr
}

/// A plain connection's HTTP/2 client, with `stall` as its read timeout.
fn plain(addr: std::net::SocketAddr, stall: Duration) -> io::Result<Link<()>> {
    let s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(TIMEOUT))?;
    Ok(Link::H2(Conn::start(s.try_clone()?, s, stall)?))
}

fn conn(addr: std::net::SocketAddr) -> Conn {
    match plain(addr, TIMEOUT).unwrap() {
        Link::H2(c) => c,
        Link::H1(()) => unreachable!(),
    }
}

fn req(path: &str) -> Request<'_> {
    Request { authority: "r.test", path, headers: &[] }
}

fn body(r: jpm_http::Response) -> io::Result<Vec<u8>> {
    let mut b = r.body;
    let mut out = Vec::new();
    b.read_to_end(&mut out)?;
    Ok(out)
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761).rotate_right(13) as u8 ^ seed).collect()
}

// --- over TLS -------------------------------------------------------------------------------

struct Tls {
    anchor: jpm_tls::Anchor<'static>,
    server: Arc<rustls::ServerConfig>,
}

/// A certificate for localhost, and rustls configured with it and with `alpn`.
fn tls(alpn: &[&[u8]]) -> Tls {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    p.subject_alt_names.push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let cert = p.self_signed(&key).unwrap();
    let der: &'static [u8] = Box::leak(cert.der().to_vec().into_boxed_slice());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
        .unwrap();
    server.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Tls { anchor: jpm_tls::Anchor::from_cert(der).unwrap(), server: Arc::new(server) }
}

type TlsStream = jpm_tls::Stream<TcpStream>;

fn dial(addr: std::net::SocketAddr, config: &jpm_tls::Config) -> io::Result<Link<TlsStream>> {
    let s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(TIMEOUT))?;
    jpm_http::tls_link(jpm_tls::Stream::connect(s, "localhost", config)?, TIMEOUT)
}

fn client_config(t: &Tls) -> jpm_tls::Config {
    jpm_tls::Config {
        roots: vec![t.anchor],
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        insecure_skip_verify: false,
        verified: Default::default(),
    }
}

#[test]
fn gets_over_tls_when_alpn_picks_h2() {
    let t = tls(&[b"h2", b"http/1.1"]);
    let config = t.server.clone();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let log = heard.clone();
    let addr = listen(move |s, _| {
        let tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config.clone()).unwrap(), s);
        let mut p = Peer::new(tls, &[(frame::MAX_CONCURRENT_STREAMS, 100)]);
        while let Some((id, fields)) = p.request() {
            let path = get(&fields, ":path").unwrap().to_string();
            log.lock().unwrap().push(fields);
            match path.as_str() {
                "/doc" => p.respond(id, 200, br#"{"name":"a"}"#),
                "/big" => p.respond(id, 200, &pattern(3 << 20, 7)),
                "/same" => p.respond(id, 304, b""),
                _ => p.respond(id, 404, b""),
            }
        }
    });
    let pool = Pool::new(1, MAX_STREAMS, TIMEOUT);
    let config = client_config(&t);
    let connects = AtomicUsize::new(0);
    let connect = || {
        connects.fetch_add(1, Ordering::Relaxed);
        dial(addr, &config)
    };
    let headers = [("accept", "application/json"), ("authorization", "Bearer t"), ("host", "x"), ("Npm-Command", "ci")];
    let request = Request { authority: "localhost:8443", path: "/doc", headers: &headers };
    let Got::H2(r) = pool.get("localhost", connect, &request).unwrap() else { panic!("HTTP/1.1") };
    assert_eq!((r.status, r.header("content-length")), (200, Some("12")));
    assert_eq!(body(r).unwrap(), br#"{"name":"a"}"#);
    for (path, status, len) in [("/big", 200, 3 << 20), ("/same", 304, 0), ("/nope", 404, 0)] {
        let Got::H2(r) = pool.get("localhost", connect, &req(path)).unwrap() else { panic!() };
        assert_eq!(r.status, status);
        let b = body(r).unwrap();
        assert_eq!(b.len(), len);
        if len > 0 {
            assert!(b == pattern(len, 7));
        }
    }
    assert_eq!(connects.load(Ordering::Relaxed), 1, "every request on one connection");
    // What the server heard: the pseudo-headers first, names lowercase, and nothing
    // connection-specific.
    let first = heard.lock().unwrap()[0].clone();
    let names: Vec<&str> = first.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, [":method", ":scheme", ":authority", ":path", "accept", "authorization", "npm-command"]);
    assert_eq!(get(&first, ":authority"), Some("localhost:8443"));
    assert_eq!(get(&first, "authorization"), Some("Bearer t"));
    assert_eq!(get(&first, ":scheme"), Some("https"));
}

#[test]
fn hands_back_http1_when_alpn_picks_it() {
    for alpn in [&[&b"http/1.1"[..]][..], &[]] {
        let t = tls(alpn);
        let config = t.server.clone();
        let addr = listen(move |s, _| {
            let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config.clone()).unwrap(), s);
            let mut line = [0; 16];
            tls.read_exact(&mut line).unwrap();
            assert_eq!(&line, b"GET / HTTP/1.1\r\n");
            tls.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
            tls.flush().unwrap();
        });
        let pool = Pool::new(2, MAX_STREAMS, TIMEOUT);
        let config = client_config(&t);
        let Got::H1(Some(mut s)) = pool.get("localhost", || dial(addr, &config), &req("/")).unwrap() else {
            panic!("expected HTTP/1.1")
        };
        assert_eq!(s.alpn(), alpn.first().copied());
        s.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n").unwrap();
        let mut got = [0; 12];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"HTTP/1.1 204");
        // The host is known now: no connection is made for it again.
        assert!(pool.is_h1("localhost"));
        let again = pool.get("localhost", || -> io::Result<Link<TlsStream>> { panic!("connected again") }, &req("/"));
        let again = again.unwrap();
        assert!(matches!(again, Got::H1(None)));
    }
}

// --- the protocol, over plain sockets -------------------------------------------------------

#[test]
fn many_streams_at_once_answered_out_of_order() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let mut ids = Vec::new();
        for _ in 0..40 {
            let (id, fields) = p.request().unwrap();
            ids.push((id, get(&fields, ":path").unwrap()[1..].parse::<usize>().unwrap()));
        }
        // Heads in reverse order, then the bodies a frame at a time, round robin.
        for &(id, n) in ids.iter().rev() {
            p.head(id, 200, &[("content-length", &(n * 1000).to_string())], n == 0);
        }
        let mut sent = vec![0; ids.len()];
        while sent.iter().zip(&ids).any(|(s, (_, n))| *s < n * 1000) {
            for (i, &(id, n)) in ids.iter().enumerate() {
                let left = n * 1000 - sent[i];
                if left > 0 {
                    let k = left.min(3000);
                    let chunk = pattern(n * 1000, n as u8)[sent[i]..sent[i] + k].to_vec();
                    p.data(id, &chunk, k == left);
                    sent[i] += k;
                }
            }
        }
        while p.frame().is_some() {}
    });
    let c = conn(addr);
    let all: Vec<_> = (0..40)
        .map(|n| {
            let c = c.clone();
            thread::spawn(move || {
                let path = format!("/{n}");
                let r = c.get(&req(&path)).unwrap();
                assert_eq!(r.status, 200);
                assert!(body(r).unwrap() == pattern(n * 1000, n as u8), "{n}");
            })
        })
        .collect();
    all.into_iter().for_each(|t| t.join().unwrap());
    assert_eq!(c.active(), 0);
}

#[test]
fn gives_window_back_as_bodies_are_read() {
    // 20 MiB on one stream, far past both windows: it only arrives if the client gives window
    // back, and the server never sends past what it was given.
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (id, _) = p.request().unwrap();
        p.respond(id, 200, &pattern(20 << 20, 3));
        while p.frame().is_some() {}
    });
    let c = conn(addr);
    let r = c.get(&req("/")).unwrap();
    let mut b = r.body;
    let mut got = Vec::new();
    let mut buf = vec![0; 7777];
    loop {
        let n = b.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got == pattern(20 << 20, 3));
}

#[test]
fn refuses_data_past_the_window() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (id, _) = p.request().unwrap();
        p.head(id, 200, &[], false);
        // The stream's window is 2 MiB: send 2 MiB and a frame more, ignoring it.
        for _ in 0..(2 << 20) / frame::DEFAULT_MAX_FRAME + 1 {
            p.send(frame::DATA, 0, id, &[0; frame::DEFAULT_MAX_FRAME]);
        }
        assert_eq!(p.goaway(), Some(frame::FLOW_CONTROL_ERROR));
    });
    let c = conn(addr);
    let r = c.get(&req("/")).unwrap();
    // Nothing is read while the server sends: the window is not given back.
    thread::sleep(Duration::from_millis(300));
    let e = body(r).unwrap_err();
    assert!(e.to_string().contains("DATA beyond the stream's window"), "{e}");
    assert!(c.is_closed());
}

#[test]
fn goaway_sends_unanswered_requests_again_on_a_new_connection() {
    let addr = listen(|s, i| {
        let mut p = Peer::new(s, &[]);
        if i == 0 {
            // Two requests in; GOAWAY says only the first will be answered.
            let (a, _) = p.request().unwrap();
            let (b, _) = p.request().unwrap();
            assert!(b > a);
            let mut payload = a.to_be_bytes().to_vec();
            payload.extend_from_slice(&0u32.to_be_bytes());
            p.send(frame::GOAWAY, 0, 0, &payload);
            p.respond(a, 200, b"first");
        } else {
            let (id, _) = p.request().unwrap();
            p.respond(id, 200, b"second");
            while p.frame().is_some() {}
        }
    });
    let pool = Pool::new(1, MAX_STREAMS, TIMEOUT);
    let connects = AtomicUsize::new(0);
    let connect = || {
        connects.fetch_add(1, Ordering::Relaxed);
        plain(addr, TIMEOUT)
    };
    thread::scope(|s| {
        let got: Vec<_> = (0..2)
            .map(|i| {
                let (pool, connect) = (&pool, &connect);
                s.spawn(move || {
                    // The second waits until the first has its stream.
                    thread::sleep(Duration::from_millis(200 * i));
                    let Got::H2(r) = pool.get("r.test", connect, &req("/")).unwrap() else { panic!() };
                    body(r).unwrap()
                })
            })
            .collect();
        let mut got: Vec<_> = got.into_iter().map(|t| t.join().unwrap()).collect();
        got.sort();
        assert_eq!(got, [b"first".to_vec(), b"second".to_vec()]);
    });
    assert_eq!(connects.load(Ordering::Relaxed), 2);
}

#[test]
fn a_refused_stream_goes_again_and_a_reset_one_fails() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (a, _) = p.request().unwrap();
        p.send(frame::RST_STREAM, 0, a, &frame::REFUSED_STREAM.to_be_bytes());
        let (b, _) = p.request().unwrap();
        p.respond(b, 200, b"ok");
        let (c, _) = p.request().unwrap();
        p.head(c, 200, &[], false);
        p.data(c, b"part", false);
        p.send(frame::RST_STREAM, 0, c, &frame::INTERNAL_ERROR.to_be_bytes());
        while p.frame().is_some() {}
    });
    let pool = Pool::new(1, MAX_STREAMS, TIMEOUT);
    let Got::H2(r) = pool.get("r.test", || plain(addr, TIMEOUT), &req("/")).unwrap() else { panic!() };
    assert_eq!(body(r).unwrap(), b"ok");
    let Got::H2(r) = pool.get("r.test", || plain(addr, TIMEOUT), &req("/")).unwrap() else { panic!() };
    let e = body(r).unwrap_err();
    assert_eq!(e.to_string(), "http2: the server reset the stream (error code 2)");
}

#[test]
fn a_dropped_body_resets_its_stream_and_the_connection_goes_on() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (a, _) = p.request().unwrap();
        p.head(a, 200, &[], false);
        p.data(a, &[1; 100_000], false);
        let (h, payload) = p.until(frame::RST_STREAM).unwrap();
        assert_eq!((h.stream, u32::from_be_bytes(payload[..4].try_into().unwrap())), (a, frame::CANCEL));
        // DATA already on its way for the reset stream is dropped by the client.
        p.send(frame::DATA, 0, a, &[2; 1000]);
        let (b, _) = p.request().unwrap();
        p.respond(b, 200, b"next");
        while p.frame().is_some() {}
    });
    let c = conn(addr);
    let r = c.get(&req("/a")).unwrap();
    let mut b = r.body;
    b.read_exact(&mut [0; 10]).unwrap();
    drop(b);
    assert_eq!(body(c.get(&req("/b")).unwrap()).unwrap(), b"next");
}

#[test]
fn reads_heads_across_continuation_and_skips_interim_and_trailers() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (id, _) = p.request().unwrap();
        // A 103, then the head in three frames, the body, and trailers.
        let mut interim = Vec::new();
        hpack::encode(&mut interim, ":status", "103", false);
        p.send(frame::HEADERS, frame::END_HEADERS, id, &interim);
        let mut block = Vec::new();
        hpack::encode(&mut block, ":status", "200", false);
        hpack::encode(&mut block, "etag", "\"abc\"", false);
        hpack::encode(&mut block, "x-long", &"v".repeat(40_000), false);
        let parts: Vec<&[u8]> = block.chunks(block.len() / 3 + 1).collect();
        p.send(frame::HEADERS, 0, id, parts[0]);
        p.send(frame::CONTINUATION, 0, id, parts[1]);
        p.send(frame::CONTINUATION, frame::END_HEADERS, id, parts[2]);
        p.send(frame::PING, 0, 0, b"pingpong");
        p.data(id, b"body", false);
        let mut trailers = Vec::new();
        hpack::encode(&mut trailers, "x-checksum", "1", false);
        p.send(frame::HEADERS, frame::END_HEADERS | frame::END_STREAM, id, &trailers);
        let (h, payload) = p.until(frame::PING).unwrap();
        assert_eq!((h.flags, &payload[..]), (frame::ACK, &b"pingpong"[..]));
        while p.frame().is_some() {}
    });
    let c = conn(addr);
    let r = c.get(&req("/")).unwrap();
    assert_eq!((r.status, r.header("etag")), (200, Some("\"abc\"")));
    assert_eq!(r.header("x-long").map(str::len), Some(40_000));
    assert_eq!(body(r).unwrap(), b"body");
}

#[test]
fn sends_a_long_head_in_continuation_frames() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (id, fields) = p.request().unwrap();
        let v = format!("{} in {} frames", get(&fields, "authorization").unwrap().len(), p.frames);
        p.respond(id, 200, v.as_bytes());
        while p.frame().is_some() {}
    });
    let long = format!("Bearer {}", "t".repeat(50_000));
    let headers = [("authorization", long.as_str())];
    let r = conn(addr).get(&Request { authority: "r.test", path: "/", headers: &headers }).unwrap();
    // 16 KiB frames, the default maximum: HEADERS and three CONTINUATION.
    assert_eq!(body(r).unwrap(), b"50007 in 4 frames");
}

/// The most streams open at once while 12 requests go at once on one connection, the server
/// allowing `server` streams and the pool `cap`. The server answers two at a time.
fn most_streams_open(server: u32, cap: usize) -> usize {
    let most = Arc::new(AtomicUsize::new(0));
    let m = most.clone();
    let addr = listen(move |s, _| {
        let mut p = Peer::new(s, &[(frame::MAX_CONCURRENT_STREAMS, server)]);
        let (first, _) = p.request().unwrap();
        p.respond(first, 200, b"x");
        // A third request before two are answered would be one stream too many.
        let mut waiting = Vec::new();
        for _ in 0..12 {
            let (id, _) = p.request().unwrap();
            waiting.push(id);
            m.fetch_max(waiting.len(), Ordering::SeqCst);
            if waiting.len() == 2 {
                for id in waiting.drain(..) {
                    p.respond(id, 200, b"x");
                }
            }
        }
        while p.frame().is_some() {}
    });
    let pool = Pool::new(1, cap, TIMEOUT);
    // The first request's answer comes after the server's SETTINGS: then ask many at once.
    let Got::H2(r) = pool.get("r.test", || plain(addr, TIMEOUT), &req("/")).unwrap() else { panic!() };
    assert_eq!(body(r).unwrap(), b"x");
    let again = || -> io::Result<Link<()>> { panic!("a second connection") };
    thread::scope(|s| {
        let all: Vec<_> = (0..12)
            .map(|_| {
                s.spawn(|| {
                    let Got::H2(r) = pool.get("r.test", again, &req("/")).unwrap() else { panic!() };
                    body(r).unwrap()
                })
            })
            .collect();
        all.into_iter().for_each(|t| assert_eq!(t.join().unwrap(), b"x"));
    });
    most.load(Ordering::SeqCst)
}

#[test]
fn keeps_to_max_concurrent_streams() {
    assert_eq!(most_streams_open(2, MAX_STREAMS), 2);
}

#[test]
fn keeps_to_its_pools_stream_cap() {
    assert_eq!(most_streams_open(100, 2), 2);
}

#[test]
fn refuses_a_header_with_a_line_break_and_keeps_its_stream() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[(frame::MAX_CONCURRENT_STREAMS, 1)]);
        while let Some((id, _)) = p.request() {
            p.respond(id, 200, b"x");
        }
    });
    let pool = Pool::new(1, MAX_STREAMS, Duration::from_secs(2));
    let Got::H2(r) = pool.get("r.test", || plain(addr, TIMEOUT), &req("/")).unwrap() else { panic!() };
    assert_eq!(body(r).unwrap(), b"x");
    let again = || -> io::Result<Link<()>> { panic!("a second connection") };
    for bad in [("x-a", "1\r\nx-b: 2"), ("x-a", "1\n"), ("x-a\r", "1"), ("x-a", "\0"), ("", "1")] {
        let headers = [bad];
        let e =
            pool.get("r.test", again, &Request { authority: "r.test", path: "/", headers: &headers }).err().unwrap();
        assert_eq!(e.kind, io::ErrorKind::InvalidInput, "{bad:?}");
    }
    // The one stream the server allows is still free.
    let Got::H2(r) = pool.get("r.test", again, &req("/")).unwrap() else { panic!() };
    assert_eq!(body(r).unwrap(), b"x");
}

#[test]
fn opens_up_to_its_connections_per_host() {
    let conns = Arc::new(AtomicUsize::new(0));
    let c = conns.clone();
    let addr = listen(move |s, _| {
        c.fetch_add(1, Ordering::SeqCst);
        let mut p = Peer::new(s, &[]);
        while let Some((id, _)) = p.request() {
            thread::sleep(Duration::from_millis(20));
            p.respond(id, 200, b"x");
        }
    });
    let pool = Pool::new(3, MAX_STREAMS, TIMEOUT);
    thread::scope(|s| {
        for _ in 0..30 {
            s.spawn(|| {
                let Got::H2(r) = pool.get("r.test", || plain(addr, TIMEOUT), &req("/")).unwrap() else { panic!() };
                assert_eq!(body(r).unwrap(), b"x");
            });
        }
    });
    assert_eq!(conns.load(Ordering::SeqCst), 3);
}

/// A request goes to the connection with the fewest bytes still to come, not the one with the
/// fewest streams: a large body arriving on one leaves the other to carry the small ones.
#[test]
fn places_a_stream_where_the_fewest_bytes_are_to_come() {
    let heard = Arc::new(Mutex::new(Vec::new()));
    let h = heard.clone();
    let addr = listen(move |s, i| {
        let mut p = Peer::new(s, &[]);
        while let Some((id, fields)) = p.request() {
            let path = get(&fields, ":path").unwrap().to_string();
            h.lock().unwrap().push((i, path.clone()));
            // A head whose body never comes: its bytes stay to come until the client resets it.
            match path.as_str() {
                "/big" => p.head(id, 200, &[("content-length", "10000000")], false),
                "/small" => p.head(id, 200, &[("content-length", "1000")], false),
                _ => p.respond(id, 200, b"x"),
            }
        }
    });
    let pool = Pool::new(2, MAX_STREAMS, TIMEOUT);
    let get = |path| {
        let Got::H2(r) = pool.get("r.test", || plain(addr, TIMEOUT), &req(path)).unwrap() else { panic!() };
        r
    };
    // One stream open on each connection: 10 MB to come on the first, 1 KB on the second.
    let (big, small) = (get("/big"), get("/small"));
    for _ in 0..3 {
        assert_eq!(body(get("/next")).unwrap(), b"x");
    }
    drop((big, small));
    let heard = heard.lock().unwrap().clone();
    let next: Vec<usize> = heard.iter().filter(|(_, p)| p == "/next").map(|(i, _)| *i).collect();
    assert_eq!((heard[0].0, heard[1].0, next), (0, 1, vec![1, 1, 1]), "{heard:?}");
}

/// Each case: what the server sends after the request's HEADERS, and what the client's error
/// says. The server must hear GOAWAY with `code`.
#[test]
fn refuses_protocol_violations() {
    let head = |status: &str| {
        let mut b = Vec::new();
        hpack::encode(&mut b, ":status", status, false);
        b
    };
    type Frames = Vec<(u8, u8, u32, Vec<u8>)>;
    let cases: Vec<(Frames, u32, &str)> = vec![
        (vec![(frame::DATA, 0, 1, b"x".to_vec())], frame::PROTOCOL_ERROR, "DATA before the response head"),
        (vec![(frame::DATA, 0, 3, b"x".to_vec())], frame::PROTOCOL_ERROR, "a frame for a stream never opened"),
        (
            vec![(frame::HEADERS, frame::END_HEADERS, 2, head("200"))],
            frame::PROTOCOL_ERROR,
            "a frame for a stream never opened",
        ),
        (
            vec![(frame::PUSH_PROMISE, frame::END_HEADERS, 1, vec![0, 0, 0, 2, 0x88])],
            frame::PROTOCOL_ERROR,
            "PUSH_PROMISE",
        ),
        (
            vec![(frame::CONTINUATION, frame::END_HEADERS, 1, head("200"))],
            frame::PROTOCOL_ERROR,
            "CONTINUATION without HEADERS",
        ),
        (
            std::iter::once((frame::HEADERS, 0, 1, head("200")))
                .chain((0..100).map(|_| (frame::CONTINUATION, 0, 1, Vec::new())))
                .collect(),
            frame::ENHANCE_YOUR_CALM,
            "too many CONTINUATION frames",
        ),
        (vec![(frame::HEADERS, frame::END_HEADERS, 1, vec![0xbf])], frame::COMPRESSION_ERROR, "hpack: bad index"),
        (vec![(frame::HEADERS, frame::END_HEADERS, 1, head("abc"))], frame::PROTOCOL_ERROR, "without a status"),
        (vec![(frame::SETTINGS, 0, 0, vec![0, 2, 0, 0, 0, 1])], frame::PROTOCOL_ERROR, "enabled push"),
        (vec![(frame::SETTINGS, 0, 0, vec![0, 5, 0, 0, 0, 1])], frame::PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE"),
        (vec![(frame::WINDOW_UPDATE, 0, 0, vec![0x7f, 0xff, 0xff, 0xff])], frame::FLOW_CONTROL_ERROR, "window above"),
        (vec![(frame::DATA, 0, 0, b"x".to_vec())], frame::PROTOCOL_ERROR, "a stream frame on stream 0"),
        (vec![(frame::PING, 0, 0, vec![0; 3])], frame::FRAME_SIZE_ERROR, "bad frame length"),
        (vec![(frame::DATA, 0, 1, vec![0; 20_000])], frame::FRAME_SIZE_ERROR, "larger than the maximum frame size"),
    ];
    for (frames, code, why) in cases {
        let heard = Arc::new(Mutex::new(None));
        let h = heard.clone();
        let addr = listen(move |s, _| {
            let mut p = Peer::new(s, &[]);
            p.request().unwrap();
            for (typ, flags, stream, payload) in &frames {
                p.send(*typ, *flags, *stream, payload);
            }
            *h.lock().unwrap() = p.goaway();
        });
        let c = conn(addr);
        let e = match c.get(&req("/")) {
            Ok(r) => body(r).unwrap_err().to_string(),
            Err(e) => e.to_string(),
        };
        assert!(e.contains(why), "{why}: {e}");
        for _ in 0..100 {
            if heard.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(*heard.lock().unwrap(), Some(code), "{why}");
        assert!(c.is_closed());
    }
}

#[test]
fn fails_a_body_cut_short_or_the_wrong_length() {
    for case in 0..3 {
        let addr = listen(move |s, _| {
            let mut p = Peer::new(s, &[]);
            let (id, _) = p.request().unwrap();
            p.head(id, 200, &[("content-length", "10")], false);
            match case {
                0 => p.data(id, b"12345", true),
                1 => p.data(id, b"12345678901", true),
                // The connection closes in the middle of the body.
                _ => {
                    p.data(id, b"12345", false);
                    p.s.shutdown(std::net::Shutdown::Write).unwrap();
                }
            }
            while p.frame().is_some() {}
        });
        let e = body(conn(addr).get(&req("/")).unwrap()).unwrap_err();
        let want = ["a body of 5 bytes where content-length said 10", "a body of 11 bytes", "connection closed"][case];
        assert!(e.to_string().contains(want), "{case}: {e}");
    }
}

#[test]
fn a_silent_server_times_out() {
    let addr = listen(|s, _| {
        let mut p = Peer::new(s, &[]);
        let (id, _) = p.request().unwrap();
        p.head(id, 200, &[], false);
        thread::sleep(Duration::from_secs(2));
    });
    let Link::H2(c) = plain(addr, Duration::from_millis(300)).unwrap() else { unreachable!() };
    let e = body(c.get(&req("/")).unwrap()).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
}
