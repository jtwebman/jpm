//! Interop with rustls as the server, over loopback: every version, suite, certificate key type
//! and group; ALPN; payloads around the record size; handshake messages cut into small records;
//! KeyUpdate; both ways a connection can end; and a stream split into a reader and a writer.

mod common;

use std::io::{ErrorKind, Read, Write};

use common::{
    KEY_TYPES, KeyType, RustlsStream, ServerOpts, connect, pattern, pki, rustls_server, rustls_server_config,
};

#[derive(Clone, Debug)]
struct Case {
    opts: ServerOpts,
    key: KeyType,
    client_alpn: Vec<&'static [u8]>,
    /// Bytes client to server, then server to client.
    up: usize,
    down: usize,
    /// Server KeyUpdates (with update_requested) before it sends its data.
    key_updates: usize,
    /// close_notify at the end, or just a TCP close.
    clean: bool,
    /// The client sends through a `Writer` split off the stream, from another thread.
    split: bool,
}

impl Case {
    fn new(tls13: bool, aead: usize, key: KeyType) -> Self {
        Self {
            opts: ServerOpts { tls13, aead, ..ServerOpts::default() },
            key,
            client_alpn: Vec::new(),
            up: 100,
            down: 100,
            key_updates: 0,
            clean: true,
            split: false,
        }
    }
}

/// What the server negotiated.
#[derive(Debug)]
struct Seen {
    alpn: Option<Vec<u8>>,
    tls13: bool,
    suite: u16,
}

fn server_side(s: &mut RustlsStream, c: &Case) -> std::io::Result<Seen> {
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    let mut got = vec![0; c.up];
    s.read_exact(&mut got)?;
    assert!(got == pattern(c.up, 1), "{c:?}: data client to server");
    let half = c.down / 2;
    let data = pattern(c.down, 2);
    for i in 0..c.key_updates {
        s.conn.refresh_traffic_keys().unwrap();
        // Some data between updates, so that each new key is used.
        s.write_all(&data[..half.min(i * 1000)])?;
    }
    s.write_all(&data)?;
    s.flush()?;
    // The client's last byte comes after it has seen the updates, under its new key.
    let mut ack = [0; 1];
    s.read_exact(&mut ack)?;
    assert_eq!(&ack, b"!");
    if c.clean {
        s.conn.send_close_notify();
        s.flush()?;
    }
    let tls13 = s.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
    let suite = u16::from(s.conn.negotiated_cipher_suite().unwrap().suite());
    Ok(Seen { alpn: s.conn.alpn_protocol().map(<[u8]>::to_vec), tls13, suite })
}

/// Run one case; the ALPN protocol our client saw.
fn run(c: &Case) -> Result<Option<Vec<u8>>, String> {
    let pki = pki(c.key);
    let config = rustls_server_config(pki, &c.opts);
    let case = c.clone();
    let (tcp, server) = rustls_server(config, move |s| server_side(s, &case));
    let client = (|| -> std::io::Result<Option<Vec<u8>>> {
        let mut s = connect(tcp, "localhost", &pki.config(&c.client_alpn))?;
        let writer = if c.split { Some(s.split(s.get_ref().try_clone()?)) } else { None };
        match &writer {
            Some(w) => {
                let (w, up) = (w.clone(), c.up);
                std::thread::spawn(move || (&w).write_all(&pattern(up, 1)).and_then(|_| (&w).flush()))
                    .join()
                    .unwrap()?;
            }
            None => {
                s.write_all(&pattern(c.up, 1))?;
                s.flush()?;
            }
        }
        // Read in uneven pieces to go through the buffered-plaintext path.
        let want = pattern(c.down + sent_before(c), 2);
        let mut got = Vec::with_capacity(want.len());
        let mut buf = vec![0; 40000];
        let mut step = 1;
        while got.len() < want.len() {
            let n = (want.len() - got.len()).min(step);
            let n = s.read(&mut buf[..n])?;
            if n == 0 {
                return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "early end"));
            }
            got.extend_from_slice(&buf[..n]);
            step = (step * 7 + 13) % 39000 + 1;
        }
        match &writer {
            Some(w) => (&*w).write_all(b"!")?,
            None => s.write_all(b"!")?,
        }
        let end = s.read(&mut buf);
        if c.clean {
            assert_eq!(end.ok(), Some(0), "{c:?}: close_notify is a clean end");
            // And stays one.
            assert_eq!(s.read(&mut buf).ok(), Some(0));
        } else {
            let e = end.expect_err("a TCP close without close_notify is an error");
            assert_eq!(e.kind(), ErrorKind::UnexpectedEof, "{c:?}: {e}");
        }
        // The data read must be what was sent, for the parts sent between key updates too.
        let mut expect = Vec::new();
        for i in 0..c.key_updates {
            expect.extend_from_slice(&pattern(c.down, 2)[..(c.down / 2).min(i * 1000)]);
        }
        expect.extend_from_slice(&pattern(c.down, 2));
        assert!(got == expect, "{c:?}: data server to client");
        Ok(s.alpn().map(<[u8]>::to_vec))
    })();
    let seen = server.join().map_err(|_| format!("{c:?}: server panicked"))?;
    match (client, seen) {
        (Ok(alpn), Ok(seen)) => {
            assert_eq!(seen.tls13, c.opts.tls13, "{c:?}");
            assert_eq!(alpn, seen.alpn, "{c:?}");
            let rsa = matches!(c.key, KeyType::Rsa2048 | KeyType::Rsa4096);
            let suite = match (c.opts.tls13, c.opts.aead, rsa) {
                (true, a, _) => [0x1301, 0x1302, 0x1303][a],
                (false, a, false) => [0xc02b, 0xc02c, 0xcca9][a],
                (false, a, true) => [0xc02f, 0xc030, 0xcca8][a],
            };
            assert_eq!(seen.suite, suite, "{c:?}");
            Ok(alpn)
        }
        (Err(e), _) => Err(format!("client: {e}")),
        (Ok(_), Err(e)) => Err(format!("server: {e}")),
    }
}

/// Bytes the server sends between key updates, before its main data.
fn sent_before(c: &Case) -> usize {
    (0..c.key_updates).map(|i| (c.down / 2).min(i * 1000)).sum()
}

fn ok(c: &Case) {
    if let Err(e) = run(c) {
        panic!("{c:?}: {e}");
    }
}

#[test]
fn every_version_suite_key_and_group() {
    for tls13 in [true, false] {
        for aead in 0..3 {
            for key in KEY_TYPES {
                for groups in [vec!["x25519"], vec!["secp256r1"]] {
                    let mut c = Case::new(tls13, aead, key);
                    c.opts.groups = groups;
                    ok(&c);
                }
            }
        }
    }
}

#[test]
fn payload_sizes() {
    let sizes = [0, 1, 16383, 16384, 16385, 8 << 20];
    for tls13 in [true, false] {
        for (i, &up) in sizes.iter().enumerate() {
            for &down in &sizes {
                if (up == 8 << 20) != (down == 8 << 20) && i % 2 == 1 {
                    continue;
                }
                let mut c = Case::new(tls13, (i + down) % 3, KeyType::P256);
                c.up = up;
                c.down = down;
                ok(&c);
            }
        }
    }
}

#[test]
fn alpn() {
    for tls13 in [true, false] {
        // Both offer: the server picks from the client's list.
        let mut c = Case::new(tls13, 0, KeyType::P256);
        c.client_alpn = vec![b"h2", b"http/1.1"];
        c.opts.alpn = vec![b"http/1.1".to_vec()];
        assert_eq!(run(&c).unwrap().as_deref(), Some(&b"http/1.1"[..]));

        // The client offers, the server has none configured: no ALPN.
        c.opts.alpn = Vec::new();
        assert_eq!(run(&c).unwrap(), None);

        // The server has ALPN, the client offers none.
        let mut c = Case::new(tls13, 0, KeyType::P256);
        c.opts.alpn = vec![b"http/1.1".to_vec()];
        assert_eq!(run(&c).unwrap(), None);

        // h2 when both have it, from either list's order.
        let mut c = Case::new(tls13, 0, KeyType::P256);
        c.client_alpn = vec![b"h2", b"http/1.1"];
        c.opts.alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        assert_eq!(run(&c).unwrap().as_deref(), Some(&b"h2"[..]));
        c.opts.alpn = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        assert!(run(&c).unwrap().is_some());

        // No overlap: rustls refuses with no_application_protocol.
        let mut c = Case::new(tls13, 0, KeyType::P256);
        c.client_alpn = vec![b"http/1.1"];
        c.opts.alpn = vec![b"spdy/1".to_vec()];
        let e = run(&c).unwrap_err();
        assert!(e.contains("tls: received alert no_application_protocol"), "{e}");
    }
}

#[test]
fn handshake_in_small_records() {
    for tls13 in [true, false] {
        for key in [KeyType::P256, KeyType::Rsa4096] {
            for groups in [vec!["x25519"], vec!["secp256r1"]] {
                for frag in [32, 64, 1000] {
                    let mut c = Case::new(tls13, 2, key);
                    c.opts.groups = groups.clone();
                    c.opts.max_fragment = Some(frag);
                    c.down = 5000;
                    ok(&c);
                }
            }
        }
    }
}

#[test]
fn key_update() {
    for aead in 0..3 {
        for updates in [1, 3] {
            let mut c = Case::new(true, aead, KeyType::P256);
            c.key_updates = updates;
            c.down = 100_000;
            ok(&c);
        }
    }
    // With the KeyUpdate cut from the data around it by small records.
    let mut c = Case::new(true, 0, KeyType::P256);
    c.key_updates = 2;
    c.opts.max_fragment = Some(64);
    ok(&c);
}

/// A split stream: the writer sends from another thread, and answers KeyUpdate for the reader.
#[test]
fn split_stream() {
    for tls13 in [true, false] {
        for aead in 0..3 {
            let mut c = Case::new(tls13, aead, KeyType::P256);
            c.split = true;
            c.up = 70_000;
            c.down = 100_000;
            ok(&c);
            if tls13 {
                c.key_updates = 3;
                ok(&c);
            }
        }
    }
    let mut c = Case::new(true, 0, KeyType::P256);
    c.split = true;
    c.clean = false;
    ok(&c);
}

#[test]
fn close_clean_and_abrupt() {
    for tls13 in [true, false] {
        for clean in [true, false] {
            for down in [0, 20000] {
                let mut c = Case::new(tls13, 0, KeyType::P256);
                c.clean = clean;
                c.down = down;
                ok(&c);
            }
        }
    }
}

/// Connections by IP address: no SNI, and the certificate's IP SAN.
#[test]
fn ip_address_host() {
    let pki = pki(KeyType::P256);
    let config = rustls_server_config(pki, &ServerOpts::default());
    let (tcp, server) = rustls_server(config, |s| {
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).unwrap();
        }
        s.conn.server_name().map(str::to_string)
    });
    let s = connect(tcp, "127.0.0.1", &pki.config(&[])).unwrap();
    drop(s);
    assert_eq!(server.join().unwrap(), None);
}

/// The certificate checks, end to end: each refusal names its reason, and the server hears
/// bad_certificate.
#[test]
fn remembers_a_checked_chain_for_its_host_only() {
    let good = pki(KeyType::P256);
    let config = jpm_tls::Config {
        roots: vec![good.anchor()],
        alpn: Vec::new(),
        insecure_skip_verify: false,
        verified: Default::default(),
    };
    let once = |host: &str, server_pki: &common::Pki| {
        let (tcp, server) = rustls_server(rustls_server_config(server_pki, &ServerOpts::default()), |s| {
            while s.conn.is_handshaking() {
                s.conn.complete_io(&mut s.sock)?;
            }
            Ok::<_, std::io::Error>(())
        });
        let r = connect(tcp, host, &config).map(|_| ());
        let _ = server.join().unwrap();
        r
    };
    once("localhost", good).unwrap();
    assert_eq!(config.verified.len(), 1);
    // The second connection takes the chain as checked, and remembers nothing new.
    once("localhost", good).unwrap();
    assert_eq!(config.verified.len(), 1);
    // The same chain for a name it does not have is still refused.
    let e = once("example.com", good).unwrap_err().to_string();
    assert_eq!(e, "tls: bad certificate: certificate is not valid for this host");
    // And a chain from another root, still unknown.
    let e = once("localhost", pki(KeyType::P384)).unwrap_err().to_string();
    assert_eq!(e, "tls: bad certificate: bad signature");
    assert_eq!(config.verified.len(), 1);
}

#[test]
fn certificate_checks() {
    let check = |server_pki: &common::Pki, host: &str, roots: Vec<jpm_tls::Anchor<'static>>| {
        let config = rustls_server_config(server_pki, &ServerOpts::default());
        let (tcp, server) = rustls_server(config, |s| {
            while s.conn.is_handshaking() {
                s.conn.complete_io(&mut s.sock)?;
            }
            Ok::<_, std::io::Error>(())
        });
        let r = connect(
            tcp,
            host,
            &jpm_tls::Config { roots, alpn: Vec::new(), insecure_skip_verify: false, verified: Default::default() },
        )
        .map(|_| ());
        (r, server.join().unwrap())
    };
    let good = pki(KeyType::P256);

    // Another root. It has the same name as the real one, so the chain reaches it and fails
    // its signature.
    let (r, server) = check(good, "localhost", vec![pki(KeyType::P384).anchor()]);
    assert_eq!(r.unwrap_err().to_string(), "tls: bad certificate: bad signature");
    assert!(server.unwrap_err().to_string().contains("BadCertificate"));
    // No roots at all.
    let (r, _) = check(good, "localhost", Vec::new());
    assert_eq!(r.unwrap_err().to_string(), "tls: bad certificate: unknown issuer");
    // Names the certificate does not have.
    for host in ["example.com", "localhost.example", "127.0.0.2", "::1", "local"] {
        let (r, _) = check(good, host, vec![good.anchor()]);
        let e = r.unwrap_err().to_string();
        assert_eq!(e, "tls: bad certificate: certificate is not valid for this host", "{host}");
    }
    // Expired, and not yet valid.
    let expired = common::make_pki(KeyType::P256, |p| {
        p.not_before = rcgen::date_time_ymd(2000, 1, 1);
        p.not_after = rcgen::date_time_ymd(2001, 1, 1);
    });
    let (r, _) = check(&expired, "localhost", vec![expired.anchor()]);
    assert_eq!(r.unwrap_err().to_string(), "tls: bad certificate: certificate expired");
    let early = common::make_pki(KeyType::P256, |p| {
        p.not_before = rcgen::date_time_ymd(2100, 1, 1);
        p.not_after = rcgen::date_time_ymd(2101, 1, 1);
    });
    let (r, _) = check(&early, "localhost", vec![early.anchor()]);
    assert_eq!(r.unwrap_err().to_string(), "tls: bad certificate: certificate not yet valid");
    // A client certificate's EKU only.
    let client_only = common::make_pki(KeyType::P256, |p| {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    });
    let (r, _) = check(&client_only, "localhost", vec![client_only.anchor()]);
    assert!(r.unwrap_err().to_string().starts_with("tls: bad certificate: "));
    // And the good one, by name, by address, and in another case.
    for host in ["localhost", "127.0.0.1", "LOCALHOST"] {
        let (r, _) = check(good, host, vec![good.anchor()]);
        r.unwrap();
    }
}
