//! The npm registry over HTTP/2. It needs the network, so it is ignored by default:
//! `cargo test -p jpm-http --test live -- --ignored --nocapture`

use std::io::{self, Read};
use std::net::TcpStream;
use std::time::Duration;

use jpm_http::{Got, Link, Pool, Request};
use jpm_tls::{Anchor, Config};

const HOST: &str = "registry.npmjs.org";
const STALL: Duration = Duration::from_secs(30);

fn config() -> Config {
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|ta| Anchor {
            subject: ta.subject.as_ref(),
            spki: ta.subject_public_key_info.as_ref(),
            name_constraints: ta.name_constraints.as_ref().map(|n| n.as_ref()),
        })
        .collect();
    Config {
        roots,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        insecure_skip_verify: false,
        verified: Default::default(),
    }
}

fn dial(config: &Config) -> io::Result<Link<jpm_tls::Stream<TcpStream>>> {
    let tcp = TcpStream::connect((HOST, 443))?;
    tcp.set_read_timeout(Some(STALL))?;
    jpm_http::tls_link(jpm_tls::Stream::connect(tcp, HOST, config)?, STALL)
}

/// The status, a header, and the body of a GET.
fn get(pool: &Pool, config: &Config, path: &str, headers: &[(&str, &str)]) -> (u16, Option<String>, Vec<u8>) {
    let req = Request { authority: HOST, path, headers };
    let Got::H2(r) = pool.get(HOST, || dial(config), &req).unwrap() else { panic!("{HOST} answered HTTP/1.1") };
    let etag = r.header("etag").map(str::to_string);
    let mut body = Vec::new();
    let status = r.status;
    let mut b = r.body;
    b.read_to_end(&mut body).unwrap();
    (status, etag, body)
}

#[test]
#[ignore = "needs the network"]
fn the_registry_over_h2() {
    let config = config();
    let pool = Pool::new(2, jpm_http::MAX_STREAMS, STALL);
    let json = [("accept", "application/vnd.npm.install-v1+json"), ("accept-encoding", "gzip")];
    let (status, etag, doc) = get(&pool, &config, "/react", &json);
    assert_eq!(status, 200);
    assert_eq!(&doc[..2], b"\x1f\x8b", "gzipped as asked");
    // The same document again, by its ETag: 304 and no body.
    let etag = etag.expect("an ETag");
    let (status, _, body) = get(&pool, &config, "/react", &[json[0], ("if-none-match", &etag)]);
    assert_eq!((status, body.len()), (304, 0));
    let (status, _, _) = get(&pool, &config, "/@jpm-test/no-such-package-exists", &json);
    assert_eq!(status, 404);
    // Tarballs, many at once over the pool's two connections.
    let versions = ["18.0.0", "18.1.0", "18.2.0", "18.3.0", "18.3.1", "19.0.0", "19.1.0", "17.0.2"];
    std::thread::scope(|s| {
        for v in versions {
            let (pool, config) = (&pool, &config);
            s.spawn(move || {
                let (status, _, tgz) = get(pool, config, &format!("/react/-/react-{v}.tgz"), &[]);
                assert_eq!(status, 200, "{v}");
                assert_eq!(&tgz[..2], b"\x1f\x8b", "{v}");
                eprintln!("react-{v}.tgz: {} bytes", tgz.len());
            });
        }
    });
    // A tarball larger than a stream's window: it comes whole only if the window is given
    // back as it is read.
    let (status, _, tgz) = get(&pool, &config, "/typescript/-/typescript-5.6.3.tgz", &[]);
    assert_eq!(status, 200);
    assert!(tgz.len() > jpm_http::STREAM_WINDOW as usize, "{} bytes", tgz.len());
}
