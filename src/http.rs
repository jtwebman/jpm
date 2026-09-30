//! A small HTTP/1.1 client over jpm-tls: pooled keep-alive connections, one DNS lookup per host,
//! chunked and gzip bodies, redirects that keep credentials on their own host, retries with
//! backoff, and proxies. TLS 1.3, and 1.2 with modern suites, trusting Mozilla's roots or the
//! certificates `.npmrc` and NODE_EXTRA_CA_CERTS name. With `JPM_HTTP2`, https goes over HTTP/2
//! (jpm-http) where the server offers it by ALPN, a few connections per host carrying every
//! request; the rest (redirects, retries, gzip, caps) is the same either way.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use flate2::read::GzDecoder;
use jpm_tls::Anchor;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::registry::auth_for;
use crate::util::from_base64;

const ATTEMPTS: u32 = 5;
const BACKOFF_MS: u64 = 100;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a connection may go without a byte before it is abandoned: silence, not slowness.
const STALL: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const USER_AGENT: &str = concat!("jpm/", env!("CARGO_PKG_VERSION"));
const MAX_HEAD: usize = 64 * 1024;
/// A registry document read whole into memory, after gunzip. Far above the largest packument.
pub const MAX_DOCUMENT: u64 = 512 * 1024 * 1024;

pub struct Response {
    pub status: u16,
    pub etag: Option<String>,
    pub cache_control: Option<String>,
    /// Seconds a cache in front of the registry has held its copy.
    pub age: Option<u64>,
    pub body: Vec<u8>,
    /// The body as the server sent it, when it gzipped it: what a cache can keep, a third of the
    /// size or less, for nothing.
    pub gzipped: Option<Vec<u8>>,
}

/// A GET, retried on a busy server, a 5xx or a dropped connection. A 4xx is an answer, not a
/// fault, and comes back for the caller to judge.
pub fn get(url: &str, headers: &[(&str, &str)], auth: &BTreeMap<String, String>) -> Result<Response> {
    get_capped(url, headers, auth, MAX_DOCUMENT)
}

/// `get`, its body refused past `cap` bytes.
pub fn get_capped(url: &str, headers: &[(&str, &str)], auth: &BTreeMap<String, String>, cap: u64) -> Result<Response> {
    retry(url, |u| {
        let mut r = client().send(u, headers, auth)?;
        let sent = read_capped(&mut r.body, cap).map_err(|e| read_error(u, &e))?;
        let (body, gzipped) = if r.gzip {
            let body = gunzip(&sent, cap).map_err(|e| read_error(u, &e))?;
            (body, Some(sent))
        } else {
            (sent, None)
        };
        Ok(Response {
            status: r.status,
            etag: r.header("etag"),
            cache_control: r.header("cache-control"),
            age: r.header("age").and_then(|a| a.parse().ok()),
            body,
            gzipped,
        })
    })
}

/// A GET whose body is read as it arrives, with its declared length; retried like `get` until
/// the body starts.
pub fn open(url: &str, auth: &BTreeMap<String, String>) -> Result<(Box<dyn Read + Send>, Option<u64>)> {
    let r = retry(url, |u| client().send(u, &[], auth))?;
    match r.status {
        200..=299 => {
            let length = r.header("content-length").and_then(|v| v.parse().ok());
            let body: Box<dyn Read + Send> = if r.gzip { Box::new(Gunzip(GzDecoder::new(r.body))) } else { r.body };
            Ok((body, length))
        }
        404 => Err(Error::new("E404", format!("Tarball {url} returned 404"))),
        s => Err(Error::new("ENETWORK", format!("Tarball {url} returned {s}"))),
    }
}

/// A full response or a streaming one: what `retry` needs to see.
trait Status {
    fn status(&self) -> u16;
}

impl Status for Response {
    fn status(&self) -> u16 {
        self.status
    }
}

impl Status for Streaming {
    fn status(&self) -> u16 {
        self.status
    }
}

fn retry<T: Status>(url: &str, mut once: impl FnMut(&str) -> Result<T>) -> Result<T> {
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(BACKOFF_MS << (attempt - 1)));
        }
        let t = std::time::Instant::now();
        let got = crate::pool::blocking(|| once(url));
        if std::env::var_os("JPM_HTTP_LOG").is_some() {
            let status = got.as_ref().map_or_else(|e| e.code.to_string(), |r| r.status().to_string());
            eprintln!("http {status} {}ms {}", t.elapsed().as_millis(), crate::ui::clean(url));
        }
        match got {
            Ok(r) if r.status() == 429 || r.status() >= 500 => {
                crate::pool::trouble();
                last = Some(Error::new("EREGISTRY", format!("{url} returned {}", r.status())));
            }
            Ok(r) => return Ok(r),
            Err(e) if matches!(e.code, "ENETWORK" | "ETIMEDOUT") => {
                crate::pool::trouble();
                last = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::new("ENETWORK", format!("{url} failed"))))
}

/// A whole body, refused past `cap` bytes: a gzip bomb stops here, not at the memory's end.
fn read_capped(body: &mut impl Read, cap: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    body.take(cap + 1).read_to_end(&mut out)?;
    if out.len() as u64 > cap {
        return Err(io::Error::other(format!("more than {cap} bytes")));
    }
    Ok(out)
}

/// Gzipped bytes unpacked, refused past `cap` bytes.
pub fn gunzip(data: &[u8], cap: u64) -> io::Result<Vec<u8>> {
    // Boxed as a streamed body is, so both are the one decoder in the binary.
    let data: Box<dyn Read + Send + '_> = Box::new(data);
    read_capped(&mut GzDecoder::new(data), cap)
}

/// Whether a redirect may be followed with the first url's credentials: same scheme, host and
/// port. A redirect from https to http is not followed at all.
fn same_origin(first: &Url, target: &Url) -> Result<bool> {
    if first.tls && !target.tls {
        return Err(Error::new("ETLS", format!("refusing a redirect from https to {}", target.origin())));
    }
    Ok(target.tls == first.tls && target.host == first.host && target.port == first.port)
}

/// The request head. A header value with a line break (from .npmrc or the environment) is
/// refused: it would add a line of its own.
fn request_head(url: &Url, path: &str, headers: &[(&str, &str)], authorization: Option<&str>) -> io::Result<String> {
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nhost: {}\r\nuser-agent: {USER_AGENT}\r\naccept-encoding: gzip\r\n",
        url.authority()
    );
    for (k, v) in headers.iter().copied().chain(authorization.map(|a| ("authorization", a))) {
        if v.contains(['\r', '\n']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the {k} header has a line break")));
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    Ok(head)
}

/// A chunk-size or trailer line, which no honest server makes long.
fn bounded_line(conn: &mut impl BufRead, line: &mut String) -> io::Result<usize> {
    let n = conn.take(4096).read_line(line)?;
    if n == 4096 && !line.ends_with('\n') {
        return Err(io::Error::other("chunk line too long"));
    }
    Ok(n)
}

fn read_error(url: &str, e: &io::Error) -> Error {
    // A certificate or protocol refusal is the same on every try: not retried.
    let code = if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        "ETIMEDOUT"
    } else if e.kind() == io::ErrorKind::InvalidData && e.to_string().starts_with("tls: ") {
        "ETLS"
    } else {
        "ENETWORK"
    };
    Error::new(code, format!("Request to {url} failed: {e}"))
}

// --- urls -------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    tls: bool,
    host: String,
    port: u16,
    /// Path and query, starting with `/`.
    target: String,
}

impl Url {
    fn parse(url: &str) -> Result<Self> {
        let bad = || Error::new("ENETWORK", format!("Invalid url {url:?}"));
        // Urls come from packuments and lockfiles: a space or control byte would split the
        // request line, and userinfo would hide the real host.
        if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(bad());
        }
        let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            _ => return Err(bad()),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let mut target = rest[end..].split('#').next().unwrap_or("").to_string();
        if !target.starts_with('/') {
            target.insert(0, '/');
        }
        if authority.contains('@') {
            return Err(bad());
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, tail) = v6.split_once(']').ok_or_else(bad)?;
            (h.to_string(), tail.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            Some(p) => p.parse().map_err(|_| bad())?,
            None if tls => 443,
            None => 80,
        };
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Self { tls, host: host.to_ascii_lowercase(), port, target })
    }

    fn origin(&self) -> String {
        format!("{}://{}", if self.tls { "https" } else { "http" }, self.authority())
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default { host } else { format!("{host}:{}", self.port) }
    }

    /// `location` read against this url.
    fn join(&self, location: &str) -> String {
        if location.contains("://") {
            location.to_string()
        } else if location.starts_with("//") {
            format!("{}:{location}", if self.tls { "https" } else { "http" })
        } else if location.starts_with('/') {
            format!("{}{location}", self.origin())
        } else {
            let dir = self.target.split('?').next().unwrap_or("/");
            let dir = &dir[..=dir.rfind('/').unwrap_or(0)];
            format!("{}{dir}{location}", self.origin())
        }
    }
}

// --- connections ------------------------------------------------------------------------------

enum Stream {
    Plain(TcpStream),
    Tls(Box<jpm_tls::Stream<TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

type Conn = BufReader<Stream>;
type PoolKey = (bool, String, u16);

struct Client {
    /// Made at the first connection over TLS.
    tls: LazyLock<jpm_tls::Config, Box<dyn FnOnce() -> jpm_tls::Config + Send>>,
    proxies: Proxies,
    pool: Mutex<HashMap<PoolKey, Vec<Conn>>>,
    dns: Mutex<HashMap<String, Vec<SocketAddr>>>,
    /// HTTP/2 connections, when `JPM_HTTP2` asks for them.
    h2: Option<jpm_http::Pool>,
    /// `tls` offering h2 before http/1.1, for the connections `h2` makes.
    tls_h2: OnceLock<jpm_tls::Config>,
    /// Bodies longer than this go over HTTP/1.1 (`JPM_HTTP2_BIG`).
    h2_big: Option<u64>,
}

static CLIENT: OnceLock<Arc<Client>> = OnceLock::new();

/// The client `configure` set up, else one with Mozilla's roots and the proxy environment.
fn client() -> &'static Arc<Client> {
    CLIENT.get_or_init(|| Arc::new(Client::new(Box::new(mozilla), &Config::default(), &env)))
}

/// The network settings of `.npmrc` and the environment, for every request from here on: the
/// roots to trust, `strict-ssl` and the proxies. Called once, before the first request.
pub fn configure(config: &Config) -> Result<()> {
    let roots = roots(config, &env, system)?;
    if config.insecure_tls {
        crate::ui::warn(
            "strict-ssl=false: certificates are not checked, so anyone on the network can pose as the registry",
        );
    }
    let client = Client::new(roots, config, &env);
    // A bad proxy fails before anything is asked, not at the first request.
    for raw in [&client.proxies.https, &client.proxies.http].into_iter().flatten() {
        parse_proxy(raw).map_err(|e| Error::new("ECONFIG", e.to_string()))?;
    }
    let _ = CLIENT.set(Arc::new(client));
    Ok(())
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Client {
    /// HTTP/1.1 by ALPN.
    fn new(roots: Roots, config: &Config, env: &dyn Fn(&str) -> Option<String>) -> Self {
        let insecure_skip_verify = config.insecure_tls;
        let tls = LazyLock::new(Box::new(move || jpm_tls::Config {
            roots: roots(),
            alpn: vec![b"http/1.1".to_vec()],
            insecure_skip_verify,
            verified: Default::default(),
        }) as Box<dyn FnOnce() -> _ + Send>);
        let h2 = http2(env);
        let h2_big = h2.as_ref().and(env("JPM_HTTP2_BIG")).and_then(|v| v.trim().parse().ok());
        let proxies = Proxies::new(config, env);
        Self { tls, proxies, pool: Mutex::default(), dns: Mutex::default(), h2, tls_h2: OnceLock::new(), h2_big }
    }

    fn tls_h2(&self) -> &jpm_tls::Config {
        self.tls_h2.get_or_init(|| jpm_tls::Config {
            roots: self.tls.roots.clone(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            insecure_skip_verify: self.tls.insecure_skip_verify,
            verified: Default::default(),
        })
    }
}

/// The HTTP/2 pool, or `None` for HTTP/1.1 only. `JPM_HTTP2=n` turns it on with `n` connections
/// per host (at most 8); unset or 0, it is off: measured on npm's registry, HTTP/2 was no faster
/// than 32 to 64 HTTP/1.1 connections. `JPM_HTTP2_STREAMS` caps the streams in flight to a
/// host, split evenly between its connections; unset, each carries as many as the server allows.
/// How many requests are in flight is still up to the callers (`JPM_CONCURRENCY`).
///
/// Experimental, `JPM_HTTP2_BIG=<bytes>`: a response over HTTP/2 whose content-length is above
/// it is cancelled (RST_STREAM CANCEL) as soon as its head arrives, and asked again over
/// HTTP/1.1 on a connection of its own. Small bodies share one connection well; a big one on it
/// shares one TCP window, and a loss stalls every stream behind it.
fn http2(env: &dyn Fn(&str) -> Option<String>) -> Option<jpm_http::Pool> {
    let number = |name| env(name).and_then(|v| v.trim().parse::<usize>().ok());
    let n = number("JPM_HTTP2").filter(|n| *n > 0)?.min(8);
    let streams = number("JPM_HTTP2_STREAMS").filter(|s| *s > 0).map_or(jpm_http::MAX_STREAMS, |s| s.div_ceil(n));
    Some(jpm_http::Pool::new(n, streams, STALL))
}

/// Mozilla's roots, as webpki-roots carries them.
fn mozilla() -> Vec<Anchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|ta| Anchor {
            subject: ta.subject.as_ref(),
            spki: ta.subject_public_key_info.as_ref(),
            name_constraints: ta.name_constraints.as_ref().map(|n| n.as_ref()),
        })
        .collect()
}

/// The roots the operating system trusts: where a company installs the root of its
/// TLS-inspecting proxy, which browsers then accept. A certificate jpm cannot read is left out.
fn system() -> Vec<Anchor<'static>> {
    let ders = crate::sys::system_roots();
    // Leaked once per run, as the PEM anchors are: they borrow the bytes for the process's life.
    ders.into_iter().filter_map(|der| Anchor::from_cert(Box::leak(der.into_boxed_slice())).ok()).collect()
}

/// Trust anchors, made when first needed.
type Roots = Box<dyn FnOnce() -> Vec<Anchor<'static>> + Send>;

/// The roots to trust. `cafile`, else `ca`, in place of the defaults: npm hands them to Node as
/// its `ca` option, which replaces the default list (NODE_EXTRA_CA_CERTS included). Otherwise
/// Mozilla's and the system's (`system`), plus the file NODE_EXTRA_CA_CERTS names, as Node
/// adds it. The files and settings are read now, so a bad one fails before anything is done;
/// the system's are read at the first connection: a run that asks nothing never reads them.
fn roots(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
    system: impl FnOnce() -> Vec<Anchor<'static>> + Send + 'static,
) -> Result<Roots> {
    let named = if let Some(file) = &config.cafile {
        pem_file(file)?
    } else if let Some(pem) = &config.ca {
        anchors(pem).map_err(|e| e.context("the ca setting"))?
    } else {
        let extra = env("NODE_EXTRA_CA_CERTS").map(|file| pem_file(Path::new(&file))).transpose()?;
        return Ok(Box::new(move || {
            let mut roots = mozilla();
            roots.extend(system());
            roots.extend(extra.into_iter().flatten());
            roots
        }));
    };
    Ok(Box::new(move || named))
}

/// A bad or unreadable file is an error: going on without it would fail later, and less clearly.
fn pem_file(file: &Path) -> Result<Vec<Anchor<'static>>> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::new("ECONFIG", format!("cannot read CA certificates from {}: {e}", file.display())))?;
    anchors(&text).map_err(|e| e.context(file.display()))
}

/// The certificates in PEM text, as trust anchors. Their bytes are leaked, once per run: the
/// anchors borrow them for as long as the process lives, as they do Mozilla's.
fn anchors(pem: &str) -> Result<Vec<Anchor<'static>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let bad = |why: String| Error::new("ECONFIG", why);
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(at) = rest.find(BEGIN) {
        rest = &rest[at + BEGIN.len()..];
        let end = rest.find(END).ok_or_else(|| bad(format!("certificate {} has no END line", out.len() + 1)))?;
        let body = &rest[..end];
        if !body.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b) || b.is_ascii_whitespace()) {
            return Err(bad(format!("certificate {} is not base64", out.len() + 1)));
        }
        let der: &'static [u8] = Box::leak(from_base64(body).into_boxed_slice());
        let anchor = Anchor::from_cert(der).map_err(|e| bad(format!("certificate {}: {e}", out.len() + 1)))?;
        out.push(anchor);
        rest = &rest[end + END.len()..];
    }
    if out.is_empty() {
        return Err(bad("no PEM certificates".into()));
    }
    Ok(out)
}

/// A response whose body has not been read yet: as sent, still gzipped when `gzip`.
struct Streaming {
    status: u16,
    headers: Vec<(String, String)>,
    body: Box<dyn Read + Send>,
    gzip: bool,
}

impl Streaming {
    fn header(&self, name: &str) -> Option<String> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }
}

impl Client {
    /// One request, following redirects. Credentials go only to the host they belong to.
    fn send(
        self: &Arc<Self>,
        url: &str,
        headers: &[(&str, &str)],
        auth: &BTreeMap<String, String>,
    ) -> Result<Streaming> {
        let mut url = url.to_string();
        let first = Url::parse(&url)?;
        for _ in 0..=MAX_REDIRECTS {
            let target = Url::parse(&url)?;
            let same = same_origin(&first, &target)?;
            let authorization = if same { auth_for(auth, &url) } else { None };
            let r = self.once(&target, headers, authorization.as_deref()).map_err(|e| read_error(&url, &e))?;
            if matches!(r.status, 301 | 302 | 303 | 307 | 308)
                && let Some(location) = r.header("location")
            {
                // Read to its end, so the connection goes back to the pool.
                let mut r = r;
                let _ = io::copy(&mut r.body, &mut io::sink());
                url = target.join(&location);
                continue;
            }
            return Ok(r);
        }
        Err(Error::new("ENETWORK", format!("{url} redirected too many times")))
    }

    fn once(
        self: &Arc<Self>,
        url: &Url,
        headers: &[(&str, &str)],
        authorization: Option<&str>,
    ) -> io::Result<Streaming> {
        let proxy = proxy_for(url, &self.proxies)?;
        let absolute = proxy.is_some() && !url.tls;
        let path = if absolute { format!("{}{}", url.origin(), url.target) } else { url.target.clone() };
        // A plain-http request goes to the proxy itself, which takes its credentials here.
        let mut all = headers.to_vec();
        if absolute && let Some(auth) = proxy.as_ref().and_then(|p| p.auth.as_deref()) {
            all.push(("proxy-authorization", auth));
        }
        // HTTP/2 when it is on and the server offers it, through a proxy's tunnel too.
        if url.tls
            && let Some(h2) = &self.h2
            && let Some(r) = self.over_h2(h2, url, proxy.as_ref(), headers, authorization)?
        {
            return Ok(r);
        }
        let head = request_head(url, &path, &all, authorization)?;
        let key: PoolKey = (url.tls, url.host.clone(), url.port);
        // A pooled connection the server has since closed fails at once: then a fresh one.
        if let Some(mut conn) = self.take(&key) {
            match exchange(&mut conn, &head) {
                Ok((status, headers)) => return Ok(self.body(conn, key, status, headers)),
                Err(e) if !is_stale(&e) => return Err(e),
                Err(_) => {}
            }
        }
        let mut conn = self.connect(url, proxy.as_ref())?;
        let (status, headers) = exchange(&mut conn, &head)?;
        Ok(self.body(conn, key, status, headers))
    }

    /// A request over HTTP/2, or `None` when the host is known to speak only HTTP/1.1, or the
    /// body is bigger than `h2_big` (its stream reset, for HTTP/1.1 to ask again). A connection
    /// just made on which ALPN picked HTTP/1.1 carries the request as HTTP/1.1.
    fn over_h2(
        self: &Arc<Self>,
        h2: &jpm_http::Pool,
        url: &Url,
        proxy: Option<&Proxy>,
        headers: &[(&str, &str)],
        authorization: Option<&str>,
    ) -> io::Result<Option<Streaming>> {
        let mut all = vec![("user-agent", USER_AGENT), ("accept-encoding", "gzip")];
        all.extend_from_slice(headers);
        all.extend(authorization.map(|a| ("authorization", a)));
        let authority = url.authority();
        let req = jpm_http::Request { authority: &authority, path: &url.target, headers: &all };
        let connect = || {
            let tcp = self.tunnel(url, proxy)?;
            let link = jpm_http::tls_link(jpm_tls::Stream::connect(tcp, &url.host, self.tls_h2())?, STALL)?;
            if matches!(link, jpm_http::Link::H2(_)) && std::env::var_os("JPM_HTTP_LOG").is_some() {
                eprintln!("http2 {}", crate::ui::clean(&url.host));
            }
            Ok(link)
        };
        match h2.get(&format!("{}:{}", url.host, url.port), connect, &req)? {
            jpm_http::Got::H2(r) => {
                let length = r.header("content-length").and_then(|v| v.trim().parse::<u64>().ok());
                if let (Some(big), Some(n)) = (self.h2_big, length)
                    && n > big
                    && (200..300).contains(&r.status)
                {
                    if std::env::var_os("JPM_HTTP_LOG").is_some() {
                        eprintln!("http2 {n} bytes, again over http/1.1 {}", crate::ui::clean(&url.target));
                    }
                    // Dropped, the body resets its stream.
                    return Ok(None);
                }
                let gzip = r.header("content-encoding").is_some_and(|e| e.to_ascii_lowercase().contains("gzip"));
                Ok(Some(Streaming { status: r.status, headers: r.headers, body: Box::new(r.body), gzip }))
            }
            jpm_http::Got::H1(Some(tls)) => {
                let mut conn = BufReader::with_capacity(128 * 1024, Stream::Tls(Box::new(tls)));
                let (status, headers) = exchange(&mut conn, &request_head(url, &url.target, headers, authorization)?)?;
                Ok(Some(self.body(conn, (true, url.host.clone(), url.port), status, headers)))
            }
            jpm_http::Got::H1(None) => Ok(None),
        }
    }

    fn take(&self, key: &PoolKey) -> Option<Conn> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner).get_mut(key)?.pop()
    }

    fn give(&self, key: PoolKey, conn: Conn) {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner).entry(key).or_default().push(conn);
    }

    /// Each host looked up once per run: a lookup per request was ~10 ms each where DNS goes
    /// through a proxy (WSL), and capped a cold install at about 100 requests a second.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let key = format!("{host}:{port}");
        if let Some(hit) = self.dns.lock().unwrap_or_else(PoisonError::into_inner).get(&key) {
            return Ok(hit.clone());
        }
        let found: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
        self.dns.lock().unwrap_or_else(PoisonError::into_inner).insert(key, found.clone());
        Ok(found)
    }

    fn tcp(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"));
        for addr in self.resolve(host, port)? {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    s.set_nodelay(true)?;
                    s.set_read_timeout(Some(STALL))?;
                    s.set_write_timeout(Some(STALL))?;
                    return Ok(s);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn connect(&self, url: &Url, proxy: Option<&Proxy>) -> io::Result<Conn> {
        let tcp = self.tunnel(url, proxy)?;
        let stream = if url.tls {
            Stream::Tls(Box::new(jpm_tls::Stream::connect(tcp, &url.host, &self.tls)?))
        } else {
            Stream::Plain(tcp)
        };
        Ok(BufReader::with_capacity(128 * 1024, stream))
    }

    /// A TCP connection to the url's host, through the proxy's tunnel when https has a proxy.
    fn tunnel(&self, url: &Url, proxy: Option<&Proxy>) -> io::Result<TcpStream> {
        if std::env::var_os("JPM_HTTP_LOG").is_some() {
            eprintln!("connect {}", crate::ui::clean(&url.host));
        }
        Ok(match proxy {
            Some(p) => {
                let mut s = self.tcp(&p.url.host, p.url.port)?;
                if url.tls {
                    // A tunnel through the proxy; TLS then runs end to end with the registry.
                    let host = if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.clone() };
                    let authority = format!("{host}:{}", url.port);
                    let auth = p.auth.as_ref().map(|a| format!("proxy-authorization: {a}\r\n")).unwrap_or_default();
                    write!(s, "CONNECT {authority} HTTP/1.1\r\nhost: {authority}\r\n{auth}\r\n")?;
                    let mut reader = BufReader::new(s.try_clone()?);
                    let (status, _) = read_head(&mut reader)?;
                    if status != 200 {
                        return Err(io::Error::other(format!("proxy refused the tunnel with {status}")));
                    }
                }
                s
            }
            None => self.tcp(&url.host, url.port)?,
        })
    }

    /// The body as a reader: framed by length or chunks, gunzipped when the server gzipped it,
    /// and the connection back in the pool once it is read to the end.
    fn body(self: &Arc<Self>, conn: Conn, key: PoolKey, status: u16, headers: Vec<(String, String)>) -> Streaming {
        let get = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.to_ascii_lowercase());
        let chunked = get("transfer-encoding").is_some_and(|t| t.contains("chunked"));
        let length = get("content-length").and_then(|v| v.trim().parse::<u64>().ok());
        let keep = get("connection").is_none_or(|c| !c.contains("close"));
        let frame = match (chunked, length, status) {
            (_, _, 204 | 304) => Frame::Length(0),
            (true, _, _) => Frame::Chunked(0),
            (false, Some(n), _) => Frame::Length(n),
            (false, None, _) => Frame::Close,
        };
        let gzip = get("content-encoding").is_some_and(|e| e.contains("gzip"));
        let raw = Body { conn: Some(conn), frame, keep, key, client: self.clone() };
        Streaming { status, headers, body: Box::new(raw), gzip }
    }
}

/// Send a request head and read the response's.
fn exchange(conn: &mut Conn, head: &str) -> io::Result<(u16, Vec<(String, String)>)> {
    conn.get_mut().write_all(head.as_bytes())?;
    conn.get_mut().flush()?;
    read_head(conn)
}

fn is_stale(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
    )
}

/// The status and headers, names lowercased. An interim 1xx is skipped, but counts toward the
/// one `MAX_HEAD` budget: a server cannot send them forever.
fn read_head(conn: &mut impl BufRead) -> io::Result<(u16, Vec<(String, String)>)> {
    let mut total = 0;
    loop {
        let mut line = String::new();
        let mut next = |line: &mut String| -> io::Result<()> {
            line.clear();
            let n = conn.take((MAX_HEAD - total) as u64 + 1).read_line(line)?;
            total += n;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed before a response"));
            }
            if total > MAX_HEAD {
                return Err(io::Error::other("response head too large"));
            }
            Ok(())
        };
        next(&mut line)?;
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::other(format!("not an HTTP response: {}", line.trim())))?;
        let mut headers = Vec::new();
        loop {
            next(&mut line)?;
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        if !(100..200).contains(&status) || status == 101 {
            return Ok((status, headers));
        }
    }
}

enum Frame {
    Length(u64),
    /// Bytes left in the current chunk.
    Chunked(u64),
    Close,
}

struct Body {
    conn: Option<Conn>,
    frame: Frame,
    keep: bool,
    key: PoolKey,
    client: Arc<Client>,
}

impl Body {
    /// The whole body is read: its connection can serve another request.
    fn finish(&mut self) {
        if let Some(conn) = self.conn.take().filter(|_| self.keep && !matches!(self.frame, Frame::Close)) {
            self.client.give(self.key.clone(), conn);
        }
    }
}

/// A gzipped body. The decoder stops at the end of the gzip stream, before the framing that
/// follows it (a chunked body's last, empty chunk); that is read too, or the connection could
/// not go back to the pool.
struct Gunzip<R>(GzDecoder<R>);

impl<R: Read> Read for Gunzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        if n == 0 && !buf.is_empty() {
            io::copy(self.0.get_mut(), &mut io::sink())?;
        }
        Ok(n)
    }
}

/// Up to `left` bytes of the body, and at least one.
fn read_some(conn: &mut Conn, buf: &mut [u8], left: u64) -> io::Result<usize> {
    let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
    let n = conn.read(&mut buf[..want])?;
    if n == 0 {
        return Err(cut_short());
    }
    Ok(n)
}

fn cut_short() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "body cut short")
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(conn) = self.conn.as_mut() else { return Ok(0) };
        if buf.is_empty() {
            return Ok(0);
        }
        match self.frame {
            Frame::Length(0) => {
                self.finish();
                Ok(0)
            }
            Frame::Length(left) => {
                let n = read_some(conn, buf, left)?;
                self.frame = Frame::Length(left - n as u64);
                if left == n as u64 {
                    self.finish();
                }
                Ok(n)
            }
            Frame::Chunked(left) if left > 0 => {
                let n = read_some(conn, buf, left)?;
                if left == n as u64 {
                    let mut crlf = [0u8; 2];
                    conn.read_exact(&mut crlf)?;
                }
                self.frame = Frame::Chunked(left - n as u64);
                Ok(n)
            }
            Frame::Chunked(_) => {
                let mut line = String::new();
                if bounded_line(conn, &mut line)? == 0 {
                    return Err(cut_short());
                }
                let hex = line.split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(hex, 16).map_err(|_| io::Error::other("bad chunk size"))?;
                if size == 0 {
                    // Trailers, then the blank line that ends the body.
                    loop {
                        line.clear();
                        if bounded_line(conn, &mut line)? <= 2 {
                            break;
                        }
                    }
                    self.finish();
                    return Ok(0);
                }
                self.frame = Frame::Chunked(size);
                self.read(buf)
            }
            Frame::Close => {
                let n = conn.read(buf)?;
                if n == 0 {
                    self.conn = None;
                }
                Ok(n)
            }
        }
    }
}

// --- proxies ----------------------------------------------------------------------------------

/// The proxies, read once as npm reads them: `.npmrc`'s `https-proxy`, else its `proxy`, for
/// every url; else `HTTPS_PROXY` then `HTTP_PROXY` for https and `HTTP_PROXY` for http (either
/// case). `noproxy`, else `NO_PROXY`, lists the hosts that go direct.
#[derive(Debug, Default)]
struct Proxies {
    https: Option<String>,
    http: Option<String>,
    skip: String,
}

impl Proxies {
    fn new(config: &Config, env: &dyn Fn(&str) -> Option<String>) -> Self {
        let var = |names: &[&str]| names.iter().find_map(|n| env(n));
        let own = config.https_proxy.clone().or_else(|| config.proxy.clone());
        Self {
            https: own.clone().or_else(|| var(&["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"])),
            http: own.or_else(|| var(&["HTTP_PROXY", "http_proxy"])),
            skip: config.noproxy.clone().or_else(|| var(&["NO_PROXY", "no_proxy"])).unwrap_or_default(),
        }
    }
}

/// The proxy for a url, and the `Basic` credentials its own url carries (`http://user:pass@host`).
struct Proxy {
    url: Url,
    auth: Option<String>,
}

/// The proxy a url goes through, unless the skip list names its host or a domain above it. A
/// set but unreadable proxy is an error: going around it would be a surprise.
fn proxy_for(url: &Url, proxies: &Proxies) -> io::Result<Option<Proxy>> {
    let raw = if url.tls { &proxies.https } else { &proxies.http };
    let Some(raw) = raw.clone() else { return Ok(None) };
    for entry in proxies.skip.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry == "*" {
            return Ok(None);
        }
        let domain = entry.trim_start_matches('*').trim_start_matches('.');
        let domain = domain.split(':').next().unwrap_or(domain);
        if url.host == domain || url.host.ends_with(&format!(".{domain}")) {
            return Ok(None);
        }
    }
    parse_proxy(&raw).map(Some)
}

/// A proxy setting: `host:port` or `http://[user:pass@]host:port`. jpm speaks plain HTTP to the
/// proxy (https itself goes through it by CONNECT), so an `https://` proxy is refused: its
/// credentials would cross the network in the clear where TLS was asked for.
fn parse_proxy(raw: &str) -> io::Result<Proxy> {
    let raw = if raw.contains("://") { raw.to_string() } else { format!("http://{raw}") };
    let (scheme, rest) = raw.split_once("://").unwrap_or(("http", &raw));
    let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("the proxy setting {why}"));
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(bad(&format!("is {scheme}://, and jpm reaches a proxy over http:// only")));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (userinfo, host) = match rest[..end].rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, &rest[..end]),
    };
    let url = Url::parse(&format!("http://{host}")).map_err(|_| bad("is not a url"))?;
    let auth = userinfo.map(|u| format!("Basic {}", crate::util::to_base64(&percent_decode(u))));
    Ok(Proxy { url, auth })
}

/// `%xx` escapes, as a proxy url's user and password may use for `@` or `:`.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn trusts_the_linux_ca_bundle() {
        if std::path::Path::new("/etc/ssl/certs/ca-certificates.crt").exists() {
            assert!(system().len() > 50, "the distribution's bundle is read");
        }
    }

    #[cfg(windows)]
    #[test]
    fn trusts_the_windows_root_store() {
        assert!(!system().is_empty(), "no readable roots in the current user's ROOT store");
    }

    #[test]
    fn parses_urls() {
        let u = Url::parse("https://registry.npmjs.org/@a%2fb?x=1#frag").unwrap();
        assert_eq!(
            (u.tls, u.host.as_str(), u.port, u.target.as_str()),
            (true, "registry.npmjs.org", 443, "/@a%2fb?x=1")
        );
        let u = Url::parse("http://[::1]:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.target.as_str()), ("::1", 8080, "/"));
        assert_eq!(u.authority(), "[::1]:8080");
        assert!(Url::parse("ftp://x").is_err());
        // Nothing that could split the request or hide the host.
        for bad in [
            "https://r.test/a b",
            "https://r.test/a\r\nx-evil: 1",
            "https://r.test/a\tb",
            "https://r.test/\u{7f}",
            "https://user:pass@r.test/a",
            "https://evil.test@r.test/a",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad:?}");
        }
        let u = Url::parse("https://r.test/a/b/c").unwrap();
        assert_eq!(u.join("/x"), "https://r.test/x");
        assert_eq!(u.join("d"), "https://r.test/a/b/d");
        assert_eq!(u.join("https://cdn.test/y"), "https://cdn.test/y");
    }

    #[test]
    fn keeps_credentials_on_their_origin() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(same_origin(&u("https://r.test/a"), &u("https://r.test/b")).unwrap());
        assert!(!same_origin(&u("https://r.test/a"), &u("https://cdn.test/b")).unwrap());
        assert!(!same_origin(&u("https://r.test/a"), &u("https://r.test:8443/b")).unwrap());
        assert!(!same_origin(&u("http://r.test/a"), &u("https://r.test/b")).unwrap());
        assert!(same_origin(&u("https://r.test:8443/a"), &u("http://r.test:8443/b")).is_err());
    }

    #[test]
    fn refuses_header_values_with_line_breaks() {
        let u = Url::parse("https://r.test/a").unwrap();
        assert!(
            request_head(&u, "/a", &[("accept", "x")], Some("Bearer t"))
                .unwrap()
                .contains("authorization: Bearer t\r\n")
        );
        assert!(request_head(&u, "/a", &[], Some("Bearer t\r\nx-evil: 1")).is_err());
        assert!(request_head(&u, "/a", &[("npm-command", "x\ny")], None).is_err());
    }

    #[test]
    fn caps_documents() {
        assert_eq!(read_capped(&mut &b"12345"[..], 5).unwrap(), b"12345");
        assert!(read_capped(&mut &b"123456"[..], 5).is_err());
        // Through gunzip: a small bomb is refused at the cap.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        io::Write::write_all(&mut gz, &vec![0u8; 1 << 20]).unwrap();
        let bomb = gz.finish().unwrap();
        assert!(read_capped(&mut flate2::read::GzDecoder::new(&bomb[..]), 1 << 16).is_err());
    }

    #[test]
    fn bounds_what_a_server_can_make_it_hold() {
        // A head line with no end, and a chunk-size line with no end.
        let endless = vec![b'a'; MAX_HEAD * 2];
        assert!(read_head(&mut &endless[..]).unwrap_err().to_string().contains("too large"));
        let mut chunk = &endless[..];
        assert!(bounded_line(&mut chunk, &mut String::new()).is_err());
        assert_eq!(bounded_line(&mut &b"1a;x=y\r\n"[..], &mut String::new()).unwrap(), 8);
    }

    #[test]
    fn skips_interim_responses() {
        let text =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (status, headers) = read_head(&mut &text[..]).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers[1], ("transfer-encoding".to_string(), "chunked".to_string()));
        // Endless interim responses run out of the one budget.
        let mut endless = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_HEAD / 25 + 1);
        endless.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
        assert!(read_head(&mut &endless[..]).unwrap_err().to_string().contains("too large"));
    }

    /// A one-connection server that answers each request with the next canned response, so a
    /// second request only works over a reused connection.
    fn serve(responses: Vec<Vec<u8>>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut writer = s;
            for r in responses {
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() <= 2 {
                        break;
                    }
                }
                writer.write_all(&r).unwrap();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn reuses_a_connection_across_framings() {
        let base = serve(vec![
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello".to_vec(),
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec(),
        ]);
        let auth = BTreeMap::new();
        assert_eq!(get(&format!("{base}/a"), &[], &auth).unwrap().body, b"hello");
        assert_eq!(get(&format!("{base}/b"), &[], &auth).unwrap().body, b"abcde");
        assert_eq!(get(&format!("{base}/c"), &[], &auth).unwrap().status, 404);
    }

    #[test]
    fn follows_redirects_and_gunzips() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"{\"ok\":true}").unwrap();
        let body = gz.finish().unwrap();
        let mut full =
            format!("HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
        full.extend(&body);
        let base = serve(vec![b"HTTP/1.1 302 Found\r\nlocation: /next\r\ncontent-length: 0\r\n\r\n".to_vec(), full]);
        let r = get(&format!("{base}/start"), &[], &BTreeMap::new()).unwrap();
        assert_eq!(r.body, b"{\"ok\":true}");
        // The bytes as sent come too, for a cache to keep.
        assert_eq!(r.gzipped, Some(body));
    }

    #[test]
    fn streams_a_gzipped_body_unpacked_and_hands_a_plain_one_as_is() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"tarball bytes").unwrap();
        let body = gz.finish().unwrap();
        let mut zipped =
            format!("HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
        zipped.extend(&body);
        let plain = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nplain".to_vec();
        let base = serve(vec![zipped, plain]);
        let (mut r, _) = open(&format!("{base}/a"), &BTreeMap::new()).unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"tarball bytes");
        let r = get(&format!("{base}/b"), &[], &BTreeMap::new()).unwrap();
        assert_eq!((r.body.as_slice(), r.gzipped), (&b"plain"[..], None));
    }

    /// A response the test's HTTP/2 server sends: status, headers, body.
    type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

    /// A one-connection HTTP/2 server over TLS that answers each request with the next of
    /// `responses`, and a client that trusts it with HTTP/2 on. The server gets each request's
    /// path, sent back to the test over the channel.
    fn h2_server(responses: Vec<Answer>) -> (String, Arc<Client>, std::sync::mpsc::Receiver<String>) {
        use jpm_http::{frame, hpack};
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        p.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()));
        let cert = p.self_signed(&key).unwrap();
        let anchor = Anchor::from_cert(Box::leak(cert.der().to_vec().into_boxed_slice())).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let (paths, heard) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut s = rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(config)).unwrap(), s);
            s.read_exact(&mut [0; 24]).unwrap();
            let mut out = Vec::new();
            frame::put(&mut out, frame::SETTINGS, 0, 0, &[]);
            let (mut decoder, mut buf) = (hpack::Decoder::default(), Vec::new());
            for (status, headers, body) in responses {
                let h = loop {
                    s.write_all(&out).unwrap();
                    out.clear();
                    let h = frame::read(&mut s, 1 << 20, &mut buf).unwrap().unwrap().unwrap();
                    if h.typ == frame::SETTINGS && h.flags & frame::ACK == 0 {
                        frame::put(&mut out, frame::SETTINGS, frame::ACK, 0, &[]);
                    }
                    if h.typ == frame::HEADERS {
                        break h;
                    }
                };
                let fields = decoder.decode(&buf, 1 << 20).unwrap();
                let path = fields.iter().find(|f| f.0 == b":path").unwrap().1.clone();
                paths.send(String::from_utf8(path).unwrap()).unwrap();
                let mut block = Vec::new();
                hpack::encode(&mut block, ":status", &status.to_string(), false);
                for (n, v) in &headers {
                    hpack::encode(&mut block, n, v, false);
                }
                let end = if body.is_empty() { frame::END_STREAM } else { 0 };
                frame::put(&mut out, frame::HEADERS, frame::END_HEADERS | end, h.stream, &block);
                if !body.is_empty() {
                    frame::put(&mut out, frame::DATA, frame::END_STREAM, h.stream, &body);
                }
            }
            s.write_all(&out).unwrap();
            while frame::read(&mut s, 1 << 20, &mut buf).is_ok_and(|f| f.is_some()) {}
        });
        let client = Client::new(Box::new(move || vec![anchor]), &Config::default(), &|n| {
            (n == "JPM_HTTP2").then(|| "1".to_string())
        });
        (url, Arc::new(client), heard)
    }

    #[test]
    fn follows_redirects_and_gunzips_over_http2() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"{\"ok\":true}").unwrap();
        let zipped = gz.finish().unwrap();
        let (url, client, heard) = h2_server(vec![
            (302, vec![("location", "/next".into())], Vec::new()),
            (200, vec![("content-encoding", "gzip".into()), ("etag", "\"1\"".into())], zipped.clone()),
            (304, vec![], Vec::new()),
        ]);
        let mut r = client.send(&format!("{url}/start"), &[("accept", "application/json")], &BTreeMap::new()).unwrap();
        assert_eq!((r.status, r.gzip, r.header("etag").as_deref()), (200, true, Some("\"1\"")));
        let mut body = Vec::new();
        r.body.read_to_end(&mut body).unwrap();
        assert_eq!(gunzip(&body, 100).unwrap(), b"{\"ok\":true}");
        let r = client.send(&format!("{url}/again"), &[("if-none-match", "\"1\"")], &BTreeMap::new()).unwrap();
        assert_eq!(r.status, 304);
        // All three on the one connection the server accepts.
        assert_eq!(heard.iter().take(3).collect::<Vec<_>>(), ["/start", "/next", "/again"]);
    }

    /// The proxies for an environment of `vars` and an .npmrc of `rc`.
    fn proxies(vars: &[(&str, &str)], rc: &str) -> Proxies {
        let layer = crate::config::parse_npmrc(rc, &|_| None).unwrap();
        let config = crate::config::to_config(&[layer], None).unwrap();
        Proxies::new(&config, &|n| vars.iter().find(|(k, _)| *k == n).map(|(_, v)| v.to_string()))
    }

    #[test]
    fn honors_no_proxy() {
        let u = Url::parse("https://registry.npmjs.org/x").unwrap();
        let skip = proxies(&[("HTTPS_PROXY", "proxy.test:3128"), ("NO_PROXY", "localhost,.npmjs.org")], "");
        assert!(proxy_for(&u, &skip).unwrap().is_none());
        let env = proxies(&[("HTTPS_PROXY", "proxy.test:3128"), ("NO_PROXY", "other.test")], "");
        let p = proxy_for(&u, &env).unwrap().unwrap();
        assert_eq!((p.url.host.as_str(), p.url.port, p.auth), ("proxy.test", 3128, None));
        // Credentials in the proxy url become a Basic header, escapes decoded.
        let auth = proxies(&[("HTTPS_PROXY", "http://me%40corp:p%3Ass@proxy.test:8080")], "");
        let p = proxy_for(&u, &auth).unwrap().unwrap();
        assert_eq!((p.url.host.as_str(), p.url.port), ("proxy.test", 8080));
        assert_eq!(p.auth.as_deref(), Some(format!("Basic {}", crate::util::to_base64(b"me@corp:p:ss")).as_str()));
        let bad = proxies(&[("HTTPS_PROXY", "http://proxy test:x")], "");
        assert!(proxy_for(&u, &bad).is_err(), "an unreadable proxy is an error, not a way around it");
        // An https:// proxy is refused: jpm would send its credentials in plain text.
        let tls = proxies(&[("HTTPS_PROXY", "https://me:secret@proxy.test:443")], "");
        let e = proxy_for(&u, &tls).err().unwrap();
        assert!(e.to_string().contains("https://, and jpm reaches a proxy over http:// only"), "{e}");
        assert!(parse_proxy("HTTP://proxy.test:1").is_ok());
    }

    #[test]
    fn npmrc_proxies_win_over_the_environment() {
        let https = Url::parse("https://registry.npmjs.org/x").unwrap();
        let http = Url::parse("http://r.test/x").unwrap();
        let host = |p: &Proxies, u: &Url| proxy_for(u, p).unwrap().map(|p| format!("{}:{}", p.url.host, p.url.port));
        let env = [("HTTPS_PROXY", "env.test:1"), ("HTTP_PROXY", "plain.test:2"), ("NO_PROXY", "npmjs.org")];
        // The environment alone: https falls back to HTTP_PROXY, as npm's agent does.
        let p = proxies(&env[..2], "");
        assert_eq!(host(&p, &https).as_deref(), Some("env.test:1"));
        assert_eq!(host(&p, &http).as_deref(), Some("plain.test:2"));
        assert_eq!(host(&proxies(&env[1..2], ""), &https).as_deref(), Some("plain.test:2"));
        assert_eq!(host(&proxies(&env, ""), &https), None);
        // https-proxy, else proxy, for every url; noproxy in place of NO_PROXY.
        let p = proxies(&env, "https-proxy=http://rc.test:3\nproxy=http://other.test:4\nnoproxy=r.test");
        assert_eq!(host(&p, &https).as_deref(), Some("rc.test:3"));
        assert_eq!(host(&p, &http), None);
        let p = proxies(&env, "proxy=http://u:p%40ss@rc.test:4\nnoproxy[]=a.test\nnoproxy[]=b.test");
        let got = proxy_for(&https, &p).unwrap().unwrap();
        assert_eq!((got.url.host.as_str(), got.url.port), ("rc.test", 4));
        assert_eq!(got.auth, Some(format!("Basic {}", crate::util::to_base64(b"u:p@ss"))));
        assert_eq!(host(&p, &Url::parse("https://x.b.test/").unwrap()), None);
        assert_eq!(host(&p, &http).as_deref(), Some("rc.test:4"));
        // An unset or `false` setting leaves the environment's.
        let p = proxies(&env[..2], "proxy=false\nhttps-proxy=");
        assert_eq!(host(&p, &https).as_deref(), Some("env.test:1"));
    }

    /// PEM text of a certificate made for the purpose.
    fn pem(cn: &str) -> String {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn reads_pem_bundles() {
        let (a, b) = (pem("a"), pem("b"));
        assert_eq!(anchors(&a).unwrap().len(), 1);
        // A bundle, with text around and between its certificates and CRLF line ends.
        let bundle = format!("# corp roots\r\n{}\nsubject=b\n{}", a.replace('\n', "\r\n"), b);
        let got = anchors(&bundle).unwrap();
        assert_eq!(got.len(), 2);
        assert_ne!(got[0].subject, got[1].subject);
        // Other PEM blocks are passed over.
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(anchors(&format!("{key}{a}")).unwrap().len(), 1);
        for (text, why) in [
            ("", "no PEM certificates"),
            (key, "no PEM certificates"),
            ("-----BEGIN CERTIFICATE-----\nMIIB", "certificate 1 has no END line"),
            (&format!("{a}{}", &b[..b.len() - 30]), "certificate 2 has no END line"),
            ("-----BEGIN CERTIFICATE-----\nMII*\n-----END CERTIFICATE-----", "certificate 1 is not base64"),
            ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "certificate 1: invalid certificate"),
            (&a.replacen("MI", "MA", 1), "certificate 1: "),
        ] {
            let e = anchors(text).unwrap_err();
            assert_eq!(e.code, "ECONFIG");
            assert!(e.message.starts_with(why), "{text:?}: {}", e.message);
        }
    }

    #[test]
    fn chooses_the_roots() {
        let dir = std::env::temp_dir().join(format!("jpm-http-roots-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.pem"), dir.join("b.pem"));
        std::fs::write(&a, pem("a")).unwrap();
        std::fs::write(&b, format!("{}{}", pem("b1"), pem("b2"))).unwrap();
        let extra = a.to_string_lossy().into_owned();
        let with_extra = |n: &str| (n == "NODE_EXTRA_CA_CERTS").then(|| extra.clone());
        let config = |rc: &str| {
            let rc = rc.replace("{b}", &b.to_string_lossy());
            crate::config::to_config(&[crate::config::parse_npmrc(&rc, &|_| None).unwrap()], None).unwrap()
        };
        let mozilla = mozilla().len();
        let n = |roots: Result<Roots>| roots.unwrap()().len();
        assert_eq!(n(roots(&config(""), &|_| None, Vec::new)), mozilla);
        // NODE_EXTRA_CA_CERTS adds to Mozilla's.
        assert_eq!(n(roots(&config(""), &with_extra, Vec::new)), mozilla + 1);
        // So do the system's, read only when the roots are first needed; cafile replaces them.
        let system = || {
            let two = roots(&config("cafile={b}"), &|_| None, Vec::new).unwrap()();
            move || two
        };
        assert_eq!(n(roots(&config(""), &with_extra, system())), mozilla + 1 + 2);
        assert!(roots(&config(""), &with_extra, || panic!("the system's roots read at once")).is_ok());
        assert_eq!(n(roots(&config("cafile={b}"), &with_extra, system())), 2);
        // cafile and ca replace them, NODE_EXTRA_CA_CERTS too; cafile wins over ca.
        assert_eq!(n(roots(&config("cafile={b}"), &with_extra, Vec::new)), 2);
        let inline = pem("c").trim_end().replace('\n', "\\n");
        assert_eq!(n(roots(&config(&format!("ca=\"{inline}\"")), &with_extra, Vec::new)), 1);
        let two = format!("ca[]=\"{inline}\"\nca[]=\"{}\"", pem("d").trim_end().replace('\n', "\\n"));
        assert_eq!(n(roots(&config(&two), &with_extra, Vec::new)), 2);
        assert_eq!(n(roots(&config(&format!("ca=\"{inline}\"\ncafile={{b}}")), &with_extra, Vec::new)), 2);
        // A bad or missing file is an error that names it.
        std::fs::write(&a, "not a certificate").unwrap();
        let e = roots(&config(""), &with_extra, Vec::new).err().unwrap();
        assert_eq!(e.message, format!("{}: no PEM certificates", a.display()));
        let missing = dir.join("missing.pem");
        let e = roots(&config(&format!("cafile={}", missing.display())), &|_| None, Vec::new).err().unwrap();
        assert!(e.message.starts_with(&format!("cannot read CA certificates from {}", missing.display())));
        let e = roots(&config("ca=junk"), &|_| None, Vec::new).err().unwrap();
        assert_eq!(e.message, "the ca setting: no PEM certificates");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
