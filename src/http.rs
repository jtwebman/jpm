//! A small HTTP/1.1 client over jpm-tls: pooled keep-alive connections, one DNS lookup per host,
//! chunked and gzip bodies, redirects that keep credentials on their own host, retries with
//! backoff, and `HTTPS_PROXY` / `HTTP_PROXY` (with `NO_PROXY`). TLS 1.3, and 1.2 with modern suites.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use flate2::read::GzDecoder;

use crate::error::{Error, Result};
use crate::registry::auth_for;

const ATTEMPTS: u32 = 5;
const BACKOFF_MS: u64 = 100;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a connection may go without a byte before it is abandoned: silence, not slowness.
const STALL: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const MAX_HEAD: usize = 64 * 1024;
/// A registry document read whole into memory, after gunzip. Far above the largest packument.
const MAX_DOCUMENT: u64 = 512 * 1024 * 1024;

pub struct Response {
    pub status: u16,
    pub etag: Option<String>,
    pub cache_control: Option<String>,
    /// Seconds a cache in front of the registry has held its copy.
    pub age: Option<u64>,
    pub body: Vec<u8>,
}

/// A GET, retried on a busy server, a 5xx or a dropped connection. A 4xx is an answer, not a
/// fault, and comes back for the caller to judge.
pub fn get(url: &str, headers: &[(&str, &str)], auth: &BTreeMap<String, String>) -> Result<Response> {
    retry(url, |u| {
        let mut r = client().send(u, headers, auth)?;
        let body = read_capped(&mut r.body, MAX_DOCUMENT).map_err(|e| read_error(u, &e))?;
        Ok(Response {
            status: r.status,
            etag: r.header("etag"),
            cache_control: r.header("cache-control"),
            age: r.header("age").and_then(|a| a.parse().ok()),
            body,
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
            Ok((r.body, length))
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
        let got = once(url);
        if std::env::var_os("JPM_HTTP_LOG").is_some() {
            let status = got.as_ref().map_or_else(|e| e.code.to_string(), |r| r.status().to_string());
            eprintln!("http {status} {}ms {url}", t.elapsed().as_millis());
        }
        match got {
            Ok(r) if r.status() == 429 || r.status() >= 500 => {
                last = Some(Error::new("EREGISTRY", format!("{url} returned {}", r.status())));
            }
            Ok(r) => return Ok(r),
            Err(e) if matches!(e.code, "ENETWORK" | "ETIMEDOUT") => last = Some(e),
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
        "GET {path} HTTP/1.1\r\nhost: {}\r\nuser-agent: jpm/{}\r\naccept-encoding: gzip\r\n",
        url.authority(),
        env!("CARGO_PKG_VERSION")
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
    tls: jpm_tls::Config,
    pool: Mutex<HashMap<PoolKey, Vec<Conn>>>,
    dns: Mutex<HashMap<String, Vec<SocketAddr>>>,
}

fn client() -> &'static Arc<Client> {
    static CLIENT: OnceLock<Arc<Client>> = OnceLock::new();
    CLIENT.get_or_init(|| Arc::new(Client { tls: tls_config(), pool: Mutex::default(), dns: Mutex::default() }))
}

/// Mozilla's roots, as webpki-roots carries them, and HTTP/1.1 by ALPN.
fn tls_config() -> jpm_tls::Config {
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|ta| jpm_tls::Anchor {
            subject: ta.subject.as_ref(),
            spki: ta.subject_public_key_info.as_ref(),
            name_constraints: ta.name_constraints.as_ref().map(|n| n.as_ref()),
        })
        .collect();
    jpm_tls::Config { roots, alpn: vec![b"http/1.1".to_vec()] }
}

/// A response whose body has not been read yet.
struct Streaming {
    status: u16,
    headers: Vec<(String, String)>,
    body: Box<dyn Read + Send>,
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
        let proxy = proxy_for(url)?;
        let absolute = proxy.is_some() && !url.tls;
        let path = if absolute { format!("{}{}", url.origin(), url.target) } else { url.target.clone() };
        // A plain-http request goes to the proxy itself, which takes its credentials here.
        let mut all = headers.to_vec();
        if absolute && let Some(auth) = proxy.as_ref().and_then(|p| p.auth.as_deref()) {
            all.push(("proxy-authorization", auth));
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
        if std::env::var_os("JPM_HTTP_LOG").is_some() {
            eprintln!("connect {}", url.host);
        }
        let tcp = match proxy {
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
        };
        let stream = if url.tls {
            Stream::Tls(Box::new(jpm_tls::Stream::connect(tcp, &url.host, &self.tls)?))
        } else {
            Stream::Plain(tcp)
        };
        Ok(BufReader::with_capacity(128 * 1024, stream))
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
        let body: Box<dyn Read + Send> = if gzip { Box::new(Gunzip(GzDecoder::new(raw))) } else { Box::new(raw) };
        Streaming { status, headers, body }
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

/// The status and headers, names lowercased. An interim 1xx is skipped.
fn read_head(conn: &mut impl BufRead) -> io::Result<(u16, Vec<(String, String)>)> {
    loop {
        let mut total = 0;
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
struct Gunzip(GzDecoder<Body>);

impl Read for Gunzip {
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

/// The proxy a url goes through: `HTTPS_PROXY` for https, `HTTP_PROXY` for http (either case),
/// unless `NO_PROXY` names its host or a domain above it.
/// The proxy for a url, and the `Basic` credentials its own url carries (`http://user:pass@host`).
struct Proxy {
    url: Url,
    auth: Option<String>,
}

/// A set but unreadable proxy is an error: going around it would be a surprise.
fn proxy_for(url: &Url) -> io::Result<Option<Proxy>> {
    let var = |names: &[&str]| names.iter().find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()));
    let raw = if url.tls { var(&["HTTPS_PROXY", "https_proxy"]) } else { var(&["HTTP_PROXY", "http_proxy"]) };
    let Some(raw) = raw else { return Ok(None) };
    let skip = var(&["NO_PROXY", "no_proxy"]).unwrap_or_default();
    for entry in skip.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry == "*" {
            return Ok(None);
        }
        let domain = entry.trim_start_matches('*').trim_start_matches('.');
        let domain = domain.split(':').next().unwrap_or(domain);
        if url.host == domain || url.host.ends_with(&format!(".{domain}")) {
            return Ok(None);
        }
    }
    let raw = if raw.contains("://") { raw } else { format!("http://{raw}") };
    let (scheme, rest) = raw.split_once("://").unwrap_or(("http", &raw));
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (userinfo, host) = match rest[..end].rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, &rest[..end]),
    };
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "the proxy setting is not a url");
    let url = Url::parse(&format!("{scheme}://{host}")).map_err(|_| bad())?;
    let auth = userinfo.map(|u| format!("Basic {}", crate::util::to_base64(&percent_decode(u))));
    Ok(Some(Proxy { url, auth }))
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
        full.extend(body);
        let base = serve(vec![b"HTTP/1.1 302 Found\r\nlocation: /next\r\ncontent-length: 0\r\n\r\n".to_vec(), full]);
        assert_eq!(get(&format!("{base}/start"), &[], &BTreeMap::new()).unwrap().body, b"{\"ok\":true}");
    }

    #[test]
    fn honors_no_proxy() {
        let u = Url::parse("https://registry.npmjs.org/x").unwrap();
        // SAFETY: tests in this module do not read these variables concurrently.
        unsafe {
            std::env::set_var("HTTPS_PROXY", "proxy.test:3128");
            std::env::set_var("NO_PROXY", "localhost,.npmjs.org");
        }
        assert!(proxy_for(&u).unwrap().is_none());
        unsafe { std::env::set_var("NO_PROXY", "other.test") };
        let p = proxy_for(&u).unwrap().unwrap();
        assert_eq!((p.url.host.as_str(), p.url.port, p.auth), ("proxy.test", 3128, None));
        // Credentials in the proxy url become a Basic header, escapes decoded.
        unsafe { std::env::set_var("HTTPS_PROXY", "http://me%40corp:p%3Ass@proxy.test:8080") };
        let p = proxy_for(&u).unwrap().unwrap();
        assert_eq!((p.url.host.as_str(), p.url.port), ("proxy.test", 8080));
        assert_eq!(p.auth.as_deref(), Some(format!("Basic {}", crate::util::to_base64(b"me@corp:p:ss")).as_str()));
        unsafe { std::env::set_var("HTTPS_PROXY", "http://proxy test:x") };
        assert!(proxy_for(&u).is_err(), "an unreadable proxy is an error, not a way around it");
        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("NO_PROXY");
        }
    }
}
