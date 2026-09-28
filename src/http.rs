//! The one HTTP client: a shared connection pool, retries with backoff, and credentials sent only
//! under the `//host/path/` they belong to.

use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::registry::auth_for;

const ATTEMPTS: u32 = 5;
const BACKOFF_MS: u64 = 100;

pub struct Response {
    pub status: u16,
    pub etag: Option<String>,
    pub cache_control: Option<String>,
    /// Seconds a cache in front of the registry has held its copy.
    pub age: Option<u64>,
    pub body: Vec<u8>,
}

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_idle_connections(256)
            .max_idle_connections_per_host(64)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .redirect_auth_headers(ureq::config::RedirectAuthHeaders::SameHost)
            .user_agent(concat!("jpm/", env!("CARGO_PKG_VERSION")))
            .build();
        let connector = ureq::unversioned::transport::DefaultConnector::default();
        ureq::Agent::with_parts(config, connector, CachedResolver::default())
    })
}

/// Each host looked up once per run. A lookup per request is a getaddrinfo call per request,
/// ~10 ms each where DNS goes through a proxy (WSL), and that capped a cold install at about
/// 100 requests a second.
#[derive(Debug, Default)]
struct CachedResolver {
    inner: ureq::unversioned::resolver::DefaultResolver,
    cache: std::sync::Mutex<std::collections::HashMap<String, ureq::unversioned::resolver::ResolvedSocketAddrs>>,
}

impl ureq::unversioned::resolver::Resolver for CachedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let key = uri.authority().map(|a| format!("{}|{}", uri.scheme_str().unwrap_or(""), a)).unwrap_or_default();
        if let Some(hit) = self.cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
            return Ok(hit);
        }
        let found = self.inner.resolve(uri, config, timeout)?;
        if let Ok(mut c) = self.cache.lock() {
            c.insert(key, found.clone());
        }
        Ok(found)
    }
}

/// A GET, retried on a busy server, a 5xx or a dropped connection. A 4xx is an answer, not a
/// fault, and comes back as a response for the caller to judge.
pub fn get(url: &str, headers: &[(&str, &str)], auth: &std::collections::BTreeMap<String, String>) -> Result<Response> {
    let authorization = auth_for(auth, url);
    let mut last = None;
    let mut wait = 0;
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            let ms = if wait > 0 { wait } else { BACKOFF_MS << (attempt - 1) };
            std::thread::sleep(Duration::from_millis(ms));
        }
        let t = std::time::Instant::now();
        let got = once(url, headers, authorization.as_deref());
        if std::env::var_os("JPM_HTTP_LOG").is_some() {
            let status = got.as_ref().map_or_else(|e| e.code.to_string(), |r| r.status.to_string());
            eprintln!("http {status} {}ms {url}", t.elapsed().as_millis());
        }
        match got {
            Ok(r) if r.status == 429 || r.status == 503 || r.status >= 500 => {
                wait = 0;
                last = Some(Error::new("EREGISTRY", format!("{url} returned {}", r.status)));
            }
            Ok(r) => return Ok(r),
            Err(e) => {
                wait = 0;
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::new("ENETWORK", format!("{url} failed"))))
}

/// A GET whose body is read as it arrives, retried like `get` until the body starts, with its
/// declared length.
pub fn open(url: &str, auth: &std::collections::BTreeMap<String, String>) -> Result<(Box<dyn Read + Send>, Option<u64>)> {
    let authorization = auth_for(auth, url);
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(BACKOFF_MS << (attempt - 1)));
        }
        let mut request = agent().get(url);
        if let Some(a) = &authorization {
            request = request.header("authorization", a);
        }
        match request.call() {
            Ok(r) if r.status().is_success() => {
                let length = r.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
                return Ok((Box::new(r.into_body().into_reader()), length));
            }
            Ok(r) if r.status() == 404 => return Err(Error::new("E404", format!("Tarball {url} returned 404"))),
            Ok(r) if r.status() == 429 || r.status().is_server_error() => {
                last = Some(Error::new("ENETWORK", format!("Tarball {url} returned {}", r.status().as_u16())));
            }
            Ok(r) => return Err(Error::new("ENETWORK", format!("Tarball {url} returned {}", r.status().as_u16()))),
            Err(e) => last = Some(network(url, &e)),
        }
    }
    Err(last.unwrap_or_else(|| Error::new("ENETWORK", format!("{url} failed"))))
}

fn once(url: &str, headers: &[(&str, &str)], authorization: Option<&str>) -> Result<Response> {
    let mut request = agent().get(url);
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    if let Some(a) = authorization {
        request = request.header("authorization", a);
    }
    let mut response = request.call().map_err(|e| network(url, &e))?;
    let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let etag = header("etag");
    let cache_control = header("cache-control");
    let age = header("age").and_then(|a| a.parse().ok());
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|e| Error::new("ENETWORK", format!("{url} failed: {e}")))?;
    Ok(Response { status, etag, cache_control, age, body })
}

fn network(url: &str, error: &ureq::Error) -> Error {
    let code = match error {
        ureq::Error::Timeout(_) => "ETIMEDOUT",
        _ => "ENETWORK",
    };
    Error::new(code, format!("Request to {url} failed: {error}"))
}
