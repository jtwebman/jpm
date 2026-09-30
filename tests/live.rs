//! Installs from registry.npmjs.org itself. They need the network, so they are ignored by
//! default: `cargo test --test live -- --ignored --nocapture`

mod common;

use common::{Env, Registry};
use serde_json::json;

/// A few packages from the npm registry over HTTP/2 when `JPM_HTTP2` asks for it, and over
/// HTTP/1.1 when it does not: the same tree either way.
#[test]
#[ignore = "network"]
fn installs_from_npm_over_http2() {
    let r = Registry::start(Vec::new());
    let mut trees = Vec::new();
    for (http2, streams) in [("2", "8"), ("0", "")] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "semver": "^7", "debug": "^4", "@types/node": "^22" } }));
        let started = std::time::Instant::now();
        let out = env
            .command(&["install"])
            .env("npm_config_registry", "https://registry.npmjs.org/")
            .env("JPM_HTTP2", http2)
            .env("JPM_HTTP2_STREAMS", streams)
            .env("JPM_HTTP_LOG", "1")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "JPM_HTTP2={http2}: {err}");
        println!("JPM_HTTP2={http2}: {:?}", started.elapsed());
        assert_eq!(err.contains("http2 registry.npmjs.org"), http2 != "0", "{err}");
        for name in ["semver", "debug", "@types/node"] {
            assert!(env.exists(&format!("node_modules/{name}/package.json")), "JPM_HTTP2={http2}: no {name}");
        }
        let lock = env.read("jpm.lock");
        assert!(lock.contains("package ms@") && lock.contains("package undici-types@"), "{lock}");
        trees.push(lock);
    }
    assert_eq!(trees[0], trees[1]);
}
