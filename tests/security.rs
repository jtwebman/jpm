//! End to end: what a package, a registry or the directories around a project can put in the
//! terminal and in the environment of the programs jpm starts.

mod common;

use common::{Env, Registry, pkg};
use serde_json::json;

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn registry_text_reaches_the_terminal_escaped() {
    // OSC 52 sets the clipboard, OSC 0 the title: in a dependency's name and range.
    let r = Registry::start(vec![
        pkg("clip", "1.0.0", json!({ "dependencies": { "\u{1b}]52;c;cm0gLXJmIH4K\u{7}x": "1.0.0" } })),
        pkg("title", "1.0.0", json!({ "dependencies": { "b": "\u{1b}]0;PWNED\u{7}" } })),
        pkg("b", "1.0.0", json!({})),
    ]);
    let env = Env::new(&r);
    for name in ["clip", "title"] {
        env.manifest(json!({ "dependencies": { name: "1.0.0" } }));
        let out = env.jpm(&["install"]);
        let err = stderr(&out);
        assert!(!out.status.success() && err.contains("\\u{1b}]"), "{name}: {err:?}");
        assert!(!err.contains(['\u{1b}', '\u{7}']), "{name}: printed raw: {err:?}");
    }
    // resolve prints the tarball url and the start of the integrity as the registry has them.
    let doc = |name: &str, tarball: &str, integrity: &str| {
        let version =
            json!({ "name": name, "version": "1.0.0", "dist": { "tarball": tarball, "integrity": integrity } });
        let doc = json!({ "name": name, "dist-tags": { "latest": "1.0.0" }, "versions": { "1.0.0": version },
            "time": { "1.0.0": "2020-01-01T00:00:00Z" } });
        r.serve(&format!("/{name}"), doc.to_string().into_bytes());
    };
    doc("link", "http://e/\u{1b}]8;;http://evil\u{1b}\\x.tgz", "sha512-abc");
    let out = env.jpm(&["resolve", "link"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("http://e/\\u{1b}]8;;"), "{text:?} {}", stderr(&out));
    assert!(!text.contains('\u{1b}'), "printed raw: {text:?}");
    // A cut at 24 characters, not bytes: the 24th byte is inside the first two-byte one.
    doc("wide", "http://e/x.tgz", "sha512-aaaaaaaaaaaaaaaa\u{e9}\u{e9}\u{e9}\u{e9}");
    let out = env.jpm(&["resolve", "wide"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && text.contains("sha512-aaaaaaaaaaaaaaaa\u{e9}\u{2026}"),
        "{text:?} {}",
        stderr(&out)
    );
}
