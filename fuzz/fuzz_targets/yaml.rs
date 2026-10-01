//! jpm's YAML reader (pnpm-lock.yaml, pnpm-workspace.yaml, .yarnrc.yml), and pnpm-workspace.yaml
//! as the overrides, patches and build rules read it.
#![no_main]

use jpm::{foreign, json, project::RootManifest, rules};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = jpm::text(data);
    let Ok(doc) = foreign::read_yaml(&text) else { return };
    let _ = json::to_string(&doc);
    if doc.as_object().is_none() {
        return;
    }
    let dir = jpm::scratch("yaml");
    std::fs::write(dir.join("pnpm-workspace.yaml"), text.as_bytes()).unwrap();
    std::fs::write(dir.join("package.json"), "{}").unwrap();
    let mut root = RootManifest::default();
    if let Ok(r) = rules::read(&dir, &root) {
        let _ = r.apply(&mut root);
    }
});
