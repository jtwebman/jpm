//! .npmrc, as a project's file (cloned, so untrusted) is read into settings.
#![no_main]

use jpm::config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = jpm::text(data);
    let env = |k: &str| (k.len() < 4).then(|| format!("v-{k}"));
    let Ok(layer) = config::parse_npmrc(&text, &env) else { return };
    let _ = config::to_config(&[layer], None);
});
