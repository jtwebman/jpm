//! jpm is a binary crate with no library: this crate compiles its `src/` modules itself. The
//! module list is read from `src/main.rs`, so a module added there needs no change here.

use std::{env, fs, path::Path};

fn main() {
    let src = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("../src").canonicalize().unwrap();
    let main = src.join("main.rs");
    println!("cargo:rerun-if-changed={}", main.display());
    let mut out = String::new();
    let mut attrs = String::new();
    for line in fs::read_to_string(&main).unwrap().lines() {
        let line = line.trim();
        if line.starts_with("#[") {
            attrs.push_str(line);
            attrs.push('\n');
            continue;
        }
        if let Some(name) = line.strip_prefix("mod ").and_then(|l| l.strip_suffix(';')) {
            let dir = src.join(name).join("mod.rs");
            let file = if dir.exists() { dir } else { src.join(format!("{name}.rs")) };
            out.push_str(&attrs);
            out.push_str(&format!("#[path = {:?}]\npub mod {name};\n", file.display().to_string()));
        }
        attrs.clear();
    }
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("modules.rs"), out).unwrap();
}
