//! Dependency specs as npm-package-arg and hosted-git-info read them: a CLI argument, a
//! package.json `name: spec` entry (the first line, then the rest), and package names.
#![no_main]

use jpm::spec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = jpm::text(data);
    let (name, rest) = text.split_once('\n').unwrap_or((&text, ""));
    let _ = spec::parse_spec(&text);
    let _ = spec::parse_spec(name);
    let _ = spec::bare_source(&text);
    let _ = spec::check_name(name, &text);
    let _ = spec::escape_name(name);
    let _ = spec::names_path(rest);
    let _ = spec::is_commit(rest);
    let _ = spec::is_git(rest);
    let _ = spec::encode_segment(name);
    let _ = spec::join_path(name, rest);
    let _ = spec::source_at(rest, name);
    if let Ok(s) = spec::parse_dep(name, rest) {
        let _ = spec::names_source(&s, "", "1.0.0");
        let _ = spec::parse_dep(&s.name, &s.fetch_spec);
    }
});
