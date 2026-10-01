//! jpm: a fast, small package manager for the npm registry.

mod bin;
mod build;
mod cli;
mod commands;
mod config;
mod copies;
mod error;
mod extensions;
mod foreign;
mod gc;
mod git;
mod glob;
mod graph;
mod http;
mod integrity;
mod json;
mod keys;
mod link;
mod lock;
mod manifest;
mod patch;
mod pgp;
mod pool;
mod project;
mod registry;
mod resolve;
mod rules;
mod run;
mod runtime;
mod semver;
mod shim;
mod spec;
mod state;
mod store;
mod sys;
mod tar;
mod ui;
mod util;

fn main() {
    ui::START.get_or_init(std::time::Instant::now);
    sys::cap_malloc_arenas();
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    let code = cli::main(&argv0, args.collect());
    std::process::exit(code);
}
