//! jpm: a fast, small package manager for the npm registry.

mod bin;
mod cli;
mod commands;
mod config;
mod error;
mod foreign;
mod gc;
mod glob;
mod graph;
mod http;
mod integrity;
mod json;
mod keys;
mod link;
mod lock;
mod manifest;
mod pool;
mod project;
mod registry;
mod resolve;
mod run;
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
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    let code = cli::main(&argv0, args.collect());
    std::process::exit(code);
}
