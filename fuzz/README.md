# Fuzzing jpm's parsers

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for everything jpm reads that someone
else wrote: tarballs, lockfiles (its own and other managers'), registry documents, specs, `.npmrc`
and certificates. Every input must end in a clean error: no panic, hang, unbounded memory or stack
overflow.

This crate is its own workspace. The root's `cargo build`, `clippy` and `test` never see it, and
nothing here reaches jpm's binary or its dependencies. jpm has no library target, so `build.rs`
compiles the modules `src/main.rs` lists into a library named `jpm` for the targets to call. A
module added to `src/main.rs` needs no change here.

## Running

Linux (or WSL) with a nightly toolchain:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
python3 fuzz/seed.py                      # seed corpora from tests/ (see below)
cd fuzz
cargo +nightly fuzz run lockfile corpus/lockfile -- -max_total_time=900 -rss_limit_mb=2048 -timeout=10 -max_len=262144
```

`+nightly` is needed because the repository's `rust-toolchain.toml` pins a stable compiler, and
cargo-fuzz needs nightly's sanitizer flags. List the targets with `cargo +nightly fuzz list`.

| target      | what it reads                                                                          |
|-------------|----------------------------------------------------------------------------------------|
| `tar`       | `tar::read_entries` over raw bytes; every path handed out must be plain                |
| `extract`   | `store::extract`, gzipped or not, into a scratch directory; nothing written beside it, no links |
| `lockfile`  | `jpm.lock`: `parse_lockfile` (parse and `validate`), then written back and read again  |
| `foreign`   | `foreign::prefer` and `foreign::load`: package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, bun.lock |
| `yaml`      | `foreign::read_yaml`, then pnpm-workspace.yaml through `rules::read`                   |
| `json`      | `json::parse` and `Scan::skip`; what is written must read back the same                |
| `semver`    | versions and ranges: `parse`, `satisfies`, `intersects`, `max_satisfying`              |
| `spec`      | `spec::parse_spec`, `parse_dep` (hosted git urls included), `check_name`               |
| `manifest`  | `Manifest::from_json`                                                                  |
| `packument` | `Packument::parse`, each version, the release cutoff and `pick_manifest`              |
| `npmrc`     | `config::parse_npmrc` and `to_config`                                                  |
| `x509`      | crates/tls: certificate DER and chain checks                                           |

The input layout of the multi-part targets is described at the top of each file in
`fuzz_targets/`. `foreign`, for example, takes a byte that picks the file, then `package.json`,
a NUL, and the lockfile.

## Corpora

`seed.py` writes `fuzz/corpus/<target>/` from the repository's own test data: the conformance
tables (semver, npm-package-arg, hosted-git-info), the arborist and bun lockfiles, generated
ustar, GNU and pax tarballs (long names, links, `..`, case clashes), and the system's CA
certificates. Two options add real-world inputs:

- `--extra DIR`: each project directory under `DIR` with its `package.json`, lockfiles, `.npmrc`,
  `pnpm-workspace.yaml` and `jpm.lock`;
- `--npm-cache ~/.npm/_cacache`: small tarballs and registry documents from npm's cache.

Keep `fuzz/target`, `fuzz/corpus`, `fuzz/artifacts` and `fuzz/Cargo.lock` out of git (see
`.gitignore`). A crash found here becomes a regression test in jpm's own suite, next to the code
it fixes, with the input inline, so it stays covered without fuzzing.

## Reproducing a crash

```sh
cargo +nightly fuzz run <target> artifacts/<target>/crash-...
cargo +nightly fuzz tmin <target> artifacts/<target>/crash-...   # minimize it
```
