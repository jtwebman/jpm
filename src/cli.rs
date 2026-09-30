//! The command line: argv in, one command run, what it returns printed, an exit code out.
//! npm's own commands (publish, login, …) go to npm through `exec`.

use std::path::PathBuf;
use std::time::Instant;

use crate::commands::{self, ExecOpts, InstallResult, Opts, Select};
use crate::config::Flags;
use crate::error::Error;
use crate::json::{self, Object, Value};
use crate::lock::{LOCKFILE, format_json};
use crate::manifest::parse_date;
use crate::ui::{self, BOLD, CYAN, GRAY, GREEN, YELLOW, paint};

const NPM_COMMANDS: &str = "access, config, create, deprecate, dist-tag, info, init, login, logout, org, owner,
  pack, ping, pkg, profile, publish, search, show, stage, team, token, trust, undeprecate,
  unpublish, version, view, whoami";

fn usage_text() -> String {
    format!(
        "jpm — a fast, small package manager for the npm registry

Usage
  jpm [install] [--production] [--frozen-lockfile] [--verify]    (also i; ci is frozen)
  jpm add <spec>... [--dev | --optional] [--exact] [-w <workspace>]
  jpm remove <name>... [-w <workspace>]    (also uninstall, rm, r, un)
  jpm dedupe
  jpm resolve <spec>...
  jpm fetch <spec>...
  jpm fetch --lock [--production]
  jpm lock
  jpm prune
  jpm approve [<name>...]
  jpm patch <name>[@version] [--edit-dir <dir>]
  jpm patch-commit <dir>
  jpm run [-w <workspace>... | --workspaces] [--if-present] [<script> [args...]]
                       (also run-script; t and tst are run test)
  jpm <script> [args...]
  jpm exec [-p <spec>...] <command> [args...]
  jpm exec [-p <spec>...] -c '<command line>'    (also x, jpx)
  jpm <npm command> [args...]

Options
  -c, --call <line>    exec: run a shell line with -p packages on PATH
  -D, --dev            add: save to devDependencies
  --before <date>      pick only versions published before this date
  --dir <path>         project directory (default: nearest package.json or workspace root)
  -E, --exact          add: save an exact version for names and tags
  --edit-dir <dir>     patch: where to put the package to edit
                       (default node_modules/.jpm_patches/<name>@<version>)
  --min-release-age <days>
                       pick only versions published at least this long ago (0: off)
  --min-release-age-exclude <name|glob>
                       exempt from the release age (repeatable)
  --frozen-lockfile    install: fail if {LOCKFILE} is missing or stale
  --if-present         run: skip a missing script, or workspaces missing it
  --include-workspace-root
                       run --workspaces: run the root first
  --json               print JSON
  --lock               fetch: use {LOCKFILE}
  --offline            never use the network; fail if the registry or a download is needed
  --prefer-offline     pick from kept registry documents without checking for newer ones
  -O, --optional       add: save to optionalDependencies
  -p, --package <spec> exec: install a package for the command (repeatable)
  -y, --yes            exec: accepted for npx compatibility; no prompts
  --production         skip dev-only packages
  --registry <url>     override the registry
  -s, --silent         no progress, run banner or install summary (also -q, --loglevel)
  --no-progress        install: no progress line (drawn only on a terminal, not in CI)
  --store <dir>        package store directory (default: JPM_STORE or ~/.jpm/store)
  --ignore-scripts     install: run no install or lifecycle scripts (also ignore-scripts=true)
  --legacy-peer-deps   install no peers; link one only to what the tree has
                       (also legacy-peer-deps=true; yarn.lock from yarn 1 is read this way)
  --verify             install: check sizes, links, bins and peers, not file contents
  --no-global-store    install: build package entries in the project, not once in the store
                       (also global-store=false in .npmrc or JPM_GLOBAL_STORE=0)
  --no-verify-node-signature
                       resolve a Node runtime without checking its SHASUMS256.txt signature
                       (also verify-node-signature=false; for mirrors that publish none)
  --no-block-exotic-subdeps
                       let registry packages take git or tarball-url dependencies
                       (also block-exotic-subdeps=false in ~/.npmrc; on by default)
  -w, --workspace <name|path>
                       add, remove, run: select workspaces (repeatable; parent paths work)
  --workspaces         run: select all workspaces
  -h, --help           show help
  -v, --version        show the version

Notes
  lock saves all platforms and dev packages; install selects this platform.
  add (also install <spec>...) and remove edit package.json, then install, keeping other locks.
  add moves groups; remove clears all groups. Explicit ranges stay; names, * and tags
  save ^version unless --exact. dedupe favors locked versions.
  With no {LOCKFILE}, install keeps the versions node_modules has where the ranges allow them.
  For a fresh resolve, delete {LOCKFILE} and run lock, or delete node_modules too.
  A url or a path to a .tgz is a tarball dependency, locked by where it is.
  link:<dir> links a directory as it is. file:<dir> (or ./<dir>) inside the project is linked
  and its dependencies installed, as a workspace's are; outside the project it is linked as
  link: is, and jpm writes nothing there.
  github:u/r, u/r, gitlab:, bitbucket:, sourcehut:, git+https://, git+ssh:// and git:// are git
  dependencies, #<commit>, #<branch|tag> or #semver:<range>; locked to a commit (git ls-remote),
  fetched as the host's archive or with git. A git package's prepare script is an install script.
  jsr:@scope/name@<range> is npm:@jsr/scope__name from npm.jsr.io (or @jsr:registry).
  node@runtime:<range> (bun@, deno@ too) installs that runtime as a package, its binary in
  node_modules/.bin, locked with every platform's build; add saves it to devEngines.runtime
  (--dev) or engines.runtime, as pnpm does. Node comes from nodejs.org or node-mirror:release,
  its SHASUMS256.txt checked against Node's release keys when the version is resolved.
  With no {LOCKFILE}, install writes one from package-lock.json, npm-shrinkwrap.json,
  pnpm-lock.yaml, bun.lock or yarn.lock: the same versions, resolved again only where package.json
  moved.
  --frozen-lockfile reads such a file as it is and writes nothing.
  Overrides apply to every edge, peers too: npm's overrides, yarn's resolutions, pnpm.overrides
  and pnpm-workspace.yaml's overrides; {LOCKFILE} records them, so a change makes it stale.

  prune removes the project's unused entries, then global entries and store content that no
  project installed from the store uses. It waits for installs using the store to finish.

  A dependency's install scripts run only when package.json lists it in trustedDependencies
  (or pnpm-workspace.yaml in allowBuilds) and {LOCKFILE} approves the version: approve adds both, and a new version needs approving
  again. approve with no names lists what waits. The project's own lifecycle scripts
  (preinstall to postprepare) run on installs that change the tree.
  Patches: pnpm-workspace.yaml's, pnpm.patchedDependencies and bun's patchedDependencies, and
  yarn's patch: ranges in the root package.json. patch copies the locked version (patched, if
  it is) to a directory to edit; patch-commit writes the difference to patches/<name>@<version>.patch
  (git diff), names it in patchedDependencies and installs.
  Config: --registry > npm_config_* > project .npmrc > ~/.npmrc > global npmrc. The project's
  cannot set ca, cafile, proxies, strict-ssl=false, block-exotic-subdeps=false,
  verify-node-signature=false or a laxer min-release-age. TLS trusts Mozilla's and the system's roots plus NODE_EXTRA_CA_CERTS, or only
  cafile or ca; proxies (http:// only) come from https-proxy, proxy and noproxy in .npmrc, else
  HTTPS_PROXY, HTTP_PROXY and NO_PROXY.
  New picks skip versions under min-release-age days old (default 1; 0 turns it off).

  run installs the tree first (a no-op when it is current), then runs the script in a shell
  with local and parent bins on PATH; no pre/post scripts. jpm flags go before the script.
  exec uses local bins, else installs into the root's node_modules/.jpm/.exec (or ~/.jpm/exec).

  npm's spellings work too: --save-dev, --save-optional, --save-exact, --omit=dev
  (--production; --include=dev undoes it), --prefix and -C (--dir). Accepted and ignored:
  -S, --save, -P, --save-prod, --no-audit, --no-fund, --verbose and --force.

Npm
  These commands run npm through exec. Only --dir goes before them.
  {NPM_COMMANDS}"
    )
}

#[derive(Debug, Default)]
struct Cli {
    command: Option<String>,
    specs: Vec<String>,
    json: bool,
    registry: Option<String>,
    min_release_age: Option<f64>,
    store: Option<String>,
    dir: Option<String>,
    edit_dir: Option<String>,
    production: bool,
    lock: bool,
    frozen: bool,
    verify: bool,
    dev: bool,
    optional: bool,
    exact: bool,
    help: bool,
    version: bool,
    implied: bool,
    workspace: Option<Vec<String>>,
    workspaces: bool,
    include_root: bool,
    if_present: bool,
    yes: bool,
    call: Option<String>,
    packages: Option<Vec<String>>,
    before: Option<String>,
    exclude: Option<Vec<String>>,
    quiet: bool,
    no_progress: bool,
    offline: bool,
    prefer_offline: bool,
    global_store: Option<bool>,
    ignore_scripts: bool,
    legacy_peer_deps: bool,
    verify_node_signature: Option<bool>,
    block_exotic_subdeps: Option<bool>,
}

const COMMANDS: [&str; 13] = [
    "install",
    "add",
    "remove",
    "dedupe",
    "resolve",
    "fetch",
    "lock",
    "prune",
    "run",
    "exec",
    "approve",
    "patch",
    "patch-commit",
];
const INSTALLS: [&str; 4] = ["install", "add", "remove", "dedupe"];
const NOOPS: [&str; 8] = ["--no-audit", "--no-fund", "--force", "--verbose", "-S", "--save", "-P", "--save-prod"];
const LOG_LEVELS: [&str; 8] = ["silent", "error", "warn", "notice", "http", "info", "verbose", "silly"];

fn npm_command(name: &str) -> bool {
    NPM_COMMANDS.split(',').any(|c| c.trim() == name)
}

fn alias(arg: &str) -> Option<&'static str> {
    Some(match arg {
        "i" | "ci" | "clean-install" => "install",
        "uninstall" | "rm" | "r" | "un" => "remove",
        "run-script" => "run",
        "x" => "exec",
        _ => return None,
    })
}

fn parse(argv: &[String]) -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut rest = false;
    let mut flags = true;
    let mut include_dev = false;
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        let npm = cli.command.as_deref().is_some_and(npm_command);
        if rest || npm {
            cli.specs.push(arg.clone());
            continue;
        }
        // Once `run` has its script and `exec` its command, the rest belongs to them.
        if matches!(cli.command.as_deref(), Some("run" | "exec")) && cli.specs.len() == 1 {
            rest = true;
            if arg != "--" || cli.command.as_deref() == Some("exec") {
                cli.specs.push(arg.clone());
            }
            continue;
        }
        if flags && arg == "--" {
            flags = false;
            continue;
        }
        if !flags || !arg.starts_with('-') || arg == "-" {
            positional(&mut cli, arg);
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = || -> Result<String, String> {
            if let Some(v) = &inline {
                return Ok(v.clone());
            }
            let v = argv.get(i).cloned().ok_or_else(|| format!("{flag} needs a value"))?;
            i += 1;
            Ok(v)
        };
        match flag.as_str() {
            "--registry" => cli.registry = Some(value()?),
            "--store" => cli.store = Some(value()?),
            "--dir" | "--prefix" | "-C" => cli.dir = Some(value()?),
            "--edit-dir" => cli.edit_dir = Some(value()?),
            "-w" | "--workspace" => cli.workspace.get_or_insert_with(Vec::new).push(value()?),
            "-c" | "--call" => cli.call = Some(value()?),
            "-p" | "--package" => cli.packages.get_or_insert_with(Vec::new).push(value()?),
            "--before" => {
                let v = value().unwrap_or_default();
                if parse_date(&v).is_none() {
                    return Err(format!("{flag} takes a date"));
                }
                cli.before = Some(v);
            }
            "--min-release-age-exclude" => cli.exclude.get_or_insert_with(Vec::new).push(value()?),
            "--min-release-age" => {
                let v = value().unwrap_or_default();
                let days: f64 = v.trim().parse().map_err(|_| format!("{flag} takes a number of days"))?;
                if days.is_nan() || days < 0.0 {
                    return Err(format!("{flag} takes a number of days"));
                }
                cli.min_release_age = Some(days);
            }
            "--omit" | "--include" => {
                let v = value().unwrap_or_default();
                match (flag.as_str(), v.as_str()) {
                    ("--include", "dev") => include_dev = true,
                    ("--include", "prod" | "optional" | "peer") => {}
                    ("--omit", "dev") => cli.production = true,
                    ("--omit", _) => return Err(format!("{flag} takes dev")),
                    _ => return Err(format!("{flag} takes dev, prod, optional or peer")),
                }
            }
            "--loglevel" => {
                let v = value().unwrap_or_default();
                let level = LOG_LEVELS
                    .iter()
                    .position(|l| *l == v)
                    .ok_or_else(|| format!("{flag} takes {}", LOG_LEVELS.join(", ")))?;
                if level < 3 {
                    cli.quiet = true;
                }
            }
            _ if NOOPS.contains(&arg.as_str()) => {}
            "-s" | "--silent" | "-q" | "--quiet" => cli.quiet = true,
            "--no-progress" => cli.no_progress = true,
            "-y" | "--yes" => cli.yes = true,
            "--workspaces" => cli.workspaces = true,
            "--include-workspace-root" => cli.include_root = true,
            "--if-present" => cli.if_present = true,
            "-h" | "--help" => cli.help = true,
            "-v" | "--version" => cli.version = true,
            "--json" => cli.json = true,
            "--production" => cli.production = true,
            "--lock" => cli.lock = true,
            "--offline" => cli.offline = true,
            "--prefer-offline" => cli.prefer_offline = true,
            "--ignore-scripts" => cli.ignore_scripts = true,
            "--legacy-peer-deps" => cli.legacy_peer_deps = true,
            "--global-store" => cli.global_store = Some(true),
            "--no-global-store" => cli.global_store = Some(false),
            "--verify-node-signature" => cli.verify_node_signature = Some(true),
            "--no-verify-node-signature" => cli.verify_node_signature = Some(false),
            "--block-exotic-subdeps" => cli.block_exotic_subdeps = Some(true),
            "--no-block-exotic-subdeps" => cli.block_exotic_subdeps = Some(false),
            "--frozen-lockfile" => cli.frozen = true,
            "--verify" => cli.verify = true,
            "--dev" | "-D" | "--save-dev" => cli.dev = true,
            "--optional" | "-O" | "--save-optional" => cli.optional = true,
            "--exact" | "-E" | "--save-exact" => cli.exact = true,
            _ => return Err(format!("unknown flag \"{arg}\"")),
        }
    }
    if include_dev {
        cli.production = false;
    }
    Ok(cli)
}

/// The first word is the command, or, as in pnpm, a script: `jpm test` is `run test`.
fn positional(cli: &mut Cli, arg: &str) {
    if cli.command.is_some() {
        cli.specs.push(arg.to_string());
    } else if let Some(cmd) = alias(arg) {
        cli.command = Some(cmd.into());
        if arg == "ci" || arg == "clean-install" {
            cli.frozen = true;
        }
    } else if arg == "t" || arg == "tst" {
        cli.command = Some("run".into());
        cli.specs.push("test".into());
    } else if COMMANDS.contains(&arg) || npm_command(arg) {
        cli.command = Some(arg.into());
    } else {
        cli.command = Some("run".into());
        cli.implied = true;
        cli.specs.push(arg.to_string());
    }
}

fn usage(message: &str) -> i32 {
    ui::error(message);
    eprintln!("\n{}", help(false));
    2
}

fn help(stdout: bool) -> String {
    usage_text()
        .lines()
        .map(|l| {
            if !l.is_empty() && l.chars().next().is_some_and(char::is_uppercase) && !l.contains(' ') {
                paint(BOLD, l, stdout)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `jpx <cmd>` is `jpm exec <cmd>`.
pub fn main(argv0: &str, args: Vec<String>) -> i32 {
    // Any case: cmd.exe passes `JPX` on as typed.
    let exec_bin = std::path::Path::new(argv0)
        .file_stem()
        .is_some_and(|s| s.eq_ignore_ascii_case("jpx") || s.eq_ignore_ascii_case("upx"));

    let args = if exec_bin { std::iter::once("exec".to_string()).chain(args).collect() } else { args };
    let cli = match parse(&args) {
        Ok(cli) => cli,
        Err(e) => return usage(&e),
    };
    ui::set_quiet(cli.quiet);
    ui::set_no_progress(cli.json || cli.no_progress);
    if cli.version {
        ui::out(&format!("{}\n", env!("CARGO_PKG_VERSION")));
        return 0;
    }
    if cli.help {
        ui::out(&format!("{}\n", help(true)));
        return 0;
    }
    // As in yarn and bun: no command is install, flags and all (`jpm --frozen-lockfile`).
    let mut command = cli.command.clone().unwrap_or_else(|| "install".into());
    if npm_command(&command) {
        let own = cli.json
            || cli.registry.is_some()
            || cli.store.is_some()
            || cli.production
            || cli.quiet
            || cli.workspace.is_some()
            || cli.packages.is_some();
        if own {
            return usage(&format!("only --dir goes before {command}"));
        }
        let dir = cli.dir.as_ref().map(PathBuf::from);
        return commands::npm(&command, &cli.specs, dir.as_deref()).unwrap_or_else(|e| {
            ui::error(&e.to_string());
            1
        });
    }
    if command == "install" && !cli.specs.is_empty() {
        command = "add".into();
    }
    let installs = INSTALLS.contains(&command.as_str());
    let from_project = matches!(command.as_str(), "lock" | "install" | "dedupe" | "prune") || cli.lock;
    if let Some(e) = check(&cli, &command, installs, from_project) {
        return usage(&e);
    }
    let result = match command.as_str() {
        "run" => run_command(&cli),
        "exec" => exec_command(&cli),
        _ => dispatch(&cli, &command, from_project).map(|out| {
            let summary = !cli.json && (installs || command == "prune" || command == "fetch");
            if !(out.is_empty() || ui::quiet() && summary) {
                ui::out(&format!("{out}\n"));
            }
            0
        }),
    };
    result.unwrap_or_else(|e| {
        ui::error(&e.to_string());
        1
    })
}

fn check(cli: &Cli, command: &str, installs: bool, from_project: bool) -> Option<String> {
    let selects = cli.workspace.is_some() || cli.workspaces;
    let patch = matches!(command, "patch" | "patch-commit");
    let rules: [(bool, String); 20] = [
        (patch && cli.specs.len() > 1, format!("{command} takes one package")),
        (cli.edit_dir.is_some() && command != "patch", "--edit-dir only applies to patch".into()),
        (command == "exec" && cli.call.is_none() && cli.specs.is_empty(), "exec needs a command or --call".into()),
        (
            cli.call.is_some() && !cli.specs.is_empty(),
            "--call is the whole command line: give no command or args with it".into(),
        ),
        (
            (cli.packages.is_some() || cli.yes || cli.call.is_some()) && command != "exec",
            "--package, --call and --yes only apply to exec".into(),
        ),
        (cli.json && command == "exec", "--json does not apply to exec".into()),
        (
            !from_project && !matches!(command, "run" | "exec" | "approve") && cli.specs.is_empty(),
            format!("{command} needs at least one {}", if command == "remove" { "name" } else { "spec" }),
        ),
        (
            from_project && !cli.lock && !cli.specs.is_empty(),
            format!("{command} reads package.json and takes no package names"),
        ),
        (
            cli.production && !installs && !(command == "fetch" && cli.lock),
            "--production only applies to install and fetch --lock".into(),
        ),
        (cli.frozen && command != "install", "--frozen-lockfile only applies to install, without package names".into()),
        (cli.verify && !installs, "--verify only applies to install".into()),
        (
            (cli.dev || cli.optional || cli.exact) && command != "add",
            "--dev, --optional and --exact only apply to add".into(),
        ),
        (cli.dev && cli.optional, "--dev and --optional are exclusive".into()),
        (cli.dev && cli.production, "--production skips what --dev adds".into()),
        (cli.lock && command != "fetch", "--lock only applies to fetch".into()),
        (
            selects && !matches!(command, "add" | "remove" | "run"),
            "-w and --workspaces only apply to add, remove and run: install is always the whole tree".into(),
        ),
        (cli.workspace.is_some() && cli.workspaces, "-w and --workspaces are exclusive".into()),
        (cli.if_present && command != "run", "--if-present only applies to run".into()),
        (
            cli.include_root && !(command == "run" && selects),
            "--include-workspace-root only applies to run -w or --workspaces".into(),
        ),
        (false, String::new()),
    ];
    rules.into_iter().find(|(bad, _)| *bad).map(|(_, why)| why)
}

fn opts(cli: &Cli) -> Opts {
    Opts {
        dir: cli.dir.as_ref().map(PathBuf::from),
        flags: Flags {
            registry: cli.registry.clone(),
            min_release_age: cli.min_release_age,
            before: cli.before.clone(),
            min_release_age_exclude: cli.exclude.clone(),
            offline: cli.offline.then_some(true),
            prefer_offline: cli.prefer_offline.then_some(true),
            global_store: cli.global_store,
            legacy_peer_deps: cli.legacy_peer_deps.then_some(true),
            verify_node_signature: cli.verify_node_signature,
            block_exotic_subdeps: cli.block_exotic_subdeps,
        },
        store: cli.store.as_ref().map(PathBuf::from),
        production: cli.production,
        verify: cli.verify,
        frozen: cli.frozen,
        group: if cli.dev {
            Some("devDependencies")
        } else if cli.optional {
            Some("optionalDependencies")
        } else {
            None
        },
        exact: cli.exact,
        workspaces: if cli.workspaces { Some(Select::All) } else { cli.workspace.clone().map(Select::Some) },
        if_present: cli.if_present,
        include_root: cli.include_root,
        ignore_scripts: cli.ignore_scripts,
    }
}

fn dispatch(cli: &Cli, command: &str, from_project: bool) -> Result<String, Error> {
    let o = opts(cli);
    let started = Instant::now();
    match command {
        "install" => Ok(installed(cli, &commands::install(o)?, started, Object::new())),
        "dedupe" => Ok(installed(cli, &commands::dedupe(o)?, started, Object::new())),
        "add" => {
            let r = commands::add(&cli.specs, o)?;
            let added: Vec<Value> = r
                .added
                .iter()
                .map(|a| {
                    json::obj([("name", (&a.name).into()), ("range", (&a.range).into()), ("group", a.group.into())])
                })
                .collect();
            let mut changes = Object::new();
            changes.insert("added", Value::Array(added));
            Ok(installed(cli, &r.install, started, changes))
        }
        "remove" => {
            let (removed, r) = commands::remove(&cli.specs, o)?;
            let mut changes = Object::new();
            changes.insert("removed", Value::from(removed));
            Ok(installed(cli, &r, started, changes))
        }
        "lock" => {
            let l = commands::lock_command(o, !cli.json)?;
            if cli.json { Ok(format_json(&l)?.trim_end().to_string()) } else { Ok(String::new()) }
        }
        "approve" => {
            let a = commands::approve(&cli.specs, o)?;
            if cli.json {
                let mut out = a.install.as_ref().map(|r| r.to_object(Object::new())).unwrap_or_default();
                out.insert("approved", Value::from(a.approved));
                out.insert("pending", Value::from(a.pending));
                return Ok(pretty(&out.into()));
            }
            let mut lines = Vec::new();
            for key in &a.approved {
                lines.push(format!("approved {key}"));
            }
            if a.install.is_none() && a.pending.is_empty() {
                lines.push("no install scripts wait for approval".into());
            }
            if !a.pending.is_empty() {
                let head = if a.install.is_none() { "waiting for approval" } else { "still waiting" };
                lines.push(format!("{head}: {}", a.pending.join(", ")));
            }
            Ok(lines.join("\n"))
        }
        "patch" => {
            let at = commands::patch(&cli.specs[0], cli.edit_dir.as_deref().map(std::path::Path::new), o)?;
            if cli.json {
                return Ok(pretty(&json::obj([("dir", at.display().to_string().into())])));
            }
            Ok(format!("edit the package in {}\nthen: jpm patch-commit {0}", at.display()))
        }
        "patch-commit" => {
            let c = commands::patch_commit(std::path::Path::new(&cli.specs[0]), o)?;
            if !cli.json {
                ui::info(&format!("wrote {}", c.file));
            }
            let mut changes = Object::new();
            changes.insert("patch", c.file.into());
            Ok(installed(cli, &c.install, started, changes))
        }
        "prune" => {
            let p = commands::prune(o)?;
            if cli.json {
                return Ok(pretty(&p.to_value()));
            }
            let swept = match &p.entries {
                Some(e) => format!("{} entries ({})", e.removed, mib(e.bytes)),
                None => "no install state, kept every entry".into(),
            };
            Ok(format!(
                "{swept}  {} shared entries ({})  {} store entries ({})",
                p.shared.removed,
                mib(p.shared.bytes),
                p.store.removed,
                mib(p.store.bytes)
            ))
        }
        "fetch" if from_project => fetched(cli, &commands::fetch_lockfile(o)?, true),
        "fetch" => fetched(cli, &commands::fetch_specs(&cli.specs, o)?, false),
        "resolve" => {
            let picked = commands::resolve_specs(&cli.specs, o)?;
            if cli.json {
                let list: Vec<Value> = picked
                    .iter()
                    .map(|m| {
                        let dist = json::obj([
                            ("tarball", m.dist.tarball.clone().into()),
                            ("integrity", m.dist.integrity.clone().into()),
                            ("shasum", m.dist.shasum.clone().into()),
                        ]);
                        json::obj([
                            ("name", (&m.name).into()),
                            ("version", (&m.version).into()),
                            ("dist", dist),
                            ("deprecated", m.deprecated.into()),
                        ])
                    })
                    .collect();
                return Ok(pretty(&Value::Array(list)));
            }
            Ok(picked
                .iter()
                .map(|m| {
                    // The registry's text, which may be anything: cut by characters, not bytes.
                    let digest = m.integrity().unwrap_or_default();
                    let digest = if digest.chars().count() > 24 {
                        format!("{}…", digest.chars().take(24).collect::<String>())
                    } else {
                        digest
                    };
                    let line =
                        [format!("{}@{}", m.name, m.version), m.dist.tarball.clone().unwrap_or_default(), digest]
                            .iter()
                            .filter(|s| !s.is_empty())
                            .map(|s| ui::clean(s).into_owned())
                            .collect::<Vec<_>>()
                            .join("  ");
                    if m.deprecated { format!("{line}\n  {}", paint(YELLOW, "! deprecated", true)) } else { line }
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        _ => Err(Error::new("EOPTION", format!("unknown command {command}"))),
    }
}

/// Pretty JSON, as `--json` prints it.
fn pretty(v: &Value) -> String {
    json::to_pretty(v, "  ").trim_end().to_string()
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / 1024.0 / 1024.0)
}

fn size(bytes: u64) -> String {
    let kb = bytes as f64 / 1000.0;
    if kb < 1000.0 { format!("{kb:.1} kB") } else { format!("{:.1} MB", kb / 1000.0) }
}

fn fetched(cli: &Cli, list: &[commands::Fetched], lock: bool) -> Result<String, Error> {
    if cli.json {
        return Ok(pretty(&Value::Array(list.iter().map(commands::Fetched::to_value).collect())));
    }
    if lock {
        let cached = list.iter().filter(|f| f.cached).count();
        let files: usize = list.iter().map(|f| f.files).sum();
        let bytes: u64 = list.iter().map(|f| f.bytes).sum();
        return Ok(format!(
            "{} packages  {files} files  {}  {cached} cache hits, {} downloaded",
            list.len(),
            size(bytes),
            list.len() - cached
        ));
    }
    Ok(list
        .iter()
        .map(|f| {
            format!(
                "{}@{}  {} files  {}  {}",
                ui::clean(&f.name),
                ui::clean(&f.version),
                f.files,
                size(f.bytes),
                if f.cached { "cache hit" } else { "downloaded" }
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// What an install did, as one line or as JSON with the package.json changes first.
fn installed(cli: &Cli, r: &InstallResult, started: Instant, changes: Object) -> String {
    let ms = started.elapsed().as_millis();
    let seconds = format!("{:.2}", ms as f64 / 1000.0);
    if cli.json {
        let mut out = r.to_object(changes);
        out.insert("seconds", seconds.into());
        return pretty(&out.into());
    }
    for id in &r.missing_optional {
        ui::info(&format!("{id} is missing from the store and was not linked"));
    }
    let others = if r.other_platforms > 0 { format!(" (+{} skipped)", r.other_platforms) } else { String::new() };
    let time = if ms < 1000 { format!(" in {ms}ms") } else { format!(" in {seconds}s") };
    let ws = if r.workspaces > 0 {
        format!(", {} workspace{}", r.workspaces, if r.workspaces == 1 { "" } else { "s" })
    } else {
        String::new()
    };
    let count = format!("{} packages{ws}", r.packages);
    if r.up_to_date {
        return format!(
            "{count}{} {}{}",
            paint(GRAY, &others, true),
            paint(GREEN, "up to date", true),
            paint(GRAY, &time, true)
        );
    }
    let s = &r.stats;
    let mut detail = format!(
        "{others}, {} entries ({} reused), {} linked, {} copied, {} bins",
        s.entries,
        s.reused,
        s.linked + s.cloned,
        s.copied,
        s.bins
    );
    if s.removed > 0 {
        detail.push_str(&format!(", {} removed", s.removed));
    }
    if s.repaired > 0 {
        detail.push_str(&format!(", {} repaired", s.repaired));
    }
    if r.built > 0 {
        detail.push_str(&format!(", {} built", r.built));
    }
    if !r.unbuilt.is_empty() {
        ui::info(&format!("install scripts not run for {}: `jpm approve <name>` runs them", r.unbuilt.join(", ")));
    }
    format!("{} {count}{}", paint(GREEN, "Installed", true), paint(GRAY, &format!("{detail}{time}"), true))
}

fn run_command(cli: &Cli) -> Result<i32, Error> {
    let o = opts(cli);
    let selects = o.workspaces.is_some();
    let Some((name, args)) = cli.specs.split_first() else {
        let lists = commands::packages(&o)?;
        let render = |scripts: &Object, indent: &str| -> String {
            scripts
                .iter()
                .map(|(n, c)| {
                    format!(
                        "{indent}{}\n{indent}  {}\n",
                        paint(CYAN, n, true),
                        paint(GRAY, c.as_str().unwrap_or(""), true)
                    )
                })
                .collect()
        };
        if !selects {
            let top = &lists[0];
            let scripts = top.manifest.scripts(&top.file)?;
            if cli.json {
                ui::out(&format!("{}\n", pretty(&scripts.into())));
            } else if scripts.is_empty() {
                ui::info(&format!("no scripts in {}", top.file.display()));
            } else {
                ui::out(&render(&scripts, ""));
            }
        } else if cli.json {
            let mut all = Object::new();
            for top in &lists {
                all.insert(top.name.clone(), Value::Object(top.manifest.scripts(&top.file)?));
            }
            ui::out(&format!("{}\n", pretty(&all.into())));
        } else {
            for top in &lists {
                ui::out(&format!("{}\n{}", ui::clean(&top.name), render(&top.manifest.scripts(&top.file)?, "  ")));
            }
        }
        return Ok(0);
    };
    let (code, results) = match commands::run_script(name, args, &o, true) {
        Ok(r) => r,
        // No package.json to find a script in, so `jpm nope` is a typo in the command.
        Err(e) if cli.implied && !selects && cli.dir.is_none() && e.code == "ENOENT" => {
            return installed_bin(cli, name, args).unwrap_or_else(|| Ok(usage(&format!("unknown command \"{name}\""))));
        }
        Err(e) => return Err(e),
    };
    let own = results.first();
    if selects || cli.if_present || !own.is_some_and(|r| r.missing) {
        return Ok(code);
    }
    let file = own.map(|r| r.file.display().to_string()).unwrap_or_default();
    let names: Vec<String> = commands::packages(&Opts { dir: o.dir.clone(), ..Opts::default() })?
        .first()
        .and_then(|t| t.manifest.scripts(&t.file).ok())
        .map(|s| s.keys().cloned().collect())
        .unwrap_or_default();
    let have = if names.is_empty() { String::new() } else { format!(" — the scripts are {}", names.join(", ")) };
    if cli.implied {
        if let Some(r) = installed_bin(cli, name, args) {
            return r;
        }
        return Ok(usage(&format!("unknown command \"{name}\", and no such script in {file}{have}")));
    }
    ui::error(&format!("missing script \"{name}\" in {file}{have} (ENOSCRIPT)"));
    Ok(1)
}

/// `jpm vitest` with no such script: a bin already installed above, never the registry.
fn installed_bin(cli: &Cli, name: &str, args: &[String]) -> Option<Result<i32, Error>> {
    let dir = cli.dir.as_ref().map_or_else(|| std::env::current_dir().unwrap_or_default(), PathBuf::from);
    if !commands::installed_bin(&dir, name) {
        return None;
    }
    let mut specs = vec![name.to_string()];
    specs.extend_from_slice(args);
    Some(exec_with(cli, &specs))
}

fn exec_command(cli: &Cli) -> Result<i32, Error> {
    exec_with(cli, &cli.specs)
}

fn exec_with(cli: &Cli, specs: &[String]) -> Result<i32, Error> {
    let (command, args) = match specs.split_first() {
        Some((c, a)) => (c.clone(), a.to_vec()),
        None => (cli.call.clone().unwrap_or_default(), Vec::new()),
    };
    commands::exec(
        &command,
        ExecOpts { opts: opts(cli), args, packages: cli.packages.clone(), call: cli.call.is_some() },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Cli {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn parses_npm_spellings() {
        let c = p(&["i", "--save-dev", "--omit=dev", "--include", "dev"]);
        assert_eq!(c.command.as_deref(), Some("install"));
        assert!(c.dev && !c.production);
        let c = p(&["ci"]);
        assert!(c.frozen);
        let c = p(&["test", "--watch"]);
        assert_eq!(
            (c.command.as_deref(), c.implied, c.specs.as_slice()),
            (Some("run"), true, ["test".to_string(), "--watch".to_string()].as_slice())
        );
        let c = p(&["run", "build", "--", "-x"]);
        assert_eq!(c.specs, ["build", "-x"]);
        let c = p(&["exec", "eslint", "--", "."]);
        assert_eq!(c.specs, ["eslint", "--", "."]);
        let c = p(&["--dir", "x", "publish", "--tag", "next"]);
        assert_eq!((c.command.as_deref(), c.specs.len()), (Some("publish"), 2));
        assert!(parse(&["--nope".to_string()]).is_err());
        // npm's shorthand for `--loglevel verbose`, accepted as that is.
        let c = p(&["install", "--verbose"]);
        assert_eq!(c.command.as_deref(), Some("install"));
        let c = p(&["run", "build", "--verbose"]);
        assert_eq!(c.specs, ["build", "--verbose"]);
        assert!(parse(&["--before".to_string(), "soon".to_string()]).is_err());
    }

    #[test]
    fn checks_combinations() {
        let c = p(&["add", "--frozen-lockfile", "x"]);
        assert!(check(&c, "add", true, false).is_some());
        let c = p(&["install", "-w", "a"]);
        assert!(check(&c, "install", true, true).is_some());
        let c = p(&["add", "x"]);
        assert!(check(&c, "add", true, false).is_none());
    }
}
