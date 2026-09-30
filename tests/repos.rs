//! End to end: git dependencies, against bare repositories on disk (`file://`, which jpm fetches
//! only under its test switch) and a local server standing in for GitHub's archives.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Env, Registry, pkg};
use serde_json::json;

fn registry() -> Registry {
    Registry::start(vec![pkg("b", "1.0.0", json!({})), pkg("b", "2.0.0", json!({}))])
}

/// git with a fixed identity and none of the user's config.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository to commit to, pushed to a bare one beside it that installs read.
struct Repo {
    work: PathBuf,
    bare: PathBuf,
}

impl Repo {
    fn new(env: &Env, name: &str) -> Self {
        let (work, bare) = (env.root.join(format!("{name}-work")), env.root.join(format!("{name}.git")));
        std::fs::create_dir_all(&work).unwrap();
        git(&env.root, &["init", "-q", "--bare", "-b", "main", bare.to_str().unwrap()]);
        git(&work, &["init", "-q", "-b", "main"]);
        Self { work, bare }
    }

    /// Commit these files (and push): the new commit's id.
    fn commit(&self, files: &[(&str, &str)]) -> String {
        for (path, text) in files {
            let file = self.work.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, text).unwrap();
        }
        git(&self.work, &["add", "-A"]);
        git(&self.work, &["commit", "-q", "-m", "c"]);
        self.push();
        git(&self.work, &["rev-parse", "HEAD"])
    }

    /// The branch checked out, and the tags.
    fn push(&self) {
        let branch = git(&self.work, &["rev-parse", "--abbrev-ref", "HEAD"]);
        git(
            &self.work,
            &["push", "-q", "-f", "--tags", self.bare.to_str().unwrap(), &format!("HEAD:refs/heads/{branch}")],
        );
    }

    fn url(&self) -> String {
        format!("git+{}", file_url(&self.bare))
    }
}

/// `file:///tmp/x`, or `file:///C:/x` on Windows: `/` separated, as a url is.
fn file_url(path: &Path) -> String {
    let path = path.display().to_string().replace('\\', "/");
    format!("file://{}{path}", if path.starts_with('/') { "" } else { "/" })
}

fn jpm(env: &Env, args: &[&str]) -> Output {
    env.command(args).env("JPM_GIT_ALLOW_FILE", "1").output().unwrap()
}

fn ok(env: &Env, args: &[&str]) -> String {
    let out = jpm(env, args);
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "jpm {args:?} failed:\n{text}");
    text
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn wipe(env: &Env) {
    let _ = Command::new("chmod").args(["-R", "u+w"]).arg(env.store()).output();
    let _ = std::fs::remove_dir_all(env.store());
    let _ = std::fs::remove_dir_all(env.project().join("node_modules"));
}

const MANIFEST: &str = r#"{ "name": "gp", "version": "1.0.0", "bin": { "gp": "lib/cli.js" },
  "files": ["lib", "!lib/secret.js"], "dependencies": { "b": "1" } }"#;

#[test]
fn installs_from_a_git_repository() {
    let r = registry();
    let env = Env::new(&r);
    let repo = Repo::new(&env, "gp");
    let files = [
        ("package.json", MANIFEST),
        ("lib/cli.js", "#!/bin/sh\necho gp\n"),
        ("lib/secret.js", "no"),
        ("test/t.js", "no"),
        ("README.md", "yes"),
        ("node_modules/x/index.js", "never"),
    ];
    let v1 = repo.commit(&files);
    git(&repo.work, &["tag", "v1.0.0"]);
    let v11 = repo.commit(&[("lib/index.js", "v1.1")]);
    git(&repo.work, &["tag", "-a", "-m", "annotated", "v1.1.0"]);
    let head = repo.commit(&[("lib/index.js", "head")]);
    repo.push();

    // A semver range over the tags; an annotated tag is its commit.
    env.manifest(json!({ "dependencies": { "gp": format!("{}#semver:^1", repo.url()) } }));
    ok(&env, &["install"]);
    assert_eq!(env.read("node_modules/gp/lib/index.js"), "v1.1");
    // What npm pack would ship: `files`, less its negation, plus the readme; never node_modules.
    assert!(env.exists("node_modules/gp/README.md") && env.exists("node_modules/gp/lib/cli.js"));
    assert!(!env.exists("node_modules/gp/test") && !env.exists("node_modules/gp/lib/secret.js"));
    assert!(!env.exists("node_modules/gp/node_modules/x"));
    assert!(env.exists("node_modules/.bin/gp") && env.exists("node_modules/gp/../b/index.js"));
    let key = format!("gp@{}#{v11}", repo.url());
    let lock = env.lock();
    assert_eq!(lock["packages"][&key]["version"], "1.0.0", "{lock}");
    assert_eq!(lock["root"]["dependencies"]["gp"], format!("{}#{v11}", repo.url()));
    assert!(ok(&env, &["install"]).contains("up to date"));

    // A branch is locked to its commit, and not followed until package.json names another ref.
    env.manifest(json!({ "dependencies": { "gp": format!("{}#main", repo.url()) } }));
    ok(&env, &["install"]);
    assert_eq!(env.read("node_modules/gp/lib/index.js"), "head");
    let moved = repo.commit(&[("lib/index.js", "moved")]);
    env.manifest(json!({ "dependencies": { "gp": format!("{}#main", repo.url()), "b": "2.0.0" } }));
    ok(&env, &["install"]);
    assert_eq!(env.read("node_modules/gp/lib/index.js"), "head", "the lockfile keeps the commit");
    assert!(env.read("jpm.lock").contains(&head));
    // The default branch, and a commit by its id.
    env.manifest(json!({ "dependencies": { "gp": repo.url() } }));
    ok(&env, &["install"]);
    assert_eq!(env.read("node_modules/gp/lib/index.js"), "moved");
    env.manifest(json!({ "dependencies": { "gp": format!("{}#{v1}", repo.url()) } }));
    ok(&env, &["install"]);
    assert!(!env.exists("node_modules/gp/lib/index.js"));
    assert!(env.read("jpm.lock").contains(&v1) && !env.read("jpm.lock").contains(&moved));

    // From jpm.lock alone, with an empty store: fetched again, and the same files.
    wipe(&env);
    ok(&env, &["ci"]);
    assert!(env.exists("node_modules/gp/lib/cli.js"));
    // A short commit id is not a ref.
    env.manifest(json!({ "dependencies": { "gp": format!("{}#{}", repo.url(), &v1[..8]) } }));
    let out = jpm(&env, &["install"]);
    assert!(stderr(&out).contains("full 40-character id"), "{}", stderr(&out));
    // file:// is for tests: a package.json cannot reach the disk through git.
    env.manifest(json!({ "dependencies": { "gp": repo.url() } }));
    let out = env.jpm(&["install"]);
    assert!(stderr(&out).contains("jpm does not fetch file:// repositories"), "{}", stderr(&out));
}

#[test]
fn fetches_a_github_repository_as_its_archive() {
    let r = registry();
    let env = Env::new(&r);
    let repo = Repo::new(&env, "r");
    let main = repo.commit(&[("package.json", r#"{ "name": "gh", "version": "2.0.0" }"#), ("index.js", "main")]);
    git(&repo.work, &["checkout", "-q", "-b", "dev"]);
    let dev = repo.commit(&[("index.js", "dev")]);
    // The archive as GitHub serves it: gzipped, under `<repo>-<commit>/`.
    let archive = |commit: &str, format: &str| {
        let out = Command::new("git")
            .args(["archive", &format!("--format={format}"), &format!("--prefix=r-{commit}/"), commit])
            .current_dir(&repo.work)
            .output()
            .unwrap();
        out.stdout
    };
    r.serve(&format!("/u/r/tar.gz/{main}"), archive(&main, "tar.gz"));
    // Refs are read from the bare repository standing in for github.com; a registry token is set.
    let host = r.url.trim_start_matches("http://");
    env.write(".npmrc", &format!("//{host}/:_authToken=SECRET\n"));
    let bare = file_url(&repo.bare);
    let run = |args: &[&str]| {
        env.command(args)
            .env("JPM_GIT_ALLOW_FILE", "1")
            .env("JPM_CODELOAD_URL", &r.url)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", format!("url.{bare}.insteadOf"))
            .env("GIT_CONFIG_VALUE_0", "https://github.com/u/r.git")
            .output()
            .unwrap()
    };
    let check = |out: &Output| assert!(out.status.success(), "{}", stderr(out));
    env.manifest(json!({ "dependencies": { "gh": "github:u/r#main" } }));
    check(&run(&["install"]));
    assert_eq!(env.read("node_modules/gh/index.js"), "main");
    let hits = r.hits.lock().unwrap().clone();
    let got = hits.iter().find(|h| h.starts_with(&format!("/u/r/tar.gz/{main}"))).expect("the archive is fetched");
    assert!(!got.contains("SECRET"), "a registry token went to the git host: {got}");
    let lock = env.lock();
    let entry = &lock["packages"][format!("gh@git+https://github.com/u/r.git#{main}")];
    assert_eq!(entry["version"], "2.0.0", "{lock}");

    // Served compressed another way, the same tree has the same integrity.
    r.serve(&format!("/u/r/tar.gz/{main}"), archive(&main, "tar"));
    wipe(&env);
    check(&run(&["ci"]));
    assert_eq!(env.read("node_modules/gh/index.js"), "main");
    // Other files under that commit are refused.
    let other = Repo::new(&env, "other");
    other.commit(&[("package.json", r#"{ "name": "gh", "version": "2.0.0" }"#), ("index.js", "evil")]);
    let evil = Command::new("git")
        .args(["archive", "--format=tar.gz", "--prefix=x/", "HEAD"])
        .current_dir(&other.work)
        .output()
        .unwrap();
    r.serve(&format!("/u/r/tar.gz/{main}"), evil.stdout);
    wipe(&env);
    let out = run(&["ci"]);
    assert!(!out.status.success() && stderr(&out).contains("EINTEGRITY"), "{}", stderr(&out));

    // No archive for a commit (a private repository): cloned with git instead.
    env.manifest(json!({ "dependencies": { "gh": "u/r#dev" } }));
    check(&run(&["install"]));
    assert_eq!(env.read("node_modules/gh/index.js"), "dev");
    assert!(env.read("jpm.lock").contains(&format!("gh@git+https://github.com/u/r.git#{dev}")));
}

#[cfg(unix)]
#[test]
fn runs_a_git_packages_prepare_only_when_approved() {
    let r = registry();
    let env = Env::new(&r);
    let repo = Repo::new(&env, "p");
    repo.commit(&[(
        "package.json",
        r#"{ "name": "prep", "version": "1.0.0", "scripts": { "prepare": "echo built > built.txt" } }"#,
    )]);
    env.manifest(json!({ "dependencies": { "prep": repo.url() } }));
    let out = ok(&env, &["install"]);
    assert!(out.contains("install scripts not run for prep@1.0.0"), "{out}");
    assert!(!env.exists("node_modules/prep/built.txt"));
    let out = ok(&env, &["approve", "prep"]);
    assert!(out.contains("approved prep@"), "{out}");
    assert_eq!(env.read("node_modules/prep/built.txt"), "built\n");
}

#[test]
fn brings_over_a_foreign_lockfile_with_a_git_dependency() {
    let r = registry();
    let env = Env::new(&r);
    let repo = Repo::new(&env, "f");
    let commit = repo.commit(&[("package.json", r#"{ "name": "f", "version": "1.0.0" }"#)]);
    let spec = format!("{}#{commit}", repo.url());
    env.manifest(json!({ "dependencies": { "f": spec, "b": "1.0.0" } }));
    let b = common::pkg("b", "1.0.0", json!({})).tarball();
    env.write(
        "package-lock.json",
        &json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "f": spec, "b": "1.0.0" } },
                "node_modules/f": { "version": "1.0.0", "resolved": spec },
                "node_modules/b": { "version": "1.0.0", "integrity": common::sha512(&b),
                    "resolved": format!("{}/b/-/b-1.0.0.tgz", r.url) }
            }
        })
        .to_string(),
    );
    let out = ok(&env, &["install"]);
    assert!(out.contains("resolving with its versions preferred"), "{out}");
    assert!(env.exists("node_modules/f/package.json") && env.exists("node_modules/b"));
}

#[test]
fn adds_a_repository_as_it_was_typed() {
    let r = registry();
    let env = Env::new(&r);
    let repo = Repo::new(&env, "a");
    repo.commit(&[("package.json", r#"{ "name": "from-repo", "version": "3.0.0" }"#)]);
    git(&repo.work, &["tag", "v3"]);
    repo.push();
    env.manifest(json!({ "name": "app" }));
    let spec = format!("{}#v3", repo.url());
    ok(&env, &["add", &spec]);
    ok(&env, &["add", &format!("alias@{spec}")]);
    let text = env.read("package.json");
    assert!(
        text.contains(&format!(r#""from-repo": "{spec}""#)) && text.contains(&format!(r#""alias": "{spec}""#)),
        "{text}"
    );
    assert!(env.read("node_modules/alias/package.json").contains("from-repo"));
}

#[test]
fn says_when_git_is_missing() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "x": "github:u/r#main" } }));
    let out = env.command(&["install"]).env("PATH", env.root.join("nowhere")).output().unwrap();
    assert!(stderr(&out).contains("git is not installed"), "{}", stderr(&out));
}

/// package.json names one repository, and an edited jpm.lock another in its place (or another
/// commit of the one it pins). Nothing installs from it, and its `prepare` never runs, though
/// the lock approves it under a trusted name.
#[cfg(unix)]
#[test]
fn a_lockfile_cannot_move_a_git_dependency_to_another_source() {
    let r = registry();
    let env = Env::new(&r);
    let good = Repo::new(&env, "good");
    let pinned = good.commit(&[("package.json", r#"{ "name": "gp", "version": "1.0.0" }"#)]);
    let evil = Repo::new(&env, "evil");
    let pwned = env.root.join("pwned");
    let prepare =
        format!(r#"{{ "name": "gp", "version": "1.0.0", "scripts": {{ "prepare": "touch {}" }} }}"#, pwned.display());
    evil.commit(&[("package.json", &prepare)]);
    // The attacker's own checkout: the other repository, trusted and approved.
    let trusted = |spec: String| json!({ "trustedDependencies": ["gp"], "dependencies": { "gp": spec } });
    env.manifest(trusted(format!("{}#main", evil.url())));
    ok(&env, &["install"]);
    ok(&env, &["approve", "gp"]);
    assert!(pwned.exists());
    std::fs::remove_file(&pwned).unwrap();
    let locked = env.read("jpm.lock");
    let (evil_main, good_main, good_pinned) =
        (format!("{}#main", evil.url()), format!("{}#main", good.url()), format!("{}#{pinned}", good.url()));
    // What a review sees, package.json and the lock's spec line, names the good repository.
    for (spec, edited) in [
        (good_main.clone(), locked.replace(&evil_main, &good_main)),
        (good_pinned.clone(), locked.replace(&evil_main, &good_pinned).replace(&evil.url(), &good.url())),
    ] {
        env.manifest(trusted(spec));
        env.write("jpm.lock", &edited);
        wipe(&env);
        let out = jpm(&env, &["ci"]);
        assert!(!out.status.success() && stderr(&out).contains("which its specs do not name"), "{}", stderr(&out));
        assert!(!env.exists("node_modules/gp"));
        // An install sets the lockfile aside, and takes what package.json names.
        let out = jpm(&env, &["install"]);
        let text = stderr(&out);
        assert!(out.status.success() && text.contains("ignoring jpm.lock"), "{text}");
        assert!(!env.read("jpm.lock").contains(&evil.url()));
        assert!(!pwned.exists());
    }
}

/// A registry package's own git dependency is refused (`block-exotic-subdeps`, on by default);
/// the user can allow it, the project cannot. Allowed, it installs as npm installs it, locked to
/// the repository its package.json names. The project's own repositories always install.
#[test]
fn locks_a_packages_own_git_dependency_to_what_it_names() {
    let r = registry();
    let env = Env::new(&r);
    let good = Repo::new(&env, "t");
    good.commit(&[("package.json", r#"{ "name": "t", "version": "1.0.0" }"#), ("index.js", "good")]);
    let other = Repo::new(&env, "u");
    other.commit(&[("package.json", r#"{ "name": "t", "version": "1.0.0" }"#), ("index.js", "other")]);
    r.publish(pkg("reg", "1.0.0", json!({ "dependencies": { "t": good.url() } })));
    env.manifest(json!({ "dependencies": { "reg": "1.0.0" } }));
    let refused = |out: Output| {
        let err = stderr(&out);
        assert!(!out.status.success() && err.contains("block-exotic-subdeps"), "{err}");
        err
    };
    refused(jpm(&env, &["install"]));
    // Not from the project's own .npmrc; from the environment, a flag, or the user's.
    env.write(".npmrc", "block-exotic-subdeps=false\n");
    assert!(refused(jpm(&env, &["install"])).contains("sets block-exotic-subdeps, which only ~/.npmrc"));
    let mut allowed = env.command(&["install"]);
    allowed.env("JPM_GIT_ALLOW_FILE", "1").env("npm_config_block_exotic_subdeps", "false");
    assert!(allowed.output().unwrap().status.success());
    ok(&env, &["install", "--no-block-exotic-subdeps"]);
    std::fs::remove_file(env.project().join(".npmrc")).unwrap();
    env.user_npmrc("block-exotic-subdeps=false\n");
    ok(&env, &["install"]);
    let locked = env.read("jpm.lock");
    assert!(locked.contains(&good.url()), "{locked}");
    // An edit giving it another repository.
    env.write("jpm.lock", &locked.replace(&good.url(), &other.url()));
    wipe(&env);
    let out = jpm(&env, &["ci"]);
    assert!(!out.status.success() && stderr(&out).contains("which its package.json does not name"), "{}", stderr(&out));
    // None of a package's own with block-exotic-subdeps: from the lockfile, or a fresh walk.
    env.write("jpm.lock", &locked);
    env.user_npmrc("");
    for command in ["ci", "install"] {
        let out = jpm(&env, &[command]);
        assert!(!out.status.success() && stderr(&out).contains("block-exotic-subdeps"), "{}", stderr(&out));
    }
    std::fs::remove_file(env.project().join("jpm.lock")).unwrap();
    let out = jpm(&env, &["install"]);
    assert!(!out.status.success() && stderr(&out).contains("block-exotic-subdeps"), "{}", stderr(&out));
    env.manifest(json!({ "dependencies": { "t": good.url() } }));
    ok(&env, &["install"]);
    assert_eq!(env.read("node_modules/t/index.js"), "good");
}

/// git runs in a directory of jpm's own: the project's repository config is never read, nor a
/// bare repository's that a checkout carries as plain files and jpm is run from.
#[cfg(unix)]
#[test]
fn reads_no_repository_config_around_the_project() {
    let r = registry();
    let env = Env::new(&r);
    let pwned = env.root.join("pwned");
    let config = format!(
        "[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tsshCommand = touch {} && false\n",
        pwned.display()
    );
    git(&env.project(), &["init", "-q"]);
    std::fs::write(env.project().join(".git/config"), config.replace("bare = true", "bare = false")).unwrap();
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"],
        "dependencies": { "x": "git+ssh://git@example.invalid/u/r.git" } }));
    env.write("packages/a/package.json", r#"{ "name": "a", "version": "1.0.0" }"#);
    for (file, text) in
        [("HEAD", "ref: refs/heads/main\n"), ("objects/info/keep", ""), ("refs/heads/keep", ""), ("config", &config)]
    {
        env.write(&format!("packages/a/{file}"), text);
    }
    for dir in [env.project(), env.project().join("packages/a")] {
        let out = env.command_in(&dir, &["install"]).output().unwrap();
        assert!(!out.status.success(), "{}", stderr(&out));
        assert!(!pwned.exists(), "{}: {}", dir.display(), stderr(&out));
    }
}

/// `<helper>::<address>` would have git run the helper: no spelling of a url reaches it.
#[cfg(unix)]
#[test]
fn never_hands_git_a_transport_helper() {
    use std::os::unix::fs::PermissionsExt;
    let r = registry();
    let env = Env::new(&r);
    let script = env.project().join("x:r");
    std::fs::write(&script, "#!/bin/sh\ntouch pwned\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    for spec in [
        "git+ssh://ext::./x:r",
        "git+ssh://git@ext::./x:r",
        "git+ssh://ext::./x:r#0123456789012345678901234567890123456789",
    ] {
        env.manifest(json!({ "dependencies": { "x": spec } }));
        let out = jpm(&env, &["install"]);
        assert!(!out.status.success() && stderr(&out).contains("not a repository"), "{spec}: {}", stderr(&out));
        assert!(!env.exists("pwned"), "{spec}");
    }
}
