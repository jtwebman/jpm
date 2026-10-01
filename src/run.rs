//! `jpm run`: one package.json script in a shell, with every `node_modules/.bin` above the
//! project first on PATH. No pre/post scripts: what runs is what the file names. `jpm exec`
//! runs a bin through the same shell.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::link;

/// `node_modules/.bin` of `dir` and of each directory above it, nearest first.
pub fn bin_dirs(dir: &Path) -> Vec<PathBuf> {
    dir.ancestors().map(|at| at.join("node_modules").join(".bin")).collect()
}

/// A program on PATH, as the shell would find it, from absolute directories only: a `.` or a
/// relative entry would find whatever the current directory holds.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .map(str::to_string)
            .collect()
    } else {
        vec![String::new()]
    };
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .find_map(|dir| exts.iter().map(|ext| dir.join(format!("{name}{ext}"))).find(|file| file.is_file()))
}

/// PATH with `dirs` first. Windows spells it `Path`, and a second key would be ignored.
pub fn with_path(dirs: &[PathBuf]) -> (OsString, OsString) {
    let key = std::env::vars_os()
        .map(|(k, _)| k)
        .find(|k| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
        .unwrap_or_else(|| "PATH".into());
    let old = std::env::var_os(&key).unwrap_or_default();
    let all = dirs.iter().cloned().chain(std::env::split_paths(&old));
    (key, std::env::join_paths(all).unwrap_or(old))
}

/// The command with its arguments appended, each quoted for the shell that reads it.
pub fn shell_line(command: &str, args: &[String], batch: bool) -> String {
    let mut line = command.to_string();
    for arg in args {
        line.push(' ');
        line.push_str(&quote(arg, cfg!(windows), batch));
    }
    line
}

/// One word, quoted for `sh` or for `cmd.exe`.
pub fn quote(arg: &str, win: bool, batch: bool) -> String {
    if win {
        return quote_cmd(arg, batch);
    }
    if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:=@+,-".contains(&b)) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// The program word of a line: under cmd.exe, plain quotes and no carets, as cmd.exe reads that
/// word itself; a quote behind a caret is only a character, so the word would end at a space.
/// A path holds no `"`.
pub fn quote_program(word: &str, win: bool) -> String {
    if !win {
        return quote(word, false, false);
    }
    let bare = !word.is_empty() && !word.contains([' ', '\t', '&', '(', ')', '<', '>', '|', '^', '!', ',', ';', '=']);
    let word = if bare { word.to_string() } else { format!("\"{word}\"") };
    word.replace('%', "%%cd:~,%")
}

/// Two layers, as npm does it: quotes for the program's own argv parser, then carets for
/// cmd.exe. A batch file's `%*` reads the carets once more, so there they are doubled; `%`
/// becomes an expression that expands to `%`.
fn quote_cmd(arg: &str, batch: bool) -> String {
    if arg.is_empty() {
        return "\"\"".into();
    }
    let quoted = if arg.contains([' ', '\t', '\n', '"']) {
        let mut out = String::from("\"");
        let mut slashes = 0;
        for c in arg.chars() {
            match c {
                '\\' => slashes += 1,
                '"' => {
                    out.push_str(&"\\".repeat(slashes * 2 + 1));
                    out.push('"');
                    slashes = 0;
                    continue;
                }
                _ => {
                    out.push_str(&"\\".repeat(slashes));
                    slashes = 0;
                    out.push(c);
                    continue;
                }
            }
        }
        out.push_str(&"\\".repeat(slashes * 2));
        out.push('"');
        out
    } else {
        arg.to_string()
    };
    let caret = |s: &str| {
        s.chars().fold(String::new(), |mut o, c| {
            if "!^&()<>|\"".contains(c) {
                o.push('^');
            }
            o.push(c);
            o
        })
    };
    let once = caret(&quoted);
    let twice = if batch { caret(&once) } else { once };
    twice.replace('%', "%%cd:~,%")
}

/// A shell running `line` in `cwd` with `dirs` first on PATH, for the project at `project`.
pub fn shell(line: &str, cwd: &Path, dirs: &[PathBuf], project: &Path) -> Command {
    let (key, mut path) = with_path(dirs);
    if let Some(dir) = node_from_bun(dirs) {
        let all = std::env::split_paths(&path).chain(std::iter::once(dir));
        path = std::env::join_paths(all).unwrap_or(path);
    }
    // The shell is named by its full path: found on the PATH the script gets, a dependency's bin
    // called `sh` (or `cmd`) would run in its place, approved or not.
    #[cfg(windows)]
    let mut command = {
        use std::os::windows::process::CommandExt;
        let system = || std::env::var_os("SystemRoot").map(|r| Path::new(&r).join("System32").join("cmd.exe"));
        let comspec = std::env::var_os("ComSpec").map(PathBuf::from).filter(|c| c.is_absolute()).or_else(system);
        let comspec = comspec.unwrap_or_else(|| "cmd.exe".into());
        let mut c = Command::new(comspec);
        c.args(["/d", "/s", "/c"]).raw_arg(format!("\"{line}\""));
        c
    };
    #[cfg(not(windows))]
    let mut command = {
        let sh = Path::new("/bin/sh");
        let mut c =
            Command::new(if sh.is_file() { sh.to_path_buf() } else { which("sh").unwrap_or_else(|| "sh".into()) });
        c.args(["-c", line]);
        c
    };
    command.current_dir(cwd).env(key, path);
    hoist_env(&mut command, project);
    command
}

/// With no `node` on PATH, a project with a bun runtime gets bun by that name, last on PATH, as
/// `bun run` does: vite, tsc and the other bins start `node`. The link is in the project's own
/// `node_modules/.jpm`, never through a link there.
#[cfg(unix)]
fn node_from_bun(dirs: &[PathBuf]) -> Option<PathBuf> {
    use std::fs;
    if which("node").is_some() {
        return None;
    }
    let bun = dirs.iter().map(|d| d.join("bun")).find(|b| b.is_file())?;
    let real_dir = |p: &Path| fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    let jpm = bun.parent()?.parent()?.join(".jpm");
    let dir = jpm.join("bun-node");
    let _ = real_dir(&jpm).then(|| fs::create_dir(&dir));
    if !real_dir(&dir) {
        return None;
    }
    let (link, target) = (dir.join("node"), fs::canonicalize(&bun).ok()?);
    if fs::read_link(&link).ok() != Some(target.clone()) {
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).ok()?;
    }
    Some(dir)
}

#[cfg(not(unix))]
fn node_from_bun(_: &[PathBuf]) -> Option<PathBuf> {
    None
}

/// Packages in the global store resolve from the store, never reaching the project's hidden
/// hoist or its `node_modules`. Where the project's own `node_modules` has the hook jpm writes
/// for them, Node looks there last: through NODE_PATH for `require`, and the hook for `import`.
/// Only the project's: a directory above it may be anyone's, and the hook runs in every node.
fn hoist_env(command: &mut Command, project: &Path) {
    let nm = project.join("node_modules");
    let jpm = nm.join(".jpm");
    if !jpm.join(link::HOOK).is_file() {
        return;
    }
    let old = std::env::var_os("NODE_PATH").unwrap_or_default();
    let mut paths: Vec<PathBuf> = std::env::split_paths(&old).filter(|p| !p.as_os_str().is_empty()).collect();
    for dir in [jpm.join(link::HOIST), nm.clone()] {
        if !paths.contains(&dir) {
            paths.push(dir);
        }
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        command.env("NODE_PATH", joined);
    }
    // Node reads NODE_OPTIONS as words, a quoted one taking `\` as an escape. A path that is not
    // Unicode cannot be spelled there, and a lossy spelling would stop every node from starting.
    let Some(file) = jpm.join(link::HOOK).to_str().map(|f| f.replace('\\', "\\\\").replace('"', "\\\"")) else {
        return;
    };
    let require = format!("--require \"{file}\"");
    let old = match std::env::var("NODE_OPTIONS") {
        Ok(old) => old,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(std::env::VarError::NotUnicode(_)) => return,
    };
    if !old.contains(&require) {
        command.env("NODE_OPTIONS", if old.is_empty() { require } else { format!("{old} {require}") });
    }
}

/// Why the shell did not start. Windows starts no process in a directory whose path is 260
/// characters or longer, whatever `LongPathsEnabled` says, and reports only "invalid".
pub fn start_error(e: &std::io::Error, command: &Command) -> Error {
    if let Some(dir) = command.get_current_dir().filter(|d| cfg!(windows) && d.as_os_str().len() >= 260) {
        return Error::new(
            "ENAMETOOLONG",
            format!(
                "cannot start the shell in {}: Windows starts no program in a directory whose path is 260 characters or longer; move the project to a shorter path",
                dir.display()
            ),
        );
    }
    Error::io(e, "cannot start the shell")
}

/// Run to completion, sharing this process's stdio; the exit code, or 128 + a signal's number.
pub fn wait(command: &mut Command) -> Result<i32> {
    let _children = crate::sys::leave_interrupts_to_children();
    let status = command.status().map_err(|e| start_error(&e, command))?;

    if let Some(code) = status.code() {
        return Ok(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        return Ok(128 + status.signal().unwrap_or(0));
    }
    #[allow(unreachable_code)]
    Ok(1)
}

/// A script's environment on top of PATH: the `npm_*` names tools read.
pub fn script_env(command: &mut Command, file: &Path, name: &str, script: &str, pkg_name: &str, pkg_version: &str) {
    let cwd = std::env::current_dir().unwrap_or_default();
    command
        .env("INIT_CWD", cwd)
        .env("npm_lifecycle_event", name)
        .env("npm_lifecycle_script", script)
        .env("npm_package_json", file)
        .env("npm_package_name", pkg_name)
        .env("npm_package_version", pkg_version)
        .env("npm_execpath", std::env::current_exe().unwrap_or_default());
}

// --- pnpm's `run /regex/` --------------------------------------------------------------------

/// A script-name pattern, `/…/` as pnpm's run takes it (`pnpm run "/^build:.*/"`), matched in
/// time linear in the name whatever the pattern: a Thompson NFA run on a set of states, never a
/// backtracking search, so a pattern from a package.json (`/^(a+)+$/`) cannot hang the run.
/// Literals, `.`, `*`, `+`, `?`, `|`, groups, `[…]` classes and `\` escapes, `^` and `$` at the
/// ends; counted repeats, backreferences and lookaround are refused by name.
pub struct ScriptPattern {
    prog: Vec<Inst>,
    start: bool,
    end: bool,
}

/// A pattern is for a script name: longer than this, or with more states, is refused.
const MAX_PATTERN: usize = 256;
const MAX_STATES: usize = 1000;
const MAX_DEPTH: usize = 32;

#[derive(Clone)]
enum Set {
    Any,
    One(char),
    Class(bool, Vec<(char, char)>),
}

impl Set {
    fn has(&self, c: char) -> bool {
        match self {
            Set::Any => true,
            Set::One(x) => *x == c,
            Set::Class(negated, ranges) => ranges.iter().any(|(a, b)| (*a..=*b).contains(&c)) != *negated,
        }
    }
}

enum Re {
    Set(Set),
    Cat(Vec<Re>),
    Alt(Vec<Re>),
    Star(Box<Re>),
    Plus(Box<Re>),
    Opt(Box<Re>),
}

enum Inst {
    Char(Set),
    Split(usize, usize),
    Jump(usize),
    Match,
}

impl ScriptPattern {
    /// `Some` for a `/…/` argument, its error for one jpm will not run.
    pub fn of(arg: &str) -> Option<std::result::Result<Self, String>> {
        let body = arg.strip_prefix('/')?.strip_suffix('/')?;
        Some(Self::parse(body).map_err(|why| format!("script pattern {arg}: {why}")))
    }

    fn parse(body: &str) -> std::result::Result<Self, String> {
        if body.len() > MAX_PATTERN {
            return Err(format!("longer than {MAX_PATTERN} characters"));
        }
        let start = body.starts_with('^');
        let body = body.strip_prefix('^').unwrap_or(body);
        let end = body.ends_with('$') && !body.ends_with("\\$");
        let body = if end { &body[..body.len() - 1] } else { body };
        let chars: Vec<char> = body.chars().collect();
        let mut at = 0;
        let re = alt(&chars, &mut at, 0)?;
        if at < chars.len() {
            return Err(format!("unmatched {:?}", chars[at]));
        }
        let mut prog = Vec::new();
        emit(&re, &mut prog);
        prog.push(Inst::Match);
        if prog.len() > MAX_STATES {
            return Err(format!("more than {MAX_STATES} states"));
        }
        Ok(Self { prog, start, end })
    }

    pub fn matches(&self, name: &str) -> bool {
        let n = self.prog.len();
        let (mut now, mut next) = (Vec::with_capacity(n), Vec::with_capacity(n));
        let mut seen = vec![usize::MAX; n];
        let mut step = 0;
        let matched = |set: &Vec<usize>| set.iter().any(|pc| matches!(self.prog[*pc], Inst::Match));
        self.add(&mut now, &mut seen, step, 0);
        for c in name.chars() {
            if matched(&now) && !self.end {
                return true;
            }
            step += 1;
            next.clear();
            for &pc in &now {
                if let Inst::Char(set) = &self.prog[pc]
                    && set.has(c)
                {
                    self.add(&mut next, &mut seen, step, pc + 1);
                }
            }
            if !self.start {
                self.add(&mut next, &mut seen, step, 0);
            }
            std::mem::swap(&mut now, &mut next);
        }
        matched(&now)
    }

    /// `pc` and every state its jumps and splits reach, once a step.
    fn add(&self, set: &mut Vec<usize>, seen: &mut [usize], step: usize, pc: usize) {
        let mut todo = vec![pc];
        while let Some(pc) = todo.pop() {
            if seen[pc] == step {
                continue;
            }
            seen[pc] = step;
            match self.prog[pc] {
                Inst::Jump(to) => todo.push(to),
                Inst::Split(a, b) => {
                    todo.push(b);
                    todo.push(a);
                }
                _ => set.push(pc),
            }
        }
    }
}

fn alt(c: &[char], at: &mut usize, depth: usize) -> std::result::Result<Re, String> {
    if depth > MAX_DEPTH {
        return Err(format!("groups nested more than {MAX_DEPTH} deep"));
    }
    let mut arms = vec![cat(c, at, depth)?];
    while c.get(*at) == Some(&'|') {
        *at += 1;
        arms.push(cat(c, at, depth)?);
    }
    Ok(if arms.len() == 1 { arms.pop().unwrap_or(Re::Cat(Vec::new())) } else { Re::Alt(arms) })
}

fn cat(c: &[char], at: &mut usize, depth: usize) -> std::result::Result<Re, String> {
    let mut parts = Vec::new();
    while let Some(&ch) = c.get(*at) {
        if ch == '|' || ch == ')' {
            break;
        }
        *at += 1;
        let atom = match ch {
            '.' => Re::Set(Set::Any),
            '(' => {
                if c.get(*at) == Some(&'?') {
                    return Err("lookaround and (?…) groups are not read".into());
                }
                let inner = alt(c, at, depth + 1)?;
                if c.get(*at) != Some(&')') {
                    return Err("unclosed (".into());
                }
                *at += 1;
                inner
            }
            '[' => Re::Set(class(c, at)?),
            '\\' => {
                let e = *c.get(*at).ok_or("a trailing \\")?;
                *at += 1;
                if e.is_ascii_digit() {
                    return Err("backreferences are not read".into());
                }
                Re::Set(match e {
                    'd' => Set::Class(false, vec![('0', '9')]),
                    'w' => Set::Class(false, vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')]),
                    _ => Set::One(e),
                })
            }
            '{' => return Err("counted repeats ({n,m}) are not read".into()),
            '*' | '+' | '?' => return Err(format!("{ch} repeats nothing")),
            '^' | '$' => return Err(format!("{ch} only at the start or end")),
            other => Re::Set(Set::One(other)),
        };
        let atom = match c.get(*at) {
            Some('*') => Re::Star(Box::new(atom)),
            Some('+') => Re::Plus(Box::new(atom)),
            Some('?') => Re::Opt(Box::new(atom)),
            _ => {
                parts.push(atom);
                continue;
            }
        };
        *at += 1;
        if matches!(c.get(*at), Some('*' | '+' | '?' | '{')) {
            return Err("a repeat of a repeat is not read".into());
        }
        parts.push(atom);
    }
    Ok(Re::Cat(parts))
}

fn class(c: &[char], at: &mut usize) -> std::result::Result<Set, String> {
    let negated = c.get(*at) == Some(&'^');
    if negated {
        *at += 1;
    }
    let mut ranges = Vec::new();
    loop {
        let mut ch = *c.get(*at).ok_or("unclosed [")?;
        *at += 1;
        if ch == ']' && !ranges.is_empty() {
            return Ok(Set::Class(negated, ranges));
        }
        if ch == '\\' {
            ch = *c.get(*at).ok_or("unclosed [")?;
            *at += 1;
        }
        if c.get(*at) == Some(&'-') && c.get(*at + 1).is_some_and(|n| *n != ']') {
            let hi = c[*at + 1];
            *at += 2;
            ranges.push((ch, hi));
        } else {
            ranges.push((ch, ch));
        }
    }
}

fn emit(re: &Re, p: &mut Vec<Inst>) {
    match re {
        Re::Set(s) => p.push(Inst::Char(s.clone())),
        Re::Cat(parts) => parts.iter().for_each(|r| emit(r, p)),
        Re::Alt(arms) => {
            let mut jumps = Vec::new();
            for (i, arm) in arms.iter().enumerate() {
                if i + 1 < arms.len() {
                    let split = p.len();
                    p.push(Inst::Split(split + 1, 0));
                    emit(arm, p);
                    jumps.push(p.len());
                    p.push(Inst::Jump(0));
                    let next = p.len();
                    p[split] = Inst::Split(split + 1, next);
                } else {
                    emit(arm, p);
                }
            }
            let end = p.len();
            for j in jumps {
                p[j] = Inst::Jump(end);
            }
        }
        Re::Star(inner) => {
            let split = p.len();
            p.push(Inst::Split(split + 1, 0));
            emit(inner, p);
            p.push(Inst::Jump(split));
            let out = p.len();
            p[split] = Inst::Split(split + 1, out);
        }
        Re::Plus(inner) => {
            let start = p.len();
            emit(inner, p);
            let out = p.len() + 1;
            p.push(Inst::Split(start, out));
        }
        Re::Opt(inner) => {
            let split = p.len();
            p.push(Inst::Split(split + 1, 0));
            emit(inner, p);
            let out = p.len();
            p[split] = Inst::Split(split + 1, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_for_sh() {
        assert_eq!(quote("plain-1.0/x", false, false), "plain-1.0/x");
        assert_eq!(quote("it's", false, false), "'it'\\''s'");
        assert_eq!(quote("", false, false), "''");
        assert_eq!(
            shell_line("echo", &["a b".into()], false),
            if cfg!(windows) { "echo ^\"a b^\"" } else { "echo 'a b'" }
        );
    }

    #[test]
    fn quotes_for_cmd() {
        assert_eq!(quote("a b", true, false), "^\"a b^\"");
        assert_eq!(quote("x&y", true, false), "x^&y");
        assert_eq!(quote("x&y", true, true), "x^^^&y");
        assert_eq!(quote("50%", true, false), "50%%cd:~,%");
        assert_eq!(quote("a\"b", true, false), "^\"a\\^\"b^\"");
    }

    #[test]
    fn quotes_a_program_for_cmd_plainly() {
        assert_eq!(quote_program(r"C:\x\a.cmd", true), r"C:\x\a.cmd");
        assert_eq!(quote_program(r"C:\my dir\a.cmd", true), r#""C:\my dir\a.cmd""#);
        assert_eq!(quote_program(r"C:\a&b (1)\x.cmd", true), r#""C:\a&b (1)\x.cmd""#);
        assert_eq!(quote_program(r"C:\100%\x.cmd", true), r"C:\100%%cd:~,%\x.cmd");
        assert_eq!(quote_program("/my dir/a", false), "'/my dir/a'");
    }

    #[test]
    fn matches_script_names_as_pnpms_run_patterns() {
        let p = |pat: &str| ScriptPattern::of(pat).unwrap().unwrap();
        let names = ["build", "build:js", "build:css", "copy-build", "test", "prebuild"];
        let hits = |pat: &str| names.iter().filter(|n| p(pat).matches(n)).copied().collect::<Vec<_>>();
        assert_eq!(hits("/^build:.*/"), ["build:js", "build:css"]);
        assert_eq!(hits("/^(copy-build|build-.*)$/"), ["copy-build"]);
        assert_eq!(hits("/build/"), ["build", "build:js", "build:css", "copy-build", "prebuild"]);
        assert_eq!(hits("/^build$/"), ["build"]);
        assert_eq!(hits("/^[bt][a-z]+$/"), ["build", "test"]);
        assert_eq!(hits("/^build:(js|css)?$/"), ["build:js", "build:css"]);
        assert!(ScriptPattern::of("build").is_none(), "a plain name is no pattern");
    }

    #[test]
    fn a_hostile_script_pattern_runs_in_linear_time() {
        // Exponential on a backtracking engine; a set of states takes them in stride.
        let long = format!("{}!", "a".repeat(10_000));
        let start = std::time::Instant::now();
        for pat in ["/^(a+)+$/", "/^(a|a)*$/", "/^(a*)*b$/", "/((a?)*)*c/"] {
            assert!(!ScriptPattern::of(pat).unwrap().unwrap().matches(&long), "{pat}");
        }
        assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
        for (pat, why) in [
            ("/a{1,9}/", "counted repeats"),
            ("/(a)\\1/", "backreferences"),
            ("/(?=a)/", "lookaround"),
            ("/a**/", "a repeat of a repeat"),
            ("/(a/", "unclosed ("),
            ("/[a/", "unclosed ["),
            ("/a^b/", "only at the start or end"),
        ] {
            let err = ScriptPattern::of(pat).unwrap().err().unwrap_or_default();
            assert!(err.contains(why), "{pat}: {err}");
        }
        assert!(ScriptPattern::of(&format!("/{}/", "a".repeat(300))).unwrap().is_err());
        assert!(ScriptPattern::of(&format!("/{}{}/", "(".repeat(40), ")".repeat(40))).unwrap().is_err());
    }
}
