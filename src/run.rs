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
    let (key, path) = with_path(dirs);
    #[cfg(windows)]
    let mut command = {
        use std::os::windows::process::CommandExt;
        let comspec = std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into());
        let mut c = Command::new(comspec);
        c.args(["/d", "/s", "/c"]).raw_arg(format!("\"{line}\""));
        c
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut c = Command::new("sh");
        c.args(["-c", line]);
        c
    };
    command.current_dir(cwd).env(key, path);
    hoist_env(&mut command, project);
    command
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
    crate::sys::leave_interrupts_to_children();
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
}
