//! A bin on Windows, as `cmd-shim` writes one for npm and pnpm: `<name>.cmd` for cmd,
//! `<name>.ps1` for PowerShell and `<name>` for Git Bash, each running the program the target's
//! `#!` line names. Compiled everywhere so it is tested everywhere; only Windows links with it.

use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};

/// A file's first bytes, enough for a `#!` line.
pub fn read_head(file: &Path) -> Option<String> {
    let mut buf = [0u8; 1024];
    let n = std::fs::File::open(file).ok()?.read(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// The program and its arguments: the `#!` line's, by name alone, `/usr/bin/node` being `node`
/// on PATH. Without one, a `.js` file is node's; anything else runs itself.
fn program_of(path: &str, head: Option<&str>) -> Option<(String, String)> {
    let line = head.unwrap_or("").trim_start().lines().next().unwrap_or("").trim_end_matches('\r');
    if let Some(rest) = line.strip_prefix("#!") {
        let mut words: Vec<&str> = rest.split_whitespace().collect();
        if words.first().is_some_and(|w| w.ends_with("/env")) {
            words.remove(0);
            if words.first() == Some(&"-S") {
                words.remove(0);
            }
            while words.first().is_some_and(|w| w.contains('=')) {
                words.remove(0);
            }
        }
        if let Some((prog, args)) = words.split_first() {
            let prog = prog.rsplit('/').next().unwrap_or(prog);
            return Some((prog.to_string(), args.join(" ")));
        }
    }
    let lower = path.to_ascii_lowercase();
    (lower.ends_with(".js") || lower.ends_with(".cjs") || lower.ends_with(".mjs"))
        .then(|| ("node".into(), String::new()))
}

/// The three shims for a bin whose file is `target`, spelled from `.bin`: suffix and text.
pub fn shims_of(target: &str, head: Option<&str>) -> Result<Vec<(&'static str, String)>> {
    let path = target.replace('\\', "/");
    // A lockfile can name the target, and a shim is a script: what its quotes cannot hold would
    // run. Only what every shell's double quotes keep literal is let in: not `"%$`!`, and not the
    // smart quotes U+2018-U+201F, which PowerShell also reads as quotes.
    if !path.chars().all(|c| c.is_alphanumeric() || " -_./@+~,=#():'".contains(c)) {
        return Err(Error::new("EBIN", format!("refusing to shim a bin at {target:?}: it cannot be quoted")));
    }
    let program = program_of(&path, head);
    let run = program.as_ref().map(|(p, a)| if a.is_empty() { format!("\"{p}\"") } else { format!("\"{p}\" {a}") });
    let cmd_path = format!("\"%dp0%\\{}\"", path.replace('/', "\\"));
    let cmd_run = match &run {
        Some(run) => format!(
            "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & set PATHEXT=%PATHEXT:;.JS;=;% & {run} {cmd_path} %*"
        ),
        None => format!("{cmd_path} %*"),
    };
    let cmd = [
        "@ECHO off",
        "GOTO start",
        ":find_dp0",
        "SET dp0=%~dp0",
        "EXIT /b",
        ":start",
        "SETLOCAL",
        "CALL :find_dp0",
        &cmd_run,
        "",
    ]
    .join("\r\n");
    let sh_run = match &run {
        Some(run) => format!("exec {run} \"$basedir_win/{path}\" \"$@\""),
        None => format!("exec \"$basedir/{path}\" \"$@\""),
    };
    let sh = [
        "#!/bin/sh",
        "basedir=$(dirname \"$(echo \"$0\" | sed -e 's,\\\\,/,g')\")",
        "basedir_win=\"$basedir\"",
        "case `uname` in",
        "  *CYGWIN*|*MINGW*|*MSYS*)",
        "    if command -v cygpath > /dev/null 2>&1; then",
        "      basedir_win=`cygpath -w \"$basedir\"`",
        "    fi",
        "  ;;",
        "esac",
        &sh_run,
        "",
    ]
    .join("\n");
    // `node.exe`, not `node`: PowerShell would take a `node.ps1` on PATH first.
    let ps1_run = program.map(|(p, a)| if a.is_empty() { format!("\"{p}$exe\"") } else { format!("\"{p}$exe\" {a}") });
    let ps1_line = format!("{} \"$basedir/{path}\" $args", ps1_run.map_or("&".to_string(), |r| format!("& {r}")));
    let ps1 = [
        "#!/usr/bin/env pwsh",
        "$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent",
        "$exe=\"\"",
        "if ($PSVersionTable.PSVersion -lt \"6.0\" -or $IsWindows) {",
        "  $exe=\".exe\"",
        "}",
        "if ($MyInvocation.ExpectingInput) {",
        &format!("  $input | {ps1_line}"),
        "} else {",
        &format!("  {ps1_line}"),
        "}",
        "exit $LASTEXITCODE",
        "",
    ]
    .join("\n");
    Ok(vec![("", sh), (".cmd", cmd), (".ps1", ps1)])
}

/// Whether cmd.exe runs `word` as a batch file (a bin's `.cmd` shim), whose `%*` reads the
/// arguments a second time. Looked up as the shell will: in `cwd`, then `first` (the `.bin`
/// directories put ahead on the child's PATH), then PATH.
pub fn is_batch(word: &str, cwd: &Path, first: &[std::path::PathBuf]) -> bool {
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into()).to_ascii_lowercase();
    let exts: Vec<&str> = pathext.split(';').filter(|e| !e.is_empty()).collect();
    let lower = word.to_ascii_lowercase();
    let names: Vec<String> = if exts.iter().any(|e| lower.ends_with(e)) {
        vec![word.to_string()]
    } else {
        exts.iter().map(|e| format!("{word}{e}")).collect()
    };
    let mut dirs = vec![cwd.to_path_buf()];
    if !word.contains(['/', '\\']) {
        dirs.extend(first.iter().cloned());
        dirs.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    }
    for dir in dirs {
        for name in &names {
            if dir.join(name).is_file() {
                let n = name.to_ascii_lowercase();
                return n.ends_with(".bat") || n.ends_with(".cmd");
            }
        }
    }
    false
}

/// The first word of a command line, unquoted.
pub fn first_word(line: &str) -> String {
    let line = line.trim_start();
    let mut out = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => break,
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shims_node_bins() {
        let shims = shims_of("../pkg/cli.js", Some("#!/usr/bin/env node\nx")).unwrap();
        assert!(shims[1].1.contains("& \"node\" \"%dp0%\\..\\pkg\\cli.js\" %*"));
        assert!(shims[0].1.contains("exec \"node\" \"$basedir_win/../pkg/cli.js\" \"$@\""));
        assert!(shims[2].1.contains("& \"node$exe\" \"$basedir/../pkg/cli.js\" $args"));
    }

    #[test]
    fn reads_env_shebangs() {
        assert_eq!(program_of("x", Some("#!/usr/bin/env -S node --flag")), Some(("node".into(), "--flag".into())));
        assert_eq!(program_of("x", Some("#!/bin/sh -e")), Some(("sh".into(), "-e".into())));
        assert_eq!(program_of("x.mjs", None), Some(("node".into(), String::new())));
        assert_eq!(program_of("x.exe", None), None);
    }

    #[test]
    fn refuses_unquotable_targets() {
        for bad in ["a%b", "a\"b", "a$b", "a`b", "a!b", "a\nb", "a\u{2018}b", "a\u{201c}b", "a\u{201f}b"] {
            assert!(shims_of(bad, None).is_err(), "{bad:?}");
        }
        let injected = "../pkg/x\u{201d}; Write-Output INJECTED; & \u{201c}y.js";
        assert!(shims_of(injected, Some("#!/usr/bin/env node")).is_err());
        assert!(shims_of("C:/Users/Jo O'Neil (x86)/.jpm/@s+a@1.0.0/node_modules/a/bin/cli-x_1.js", None).is_ok());
    }

    #[test]
    fn finds_the_first_word() {
        assert_eq!(first_word("  \"my prog\" -x"), "my prog");
        assert_eq!(first_word("eslint ."), "eslint");
    }
}
