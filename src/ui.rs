//! What a person sees: progress and warnings on stderr, colored only for a terminal that takes
//! color, and `NO_COLOR` / `FORCE_COLOR` decide over that.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

static QUIET: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Progress: dropped under `--silent`.
    Info,
    /// Wants a person's attention.
    Warn,
}

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

fn color(stream_is_tty: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if let Some(v) = std::env::var_os("FORCE_COLOR") {
        return v != "0" && v != "false";
    }
    stream_is_tty && std::env::var("TERM").map_or(!cfg!(unix), |t| t != "dumb")
}

pub fn paint(code: &str, text: &str, stdout: bool) -> String {
    let tty = if stdout { std::io::stdout().is_terminal() } else { std::io::stderr().is_terminal() };
    let text = clean(text);
    if color(tty) { format!("\x1b[{code}m{text}\x1b[0m") } else { text.into_owned() }
}

/// Text from a registry or a package, safe for a terminal: each control character but a line
/// break and a tab (C0, DEL and C1) written out as `\u{1b}`, so none can set the clipboard, the
/// title or a link, or move the cursor over what jpm printed.
pub fn clean(text: &str) -> std::borrow::Cow<'_, str> {
    let bad = |c: char| c.is_control() && c != '\n' && c != '\t';
    if !text.chars().any(bad) {
        return text.into();
    }
    // A script's `\r\n` is a line break.
    let text = text.replace("\r\n", "\n");
    text.chars().map(|c| if bad(c) { c.escape_unicode().to_string() } else { c.to_string() }).collect()
}

/// `clean`, keeping the colors `paint` writes (`ESC [ digits m`): stdout's text is built with them.
fn clean_keeping_color(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\x1b') {
        out.push_str(&clean(&rest[..at]));
        let sgr = rest[at + 1..]
            .strip_prefix('[')
            .and_then(|a| a.find(|c: char| !c.is_ascii_digit() && c != ';').filter(|end| a[*end..].starts_with('m')));
        let len = sgr.map_or(0, |end| end + 3); // ESC, `[`, the digits, `m`
        out.push_str(if len > 0 { &rest[at..at + len] } else { "\\u{1b}" });
        rest = &rest[at + len.max(1)..];
    }
    out.push_str(&clean(rest));
    out
}

pub const GRAY: &str = "90";
pub const GREEN: &str = "32";
pub const YELLOW: &str = "33";
pub const RED_BOLD: &str = "1;31";
pub const CYAN: &str = "36";
pub const BOLD: &str = "1";

pub fn note(message: &str, level: Level) {
    let line = match level {
        Level::Info if quiet() => return,
        Level::Info => format!("{} {}", paint(GRAY, "jpm:", false), clean(message)),
        Level::Warn => format!("{} {}", paint(YELLOW, "jpm:", false), paint(YELLOW, message, false)),
    };
    let mut screen = screen();
    let erase = screen.as_mut().map_or("", Screen::hide);
    let _ = writeln!(std::io::stderr(), "{erase}{line}");
}

pub fn info(message: &str) {
    note(message, Level::Info);
}

pub fn warn(message: &str) {
    note(message, Level::Warn);
}

pub fn error(message: &str) {
    let mut screen = screen();
    let _ = write!(std::io::stderr(), "{}", screen.as_mut().map_or("", Screen::hide));
    let _ = writeln!(std::io::stderr(), "{} {}", paint(RED_BOLD, "jpm:", false), paint("31", message, false));
}

/// Print to stdout; a reader that left (`| head`) is not a failure. No escape sequence but
/// `paint`'s colors gets through.
pub fn out(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(clean_keeping_color(text).as_bytes());
    let _ = stdout.flush();
}

/// `JPM_PHASES=1`: milliseconds since start at each named phase, on stderr.
pub fn phase(name: &str) {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("JPM_PHASES").is_some()) {
        let _ = writeln!(
            std::io::stderr(),
            "phase {name} {}ms",
            START.get_or_init(std::time::Instant::now).elapsed().as_millis()
        );
    }
}

pub static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

// --- install progress -----------------------------------------------------------------------

/// What an install has done so far, counted as it goes; `Progress` draws it.
pub static RESOLVED: AtomicUsize = AtomicUsize::new(0);
pub static FETCHED: AtomicUsize = AtomicUsize::new(0);
pub static TO_FETCH: AtomicUsize = AtomicUsize::new(0);
pub static LINKED: AtomicUsize = AtomicUsize::new(0);
pub static TO_LINK: AtomicUsize = AtomicUsize::new(0);

pub fn count(counter: &AtomicUsize, n: usize) {
    counter.fetch_add(n, Ordering::Relaxed);
}

fn counts() -> [usize; 5] {
    [&RESOLVED, &FETCHED, &TO_FETCH, &LINKED, &TO_LINK].map(|c| c.load(Ordering::Relaxed))
}

static NO_PROGRESS: AtomicBool = AtomicBool::new(false);

/// `--json` and `--no-progress`.
pub fn set_no_progress(off: bool) {
    NO_PROGRESS.store(off, Ordering::Relaxed);
}

/// Redraws are at least this far apart, and the first waits this long: an install done by then
/// draws nothing.
const TICK: Duration = Duration::from_millis(100);
const ERASE: &str = "\r\x1b[K";
/// What Ctrl+C leaves: no line, and no progress on the terminal's tab.
const UNDO: &str = "\r\x1b[K\x1b]9;4;0\x1b\\";

/// The progress line and the terminal's progress report (OSC 9;4) on screen now.
#[derive(Debug, Default)]
struct Screen {
    osc: bool,
    line: String,
    report: String,
    /// Ctrl+C takes them off.
    armed: bool,
}

/// `Some` while an install shows progress: other output takes the line off first.
static SCREEN: Mutex<Option<Screen>> = Mutex::new(None);

fn screen() -> std::sync::MutexGuard<'static, Option<Screen>> {
    SCREEN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `jpm: resolved 812, fetched 640/1203, linked 300/1203`, each part once it has begun.
fn line([resolved, fetched, to_fetch, linked, to_link]: [usize; 5]) -> String {
    let mut parts = Vec::new();
    if resolved > 0 {
        parts.push(format!("resolved {resolved}"));
    }
    if to_fetch > 0 {
        parts.push(format!("fetched {fetched}/{to_fetch}"));
    }
    if to_link > 0 {
        parts.push(format!("linked {linked}/{to_link}"));
    }
    if parts.is_empty() { String::new() } else { format!("jpm: {}", parts.join(", ")) }
}

/// Unknown while the tree is resolved and more is queued; then fetching and linking are half
/// each, or linking alone when nothing was queued to fetch.
fn percent([_, fetched, to_fetch, linked, to_link]: [usize; 5]) -> Option<usize> {
    if to_link == 0 {
        return None;
    }
    let link = linked.min(to_link) * 100 / to_link;
    Some(match (fetched.min(to_fetch) * 100).checked_div(to_fetch) {
        Some(fetch) => (fetch + link) / 2,
        None => link,
    })
}

/// OSC 9;4: `Some(Some(p))` is p percent, `Some(None)` busy with no known end, `None` off.
fn osc(state: Option<Option<usize>>) -> String {
    let state = match state {
        None => "0".to_string(),
        Some(None) => "3".to_string(),
        Some(Some(p)) => format!("1;{p}"),
    };
    format!("\x1b]9;4;{state}\x1b\\")
}

/// Terminals known to show OSC 9;4 on their tab or taskbar. Others may show any OSC 9 as a
/// desktop notification, so they get none.
fn takes_osc() -> bool {
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let program = var("TERM_PROGRAM");
    let version: Vec<u32> = var("TERM_PROGRAM_VERSION").split('.').take(2).map(|p| p.parse().unwrap_or(0)).collect();
    std::env::var_os("WT_SESSION").is_some()
        || var("ConEmuANSI") == "ON"
        || matches!(program.as_str(), "ghostty" | "WezTerm" | "vscode")
        || (program == "iTerm.app" && version >= vec![3, 6])
}

impl Screen {
    /// What to write to show `counts`: nothing when the screen shows them already.
    fn draw(&mut self, counts: [usize; 5]) -> String {
        let line = line(counts);
        let report = if self.osc { osc(Some(percent(counts))) } else { String::new() };
        if line == self.line && report == self.report {
            return String::new();
        }
        let mut out = if report == self.report { String::new() } else { report.clone() };
        out.push('\r');
        out.push_str(&line);
        out.push_str("\x1b[K");
        self.line = line;
        self.report = report;
        out
    }

    /// Takes the line off; the next tick draws it again.
    fn hide(&mut self) -> &'static str {
        if std::mem::take(&mut self.line).is_empty() { "" } else { ERASE }
    }

    /// Takes the line and the report off for good.
    fn clear(&mut self) -> String {
        let mut out = self.hide().to_string();
        if !std::mem::take(&mut self.report).is_empty() {
            out.push_str(&osc(None));
        }
        out
    }
}

/// The install's progress, drawn on stderr by a thread until dropped.
pub struct Progress {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
    write: fn(&str),
}

fn to_stderr(text: &str) {
    let _ = std::io::stderr().write_all(text.as_bytes());
}

/// Progress when a person is watching: stderr is a terminal that moves the cursor, not in CI,
/// not under `--silent`, `--json` or `--no-progress`.
pub fn progress() -> Option<Progress> {
    let ci = std::env::var_os("CI").is_some_and(|v| v != "false");
    let dumb = std::env::var_os("TERM").is_some_and(|t| t == "dumb");
    if quiet() || NO_PROGRESS.load(Ordering::Relaxed) || ci || dumb || !std::io::stderr().is_terminal() {
        return None;
    }
    // A Windows console that takes no escape sequences gets none.
    crate::sys::vt().then(|| start(takes_osc(), to_stderr))
}

fn start(osc: bool, write: fn(&str)) -> Progress {
    for c in [&RESOLVED, &FETCHED, &TO_FETCH, &LINKED, &TO_LINK] {
        c.store(0, Ordering::Relaxed);
    }
    *screen() = Some(Screen { osc, ..Screen::default() });
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let signal = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut stopped = signal.0.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            stopped = signal.1.wait_timeout_while(stopped, TICK, |s| !*s).unwrap_or_else(PoisonError::into_inner).0;
            if *stopped {
                return;
            }
            let mut screen = screen();
            let Some(s) = screen.as_mut() else { return };
            let text = s.draw(counts());
            if !text.is_empty() && !s.armed {
                crate::sys::on_interrupt(Some(if s.osc { UNDO } else { ERASE }));
                s.armed = true;
            }
            write(&text);
        }
    });
    Progress { stop, thread: Some(thread), write }
}

impl Drop for Progress {
    fn drop(&mut self) {
        *self.stop.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.stop.1.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let Some(mut s) = screen().take() else { return };
        (self.write)(&s.clear());
        if s.armed {
            crate::sys::on_interrupt(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_progress() {
        assert_eq!(line([0; 5]), "");
        assert_eq!(line([812, 0, 0, 0, 0]), "jpm: resolved 812");
        assert_eq!(line([812, 640, 1203, 300, 1203]), "jpm: resolved 812, fetched 640/1203, linked 300/1203");
        assert_eq!(line([0, 0, 0, 3, 10]), "jpm: linked 3/10");
        assert_eq!(percent([812, 640, 1203, 0, 0]), None, "still resolving");
        assert_eq!(percent([812, 1203, 1203, 0, 1203]), Some(50));
        assert_eq!(percent([0, 0, 0, 5, 10]), Some(50), "linking alone");
        assert_eq!(percent([0, 9, 4, 9, 4]), Some(100));
        assert_eq!(osc(Some(Some(42))), "\x1b]9;4;1;42\x1b\\");
        assert_eq!(osc(Some(None)), "\x1b]9;4;3\x1b\\");
        assert_eq!(osc(None), "\x1b]9;4;0\x1b\\");
    }

    #[test]
    fn writes_control_characters_out() {
        assert_eq!(clean("plain\tline\n"), "plain\tline\n");
        assert_eq!(clean("a\x1b]52;c;eA==\x07b"), "a\\u{1b}]52;c;eA==\\u{7}b");
        assert_eq!(clean("del\x7f c1\u{9b}2J ok\r\nnext\rover"), "del\\u{7f} c1\\u{9b}2J ok\nnext\\u{d}over");
        // stdout keeps paint's colors, and only those.
        let text = "\x1b[32mInstalled\x1b[0m x\x1b]8;;http://e\x1b\\y\x1b[2J\x1b[";
        assert_eq!(
            clean_keeping_color(text),
            "\x1b[32mInstalled\x1b[0m x\\u{1b}]8;;http://e\\u{1b}\\y\\u{1b}[2J\\u{1b}["
        );
    }

    #[test]
    fn draws_only_what_changed() {
        let mut s = Screen { osc: true, ..Screen::default() };
        assert_eq!(s.draw([5, 0, 0, 0, 0]), "\x1b]9;4;3\x1b\\\rjpm: resolved 5\x1b[K");
        assert_eq!(s.draw([5, 0, 0, 0, 0]), "", "the same counts are not drawn again");
        assert_eq!(s.draw([6, 0, 0, 0, 0]), "\rjpm: resolved 6\x1b[K", "the report is the same");
        assert_eq!(s.hide(), ERASE);
        assert_eq!(s.draw([6, 0, 0, 0, 0]), "\rjpm: resolved 6\x1b[K", "a hidden line comes back");
        assert_eq!(s.clear(), "\r\x1b[K\x1b]9;4;0\x1b\\");
        assert_eq!(s.clear(), "");
        let mut plain = Screen::default();
        assert_eq!(plain.draw([0, 0, 0, 1, 2]), "\rjpm: linked 1/2\x1b[K");
        assert_eq!(plain.clear(), ERASE);
    }

    static SINK: Mutex<String> = Mutex::new(String::new());

    fn sink(text: &str) {
        SINK.lock().unwrap().push_str(text);
    }

    #[test]
    fn draws_after_a_tick_and_clears() {
        // An install done within a tick draws nothing.
        drop(start(true, sink));
        assert_eq!(*SINK.lock().unwrap(), "");
        let p = start(true, sink);
        count(&RESOLVED, 3);
        std::thread::sleep(TICK * 3);
        drop(p);
        let out = SINK.lock().unwrap().clone();
        assert!(out.starts_with("\x1b]9;4;3\x1b\\\rjpm: resolved 3\x1b[K"), "{out:?}");
        assert!(out.ends_with("\r\x1b[K\x1b]9;4;0\x1b\\"), "{out:?}");
    }
}
