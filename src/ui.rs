//! What a person sees: progress and warnings on stderr, colored only for a terminal that takes
//! color, and `NO_COLOR` / `FORCE_COLOR` decide over that.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

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
    if color(tty) { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
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
        Level::Info => format!("{} {message}", paint(GRAY, "jpm:", false)),
        Level::Warn => format!("{} {}", paint(YELLOW, "jpm:", false), paint(YELLOW, message, false)),
    };
    let _ = writeln!(std::io::stderr(), "{line}");
}

pub fn info(message: &str) {
    note(message, Level::Info);
}

pub fn warn(message: &str) {
    note(message, Level::Warn);
}

pub fn error(message: &str) {
    let _ = writeln!(std::io::stderr(), "{} {}", paint(RED_BOLD, "jpm:", false), paint("31", message, false));
}

/// Print to stdout; a reader that left (`| head`) is not a failure.
pub fn out(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
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
