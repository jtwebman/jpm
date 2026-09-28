//! One error type for the whole crate: a stable `code` a caller can match on, and a message
//! for people. Codes follow npm's `E…` convention so scripts written against npm or upm keep
//! working.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// The same error with `what` said first: which edge, file or url it was about.
    #[must_use]
    pub fn context(mut self, what: impl fmt::Display) -> Self {
        self.message = format!("{what}: {}", self.message);
        self
    }

    /// The same error under another code.
    #[must_use]
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }

    /// An I/O error, keeping the OS's own code (`ENOENT`) where it has one.
    pub fn io(error: &std::io::Error, what: impl fmt::Display) -> Self {
        Self::new(io_code(error), format!("{what}: {error}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for Error {}

pub fn io_code(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match error.kind() {
        NotFound => "ENOENT",
        PermissionDenied => "EACCES",
        AlreadyExists => "EEXIST",
        DirectoryNotEmpty => "ENOTEMPTY",
        NotADirectory => "ENOTDIR",
        CrossesDevices => "EXDEV",
        TimedOut => "ETIMEDOUT",
        _ => "EIO",
    }
}
