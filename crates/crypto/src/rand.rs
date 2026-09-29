//! The operating system's random numbers: getrandom(2) on Linux, getentropy(3) on macOS,
//! BCryptGenRandom on Windows. There is no fallback; without them jpm aborts.

pub fn fill(buf: &mut [u8]) {
    todo!("{}", buf.len())
}
