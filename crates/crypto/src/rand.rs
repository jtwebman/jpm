//! The operating system's random numbers: getrandom(2) on Linux, getentropy(3) on macOS,
//! BCryptGenRandom on Windows. Without them jpm aborts.
//!
//! On Linux it is the system call, not glibc's wrapper: the release is built against glibc 2.17,
//! which has none (2.25 added it). A kernel older than 3.17, which has no such call, gets
//! /dev/urandom instead.

/// Fills `buf` with random bytes from the operating system. Aborts if it cannot.
pub fn fill(buf: &mut [u8]) {
    if !os_fill(buf) {
        std::process::abort();
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn os_fill(mut buf: &mut [u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: the pointer and length describe `buf`, which the kernel only writes into.
        let n = unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), 0) };
        if n < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ENOSYS) => return urandom(buf),
                _ => return false,
            }
        }
        // Reads over 32 MiB, or interrupted ones, may come back short.
        buf = &mut buf[n as usize..];
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn urandom(buf: &mut [u8]) -> bool {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).is_ok()
}

#[cfg(target_os = "macos")]
fn os_fill(buf: &mut [u8]) -> bool {
    // getentropy takes at most 256 bytes a call.
    buf.chunks_mut(256).all(|chunk| {
        // SAFETY: the pointer and length describe `chunk`, which is at most 256 bytes.
        unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) == 0 }
    })
}

#[cfg(windows)]
fn os_fill(buf: &mut [u8]) -> bool {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(alg: *mut core::ffi::c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
    }

    // The length is a u32, so ask in pieces no longer than that.
    buf.chunks_mut(u32::MAX as usize).all(|chunk| {
        // SAFETY: a null algorithm handle is allowed with BCRYPT_USE_SYSTEM_PREFERRED_RNG; the
        // pointer and length describe `chunk`.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        status >= 0
    })
}

#[cfg(test)]
mod tests {
    use super::fill;

    #[test]
    fn fills_every_size() {
        for n in [0, 1, 255, 256, 257, 100_000] {
            let mut a = vec![0u8; n];
            let mut b = vec![0u8; n];
            fill(&mut a);
            fill(&mut b);
            if n >= 16 {
                assert!(a.iter().any(|&x| x != 0), "{n} bytes all zero");
                assert_ne!(a, b, "{n} bytes repeated");
            }
        }
    }

    #[test]
    fn differs_across_calls() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let mut x = [0u8; 16];
            fill(&mut x);
            assert!(seen.insert(x));
        }
    }

    /// Every byte of a large buffer gets written: none of 64 fills leaves a byte at zero
    /// in all of them.
    #[test]
    fn writes_every_byte() {
        let mut or = vec![0u8; 4096];
        for _ in 0..64 {
            let mut x = vec![0u8; 4096];
            fill(&mut x);
            for (o, x) in or.iter_mut().zip(&x) {
                *o |= x;
            }
        }
        assert!(or.iter().all(|&o| o != 0));
    }

    /// The fallback for kernels without getrandom(2) fills as the system call does.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn urandom_fills() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        assert!(super::urandom(&mut a) && super::urandom(&mut b));
        assert_ne!(a, b);
    }
}
