//! Linux: hardlinks file by file, and the C library read off the loader that is installed.

pub use super::unix::{
    alive, clone_dir, exec, leave_interrupts_to_children, links_to, on_interrupt, read_link, symlink_dir, vt,
};

/// `SSL_CERT_FILE`, else the distribution's bundle: Debian and Alpine, then Fedora, then SUSE.
pub fn system_roots() -> Vec<Vec<u8>> {
    let named = std::env::var_os("SSL_CERT_FILE").map(std::path::PathBuf::from);
    let known = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem"];
    let Some(pem) = named.into_iter().chain(known.iter().map(Into::into)).find_map(|f| std::fs::read(f).ok()) else {
        return Vec::new();
    };
    // Leniently: a bundle entry jpm cannot read is left out, not an error for every install.
    let text = String::from_utf8_lossy(&pem);
    text.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|block| block.split("-----END CERTIFICATE-----").next())
        .map(crate::util::from_base64)
        .filter(|der| !der.is_empty())
        .collect()
}

/// musl's loader is `/lib/ld-musl-<arch>.so.1`; a system without one is glibc. Read off the
/// system, not this binary: the static musl build runs on glibc systems too.
pub fn libc() -> Option<&'static str> {
    let musl = std::fs::read_dir("/lib")
        .map(|dir| dir.flatten().any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-")))
        .unwrap_or(false);
    Some(if musl { "musl" } else { "glibc" })
}

/// glibc's malloc keeps an arena per thread, up to eight per core, and each holds on to what was
/// freed in it: an install's forty-odd threads (downloads, writers, the walk) put nuxt's peak at
/// 42 MB from a lockfile, where one arena per core holds it to 26 MB for the same CPU. A
/// `MALLOC_ARENA_MAX` the user set is left to glibc; the musl build's malloc has no arenas.
pub fn cap_malloc_arenas() {
    #[cfg(target_env = "gnu")]
    if let Some(n) = arena_cap(std::env::var_os("MALLOC_ARENA_MAX").is_some(), crate::pool::disk_threads()) {
        // SAFETY: mallopt only sets the limit malloc reads when it next makes an arena.
        unsafe { libc::mallopt(libc::M_ARENA_MAX, n) };
    }
}

/// One arena per core, unless the environment names a limit.
#[cfg(target_env = "gnu")]
fn arena_cap(named: bool, cores: usize) -> Option<libc::c_int> {
    (!named).then(|| libc::c_int::try_from(cores).unwrap_or(libc::c_int::MAX))
}

#[cfg(all(test, target_env = "gnu"))]
mod tests {
    #[test]
    fn caps_arenas_at_the_cores_unless_the_environment_does() {
        assert_eq!(super::arena_cap(false, 4), Some(4));
        assert_eq!(super::arena_cap(true, 4), None);
        assert_eq!(super::arena_cap(false, usize::MAX), Some(libc::c_int::MAX));
        // Setting it is harmless at any point: later allocations still work.
        super::cap_malloc_arenas();
        let v: Vec<Vec<u8>> = std::thread::scope(|s| {
            (0..8)
                .map(|i| s.spawn(move || vec![i; 1 << 16]))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        assert!(v.iter().enumerate().all(|(i, b)| b.len() == 1 << 16 && b[0] == i as u8));
    }
}
