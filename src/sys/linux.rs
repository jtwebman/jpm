//! Linux: hardlinks file by file, and the C library read off the loader that is installed.

pub use super::unix::{alive, clone_dir, exec, leave_interrupts_to_children, links_to, read_link, symlink_dir};

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
/// system, not this binary, which is static and would say musl on any machine.
pub fn libc() -> Option<&'static str> {
    let musl = std::fs::read_dir("/lib")
        .map(|dir| dir.flatten().any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-")))
        .unwrap_or(false);
    Some(if musl { "musl" } else { "glibc" })
}
