# Development

```sh
cargo test --workspace           # unit tests and end-to-end tests against a local registry
cargo build --release            # built for size, the CPU-heavy crates for speed
cargo build --profile fast       # every crate at full speed, for comparing
```

Platform-specific code lives in `src/sys/`, one file per OS; only the target's file is
compiled.

The git tests use bare repositories on disk and a local server for GitHub's archives, through
two switches meant for tests only: `JPM_GIT_ALLOW_FILE=1` lets git fetch `file://` urls, and
`JPM_CODELOAD_URL` replaces `https://codeload.github.com`. The runtime tests serve real Node
release signatures and keys (`tests/fixtures/node`) from a local server, which
`JPM_NODE_KEYS_URL` points jpm at in place of nodejs/release-keys; a key is still used only when
its fingerprint is one jpm carries.

jpm has its own TLS and cryptography, in three crates:

- `crates/crypto` (`jpm-crypto`): SHA-1/2, HMAC, HKDF, AES-GCM and ChaCha20-Poly1305, built for
  speed. It uses the CPU's AES, carry-less multiply and SHA instructions where it has them and
  constant-time portable code where it does not.
- `crates/pk` (`jpm-pk`): X25519, P-256, P-384 and RSA signature checks, built for size: they
  run a few times per connection, not per byte. Ed25519 checks too, for Node's release keys.
- Both are tested against RFC and NIST vectors, the Wycheproof suites, and ring on random
  inputs.
- `crates/tls` (`jpm-tls`): a TLS 1.3 and 1.2 client (ECDHE and AEAD suites only) and Web PKI
  certificate checks, with Mozilla's roots from `webpki-roots`. Tested against rustls-webpki
  and the x509-limbo suite, against rustls and OpenSSL servers, and with a scripted server
  that sends every kind of bad message.

The tests that need the network are ignored by default:
`cargo test -p jpm-tls --release --test live -- --ignored` (registries and badssl.com), and
`--test openssl` for OpenSSL interop, which needs the `openssl` command.
