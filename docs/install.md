# Install

```sh
curl -fsSL https://getjpm.sh | sh                  # macOS and Linux
```

```powershell
irm https://getjpm.sh/install.ps1 | iex              # Windows
```

Where security software stops a script piped into `iex`, download it and run it as a file:
`irm https://getjpm.sh/install.ps1 -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File install.ps1`.

The script downloads the binary for your platform from the
[latest release](https://github.com/jtwebman/jpm/releases/latest), checks its SHA-256, and
puts `jpm` and `jpx` in `~/.jpm/bin`. `JPM_VERSION=v1.0.0` picks a release and `JPM_INSTALL`
another directory. A release candidate is a pre-release, never the latest: the script installs
one only when `JPM_VERSION` names it. Each script puts the directory on your `PATH`: on Windows
in your user `PATH`, for new terminals and the one it ran in; on macOS and Linux with a line in
your shell's startup file (`~/.zshrc`, `~/.bashrc`, `~/.bash_profile` on macOS, `~/.profile`, or
fish's `conf.d/jpm.fish`), added once. `JPM_NO_MODIFY_PATH=1` leaves both alone and says how
to add it instead. The SHA-256 comes from the `SHA256SUMS` of the same release, so it catches a
download cut short or corrupted, not a release whose files were replaced: for that, see
[Verifying a release](#verifying-a-release). Each platform has its own build:

| Platform          | Release asset           | Target                                       |
| ----------------- | ----------------------- | -------------------------------------------- |
| Linux x64         | `jpm-linux-x64`         | `x86_64-unknown-linux-gnu` (glibc 2.17)      |
| Linux arm64       | `jpm-linux-arm64`       | `aarch64-unknown-linux-gnu` (glibc 2.17)     |
| Linux armv7       | `jpm-linux-armv7`       | `armv7-unknown-linux-gnueabihf` (glibc 2.17) |
| Linux x64, musl   | `jpm-linux-x64-musl`    | `x86_64-unknown-linux-musl`                  |
| Linux arm64, musl | `jpm-linux-arm64-musl`  | `aarch64-unknown-linux-musl`                 |
| Linux armv7, musl | `jpm-linux-armv7-musl`  | `armv7-unknown-linux-musleabihf`             |
| macOS x64         | `jpm-darwin-x64`        | `x86_64-apple-darwin`                        |
| macOS arm64       | `jpm-darwin-arm64`      | `aarch64-apple-darwin`                       |
| Windows x64       | `jpm-windows-x64.exe`   | `x86_64-pc-windows-msvc`                     |
| Windows arm64     | `jpm-windows-arm64.exe` | `aarch64-pc-windows-msvc`                    |

The plain Linux builds link against glibc 2.17, so they run on CentOS 7, Debian 8, Ubuntu 14.04
and anything newer, and need nothing else from the system. The `-musl` builds are static, for
Alpine and other systems without glibc; they run anywhere, but musl's allocator makes a large
install 12-25% slower, with 14-35% more CPU (nuxt and next, from a lockfile and without one).
install.sh takes the glibc build where `getconf` reports glibc 2.17 or later and the musl build
otherwise; `JPM_LIBC=musl` or `JPM_LIBC=glibc` picks one. Tests run on Linux x64, Windows x64
and macOS arm64.

Or build it:

```sh
cargo build --release    # target/release/jpm
```

## Verifying a release

Every file of a release (each binary, `install.sh`, `install.ps1`, `LICENSE`,
`THIRD_PARTY_NOTICES.md` and `SHA256SUMS`) has a signed
[build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations):
a record, signed through Sigstore with a certificate GitHub Actions issues and logged in Sigstore's
public transparency log, that the file with that SHA-256 was built by
[`release.yml`](../.github/workflows/release.yml) in `jtwebman/jpm` from a `v*` tag. Someone who
replaced a release's files, and its `SHA256SUMS` with them, cannot make these. Checking one takes
the [GitHub CLI](https://cli.github.com) 2.49 or later, signed in (`gh auth login`).

**The install scripts do not check attestations.** They check the SHA-256 against `SHA256SUMS`
only, which a replaced release would replace too. Checking provenance would need `gh`, which most
machines do not have, and an installer that checks only where it can would pass the same
tampered release elsewhere, so they leave it to you. Check the binary the script installed:

```sh
gh attestation verify ~/.jpm/bin/jpm --repo jtwebman/jpm                    # macOS and Linux
```

```powershell
gh attestation verify $HOME\.jpm\bin\jpm.exe --repo jtwebman/jpm            # Windows
```

Or download and check the files yourself before running anything. Set the version and the asset
for your platform (the table above):

Linux:

```sh
gh release download v1.0.0 --repo jtwebman/jpm --pattern jpm-linux-x64
gh attestation verify jpm-linux-x64 --repo jtwebman/jpm
chmod +x jpm-linux-x64 && mkdir -p ~/.jpm/bin && mv jpm-linux-x64 ~/.jpm/bin/jpm
ln -sf jpm ~/.jpm/bin/jpx
```

macOS:

```sh
gh release download v1.0.0 --repo jtwebman/jpm --pattern jpm-darwin-arm64
gh attestation verify jpm-darwin-arm64 --repo jtwebman/jpm
chmod +x jpm-darwin-arm64 && mkdir -p ~/.jpm/bin && mv jpm-darwin-arm64 ~/.jpm/bin/jpm
ln -sf jpm ~/.jpm/bin/jpx
```

curl and gh download without macOS's quarantine mark. A browser adds it, and macOS then refuses
to open the binary, which is not notarized: `xattr -d com.apple.quarantine ~/.jpm/bin/jpm` takes
the mark off once you have checked the file as above.

Windows (PowerShell):

```powershell
gh release download v1.0.0 --repo jtwebman/jpm --pattern jpm-windows-x64.exe
gh attestation verify jpm-windows-x64.exe --repo jtwebman/jpm
New-Item -ItemType Directory -Force "$HOME\.jpm\bin" | Out-Null; Move-Item -Force jpm-windows-x64.exe "$HOME\.jpm\bin\jpm.exe"
```

To check the install script itself before running it (it then installs the latest release):

```sh
gh release download --repo jtwebman/jpm --pattern install.sh
gh attestation verify install.sh --repo jtwebman/jpm && sh install.sh
```

```powershell
gh release download --repo jtwebman/jpm --pattern install.ps1
gh attestation verify install.ps1 --repo jtwebman/jpm; if ($?) { powershell -ExecutionPolicy Bypass -File install.ps1 }
```

`gh attestation verify` exits non-zero, and prints why, when a file has no attestation from
`jtwebman/jpm` or its signature does not check out; don't run a file that fails. To also require
the release workflow and the tag you meant, add
`--signer-workflow jtwebman/jpm/.github/workflows/release.yml --source-ref refs/tags/v1.0.0`.
`SHA256SUMS` is attested too: once it verifies, the sums in it vouch for every other file of the
release.
