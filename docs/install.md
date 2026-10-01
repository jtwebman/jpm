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
puts `jpm` and `jpx` in `~/.jpm/bin`. `JPM_VERSION=v0.1.0` picks a release and `JPM_INSTALL`
another directory. Each platform has its own build:

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
