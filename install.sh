#!/bin/sh
# Install jpm: curl -fsSL https://getjpm.sh | sh
# JPM_VERSION picks a release (default: latest); JPM_INSTALL moves it (default: ~/.jpm/bin);
# JPM_LIBC=glibc or musl picks the Linux build (default: the system's).
set -eu

# All in a function called on the last line: a download cut short runs nothing.
main() {
  repo="jtwebman/jpm"
  dir="${JPM_INSTALL:-$HOME/.jpm/bin}"

  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) echo "jpm: no build for $(uname -s); use install.ps1 on Windows" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) cpu=x64 ;;
    arm64 | aarch64) cpu=arm64 ;;
    armv7l | armv8l) cpu=armv7 ;;
    *) echo "jpm: no build for $(uname -m)" >&2; exit 1 ;;
  esac
  # A shell under Rosetta reports x86_64 on an arm64 Mac: take the native build.
  if [ "$os" = darwin ] && [ "$cpu" = x64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    cpu=arm64
  fi

  asset="jpm-$os-$cpu"
  # Linux has a glibc build and a static musl one. glibc 2.17 or later, as getconf reports it, takes
  # the glibc build; anything else (musl, as on Alpine, or an older glibc) the static one, which runs
  # anywhere. getconf, not a look for musl's loader: Debian's musl package installs one beside glibc.
  # JPM_LIBC=glibc or musl decides instead.
  if [ "$os" = linux ]; then
    libc="${JPM_LIBC:-}"
    if [ -z "$libc" ]; then
      v="$(getconf GNU_LIBC_VERSION 2>/dev/null | sed -n 's/^glibc 2\.\([0-9]*\).*/\1/p')"
      if [ -n "$v" ] && [ "$v" -ge 17 ]; then libc=glibc; else libc=musl; fi
    fi
    case "$libc" in
      glibc | gnu) ;;
      musl) asset="$asset-musl" ;;
      *) echo "jpm: JPM_LIBC must be glibc or musl, not $libc" >&2; exit 1 ;;
    esac
  fi
  if [ -n "${JPM_VERSION:-}" ]; then
    # A tag's name: no `/` to lead the url to another repository's release.
    case "$JPM_VERSION" in
      *[!A-Za-z0-9._+-]*) echo "jpm: JPM_VERSION must be a release tag, such as v0.1.0, not $JPM_VERSION" >&2; exit 1 ;;
    esac
    base="https://github.com/$repo/releases/download/$JPM_VERSION"
  else
    base="https://github.com/$repo/releases/latest/download"
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "jpm: downloading $asset"
  curl -fsSL --proto =https --proto-redir =https --tlsv1.2 "$base/$asset" -o "$tmp/jpm"
  curl -fsSL --proto =https --proto-redir =https --tlsv1.2 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"

  want="$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
  if command -v sha256sum >/dev/null 2>&1; then
    have="$(sha256sum "$tmp/jpm" | cut -d' ' -f1)"
  else
    have="$(shasum -a 256 "$tmp/jpm" | cut -d' ' -f1)"
  fi
  if [ -z "$want" ] || [ "$want" != "$have" ]; then
    echo "jpm: checksum mismatch for $asset" >&2
    exit 1
  fi

  mkdir -p "$dir"
  chmod +x "$tmp/jpm"
  mv "$tmp/jpm" "$dir/jpm"
  ln -sf jpm "$dir/jpx"
  echo "jpm: installed $("$dir/jpm" --version) to $dir/jpm"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "jpm: add $dir to your PATH, for example: echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
  esac
}

main "$@"
