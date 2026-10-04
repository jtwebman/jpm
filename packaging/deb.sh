#!/bin/sh
# A .deb of one jpm binary for Debian and Ubuntu: /usr/bin/jpm, jpx beside it as a link, and the
# license and notices in /usr/share/doc/jpm.
#   packaging/deb.sh <binary> <amd64|arm64|armhf> <version> <out dir>
# The glibc builds need libc6 2.17 or later and nothing else (libpthread and libdl are libc6's).
# Run from the repository root: LICENSE and THIRD_PARTY_NOTICES.md are read from there.
set -eu

bin=$1 arch=$2 version=$3 out=$4
case "$arch" in
  amd64 | arm64 | armhf) ;;
  *) echo "deb.sh: no Debian architecture $arch" >&2; exit 1 ;;
esac
# Cargo's 1.0.0-rc.1 is Debian's 1.0.0~rc.1: a `~` sorts before the release, and a `-` would start
# a Debian revision.
deb_version=$(printf '%s' "$version" | tr - '~')

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 0755 "$root"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/jpm"
install -m 0755 "$bin" "$root/usr/bin/jpm"
ln -s jpm "$root/usr/bin/jpx"
install -m 0644 LICENSE "$root/usr/share/doc/jpm/copyright"
install -m 0644 THIRD_PARTY_NOTICES.md "$root/usr/share/doc/jpm/THIRD_PARTY_NOTICES.md"
size=$(du -sk "$root/usr" | cut -f1)

cat > "$root/DEBIAN/control" <<EOF
Package: jpm
Version: $deb_version
Architecture: $arch
Maintainer: JT Turner <jtwebman@gmail.com>
Installed-Size: $size
Depends: libc6 (>= 2.17)
Section: devel
Priority: optional
Homepage: https://getjpm.sh
Description: fast, small, secure-by-default package manager for JavaScript
 jpm installs packages from the npm registry, from one binary. It reads
 package-lock.json, pnpm-lock.yaml, yarn.lock and bun.lock and keeps their
 versions, and runs a dependency's install scripts only once approved.
EOF

# The file is named by Cargo's version: a release file's name keeps to letters, digits, `.`, `_`
# and `-`, which a `~` is not.
mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out/jpm_${version}_${arch}.deb" > /dev/null
echo "$out/jpm_${version}_${arch}.deb"
