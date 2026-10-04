#!/bin/sh
# The apt repository's index, with one release's .deb files added, and signed.
#   packaging/apt.sh <repo dir> <version> <dir holding jpm_<version>_<arch>.deb>
# <repo dir> is the repository as the `apt` branch keeps it: dists/stable, jpm.gpg, jpm.asc. The
# .deb files themselves are not kept there: getjpm.sh/apt answers pool/ with the release's own
# files. Each architecture's Packages keeps every version (apt takes the newest; one can be
# pinned), this one's entry made from the package. Release, signed inline (InRelease) and
# detached (Release.gpg), lists every index's hashes. It signs with gpg's default key: the
# release workflow imports APT_SIGNING_KEY first. Needs dpkg-dev, apt-utils and gpg.
set -eu

repo=$1 version=$2 debs=$3
dist="$repo/dists/stable"
pool=pool/main/j/jpm
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/$pool"
cp "$debs"/jpm_"$version"_*.deb "$work/$pool/"

for arch in amd64 arm64 armhf; do
  dir="$dist/main/binary-$arch"
  mkdir -p "$dir"
  file="$pool/jpm_${version}_${arch}.deb"
  [ -f "$work/$file" ] || { echo "apt.sh: no $file" >&2; exit 1; }
  # The earlier versions' entries (this one's left out, so a second run does not add it twice),
  # then this one's.
  if [ -f "$dir/Packages" ]; then
    awk -v f="Filename: $file" 'BEGIN { RS = ""; ORS = "\n\n" } index($0, f) == 0' "$dir/Packages" > "$work/Packages"
  else
    : > "$work/Packages"
  fi
  (cd "$work" && dpkg-scanpackages --multiversion --arch "$arch" "$pool" /dev/null 2>/dev/null) >> "$work/Packages"
  mv "$work/Packages" "$dir/Packages"
  gzip -9nc "$dir/Packages" > "$dir/Packages.gz"
done

# Release, made outside dists/stable so it does not list itself, nor the last one's signatures.
rm -f "$dist/Release" "$dist/InRelease" "$dist/Release.gpg"
(cd "$dist" && apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=jpm \
  -o APT::FTPArchive::Release::Label=jpm \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o "APT::FTPArchive::Release::Architectures=amd64 arm64 armhf" \
  -o APT::FTPArchive::Release::Components=main \
  -o "APT::FTPArchive::Release::Description=jpm, a package manager for JavaScript (getjpm.sh)" \
  release .) > "$work/Release"
mv "$work/Release" "$dist/Release"
gpg --batch --yes --clearsign --output "$dist/InRelease" "$dist/Release"
gpg --batch --yes --armor --detach-sign --output "$dist/Release.gpg" "$dist/Release"
echo "apt.sh: jpm $version in $dist"
