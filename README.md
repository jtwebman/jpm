# jpm's apt repository

What https://getjpm.sh/apt serves, for Debian and Ubuntu (amd64, arm64, armhf). The release
workflow adds each release here (`packaging/apt.sh` on `main`) and signs the index with the key
in `jpm.gpg` (`jpm.asc`, the same key as text):

    6FFE A00B A32B 6232 0912  A689 2E2F EC89 6159 4F71  jpm apt repository <apt@getjpm.sh>

The packages themselves are the releases' `.deb` files: getjpm.sh/apt answers `pool/` with
them. To install jpm from here, see docs/install.md on `main`.
