#!/bin/sh
# Certificates rcgen cannot make: other pairings of key and hash, SHA-1, ECDSA with SHA-512,
# and RSA-PSS. Each case is a root (the trust anchor) and a leaf for example.com that it
# signed. Valid from the day they were made for 100 years; the tests check them in 2030.
# Run from this directory with OpenSSL 3: sh gen.sh
set -e
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

key() {
	case $1 in
	rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$2" 2>/dev/null ;;
	p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" ;;
	p384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$2" ;;
	esac
}

printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign\n' >"$tmp/ca.ext"
printf 'subjectAltName=DNS:example.com\nextendedKeyUsage=serverAuth\n' >"$tmp/leaf.ext"

# make name root-key leaf-key leaf-signing-options...
make() {
	name=$1 rootkey=$2 leafkey=$3
	shift 3
	key "$rootkey" "$tmp/root.key"
	key "$leafkey" "$tmp/leaf.key"
	openssl req -new -key "$tmp/root.key" -subj "/CN=$name root" -out "$tmp/root.csr"
	openssl x509 -req -in "$tmp/root.csr" -key "$tmp/root.key" -days 36500 -set_serial 1 \
		-extfile "$tmp/ca.ext" -sha256 -out "$tmp/root.pem" 2>/dev/null
	openssl req -new -key "$tmp/leaf.key" -subj "/CN=$name leaf" -out "$tmp/leaf.csr"
	openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/root.pem" -CAkey "$tmp/root.key" \
		-days 36500 -set_serial 2 -extfile "$tmp/leaf.ext" "$@" -out "$tmp/leaf.pem" 2>/dev/null
	cat "$tmp/leaf.pem" "$tmp/root.pem" >"$name.pem"
}

make rsa-sha256 rsa rsa -sha256
make rsa-sha1 rsa rsa -sha1
make p256-sha1 p256 p256 -sha1
make p256-sha384 p256 p256 -sha384
make p256-sha512 p256 p256 -sha512
make p384-sha256 p384 p384 -sha256
make p384-sha512 p384 p384 -sha512
make pss-sha256 rsa p256 -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
make pss-sha384 rsa rsa -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
make pss-sha512 rsa p384 -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
make pss-salt20 rsa rsa -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20
make pss-mgf-sha1 rsa rsa -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
	-sigopt rsa_mgf1_md:sha1
