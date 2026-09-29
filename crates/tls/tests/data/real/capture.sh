#!/bin/sh
# Capture the certificate chains the registries send, as the tests use them: one PEM file per
# host, the server's certificate first. Run from this directory: sh capture.sh
# The capture time goes in captured-at (seconds since the epoch, UTC).
set -e
for host in registry.npmjs.org registry.yarnpkg.com github.com codeload.github.com \
	objects.githubusercontent.com registry.npmmirror.com; do
	openssl s_client -showcerts -servername "$host" -connect "$host:443" </dev/null 2>/dev/null |
		sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' >"$host.pem"
	echo "$host: $(grep -c BEGIN "$host.pem") certificates"
done
date -u +%s >captured-at
