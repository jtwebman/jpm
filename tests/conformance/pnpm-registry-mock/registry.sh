#!/usr/bin/env bash
# Starts pnpm's registry-mock at the pinned version, in the background, and waits until it answers.
#
#   bash tests/conformance/pnpm-registry-mock/registry.sh <dir> [port]
#
# <dir> holds its install and its storage (reused if it is there already); the port defaults to
# 4873. The server's pid is written to <dir>/registry.pid and its log to <dir>/registry.log.
set -euo pipefail
REGISTRY_MOCK=6.0.0
# registry-mock takes verdaccio as a peer (^5.20.1 || ^6.1.6); 6.9 and later no longer export the
# bin/verdaccio path it starts.
VERDACCIO=6.8.0
dir=$1
port=${2:-4873}
mkdir -p "$dir"
cd "$dir"
if [ ! -d node_modules/@pnpm/registry-mock ]; then
  [ -f package.json ] || echo '{ "private": true }' > package.json
  npm install --no-audit --no-fund --no-save --loglevel=error "@pnpm/registry-mock@$REGISTRY_MOCK" "verdaccio@$VERDACCIO" >/dev/null
  # The storage ships a 64-character secret, and verdaccio on Node 22 and later wants 32.
  node -e '
    const fs = require("fs")
    const p = "node_modules/@pnpm/registry-mock/registry/storage-cache/.verdaccio-db.json"
    const db = JSON.parse(fs.readFileSync(p, "utf8"))
    db.secret = db.secret.slice(0, 32)
    fs.writeFileSync(p, JSON.stringify(db))
  '
fi
export PNPM_REGISTRY_MOCK_PORT=$port
npx registry-mock prepare
nohup npx registry-mock > registry.log 2>&1 &
echo $! > registry.pid
for _ in $(seq 1 60); do
  if curl -fs "http://localhost:$port/@pnpm.e2e%2fabc" >/dev/null; then
    echo "registry-mock $REGISTRY_MOCK on http://localhost:$port/ (pid $(cat registry.pid))"
    exit 0
  fi
  sleep 1
done
cat registry.log
echo "registry-mock did not start" >&2
exit 1
