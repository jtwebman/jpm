#!/bin/bash
set -u
cargo build --release 2>&1 | tail -1
J=$PWD/target/release/jpm
W=$RUNNER_TEMP/p4; mkdir -p $W/proj; cp bench/fixtures/nuxt/package.json $W/proj/
(cd $W/proj && HOME=$W/home JPM_STORE=$W/home/store $J install --ignore-scripts >/dev/null 2>&1)
pip install --quiet 'httpx[http2]' 2>&1 | tail -1
python3 bench/h2probe.py $W/proj/jpm.lock 2>&1
