#!/bin/bash
set -u

J=$PWD/target/release/jpm
W=$RUNNER_TEMP/p4; mkdir -p $W/proj; cp bench/fixtures/nuxt/package.json $W/proj/

pip install --quiet 'httpx[http2]' 2>&1 | tail -1
python3 bench/h2probe.py bench/nuxt-urls.txt 2>&1
