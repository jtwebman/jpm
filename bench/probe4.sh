#!/bin/bash
set -u

J=$PWD/target/release/jpm
W=$RUNNER_TEMP/p4; mkdir -p $W/proj; cp bench/fixtures/nuxt/package.json $W/proj/


node bench/h2probe.mjs bench/nuxt-urls.txt
