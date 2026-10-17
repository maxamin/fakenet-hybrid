#!/bin/sh
# Runs the Linux diverter test inside a private user + network namespace: iptables rules,
# routes and connections there never touch the host's network.
set -eu
cd "$(dirname "$0")/.."
cargo test -p fakenet-cli --test linux_diversion --no-run
binary=$(ls -t target/debug/deps/linux_diversion-* | grep -v '\.d$' | head -1)
exec unshare --map-root-user --net env FAKENET_NETNS_TEST=1 "$binary" --ignored --nocapture "$@"
