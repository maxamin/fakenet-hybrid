#!/bin/sh
# Builds a release package: dist/fakenet-hybrid-<version>-<target>.tar.gz with the nucleus,
# the daemon (jar + lib/ + routes), the sample config, deploy scripts and docs.
# Linux builds here; for Windows, build the nucleus on Windows (see README) and use
# deploy/windows/install.ps1 with the same layout.
set -eu
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' nucleus/Cargo.toml | head -1)
TARGET=$(rustc -vV | sed -n 's/^host: //p')
(cd nucleus && cargo build --release -p fakenet-cli)
(cd daemon && mvn -q -B package)
STAGE="dist/fakenet-hybrid-$VERSION-$TARGET"
rm -rf "$STAGE" && mkdir -p "$STAGE/bin" "$STAGE/daemon" "$STAGE/config"
cp nucleus/target/release/fakenet-nucleus "$STAGE/bin/"
cp -r daemon/target/fakenet-daemon.jar daemon/target/lib daemon/routes "$STAGE/daemon/"
cp -r nucleus/config/fakenet.toml nucleus/config/default-files nucleus/config/fingerprints nucleus/config/hooks "$STAGE/config/"
cp -r deploy schema docs plugins design README.md "$STAGE/"
tar -C dist -czf "$STAGE.tar.gz" "$(basename "$STAGE")"
sha256sum "$STAGE.tar.gz" > "$STAGE.tar.gz.sha256"
echo "Built $STAGE.tar.gz"
