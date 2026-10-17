# Upstream reference

`flare-fakenet-ng/` is a clone of FakeNet-NG (https://github.com/mandiant/flare-fakenet-ng,
Apache-2.0), the Python original this project follows. It's kept for reference only: nothing
in fakenet-hybrid builds from or reads it (the default files, sample configs and Custom
Response examples it needs are vendored, with attribution, under `nucleus/`). It's
git-ignored; update it with `git -C upstream/flare-fakenet-ng pull`, or delete it.

`fakenet-rs-source-2026-10-16.tar.gz` is the source of fakenet-rs, an earlier Rust port of
FakeNet-NG's listeners that was fused into this project (everything it did lives in
`nucleus/` now). Kept for reference; nothing uses it.
