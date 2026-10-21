# Building

## Nucleus

```sh
cd nucleus
cargo build                 # debug
cargo build --release       # target/release/fakenet-nucleus (stripped, thin LTO)
cargo clippy --workspace --all-targets
cargo doc --workspace --no-deps --open
```

- Toolchain: Rust 1.85 or newer (`rust-version`). Dependencies are pinned with `=` in the
  workspace `Cargo.toml`, and `Cargo.lock` is committed.
- Windows: set `WINDIVERT_PATH` to the folder with `WinDivert.dll`, `WinDivert.lib` and
  `WinDivert64.sys` (x64) before building, and copy the DLL and driver next to the binary.
- The `listeners` crate's `fuzzing` feature compiles the in-memory harness used by
  `nucleus/fuzz`.

## Daemon

```sh
cd daemon
mvn package                 # target/fakenet-daemon.jar + target/lib/ (runs the tests)
mvn -DskipTests package
```

Java 21 and Maven 3.9. The jar's manifest points at `lib/` for its dependencies, so keep
them together.

## Documentation

```sh
python3 -m venv .venv && .venv/bin/pip install -r docs/requirements.txt
.venv/bin/sphinx-build -W -b html docs docs/_build/html
```

Read the Docs builds the same thing from `.readthedocs.yaml`. Pages are Markdown (MyST).

## Release package

`scripts/package.sh` (Linux) builds both halves and writes `dist/`. Tagging `v*` runs the
release workflow, which also builds the Windows zip and MSI and signs everything with
cosign.
