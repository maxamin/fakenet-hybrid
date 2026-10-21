# Deployment, packaging and CI (`DEP-*`)

## DEP-01

**No install path ships the fingerprint list the configs require** · High · Confirmed

- Where: `nucleus/config/fakenet.toml:16` and `deploy/docker/fakenet.container.toml:17`
  set `fingerprints = ["fingerprints/sslbl-ja3.csv"]`. Not copied by
  `scripts/package.sh:16`, `deploy/docker/Dockerfile:36`, `.github/workflows/release.yml:64`
  (Windows zip and MSI), nor rewritten by `deploy/linux/install.sh`.
- What: `main.rs` calls `config.known_fingerprints()?` at start; reading a missing file is
  an error.
- Impact: the Linux tarball install, the Windows zip and MSI, and the container all fail
  at start-up with `reading fingerprints .../fingerprints/sslbl-ja3.csv`.
- Fix: copy `nucleus/config/fingerprints/` in all four places, and have `install.sh` and
  `register-tasks.ps1` rewrite the path. Add a CI step that starts the packaged nucleus
  with `--check`.

## DEP-02

**The Docker builder's Rust is too old** · High · Confirmed

- Where: `deploy/docker/Dockerfile:13` (`FROM rust:1.83-slim-bookworm`).
- What: the workspace declares `rust-version = "1.85"`, and the code uses
  `std::task::Waker::noop` (`listeners/src/http.rs:336`), stable since 1.85.
- Impact: `docker build` fails.
- Fix: `rust:1.85-slim-bookworm` or newer, pinned by digest.

## DEP-03

**The container entrypoint and HEALTHCHECK rely on bash's `/dev/tcp`** · High · Confirmed

- Where: `deploy/docker/entrypoint.sh:19` (`#!/bin/sh`), `Dockerfile:42-43`
  (`/bin/sh -c "exec 3<>/dev/tcp/..."`).
- What: on `eclipse-temurin:21-jre-noble`, `/bin/sh` is `dash`, which has no `/dev/tcp`. A
  failed redirection on the special built-in `exec` makes a POSIX shell exit. Reproduced:
  `dash -c 'if { exec 3<>/dev/tcp/127.0.0.1/1; } 2>/dev/null; then :; fi; echo after'`
  prints nothing and exits with status 2.
- Impact: the entrypoint exits on the first wait iteration, before `exec fakenet-nucleus`,
  so the container stops. The HEALTHCHECK always reports unhealthy.
- Fix: use `#!/bin/bash` (present in the image), or poll with `java`/`curl`, or have the
  nucleus retry the daemon on its own, which it already does.

## DEP-04

**WinDivert is downloaded without a checksum** · Low · Confirmed

- Where: `.github/workflows/ci.yml:42` (and the release workflow's equivalent).
- What: `Invoke-WebRequest` of the release zip with no hash check, and the DLL and driver
  are shipped in signed releases.
- Fix: compare against a pinned SHA-256 before extracting.

## DEP-05

**`fuzz/run-all.sh` always succeeds** · Low · Confirmed

- Where: `nucleus/fuzz/run-all.sh` (no `set -e` or `pipefail`; output piped to `grep` and
  `tail`).
- What: a crash only shows in the filtered output; the exit status is `tail`'s.
- Fix: `set -o pipefail`, record each target's status, exit non-zero if any failed or
  if `fuzz/artifacts/` gained files.

## DEP-06

**Compiled Python files are committed** · Low · Confirmed

- Where: `nucleus/crates/listeners/tests/fixtures/custom/__pycache__/*.pyc`.
- What: interpreter-specific build output (CPython 3.14) in the repository.
- Fix: delete them and add `__pycache__/` to `.gitignore`.
