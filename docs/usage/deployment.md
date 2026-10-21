# Deployment

Installation steps are in {doc}`../getting-started/installation`. This page describes
what each deployment file does.

## Linux (systemd)

| File | What it does |
|---|---|
| `deploy/linux/install.sh` | Run as root from an unpacked package. Installs to `/opt/fakenet-hybrid`; creates the `fakenet` system user and `/var/lib/fakenet/audit`; writes `/etc/fakenet/fakenet.toml` from the sample (rewriting `capture_dir`, `default-files` and `secret_file` with `sed`, only if the file doesn't exist); generates `/etc/fakenet/link.secret` (0640, `root:fakenet`); installs both units. Never enables them, nor diversion |
| `deploy/linux/fakenet-daemon.service` | `User=fakenet`, `WorkingDirectory=/opt/fakenet-hybrid/daemon`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`; writable: the audit folder and `routes/`. `Restart=on-failure` |
| `deploy/linux/fakenet-nucleus.service` | Runs as root. `KillSignal=SIGINT` (clean shutdown with report), `ExecStopPost=... --restore-network`, `Restart=on-failure` |

Because `ExecStopPost` removes the diversion after every stop, including crashes, the
VM is online between a crash and the restart (flaw LEAK-01).

## Windows

| File | What it does |
|---|---|
| `deploy/windows/install.ps1` | As Administrator, from the unpacked zip: copies the layout to `C:\FakeNetHybrid` and runs `register-tasks.ps1` |
| `deploy/windows/register-tasks.ps1` | Creates `C:\ProgramData\FakeNetHybrid\{capture,audit}` and the live config (regex rewrites of the sample), generates the secret with an ACL for SYSTEM and Administrators only, and registers two SYSTEM scheduled tasks started at boot |
| `deploy/windows/uninstall.ps1` | Stops and unregisters both tasks; keeps the data |
| `deploy/windows/fakenet-hybrid.wxs` | WiX v4 MSI: installs `stage\**` under `Program Files\FakeNet Hybrid`, with Start Menu shortcuts for setup (runs `register-tasks.ps1`) and the folder |

## Container

| File | What it does |
|---|---|
| `deploy/docker/Dockerfile` | Three stages: the nucleus (`rust:1.83-slim-bookworm`, too old: flaw DEP-02), the daemon (Maven, Temurin 21), and the runtime (`eclipse-temurin:21-jre-noble`, user `fakenet`, uid 10001). Copies the routes, the default files, the container config and the entrypoint. The HEALTHCHECK uses `/dev/tcp` under `/bin/sh` (flaw DEP-03) |
| `deploy/docker/entrypoint.sh` | Generates the secret, starts the daemon in the background, waits up to 60 s for `:8092/observe/health`, then `exec`s the nucleus. Under `dash` the wait loop exits the script (flaw DEP-03) |
| `deploy/docker/fakenet.container.toml` | The sample config with `bind = "0.0.0.0"`, `secret_file = "/opt/fakenet/link.secret"` and diversion off |

Mount `daemon/routes` at `/opt/fakenet/routes` to edit rules live.

## Packaging and releases

- `scripts/package.sh`: builds the nucleus (release) and the daemon (`mvn package`, with
  tests), stages `bin/`, `daemon/{jar,lib,routes}`, `config/{fakenet.toml,default-files}`,
  `deploy`, `schema`, `docs` and `README.md`, and writes
  `dist/fakenet-hybrid-<version>-<host triple>.tar.gz` plus `.sha256`. It leaves out
  `config/fingerprints/` (flaw DEP-01).
- `.github/workflows/release.yml` (on `v*` tags): the Linux tarball; the Windows zip and
  MSI; `SHA256SUMS`; keyless `cosign sign-blob` for every file; a GitHub release.
