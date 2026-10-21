# Installation

## Requirements

| Need | Version | For |
|---|---|---|
| Rust | 1.85 or newer (`rust-version` in `nucleus/Cargo.toml`) | the nucleus |
| Java and Maven | Java 21, Maven 3.9 | the daemon |
| iptables / ip6tables with the `nat` table | any recent | Linux diversion (root) |
| `nfnetlink_queue` kernel module | | Linux `excluded_processes` |
| WinDivert 2.2 (`WinDivert.dll`, `.lib`, `WinDivert64.sys`) | 2.2.x | Windows diversion (Administrator) |
| YARA 4 (`yara`, `yarac` on `PATH`) | optional | `[yara]` scanning |
| `python3` | optional, Unix only | FakeNet-NG dynamic Custom Response providers |

## Build from source

Linux:

```sh
cd nucleus && cargo build --release        # target/release/fakenet-nucleus
cd ../daemon && mvn package                 # target/fakenet-daemon.jar and target/lib/
```

Windows (PowerShell):

```powershell
$env:WINDIVERT_PATH = "C:\tools\WinDivert-2.2.2-A\x64"
cd nucleus; cargo build --release
Copy-Item "$env:WINDIVERT_PATH\WinDivert.dll", "$env:WINDIVERT_PATH\WinDivert64.sys" target\release\
cd ..\daemon; mvn package
```

## Install as services

`scripts/package.sh` builds `dist/fakenet-hybrid-<version>-<target>.tar.gz` and a `.sha256`.

Linux, from the unpacked package and as root:

```sh
sudo deploy/linux/install.sh
sudo systemctl enable --now fakenet-daemon fakenet-nucleus
```

The installer:

- copies the binaries to `/opt/fakenet-hybrid`,
- writes `/etc/fakenet/fakenet.toml` from the sample config, rewriting `capture_dir`, the
  `default-files` paths and `secret_file`,
- creates the `fakenet` system user,
- generates `/etc/fakenet/link.secret` (mode 0640, `root:fakenet`),
- installs `fakenet-daemon.service`, which runs unprivileged and sandboxed, and
  `fakenet-nucleus.service`, which runs as root and calls `--restore-network` after every
  stop.

It never enables diversion.

```{important}
The packaged configs reference `fingerprints/sslbl-ja3.csv`, but no install path ships
that file. The nucleus then fails at start-up with `reading fingerprints`. Until this is
fixed (flaw DEP-01), remove the `fingerprints = [...]` line or copy
`nucleus/config/fingerprints/` next to the installed config.
```

Windows: either install the MSI built by the release workflow and run its Start Menu
"Set up" shortcut, or run `deploy\windows\install.ps1` as Administrator from the unpacked
zip. Both register two SYSTEM scheduled tasks through `register-tasks.ps1`. Runtime data
goes under `C:\ProgramData\FakeNetHybrid`. `uninstall.ps1` removes the tasks and keeps the
data.

Container:

```sh
docker build -f deploy/docker/Dockerfile -t fakenet-hybrid .
docker run --rm -p 8080:8080 -p 53:53/udp \
  -v "$PWD/daemon/routes:/opt/fakenet/routes" fakenet-hybrid
```

The image runs both processes, so they share loopback, and serves the fake services on the
published ports with no host diversion. As shipped, the image doesn't build (the builder
stage is `rust:1.83` while the code needs 1.85, flaw DEP-02), and its `/bin/sh`
entrypoint exits under `dash` before starting the nucleus (flaw DEP-03).

## Verify a release

Each release artifact comes with a Sigstore bundle:

```sh
cosign verify-blob --bundle FILE.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/maxamin/fakenet-hybrid/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com FILE
```
