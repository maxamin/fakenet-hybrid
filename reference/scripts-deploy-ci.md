# Scripts, deployment, CI and tests

## Scripts

| Script | Usage | What it does |
|---|---|---|
| `scripts/package.sh` | `scripts/package.sh` | Builds the nucleus (release) and the daemon (`mvn package`, tests included), then stages `bin/`, `daemon/{jar,lib,routes}`, `config/{fakenet.toml,default-files,fingerprints,hooks}`, `deploy schema docs README.md` into `dist/fakenet-hybrid-<ver>-<host-triple>.tar.gz` plus a `.sha256`. |
| `nucleus/scripts/interop.sh` | `cargo build && scripts/interop.sh [binary]` (`KEEP_OUTPUT=1`) | Runs the nucleus on 127.0.0.1 high ports with no daemon and no diversion, then makes 42+ checks with curl, dig, ssh, redis-cli, swaks, logger, nc, python (`interop-iot.py`), smbclient, ldapsearch, FreeRDP and john. Missing tools are skipped. `check`, `need` and `event` are its helpers |
| `nucleus/scripts/interop-iot.py` | `interop-iot.py mqtt\|coap\|websocket PORT` | Stdlib-only clients: an MQTT CONNECT that waits for CONNACK, a CoAP GET of `/.well-known/core`, a WebSocket upgrade with an echo frame |
| `nucleus/scripts/rea-hints.sh` | `rea-hints.sh SAMPLE OUT.jsonl [ghidra\|ida\|…]` | Runs REA (`rea`, or `npx -y rea-agents@6.5.0`): search procedures, search strings, analyze. The output is JSONL for `[explorer] rea` |
| `nucleus/scripts/test-linux-diversion.sh` | `test-linux-diversion.sh` | Builds the `linux_diversion` test and runs it under `unshare --map-root-user --net` with `FAKENET_NETNS_TEST=1` |
| `nucleus/fuzz/run-all.sh` | `run-all.sh [SECONDS]` | `RUSTC_BOOTSTRAP=1 cargo fuzz run -s none` for each of `handlers parsers packets link_messages report_and_import`, with `seeds/<t>` and `corpus/<t>`. Prints only stats. Always exits 0 (flaw `CI-02`) |
| `nucleus/examples/explorer-demo/run-demo.sh` | `run-demo.sh [REA_JSON…]` (`ROUNDS`, `KEEP`) | See [explorer.md](explorer.md#demo) |
| `daemon/src/main/java/...` and `nucleus/crates/listeners/src/providers.py` | | Documented in [link-and-daemon.md](link-and-daemon.md) and [listeners.md](listeners.md) |

## Deployment

| File | What it does |
|---|---|
| `deploy/linux/install.sh` (root) | Installs to `/opt/fakenet-hybrid`. Creates the `fakenet` system user and `/var/lib/fakenet/audit`. Writes `/etc/fakenet/fakenet.toml` from the sample config, rewriting `capture_dir`, `default-files` and `secret_file` with sed. Generates `/etc/fakenet/link.secret` with mode 0640 `root:fakenet`. Installs both units. Never enables them or diversion |
| `deploy/linux/fakenet-daemon.service` | `User=fakenet`, `WorkingDirectory=/opt/fakenet-hybrid/daemon`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`. The only writable paths are audit and routes |
| `deploy/linux/fakenet-nucleus.service` | Runs as root. `ExecStopPost=--restore-network`, `KillSignal=SIGINT`, `Restart=on-failure` |
| `deploy/docker/Dockerfile` | Three stages: the nucleus (`rust:1.89`), the daemon (maven, temurin 21), and the runtime (`eclipse-temurin:21-jre-noble`, user `fakenet` uid 10001). Copies `routes/`, `default-files`, the container config and the entrypoint. `HEALTHCHECK` uses bash's `/dev/tcp` |
| `deploy/docker/entrypoint.sh` | Generates the secret, starts the daemon in the background, waits up to 60 s for `:8092/observe/health` (using `/dev/tcp`), then `exec`s the nucleus |
| `deploy/docker/fakenet.container.toml` | The sample config with `secret_file = "/opt/fakenet/link.secret"` and diversion off |
| `deploy/windows/install.ps1` (Administrator) | Copies the zip layout to `C:\FakeNetHybrid`, then calls `register-tasks.ps1` |
| `deploy/windows/register-tasks.ps1` | Creates `C:\ProgramData\FakeNetHybrid\{capture,audit}` and the live config (regex rewrites). Generates the secret with ACLs for SYSTEM and Administrators only. Registers two SYSTEM scheduled tasks that start at boot |
| `deploy/windows/uninstall.ps1` | Stops and unregisters both tasks. Keeps the data |
| `deploy/windows/fakenet-hybrid.wxs` | WiX v4 MSI. Installs `stage\**` under `Program Files\FakeNet Hybrid`, plus Start Menu shortcuts (setup through `register-tasks.ps1`, and the folder) |

## CI (`.github/workflows/`)

| Job | What it runs |
|---|---|
| `ci.yml` `nucleus-linux` | Installs the apt clients, `cargo test --workspace`, `scripts/interop.sh`, and the `linux_diversion` test as root in `unshare --net` |
| `ci.yml` `nucleus-windows` | Downloads WinDivert 2.2.2 (no hash check), `cargo test --workspace` |
| `ci.yml` `daemon` | `mvn -B package`, then `cargo test -p fakenet-cli --test camel_link -- --ignored` |
| `release.yml` (on `v*` tags) | Linux: `scripts/package.sh`. Windows: build, stage, zip, then `wix build` the MSI. Release: `SHA256SUMS`, `cosign sign-blob` (keyless) for every file, `gh release create` |

## Test suites

| Location | What it covers |
|---|---|
| `crates/*/src` `#[cfg(test)]` | Unit tests in nearly every module: parsers, rule generation, NTLM vectors, HMAC vectors, report escaping, and so on |
| `crates/listeners/tests/listeners.rs` | Fallback when the daemon is stopped or slow (`falls_back_to_defaults_when_the_daemon_is_stopped`, `a_slow_daemon_misses_the_deadline_and_defaults_apply`), forged actions, filters, Custom Responses |
| `crates/listeners/tests/protocols.rs` | Every protocol handler against real client libraries or hand-built clients |
| `crates/link/tests/link.rs` | WebSocket and HTTP channels, the handshake, reconnects |
| `crates/cli/tests/camel_link.rs` (`--ignored`) | The real daemon jar: handshake, both channels, scripted replies, hot reload, Wire Tap, kill and restart |
| `crates/cli/tests/run_and_dashboard.rs` | `--run`, dashboard auth |
| `crates/cli/tests/linux_diversion.rs` (`--ignored`, `FAKENET_NETNS_TEST=1`) | REDIRECT, original TCP/UDP destinations, ping, exclusions, wire capture, cleanup |
| `crates/capture/tests/tshark.rs` | The synthesized pcap decodes in tshark |
| `crates/sniffer/tests/*.rs` | JA3/JA4 on real ClientHellos, the newer protocols' first bytes |
| `crates/explorer/tests/simulated_bot.rs` | The explorer against REA fixtures |
| `daemon/src/test/java` | `LinkAuthTest`, `LinkProcessorsTest`, `DecisionRulesTest`, `LibraryRulesTest`, `SessionStateTest`, `SiemTest` |
| `nucleus/fuzz/fuzz_targets` | `handlers` (every TCP/UDP handler through the `fuzzing` harness), `parsers` (sniffer, ClientHello, KEXINIT, NTLM, LDAP filters, DNS answers, CoAP, …), `packets` (`diverter::packet`), `link_messages` (Event/Action JSON and auth), `report_and_import` (report rendering and the INI importer) |
