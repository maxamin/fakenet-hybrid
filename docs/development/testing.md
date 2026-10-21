# Testing

| What | Command | Notes |
|---|---|---|
| Rust unit and integration tests | `cd nucleus && cargo test` | Every protocol with real client libraries, TLS, STARTTLS, HTTP/2, tunnels, Custom Responses, filters, link authentication, rotation, the report, fallback when the daemon is stopped or slow |
| One crate | `cargo test -p fakenet-listeners` | Crate names: `fakenet-schema`, `-sniffer`, `-link`, `-capture`, `-listeners`, `-diverter`, `-explorer`, `-cli` |
| Daemon | `cd daemon && mvn test` | HMAC vectors shared with Rust, processors, shipped rules, rules library, state, SIEM |
| Rust ↔ Camel | `cd daemon && mvn package`, then `cd nucleus && cargo test -p fakenet-cli --test camel_link -- --ignored` | Uses `JAVA_HOME` or `java` on `PATH`. Handshake, both channels, scripted replies, hot reload, Wire Tap, kill and restart |
| Real clients | `cd nucleus && cargo build && scripts/interop.sh` | 42+ checks; missing tools are skipped |
| Linux diversion | `nucleus/scripts/test-linux-diversion.sh` | Needs NAT modules and unprivileged user namespaces; or `sudo unshare --net` the test binary, as CI does |
| Fuzzing | `cd nucleus/fuzz && ./run-all.sh 300` | cargo-fuzz; nightly, or `RUSTC_BOOTSTRAP=1` as the script sets. Crashes land in `fuzz/artifacts/`. Check them yourself: the script exits 0 regardless |
| Explorer end to end | `nucleus/examples/explorer-demo/run-demo.sh` | gcc, and REA with Ghidra unless you pass REA JSON |
| Documentation | `sphinx-build -W -b html docs docs/_build/html` | `-W` turns warnings into errors |

## Tests worth reading first

- `falls_back_to_defaults_when_the_daemon_is_stopped` and
  `a_slow_daemon_misses_the_deadline_and_defaults_apply` in
  `nucleus/crates/listeners/tests/listeners.rs`.
- The kill-and-restart section of `nucleus/crates/cli/tests/camel_link.rs`.
- `signatures_match_the_shared_vectors` (Rust) and `LinkAuthTest` (Java): change both
  together.

## Test layout

| Location | Covers |
|---|---|
| `crates/*/src` `#[cfg(test)]` | Unit tests in nearly every module |
| `crates/listeners/tests/listeners.rs` | Fallbacks, forged actions, filters, Custom Responses |
| `crates/listeners/tests/protocols.rs` | Each protocol handler |
| `crates/link/tests/link.rs` | Both channels, handshake, reconnects |
| `crates/cli/tests/camel_link.rs` (ignored by default) | The real daemon |
| `crates/cli/tests/run_and_dashboard.rs` | `--run` and dashboard authentication |
| `crates/cli/tests/linux_diversion.rs` (ignored; `FAKENET_NETNS_TEST=1`) | REDIRECT, original destinations, ping, exclusions, wire capture, cleanup |
| `crates/capture/tests/tshark.rs` | The synthesized pcap decodes in tshark (skipped without it) |
| `crates/sniffer/tests/*.rs` | JA3/JA4 on real ClientHellos; newer protocols' first bytes |
| `crates/explorer/tests/simulated_bot.rs` | The explorer against REA fixtures |

## Not covered by any test

- The WinDivert diverter (ARCH-01).
- TFTP under Linux diversion: transfers are sent from the original destination with `IP_TRANSPARENT` (needs root); not covered by `linux_diversion.rs`.
- Installing from the release packages and the Docker image (CI builds them; nothing starts them).
