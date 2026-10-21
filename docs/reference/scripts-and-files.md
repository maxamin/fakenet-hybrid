# Scripts, data files and CI

## Scripts

| Script | Usage | What it does |
|---|---|---|
| `scripts/package.sh` | `scripts/package.sh` | Release build of both halves, staged into `dist/fakenet-hybrid-<version>-<triple>.tar.gz` and `.sha256` (see {doc}`../usage/deployment`) |
| `nucleus/scripts/interop.sh` | `cargo build && scripts/interop.sh [BINARY]` (`KEEP_OUTPUT=1` keeps the temp folder) | Runs the nucleus on 127.0.0.1 high ports, no daemon, no diversion, then 42+ checks with curl, dig, ssh, redis-cli, swaks, logger, nc, Python (`interop-iot.py`), smbclient, ldapsearch, FreeRDP and john. Missing tools are skipped |
| `nucleus/scripts/interop-iot.py` | `interop-iot.py mqtt\|coap\|websocket PORT` | Standard-library clients: MQTT CONNECT and CONNACK, CoAP GET `/.well-known/core`, WebSocket upgrade with an echo frame |
| `nucleus/scripts/rea-hints.sh` | `rea-hints.sh SAMPLE OUT.jsonl [ghidra\|ida\|...]` | Runs REA (`rea`, or `npx -y rea-agents@6.5.0`): procedures, strings, analysis → JSONL for `[explorer] rea` |
| `nucleus/scripts/test-linux-diversion.sh` | `test-linux-diversion.sh` | Builds the `linux_diversion` test and runs it under `unshare --map-root-user --net` with `FAKENET_NETNS_TEST=1` (never touches the host's iptables) |
| `nucleus/fuzz/run-all.sh` | `run-all.sh [SECONDS]` (default 120) | `cargo fuzz run` for each target with `seeds/<target>` and `corpus/<target>`, printing only statistics. Always exits 0 (flaw DEP-05) |
| `nucleus/examples/explorer-demo/run-demo.sh` | `run-demo.sh [REA_JSON...]` (`ROUNDS`, `KEEP`) | The explorer demo (see {doc}`../usage/explorer`) |

## Data files

| Path | Content |
|---|---|
| `nucleus/config/fakenet.toml` | The sample config, commented |
| `nucleus/config/default-files/` | FakeNet-NG's typed default files (`FakeNetMini.exe`, `.png`, `.jpg`, `.gif`, `.ico`, `.pdf`, `.txt`, `.html`), `ncsi.txt`, and a NOTICE |
| `nucleus/config/fingerprints/sslbl-ja3.csv` | abuse.ch SSLBL JA3 list (see its README for the source and licence) |
| `nucleus/crates/explorer/templates/default.toml` | The explorer's ~60 templates |
| `schema/fakenet-link-v1.schema.json`, `schema/examples/*.json` | Wire schema and examples (used by tests on both sides) |
| `daemon/routes/*.yaml` | The live routes |
| `daemon/rules-library/*.yaml`, `recorded-example.har` | Ready-made rules and a HAR example |
| `nucleus/crates/*/tests/fixtures/` | Real ClientHellos, protocol first messages, REA output, FakeNet-NG configs and Custom Response examples |
| `upstream/README.md` | Where the FakeNet-NG clone and the archived fakenet-rs source go (git-ignored) |

## CI (`.github/workflows/`)

| Workflow / job | Runs |
|---|---|
| `ci.yml` `nucleus-linux` | Installs the protocol clients, `cargo test --workspace`, `scripts/interop.sh`, and the `linux_diversion` test as root in `unshare --net` |
| `ci.yml` `nucleus-windows` | Downloads WinDivert 2.2.2 (no checksum, flaw DEP-04), `cargo test --workspace` (the diverter isn't exercised) |
| `ci.yml` `daemon` | `mvn -B package`, then `cargo test -p fakenet-cli --test camel_link -- --ignored` against the real jar |
| `release.yml` (tags `v*`) | Linux tarball (`package.sh`); Windows build, stage, zip, `wix build` MSI; `SHA256SUMS`; keyless `cosign sign-blob` for every file; `gh release create` |

## Fuzz targets (`nucleus/fuzz/fuzz_targets/`)

| Target | Exercises |
|---|---|
| `handlers` | Every TCP and UDP protocol handler through `listeners::fuzzing` |
| `parsers` | The sniffer, ClientHello, KEXINIT, NTLM, LDAP filters, DNS answers, CoAP, ... |
| `packets` | `diverter::packet` decoding and rewriting |
| `link_messages` | Event/Action JSON and authentication |
| `report_and_import` | Report rendering and the INI importer |
