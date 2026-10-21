---
name: fakenet-hybrid
description: Working knowledge of the fakenet-hybrid repository (Rust "nucleus" network simulator plus Java/Camel "daemon" for malware-analysis VMs). Use for any task in this repo — fixing bugs, adding protocols or config keys, writing Camel rules, reviewing diversion/link security, reading captures (events.jsonl), updating docs/ or flaws/. Gives the code map, invariants, test commands, the flaw registry, and a token-cheap way to navigate.
---

# fakenet-hybrid

A FakeNet-NG-style simulator for isolated malware-analysis VMs.

- **nucleus** (`nucleus/`, Rust 1.85+, tokio): diverts traffic (iptables REDIRECT / WinDivert),
  sniffs the protocol, answers with a built-in default **or** the daemon's decision within
  a deadline (200 ms), records everything.
- **daemon** (`daemon/`, Java 21, stock Camel 4.18): YAML routes decide answers; hot reload.
- **link**: WebSocket (primary) + HTTP POST (fallback), HMAC-signed Event/Action JSON.
- **explorer** (optional): answers what rules leave at the default, learning from novelty.

Full docs: `docs/` (Sphinx + MyST, Read the Docs). Known defects: `flaws/README.md`.
Read those instead of re-deriving from source.

## Save tokens: navigate, don't dump

Installed: `rg`, `jq`. Not installed: fd, bat, eza, tokei, ast-grep (`sg` here is util-linux,
not ast-grep). So:

- Find code: `rg -n 'fn decide' nucleus/crates` → then `sed -n 'START,ENDp' FILE` for just
  that range. Never `cat` a whole handler (`http.rs` is 500 lines, the explorer 600).
- List files: `rg --files nucleus/crates/listeners/src`; count lines: `wc -l`.
- Public API of a crate without reading it:
  `rg -o '^\s*pub (async )?(fn|struct|enum|const) \w+' nucleus/crates/<crate>/src`.
- Record kinds the code can emit: `rg -o --no-filename 'log\("[a-z_]+"' nucleus/crates | sort -u`.
- Captures: query with `jq`, never open `events.jsonl` raw (payloads are base64 and huge):
  `jq -c 'select(.kind=="credentials")' events.jsonl`,
  `jq -r .kind events.jsonl | sort | uniq -c`.
- Answer from `docs/reference/*.md` and `flaws/*.md` first; open source only to change it
  or to verify a specific line.

## Code map (where to look)

| Task | Files |
|---|---|
| Wire format, HMAC texts | `nucleus/crates/schema/src/lib.rs`, `schema/fakenet-link-v1.schema.json`, `daemon/.../{LinkAuth,LinkSchema,EventIn,ActionOut}.java` |
| Deadline, fallback, reconnect | `nucleus/crates/link/src/lib.rs` |
| Protocol detection, JA3/JA4 | `nucleus/crates/sniffer/src/{lib,tls}.rs` |
| Accept loops, UDP sessions | `listeners/src/server.rs` |
| Decide-or-default step | `listeners/src/session.rs` (`Session::decide`, `answer`) |
| TLS unwrap, sniff, tunnels | `listeners/src/dispatch.rs`; CA in `listeners/src/tls.rs` |
| One protocol | `listeners/src/<protocol>.rs` (30 handlers; NTLM shared in `ntlm.rs`) |
| Limits / memory budget | `listeners/src/limits.rs` |
| Process attribution | `listeners/src/process.rs` (Linux /proc) |
| Recording, rotation, report, IOCs, YARA | `nucleus/crates/capture/src/` |
| iptables / NFQUEUE | `nucleus/crates/diverter/src/linux.rs`; Windows: `windows.rs`, `reflect.rs` |
| Config model + validation, control server | `nucleus/crates/cli/src/lib.rs`; start-up/shutdown in `main.rs` |
| `--run`, `--replay`, HAR, INI import | `cli/src/{run,replay,har,import}.rs` |
| Explorer | `nucleus/crates/explorer/src/`, templates in `explorer/templates/default.toml` |
| Analyst rules, transport routes, SIEM | `daemon/routes/{decisions,link,siem}.yaml`, `daemon/rules-library/` |
| Install, container, CI | `deploy/`, `scripts/package.sh`, `.github/workflows/` |

## Invariants (don't break)

1. Never block a client beyond the deadline: compute or keep a default, go through
   `Session::answer`/`decide`.
2. Control plane loopback-only (`Config::validate`, `application.properties`).
3. Sample data is hostile: bound every read, escape every render, never interpolate it into
   code (Groovy/YAML/HTML/CSV).
4. Link changes go to Rust **and** Java together, with the shared HMAC test vectors
   (`signatures_match_the_shared_vectors`, `LinkAuthTest`) and the JSON Schema.
5. Diversion is off by default; nothing turns it on implicitly.
6. Stock Camel components only.
7. A new protocol touches: `schema::Protocol`, JSON Schema enum, sniffer tables,
   `dispatch::serve`, `WarmUp.PROTOCOLS`, `fuzzing.rs`, tests, `docs/reference/protocols.md`.

## Build and test

```sh
cd nucleus && cargo build && cargo test                      # all Rust tests
cargo test -p fakenet-listeners <name>                      # one crate / test
cd daemon && mvn test                                       # daemon
cd daemon && mvn package && cd ../nucleus && cargo test -p fakenet-cli --test camel_link -- --ignored
cd nucleus && scripts/interop.sh                            # real clients
nucleus/scripts/test-linux-diversion.sh                     # netns diversion test
sphinx-build -W -b html docs docs/_build/html               # docs (pip install -r docs/requirements.txt)
```

Run the narrowest test that covers the change first; the full suite only before finishing.

## Flaw registry

`flaws/` lists 16 defects (`SEC`, `LEAK`, `BUG`, `PERF`, `DEP`, `ARCH`) plus `ENH` ideas,
each with `file:line`, impact and a suggested fix. Highest priority: the link's authentication
(SEC-03..06); ARCH-01 (run the Windows containment on Windows).

- Before changing an area, `rg -n 'path/to/file.rs' flaws` to see known issues there.
- After fixing one: delete its section, its index row in `flaws/README.md`, adjust the
  count in `docs/reference/known-flaws.md`, and `rg -n 'ID' docs flaws` to update mentions.
- New defect found: add it under the right prefix with the next number, status
  Confirmed/Likely, severity, location, what, impact, fix; add the index row.

## Keeping docs in sync

| Change | Update |
|---|---|
| Config key | `docs/getting-started/configuration.md`, both sample TOMLs |
| CLI flag | `docs/usage/cli.md` |
| Record kind | `docs/reference/event-records.md` |
| Handler behaviour / meta | `docs/reference/protocols.md`, `docs/usage/writing-rules.md` |
| Public Rust item | `docs/reference/rust-api.md` |
| Link format | `docs/architecture/link-protocol.md` |

Docs style: plain declarative sentences, tables for reference data, `file:line` anchors,
flaw IDs instead of repeating defect explanations.
