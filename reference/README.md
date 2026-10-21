# fakenet-hybrid reference

This folder documents every component, public function, CLI mode and script in the
repository, together with the use cases each one serves. It sits alongside the
project's own `README.md` (the user guide) and `docs/ARCHITECTURE.md` (design and
trade-offs). Known bugs and unintended behaviours are in [`../flaws/`](../flaws/README.md).
The Claude Code skill for working on this project is in
[`../.claude/skills/fakenet-hybrid/`](../.claude/skills/fakenet-hybrid/SKILL.md).

Everything here comes from reading the source at commit `1168ac0`. Line numbers are
approximate anchors (`file:line`) and may drift.

## Contents

| File | Covers |
|---|---|
| [use-cases.md](use-cases.md) | What the tool is for, end-to-end workflows, and which component handles each step |
| [config.md](config.md) | Every TOML key (`[nucleus]`, `[daemon]`, `[limits]`, `[yara]`, `[diverter]`, `[defaults.*]`, `[[listener]]`, `[explorer]`) and every daemon property |
| [cli.md](cli.md) | The `fakenet-nucleus` binary: every flag, the startup and shutdown sequence, the control server and dashboard, and the `cli` crate's functions (`run`, `replay`, `har`, `import`) |
| [link-and-daemon.md](link-and-daemon.md) | The wire schema (`schema` crate and JSON schema), HMAC authentication, the `link` crate, the Java daemon classes, the Camel routes, the SIEM outputs and the rules library |
| [listeners.md](listeners.md) | The `listeners` crate: server, session, dispatch, limits, process attribution, streams, Custom Responses, TLS, and **each of the 30 protocol handlers** (events, `meta` fields, response formats, defaults, credential records) |
| [sniffer-and-capture.md](sniffer-and-capture.md) | Protocol detection (scoring, silent clients, JA3/JA4) and everything recorded: the event-record catalogue, pcap synthesis, the HTML report, indicators (CSV/STIX/MISP), YARA |
| [diverter.md](diverter.md) | Linux iptables/NFQUEUE, Windows WinDivert reflection, packet rewriting, wire capture, Windows host settings |
| [explorer.md](explorer.md) | The response explorer: templates and slot language, hints (strings, REA), the UCB1 bandit, novelty signatures, coverage ingestion, `explorer-map.json` |
| [scripts-deploy-ci.md](scripts-deploy-ci.md) | Every shell, PowerShell and Python script, the Dockerfile and entrypoint, systemd units, the WiX MSI, the CI and release workflows, fuzz targets, the test suites |

## System in one paragraph

A Rust **nucleus** (`nucleus/`) diverts a malware VM's outbound traffic (iptables
REDIRECT on Linux, WinDivert reflection on Windows) to local listeners. An "auto"
listener sniffs each connection's first bytes to choose one of 30 protocol handlers,
unwrapping TLS with certificates it mints on the fly. Each handler computes a built-in
default answer and then asks the Java/Camel **daemon** (`daemon/`) over an
HMAC-authenticated WebSocket (with HTTP as fallback) whether to answer differently. The
deadline for that is 200 ms by default. When the daemon is late or absent, the default
is used. When the analyst's rules leave a request undecided, the optional **explorer**
can answer with a learned template. Everything is recorded to `events.jsonl`,
`traffic.pcap` (plaintext, synthesized), an optional `wire.pcap`, `files/`, the HTML
report and the indicator exports.

## Source map

```
schema/fakenet-link-v1.schema.json     wire format (Event, Action, Hello)
nucleus/crates/schema                  Rust types for it + HMAC texts            -> link-and-daemon.md
nucleus/crates/link                    WebSocket/HTTP client with deadline       -> link-and-daemon.md
nucleus/crates/sniffer                 protocol scoring, TLS ClientHello, JA3/4  -> sniffer-and-capture.md
nucleus/crates/capture                 events, pcap, files, report, IOCs, YARA   -> sniffer-and-capture.md
nucleus/crates/listeners               server + 30 protocol handlers             -> listeners.md
nucleus/crates/diverter                iptables/NFQUEUE, WinDivert, wire.pcap    -> diverter.md
nucleus/crates/explorer                template bandit, hints, coverage          -> explorer.md
nucleus/crates/cli                     fakenet-nucleus binary, dashboard         -> cli.md
nucleus/fuzz                           cargo-fuzz targets                        -> scripts-deploy-ci.md
nucleus/scripts, examples              interop, REA hints, diversion test, demo  -> scripts-deploy-ci.md
daemon/src/main/java                   Camel entry point, processors             -> link-and-daemon.md
daemon/routes, rules-library           YAML routes                               -> link-and-daemon.md
deploy/, scripts/package.sh, .github   install, container, MSI, CI, release      -> scripts-deploy-ci.md
```
