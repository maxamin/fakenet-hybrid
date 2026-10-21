# Architecture overview

The system is split by responsibility: the **nucleus** owns the network and never depends on
anything else; the **daemon** owns the decisions and may be absent, slow or restarting.

```text
                            Analysis VM
 ┌──────────────┐  all outbound  ┌──────────────────── nucleus (Rust) ─────────────────────┐
 │ malware      │ ─────────────► │ diverter ─► listeners ─► sniffer ─► protocol handler     │
 │ sample       │ ◄───────────── │   (iptables / WinDivert)        │            │            │
 └──────────────┘  fake replies  │                                 │ default    │ Event      │
                                 │   capture ◄─────────────────────┘ answer     ▼            │
                                 │   events.jsonl, pcaps, files,         link (deadline)     │
                                 │   report, indicators, YARA              │   ▲             │
                                 └─────────────────────────────────────────┼───┼─────────────┘
                                            WebSocket (primary) / HTTP POST │   │ Action
                                 ┌──────────────────── daemon (Java/Camel) ─▼───┴─────────────┐
                                 │ EventIn ─► direct:decide (analyst rules) ─► ActionOut       │
                                 │                         └─► Wire Tap ─► audit, log, SIEM    │
                                 └──────────────────────────────────────────────────────────────┘
                     (optional) explorer: answers what the rules leave at the default
```

## Components

| Component | Where | Responsibility |
|---|---|---|
| `schema` | `nucleus/crates/schema` | Event, Action and Hello types (v1), base64 payloads, session IDs, HMAC texts. Mirrors `schema/fakenet-link-v1.schema.json` |
| `sniffer` | `nucleus/crates/sniffer` | Pure functions: scores each protocol on a connection's first bytes and port; picks a server-speaks-first protocol for silent clients; parses TLS ClientHellos and computes JA3/JA4 |
| `link` | `nucleus/crates/link` | `Link::decide`: one Action within the deadline, or a `Fallback` with a reason. WebSocket with request-ID correlation and reconnection; HTTP POST while it's down; HMAC verification |
| `listeners` | `nucleus/crates/listeners` | tokio listeners, the dispatcher (TLS termination, sniffing, tunnels), 30 protocol handlers, sessions, limits, process attribution, Custom Responses, the per-run CA |
| `capture` | `nucleus/crates/capture` | `events.jsonl`, synthesized `traffic.pcap`, `wire.pcap`, `files/`, rotation and budgets, the HTML report, indicators, YARA |
| `diverter` | `nucleus/crates/diverter` | Linux: iptables NAT REDIRECT plus NFQUEUE marking. Windows: WinDivert packet reflection. Wire capture |
| `explorer` | `nucleus/crates/explorer` | Template bandit for undecided requests, hints from strings/REA/traffic, coverage ingestion, `explorer-map.json` |
| `cli` | `nucleus/crates/cli` | The `fakenet-nucleus` binary: config, start-up and shutdown, control server and dashboard, `--run`, `--replay`, `--rules-from-har`, `--import-fakenet-ini`, `--report`, `--indicators` |
| daemon | `daemon/` | `camel-main` application: YAML routes (hot reload), content-based router, Groovy/Simple answers, Wire Tap to audit/log/SIEM, `state` bean, warm-up |

## Crate dependencies

```text
cli ──► listeners ──► link ──► schema
 │          │──────► sniffer ─► schema
 │          │──────► capture ─► schema
 │          └──────► explorer ─► schema
 ├──► diverter ─► listeners (process lookup, Original type)
 └──► capture, link, explorer
```

`schema` and `sniffer` do no I/O, which is why they and the protocol parsers are the
fuzzing targets.

## Threads and tasks

- One multi-threaded tokio runtime (`#[tokio::main]`). Each listener runs an accept loop
  (TCP) or a receive loop (UDP, QUIC); each connection is a task; UDP datagrams become tasks
  bounded at 1,024 per listener.
- The link keeps one task maintaining the WebSocket, and one writer task per connection.
- OS threads: the NFQUEUE loop (Linux exclusions), the WinDivert loops (Windows), the
  AF_PACKET wire capture, and the YARA scanner.
- Shared state: `Context` (link, capture, `ArcSwap<Defaults>`, CA, limits, explorer,
  fingerprints), passed as `Arc` to every session.

## Where to read next

- {doc}`message-flow`: one request from packet to answer.
- {doc}`link-protocol`: the wire format and authentication.
- {doc}`design-decisions`: why it is built this way, and the costs.
