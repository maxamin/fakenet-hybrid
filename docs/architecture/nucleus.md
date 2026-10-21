# The nucleus

The Rust workspace in `nucleus/` (edition 2021, Rust 1.85+). Exact dependency versions are
pinned in `Cargo.toml` and `Cargo.lock`. The release profile strips symbols and uses thin
LTO.

## Listener framework (`crates/listeners`)

| Module | Role |
|---|---|
| `server.rs` | `Server::start` binds each `[[listener]]`, loads its Custom Responses, and spawns `serve_tcp`, `serve_udp` or `http3::serve`. A UDP client address is one session; at most 1,024 datagrams are being answered per listener; idle UDP sessions expire after `timeout_ms`. Dropping the `Server` stops everything |
| `session.rs` | `Context` (shared by all sessions) and `Session` (per connection or UDP flow): event numbering, the pcap flow, `decide`, `answer`, `notify`, `log`. `Drop` sends a "closed" notification and logs `session_end` |
| `dispatch.rs` | Chooses the handler: TLS termination for `tls = true` listeners; peek, TLS unwrap and sniff for `auto` listeners; proxy and SOCKS tunnels become new `auto` sessions (`serve_tunnel`) |
| `limits.rs` | Session semaphore, per-source token bucket, shared memory budget (`Held::grow`) |
| `process.rs` | Linux process attribution through `/proc/net/*` and `/proc/<pid>/fd` |
| `original_dst.rs` | `SO_ORIGINAL_DST` (TCP) and `IP(V6)_RECVORIGDSTADDR` with `recvmsg` (UDP); the crate's only networking `unsafe` |
| `stream.rs` | `BoxStream`, bounded line reads (8 KiB), `PrefixedStream` to replay peeked bytes |
| `lines.rs` | Line protocols: read, send (recorded in the pcap), `respond` (daemon or default), `starttls` (discards pipelined bytes and logs `starttls_injection_discarded`) |
| `custom.rs` + `providers.py` | FakeNet-NG Custom Responses and the Python provider shim; listener filters |
| `tls.rs` | `TlsAuthority`: per-run CA, per-name leaf certificates (cached; random serial; back-dated 30–200 days; 90, 365 or 397-day lifetime), NSS key log |
| `config.rs` | `ListenerConfig` and every `*Defaults` table |
| `fuzzing.rs` | Feature `fuzzing`: drives any handler with in-memory bytes for cargo-fuzz |

## The default-first rule

Every handler computes the answer it would give on its own, then asks the daemon. The
daemon's response wins when it arrives in time; otherwise the default goes out. That's
why the sample sees the same timely behaviour whether the daemon is up, down or slow.
In code: `Session::answer(payload, meta, default, close)` returns `(bytes, close)`.

For HTTP, the default is computed after the decision (only when needed), because the
Custom Response provider may be expensive; the timing guarantee is the same.

## Sniffing (`crates/sniffer`)

- `score(protocol, data, port, transport)`: +1 if the port is one of the protocol's usual
  ports; +2 if the first message is recognised; FTP-only and POP3-only commands add +1 more
  to break the USER/PASS tie. Raw always scores 1. Protocols that don't exist on the
  transport score 0.
- `sniff`: the highest score wins; ties go to the earlier candidate in `DEFAULT_ORDER`
  (HTTP first, raw last; FTP before POP3).
- `sniff_silent(port)`: for clients that send nothing within `first_data_timeout_ms`, the
  first server-speaks-first protocol (SMTP, POP3, FTP, IMAP, SSH, Telnet, daytime, chargen,
  time, qotd, VNC) whose usual port matches; else raw.
- Recognisers: HTTP methods and the h2 preface, SMTP/POP3/FTP/IRC command prefixes,
  `is_dns_query` (also TCP with its length prefix), `is_imap`, `is_redis`, `is_telnet`,
  `is_ntp`, `is_socks`, `is_syslog`, `is_tftp`, `is_mqtt`, `is_coap`, `is_rdp`, `is_ldap`,
  `is_smb`, `looks_like_tls`, `SSH-`, `RFB 00`.
- `tls.rs`: `ClientHello::parse` (reassembles records), `ja3_string`/`ja3` (GREASE
  removed), `ja4` (FoxIO format), `hello_wants_more` (bounded at 20 KiB), `parse_known`
  for fingerprint CSVs.

## Capture (`crates/capture`)

`Capture` is shared by every session. `log` writes one JSON line and flushes it, and keeps
the last 5,000 records in memory for the dashboard. `save_file` enforces the files budget
and queues YARA. `tcp_flow`, `udp_datagram` and `wire_packet` write packets.
Rotation: `events.jsonl` past `max_events_mb`, `traffic.pcap` and `wire.pcap` past
`max_pcap_mb`, keeping `keep_rotations`. Details in {doc}`../usage/outputs`.

## Resource limits

| Limit | Applies to | When exceeded |
|---|---|---|
| `max_sessions` | TCP connections, UDP client addresses, QUIC connections | New ones dropped at accept; counted |
| `per_source_per_second` / `per_source_burst` | New sessions per source IP | Dropped; counted |
| `memory_budget_mb` | Buffers that call `Held::grow` | That request fails (413, protocol error); counted |
| Per handler | HTTP body 16 MiB (configurable), SMTP message 32 MiB, FTP upload 64 MiB, TFTP upload 32 MiB, Redis bulk 16 MiB and command 64 MiB, LDAP/SMB/MQTT messages 1 MiB, RDP PDU 64 KiB, WebSocket message 1 MiB, syslog message 64 KiB, chargen 1 MiB, line 8 KiB | The connection is closed or the transfer refused |

Proxy and SOCKS tunnels and WebSocket child sessions don't take a session permit (flaw
PERF-05).

## Hot reload

On SIGHUP the CLI reloads the config file and swaps `Context.defaults` (an `ArcSwap`).
Sessions read the defaults when they need them, so new answers apply immediately without
dropping connections.
