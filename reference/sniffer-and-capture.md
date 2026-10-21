# Sniffer and capture

## Sniffer (`nucleus/crates/sniffer`)

`lib.rs` is pure and does no I/O.

| Item | What it does |
|---|---|
| `DEFAULT_ORDER` | The candidates in tie-break order. HTTP comes first and raw last. FTP comes before POP3, so a bare `USER` on an odd port counts as FTP |
| `score(protocol, data, port, transport)` | +1 if the port is one of the protocol's usual ports, +2 if the first message is recognised (FTP-only and POP3-only commands add +1 more). Raw always scores 1. A protocol the transport doesn't support scores 0 |
| `sniff(candidates, data, port, transport)` | The highest score wins. A tie goes to the earlier candidate |
| `sniff_silent(candidates, port)` | For a silent client: the first server-speaks-first protocol (SMTP, POP3, FTP, IMAP, SSH, Telnet, daytime, chargen, time, qotd, VNC) whose usual port matches |
| `supports`, `default_ports`, `server_speaks_first` | Protocol tables |
| Recognisers | `is_dns_query`, `is_imap`, `is_redis`, `is_telnet`, `is_ntp`, `is_socks`, `is_syslog`/`syslog_priority`, `is_tftp`, `is_mqtt`, `is_coap`, `is_rdp`, `is_ldap`, `is_smb`, `looks_like_tls`. HTTP, SMTP, POP3, FTP and IRC match their command prefixes case-insensitively |

`tls.rs`:

| Item | What it does |
|---|---|
| `ClientHello::parse` | Reassembles the handshake across records. Extracts the version, ciphers, extensions, groups, point formats, signature algorithms, supported versions, ALPN and SNI |
| `ja3_string`, `ja3` | The JA3 string and its MD5, with GREASE removed |
| `ja4(quic)` | FoxIO JA4 (`t13d1516h2_…`) |
| `hello_wants_more` | Says when a ClientHello is complete (at most 20 KiB) |
| `is_grease` | GREASE value check |
| `parse_known(csv)` | Fingerprint lists: first field is the fingerprint, last is the label, `#` starts a comment |

## Capture (`nucleus/crates/capture`)

### `lib.rs`: `Capture`

| Method | What it does |
|---|---|
| `open` / `open_with(dir, Limits)` | Creates `files/`, appends to `events.jsonl`, rotates the previous `traffic.pcap` (only when `max_pcap_bytes > 0`) and creates a new one |
| `log(kind, fields)` | Writes `{timestamp, kind, …fields}` as one JSON line and flushes it immediately. Rotates at `max_events_bytes`. Also kept in a 5000-record in-memory ring for the dashboard |
| `recent(after, limit)` | Records from the ring with a sequence number greater than `after` |
| `event_files()` | Rotated files oldest first, then the current one |
| `save_file(prefix, name, data)` | Writes `files/<prefix>_<NNNNNN>_<sanitized basename, at most 100 chars>`. Checks the budget first and queues a YARA scan |
| `tcp_flow(client, server)` gives a `TcpFlow { client_data, server_data, Drop → close }` | A synthesized TCP conversation in `traffic.pcap` |
| `udp_datagram(src, dst, data)` | One synthesized UDP packet |
| `wire_packet(packet)` | `wire.pcap`, created lazily and rotated |
| `enable_yara`, `finish_scans` | YARA control |
| `dir()` | The capture directory |

### Record catalogue (`events.jsonl` `kind`)

Every session record carries `listener`, `session_id`, `protocol`, `transport`, `tls`,
`src`, `dst`, and `process` when it is known.

| Group | Kinds |
|---|---|
| Lifecycle | `nucleus_started`, `nucleus_stopped`, `config_reloaded`, `session_start`, `session_end`, `detected`, `filtered` |
| Link | `event` (the full Event, with the payload in base64), `decision`, `fallback`, `explored` |
| TLS | `tls_handshake`, `tls_failed`, `starttls_injection_discarded` |
| HTTP | `bad_request`, `connectivity_check`, `custom_response`, `custom_failed`, `proxy_connect`, `proxy_tunnel`, `doh`, `websocket_open`, `websocket_message` |
| DNS | `malformed`, `invalid_answer` |
| Credentials and data | `credentials`, `email`, `upload`, `upload_too_large`, `download`, `rename`, `transfer_failed` |
| Protocols | `ssh_client`, `no_version`, `join`, `message`, `quit`, `registered`, `suspicious_command`, `socks_refused`, `unsupported_command`, `syslog_message`, `time_request`, `query`, `chargen`, `echo`, `discard`, `daytime`, `time`, `qotd`, `netbios_session`, `smb_negotiate`, `smb_command`, `ldap_search`, `ldap_change`, `rdp_connect`, `rdp_client`, `vnc_client`, `mqtt_connect`, `mqtt_publish`, `mqtt_subscribe`, `coap_request` |
| Runs | `sample_started`, `sample_exited`, `sample_killed`, `sample_failed` |
| Analysis | `yara_match`, `yara_error`, `coverage` |

### `pcap.rs`

| Item | What it does |
|---|---|
| `PcapWriter::{create, write}` | Classic pcap, LINKTYPE_RAW (101), flushed after every packet |
| `TcpConversation::{new, open, client_data, server_data, close}` | Synthesized SYN/SYN-ACK/ACK handshake, 1400-byte segments with correct sequence numbers and checksums, and a FIN exchange. The initial sequence numbers are deterministic, derived from the ports |
| `udp_packet` | One UDP packet |
| `same_family` | Maps IPv4-mapped addresses to IPv4. A mixed v4/v6 pair becomes all-IPv6 |
| `checksum`, `ip_packet`, `v6_packet` | Header and checksum construction |

### `report.rs`

| Item | What it does |
|---|---|
| `render(records)`, `render_with_map(records, map)`, `render_file(path)` | Static HTML: CSP `default-src 'none'`, every value escaped, no scripts. Key-indicator tallies cover DNS, HTTP, SNI, TLS fingerprints, YARA, credentials, emails, files, SSH, IRC, suspicious commands, tunnels, routes and fallbacks. Then the explorer section, then every record grouped by process and protocol |
| `escape` | HTML escaping |

### `indicators.rs`

| Item | What it does |
|---|---|
| `collect(records)` | Gathers `Indicator {kind, value, count, first_seen, protocols, known}` of kinds `Domain`, `Url`, `Ip`, `UserAgent`, `Email`, `Ja3`, `Ja4`, `Hassh`. Domains come from DNS (except PTR), HTTP host, SNI and tunnel targets. URLs come from HTTP. IPs come from `session_start` destinations when `is_global`, which excludes private, documentation, CGNAT, 198.18/15 and 192.0.0/24. Connectivity-check and OS noise (`NOISE`) is dropped |
| `to_csv` | CSV export |
| `to_stix(found, sample)` | STIX 2.1 bundle: identity, optional file and malware (deterministic UUIDv5 observable ID), one indicator per value plus `indicates` relationships. JA3, JA4 and HASSH are skipped because STIX has no pattern for them |
| `to_misp(found, sample)` | A MISP event with `to_ids: false` |
| `is_global` | The IP filter above |

### `yara.rs`

| Item | What it does |
|---|---|
| `rule_files(paths)` | Rule files, plus any directories searched recursively and sorted |
| `compile(yarac, rules, out)` | Runs `yarac` |
| `scan(yara, compiled, file)` | Runs `yara -w -a 30 -C` and returns the matching rule names |
| `Scanner::{start, queue, finish}` | One background thread with an unbounded queue. Logs `yara_match` / `yara_error` |
