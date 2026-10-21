# Outputs

Everything goes into `capture_dir` (with `--run`, a sub-folder per run). Writes are flushed
immediately, because analysis VMs are often reverted abruptly.

| File | Content |
|---|---|
| `events.jsonl` | One JSON record per line. Rotated as `events.1.jsonl` (newest) … `events.<keep>.jsonl` |
| `traffic.pcap` | Conversations as the listeners saw them, synthesized into packets, with TLS already decrypted |
| `wire.pcap` | With `wire_capture = true`: every real packet, including traffic never diverted |
| `tls-keys.log` | With `tls_keylog = true` (default): TLS secrets in NSS key-log format, to decrypt `wire.pcap` in Wireshark |
| `files/` | HTTP request bodies, emails (`.eml`), FTP and TFTP uploads |
| `ca.pem` | The interception CA: the saved one (`[nucleus] ca_cert`), or a new one for this start |
| `yara-rules.compiled` | With `[yara]`: the compiled rules |
| `report.html` | Written at every stop |
| `indicators.csv`, `indicators.stix.json`, `indicators.misp.json` | Written at every stop |
| `explorer-map.json` | With the explorer: refreshed every 10 s and at stop |
| `run.json` | With `--run` |

The daemon writes its own audit trail: `daemon/audit/events-YYYYMMDD.jsonl` (`{event,
action}` per decision).

## `events.jsonl`

Every record has `timestamp` (RFC 3339, UTC) and `kind`. Records about a session also have
`listener`, `session_id`, `protocol`, `transport`, `tls`, `src`, `dst` (the original
destination) and, when known, `process` (`{pid, name, exe}`).

The full catalogue of kinds is in {doc}`../reference/event-records`. The most useful ones:

| Kind | Meaning |
|---|---|
| `session_start`, `session_end` | A connection or UDP flow began or ended |
| `detected` | An `auto` listener chose a protocol (`detected`, `tls`) |
| `event` | The full Event sent to the daemon, with `payload` in base64 and `meta` |
| `decision` | The daemon answered: `route`, `default` (no response), `close`, `delay_ms`, `response_bytes` |
| `fallback` | The default was used: `fallback.reason` is `disabled`, `unavailable`, `timeout`, `error` or `invalid` |
| `explored` | The explorer answered: `template`, `tokens` |
| `tls_handshake` | `sni`, `certificate`, `alpn`, `ja3`, `ja3_string`, `ja4`, `known` |
| `credentials` | `username`, `password`, and per protocol `mechanism`, `hash` lines for NTLM and VNC |
| `email`, `upload`, `download` | Mail and file transfers, with `saved` paths |

Useful `jq` queries:

```sh
jq -c 'select(.kind=="event" and .protocol=="dns") | .meta.qname' events.jsonl | sort -u
jq -c 'select(.kind=="credentials")' events.jsonl
jq -r 'select(.kind=="fallback") | .fallback.reason' events.jsonl | sort | uniq -c
jq -c 'select(.kind=="event" and .protocol=="http") | [.meta.method,.meta.host,.meta.path]' events.jsonl
```

## `traffic.pcap`

Classic pcap with link type 101 (raw IP). Source: `nucleus/crates/capture/src/pcap.rs`.

- TCP: a synthetic SYN / SYN-ACK / ACK, then data in 1,400-byte segments with correct
  sequence numbers and checksums, an ACK after each burst, and a FIN exchange at the end.
  Initial sequence numbers are derived from the ports.
- UDP: one packet per datagram.
- IPv4-mapped addresses become IPv4; a mixed v4/v6 pair becomes all-IPv6.
- Timestamps are the time of writing, not of the wire.

It is not a byte-exact capture; use `wire.pcap` (or tcpdump) for that.

## Saved files

`Capture::save_file` writes `files/<prefix>_<NNNNNN>_<name>`. The name is the client's,
reduced to its last path component, with characters other than ASCII letters, digits and
`.-_` replaced by `_`, and cut to 100 characters. Prefixes: `http_body`, `smtp`, `ftp`,
`tftp`. Files are never overwritten. When a start finds a previous run in the capture folder, it
moves that run's outputs (events, pcaps, `files/`, report, indicators) to
`previous/<UTC time>/` first. Past `max_files_mb`, files are logged but not saved.

## `report.html`

Source: `nucleus/crates/capture/src/report.rs`. A static page with no scripts and a
`default-src 'none'` CSP; every value is HTML-escaped. It contains:

1. Key indicators, each deduplicated with counts: DNS queries, HTTP requests, SNI, TLS
   client fingerprints, YARA matches, credentials, emails, file transfers, SSH clients,
   IRC, suspicious commands, tunnels, daemon decisions by route, fallbacks by reason.
2. The explorer section, when `explorer-map.json` exists.
3. Every record, grouped by process and then by protocol, plus a "Nucleus & daemon link"
   group for records without a protocol.

## Indicators

Source: `nucleus/crates/capture/src/indicators.rs`.

| Kind | Collected from |
|---|---|
| `domain` | DNS queries (not PTR), HTTP `Host`, SNI, CONNECT and SOCKS targets |
| `url` | HTTP requests (not CONNECT) |
| `ip` | `session_start` destinations that are publicly routable |
| `user-agent` | HTTP requests |
| `email` | SMTP envelope sender and recipients |
| `ja3`, `ja4`, `hassh` | TLS and SSH client fingerprints, with `known` labels |

Excluded: connectivity-check domains, `in-addr.arpa`, `ip6.arpa`, `local`, `localhost`,
`wpad`, names without a dot, and non-global addresses (private, loopback, link-local,
documentation, CGNAT, `198.18.0.0/15`, `192.0.0.0/24`, multicast, reserved).

- CSV: `type,value,count,first_seen,protocols,known`. Values starting with `=`, `+`, `-`, `@`, tab or CR get a leading `'` so
  spreadsheets don't evaluate them as formulas.
- STIX 2.1: an identity, optionally a `file` (deterministic ID) and a `malware` object for
  the `--run` sample, one `indicator` per value and an `indicates` relationship to the
  malware. JA3/JA4/HASSH are left out (no STIX pattern for them).
- MISP: an event whose attributes all have `to_ids: false`, so an analyst must promote them.

These are sandbox observations. Review them before blocking anything.
