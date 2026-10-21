# Performance and denial of service (`PERF-*`)

The nucleus faces hostile, often noisy clients: scanners, worms, DGA bursts, large
uploads. `[limits]` caps sessions and buffered payloads, but these paths are outside
those caps.

## PERF-03

**The memory budget counts one copy of each payload** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/http.rs` (body, then the `raw` request copy),
  `session.rs` (the Event's payload, then its JSON for `events.jsonl`).
- What: `Held::grow` counts a body once, but inside the nucleus a large request still
  exists about four times while it is handled (body, raw request, Event payload, the
  base64 JSON line). The link (`[daemon] max_payload_kb`), the dashboard ring (4 KiB per
  record), the daemon's text header and its audit log no longer copy large payloads.
- Impact: `memory_budget_mb` understates real use by a factor of about four for large
  uploads.
- Fix: share the body as `Bytes` between the request, the Event and the log writer, and
  serialise the event line straight from it.

## PERF-08

**UdpDynamic providers start one interpreter per datagram** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/custom.rs` (`run_udp_provider`).
- What: each datagram to a listener with a UdpDynamic Custom Response starts `python3`.
  (Datagrams from one client are otherwise answered concurrently.)
- Impact: a chatty UDP sample costs an interpreter start per packet.
- Fix: run UDP providers as one long-lived process fed through a pipe.
