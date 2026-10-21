# Architectural inconveniences (`ARCH-*`)

These are not bugs in a single function. They are design choices that cost analysts or
maintainers time.

## ARCH-01

**The Windows diverter has never run automatically** · Medium · Confirmed

- Where: `nucleus/crates/diverter/src/windows.rs`; CI's `nucleus-windows` job; stated in
  `docs/ARCHITECTURE.md` ("type-checks for Windows but has not run on Windows").
- What: the pure reflection logic (`reflect.rs`) is unit-tested on Linux, but the
  WinDivert glue (`track_owners`, `reflect_outbound`, `reflect_forwarded`, the PowerShell
  host settings) is untested end to end.
- Fix: a self-hosted Windows VM runner, or a nightly job on a Windows VM in a cloud
  account, running the README's manual check (`curl`, `nslookup`, `ping`) through the
  diverter.

## ARCH-02

**The explorer counts scanning as new behaviour** · Medium · Confirmed

- Where: `nucleus/crates/explorer/src/explorer.rs:435` (`signatures`: a
  `destination <ip:port>` signature for every event).
- What: the reward for an answer is the number of new signatures within `window_ms`. A
  worm or scanner produces a new destination on almost every connection, whatever it
  was answered.
- Impact: for scanning samples, every template looks equally rewarding, the bandit learns
  nothing, and `explorer-map.json` attributes scanning to whichever answer came last.
- Fix: abstract destinations (count new /24s or new ports, capped per window), or
  subtract a baseline novelty rate measured on default-answered requests.

## ARCH-03

**Schema and HMAC logic exist twice** · Low · Confirmed

- Where: `nucleus/crates/schema/src/lib.rs` and `daemon/.../{LinkAuth,LinkSchema,EventIn,ActionOut}.java`;
  `schema/fakenet-link-v1.schema.json`.
- What: the two implementations agree because they share three HMAC test vectors and the
  example JSON files. Neither side validates messages against the JSON Schema at run
  time, and the protocol list is hand-copied (`WarmUpTest` now checks it against the schema).
- Fix: generate the Java constants and protocol list from the JSON Schema, and run a
  schema-validation test over both sides' serialised output.

## ARCH-04

**Payloads are stored twice** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/session.rs` (the Event, with payload, in
  `events.jsonl`) and `Capture::save_file` (`files/`).
- What: a saved upload is in `files/` and, base64-encoded, in its `event` record. (The link
  cuts payloads past `[daemon] max_payload_kb`; the daemon's audit log keeps 256 bytes and a
  SHA-256.)
- Fix: above a threshold, log the event with a preview, the SHA-256 and the `saved` path.

## ARCH-05

**Live reload is narrow** · Low · Confirmed

- Where: `nucleus/crates/cli/src/main.rs` (the SIGHUP task, `#[cfg(unix)]`).
- What: only `[defaults]` reloads. Fingerprint lists, listeners, `[limits]`, the explorer
  and YARA rules need a restart, which also replaces the CA unless `ca_cert`/`ca_key` are set. Windows has no reload
  at all.
- Fix: also reload the fingerprint map and YARA rules (both are swappable); on Windows,
  watch the config file or add a control endpoint (`POST /reload`, authenticated).

## ARCH-06

**Listener filters close connections; host filters are IP-only** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/custom.rs` (`filter`), `dispatch.rs`
  (`handle_tcp` returns after logging `filtered`).
- What: a connection failing a listener's process or host filter is closed. It isn't
  handed to another listener or let through. `host_*` entries must be IP addresses; host
  names in an imported FakeNet-NG config never match and nothing warns.
- Fix: validate host entries at load time; consider a `fallthrough` action (send to the
  `auto` listener).

## ARCH-07

**Process-wide global state** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/dns.rs` (`REVERSE`: a static PTR map, up to
  100,000 entries, never cleared); `nucleus/crates/schema/src/lib.rs` (`SESSION_COUNTER`).
- What: statics outlive config reloads (a changed `dns.pool` keeps the old PTR entries)
  and are shared between tests in one process.
- Fix: move them into `Context` (the PTR map into the DNS defaults' runtime state).
