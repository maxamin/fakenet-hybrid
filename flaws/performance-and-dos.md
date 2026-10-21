# Performance and denial of service (`PERF-*`)

The nucleus faces hostile, often noisy clients: scanners, worms, DGA bursts, large
uploads. `[limits]` caps sessions and buffered payloads, but these paths are outside
those caps.

## PERF-01

**Blocking file I/O on the async runtime, under global mutexes** · Medium · Confirmed

- Where: `nucleus/crates/capture/src/lib.rs` (`log`: a `std::sync::Mutex`, then
  `write` + `flush` per record; `write_packets` / `PcapWriter::write`: a flush per
  packet), called from every tokio task. Also `std::fs::read` of webroot files in
  `http::default_content` and `save_file`.
- What: every record and every synthesized packet is a blocking syscall made by a runtime
  worker while it holds a lock that every other session needs.
- Impact: under load (thousands of events per second, or a slow disk) all listeners stall
  together, and answers miss what the deadline was meant to guarantee.
- Fix: send records and packets over a bounded channel to one writer thread that batches
  and flushes, for example every 100 ms or 64 KiB, plus an fsync policy for abrupt VM
  reverts. Use `spawn_blocking` for file reads.

## PERF-02

**`/proc` scan for every new connection** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/process.rs:68` (`find_process`), called from
  `Session::new`; and per new connection in the NFQUEUE thread (`linux.rs`).
- What: reads `/proc/net/{tcp,tcp6}` (or the UDP tables), then `readlink`s every fd of
  every process until it finds the socket inode. `is_local` binds a UDP socket per call.
  All of it is synchronous inside async code.
- Impact: a port-scanning sample costs a full `/proc` walk per connection attempt. The
  NFQUEUE thread holds the first packet of every new connection while it works.
- Fix: use `NETLINK_SOCK_DIAG` (inode and UID in one call), cache inode-to-PID, run it on
  `spawn_blocking`, and cache `is_local` from the interface list.

## PERF-03

**The memory budget ignores payload copies** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/http.rs` (body, then `raw` copy),
  `session.rs:136` (the Event, with the payload, logged as JSON with base64), `link`
  (`signed()` clones the Event, then serialises it), `daemon/.../EventIn.java:89`
  (`FakenetPayload` bytes plus `FakenetText` string plus the raw JSON property).
- What: `Held::grow` counts the body once. A 16 MiB POST then exists as roughly six copies
  in the nucleus (body, raw request, Event payload, base64 JSON for the log, a signed clone,
  base64 JSON for the link) and three or four in the daemon.
- Impact: `memory_budget_mb = 1024` allows several GB of real allocation; the daemon's
  heap (default JVM sizing) can run out under a few concurrent large uploads.
- Fix: share payloads with `Bytes`; send only a preview plus hash over the link above a
  size threshold (with `meta.saved` pointing at the file); and have `EventIn` set
  `FakenetText` lazily or only for small payloads.

## PERF-04

**HTTP/2 and HTTP/3 multiplexing is serialized** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/http.rs:27` (`Arc<Mutex<Session>>`, held across
  `respond`), `http3.rs:130`.
- What: each request locks the connection's session for the whole decision (up to the
  deadline plus latency), so requests on one connection are answered one after another.
- Impact: a browser-like client opening 50 streams waits up to 50 × 200 ms when the daemon
  is slow or absent.
- Fix: keep the per-session event counter behind a small lock and do the decision outside
  it, for example `EventBuilder` behind its own mutex and `decide` taking `&Session`.

## PERF-05

**Unbounded caches keyed by sample-controlled values** · Medium · Confirmed

- Where:
  - `nucleus/crates/listeners/src/tls.rs:129`: leaf certificates per SNI, never evicted;
    a key pair is generated while the cache mutex is held.
  - `nucleus/crates/explorer/src/explorer.rs:103`: `seen` behaviour signatures, which
    include `destination <ip:port>`.
  - `daemon/.../SessionState.java:27`: pruning removes idle actors only, so 10,000
    active actors are not a limit.
  - `nucleus/crates/listeners/src/dispatch.rs:42`: CONNECT and SOCKS tunnels create
    sessions without a `[limits]` permit and can nest without a depth limit.
- Impact: a DGA- or scanning-heavy sample grows memory for the whole run, and the TLS
  lock serialises handshakes.
- Fix: LRU caps (for example 10,000 certificates, generated outside the lock); cap `seen`
  and the tunnel nesting depth (for example 4); take a permit per tunnel session.

## PERF-06

**YARA scanning: unbounded queue, slow shutdown** · Low · Confirmed

- Where: `nucleus/crates/capture/src/yara.rs` (`mpsc::channel`, one `yara` process per
  file; `finish` at `:94`).
- What: every saved file queues a scan in one thread. At shutdown, `finish_scans` waits for
  the whole queue, and each scan may take up to 30 s.
- Impact: a sample that uploads thousands of files makes shutdown take hours.
- Fix: use `yara`'s ability to scan a folder (or libyara) in batches; bound the queue and
  log skipped files; put a time limit on `finish`.

## PERF-07

**Coverage watcher re-reads whole files** · Low · Confirmed

- Where: `nucleus/crates/cli/src/lib.rs:335`.
- What: every second, each `*.jsonl` file in `coverage_dir` is read in full, then sliced
  from the last offset. A file that isn't valid UTF-8 is skipped forever.
- Fix: keep a `File` per path and read from the saved offset as bytes.

## PERF-08

**One UDP client is served one datagram at a time** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/server.rs:161` (the per-client `Mutex<Session>`);
  `raw.rs` and `custom.rs` (UdpDynamic: one `python3` per datagram).
- What: datagrams from the same address wait for the previous decision. A resolver that
  sends many queries from one socket gets about 1 / (deadline + latency) answers per
  second while the daemon is down. Each UdpDynamic datagram starts a Python interpreter,
  up to 1,024 at a time.
- Fix: decide outside the session lock (see PERF-04); run UDP providers as one long-lived
  process fed through a pipe.

## PERF-09

**Daemon audit log grows without a limit** · Low · Confirmed

- Where: `daemon/routes/link.yaml:120`.
- What: every event, with its full payload, is appended to `events-YYYYMMDD.jsonl`. There
  is no size cap, rotation within the day, or retention. It duplicates the nucleus's
  `events.jsonl`.
- Fix: a size-based roll (`camel-file` can't do it alone; a log4j2 appender can), or
  drop payloads from the audit copy.

## PERF-10

**The report and indicators load the whole capture into memory** · Low · Confirmed

- Where: `nucleus/crates/cli/src/lib.rs` (`read_records`),
  `nucleus/crates/capture/src/report.rs` (`render_with_map`).
- What: every record, from every rotated file, is parsed into memory at stop. The report
  embeds every record including base64 payloads, so a 1 GB event log gives a
  multi-GB HTML file that browsers can't open.
- Fix: stream the records; show summaries and truncated payloads in the report, and link
  to `files/` for full content.
