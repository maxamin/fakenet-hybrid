# Functional bugs (`BUG-*`)

## BUG-01

**DNS TXT strings over 255 bytes: no answer at all** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/dns.rs:132` (`TXT::new(vec![value])`), `:195`
  (`response.to_vec().ok()?`); also `default_answer` for `defaults.dns.txt`.
- What: a DNS character-string holds at most 255 bytes. A longer TXT value, from a rule or
  from `defaults.dns.txt`, makes encoding fail. `answer` then returns `None`, so the client
  gets no reply and nothing explains why in `events.jsonl` (the `decision` record looks
  normal).
- Impact: DNS TXT tasking (`rules-library/dns-txt-tasking.yaml`) with long base64 tasks
  silently times out.
- Fix: split long values into 255-byte chunks (`TXT::new(chunks)`, as real servers do),
  and log an `invalid_answer` record when encoding fails.

## BUG-02

**An error while removing diversion skips every output** · Medium · Confirmed

- Where: `nucleus/crates/cli/src/main.rs:265-267`: `diverter.stop()?`.
- What: on error, `main` returns before `finish_scans`, `nucleus_stopped`, `report.html`,
  `run.json` and the indicators.
- Impact: a failing `iptables -D` (for example the xtables lock, or a rule removed by
  hand) loses the run's summary outputs. `events.jsonl` and the pcaps survive.
- Fix: log the error and continue; return a non-zero status at the end.

## BUG-03

**`max_pcap_mb = 0` truncates the previous capture** · Low · Confirmed

- Where: `nucleus/crates/capture/src/lib.rs:98-101`.
- What: the previous `traffic.pcap` is rotated only when `max_pcap_bytes > 0`.
  `PcapWriter::create` then truncates the file.
- Fix: always rotate an existing file at start (with `keep.max(1)`), or open a new
  timestamped file.

## BUG-04

**Re-using a capture folder overwrites saved files and mixes runs** · Medium · Confirmed

- Where: `nucleus/crates/capture/src/lib.rs:203-205` (`file_counter` starts at 0;
  `std::fs::write` truncates), `open_with` (`events.jsonl` is appended);
  `main.rs:163-166` (`ca.pem` rewritten).
- What: without `--run`, every start uses the same `capture_dir`. Saved names are
  `<prefix>_<counter>_<name>`, with the counter starting from 0, so the second run's first
  `http_body` for `/gate.php` overwrites the first run's. `events.jsonl` keeps growing
  across runs, and the report and indicators written at stop cover every run.
- Impact: lost evidence, and indicators attributed to the wrong sample.
- Fix: start the counter after the highest existing number, or open with
  `create_new` and retry. Log a `nucleus_started` boundary and render only the current run
  by default, or give every start its own sub-folder as `--run` does.

## BUG-05

**A new CA on every start** · High · Confirmed

- Where: `nucleus/crates/cli/src/main.rs:163` (`TlsAuthority::generate()`),
  `nucleus/crates/listeners/src/tls.rs:52-70`.
- What: the interception CA is generated in memory at each start and written to
  `capture/ca.pem`. Its private key is never saved.
- Impact: after any restart (SIGHUP doesn't restart, but a config change, crash or reboot
  does), every TLS client in the VM fails with `tls_failed` until the new `ca.pem` is
  installed. VM snapshots taken with the old CA trusted are useless.
- Fix: add `[nucleus] ca_cert` / `ca_key` (PEM): load them when present, otherwise
  generate them once and save the key with 0600 permissions next to the config.

## BUG-06

**Default FTP passive ports break under diversion** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/config.rs` (`FtpDefaults`: `(0, 0)`),
  `nucleus/crates/cli/src/lib.rs:230` (no passive range in the plan), `ftp.rs`
  (`passive` binds port 0).
- What: with `[0, 0]`, PASV binds a random port. The diverter has no rule for it, so the
  client's data connection hits the catch-all REDIRECT and lands on the `auto` listener,
  not the waiting data socket. The sample config sets `[60000, 60010]`, but configs written
  from scratch or by `--import-fakenet-ini` without a port range get the broken default.
- Fix: default to a range, or reject `[0, 0]` when the diverter is enabled.

## BUG-07

**Line protocols store lossy UTF-8; long lines abort** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/stream.rs:55` (`String::from_utf8_lossy`),
  `MAX_LINE = 8192`; `smtp.rs:143` (`read_message`).
- What: SMTP DATA (and every line handler) reads lines as `String`. Bytes that aren't
  UTF-8 become U+FFFD. A line over 8 KiB is an error that drops the connection.
- Impact: `.eml` files of 8-bit messages (Latin-1, Shift-JIS, raw binary) are corrupted,
  so hashes and YARA matches differ from the real payload. An unwrapped long line
  loses the whole message.
- Fix: read `Vec<u8>` (`read_raw_line`) for DATA and keep the bytes. Allow longer DATA lines
  or store over-long ones in pieces.

## BUG-08

**Sniffing reads once** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/dispatch.rs:107` (`peek`: one `read` of up to
  4 KiB).
- What: the protocol is chosen from whatever the first `read` returns. A client that writes
  its request in pieces (`GE` then `T / HTTP/1.1`), a DNS-over-TCP client that writes the
  length prefix separately, or a slow link gives the sniffer a fragment, and the session
  becomes `raw` (or the wrong protocol) for its whole life.
- Fix: keep reading until a recogniser is confident, `first_data_timeout` passes, or 4 KiB
  arrive. The scoring is pure, so re-scoring each time is cheap.

## BUG-09

**No process attribution for wildcard-bound UDP clients** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/process.rs:81`.
- What: the socket table is searched for `local == client address`. A UDP client that calls
  `sendto()` without `connect()` is bound to `0.0.0.0:port` (`[::]:port`), so the table
  shows the wildcard address and never matches.
- Impact: missing `process` on many DNS and other UDP events, so process filters,
  per-process report grouping and the daemon's `FakenetActor` fall back to the IP.
- Fix: fall back to matching the port with a wildcard local address.

## BUG-10

**HTTP/3 events record the listener as the destination** · Medium · Confirmed

- Where: `nucleus/crates/listeners/src/http3.rs:61` and the `Session::new(..., None)` call
  after it.
- What: QUIC goes through quinn, which doesn't expose `IP_ORIGDSTADDR`, so the
  REDIRECTed original destination is lost. `dst` becomes the local IP and the listener's
  port.
- Impact: HTTP/3 events, the pcap and the indicators lose the IP the sample contacted
  (the SNI is still recorded).
- Fix: look the flow up in conntrack (netlink, or `/proc/net/nf_conntrack`) by the client's
  address and port, or wrap the UDP socket so quinn receives `IP_ORIGDSTADDR`.

## BUG-11

**TFTP data under Linux diversion** · Low · Likely

- Where: `nucleus/crates/listeners/src/tftp.rs:92` (`bind_transfer`).
- What: each transfer uses a new socket bound to `session.local` (often `0.0.0.0`) and
  connected to the client. Its packets are a new flow without the REDIRECT's reverse NAT,
  so they come from the VM's own address rather than the address the client asked for.
  RFC 1350 clients that check the server address drop them. `linux_diversion.rs` doesn't
  test TFTP.
- Fix: reply from an address equal to the original destination (`IP_TRANSPARENT` with a
  bind to it, or an SNAT rule for the transfer port).

## BUG-12

**Daemon warm-up skips ten protocols** · Low · Confirmed

- Where: `daemon/src/main/java/lab/fakenet/daemon/WarmUp.java:40`.
- What: placeholder events are sent for 20 protocols. `socks`, `syslog`, `echo`,
  `discard`, `daytime`, `chargen`, `time`, `qotd`, `finger` and `whois` are missing.
- Impact: a Groovy rule for, say, `whois` compiles on the first real request and may miss
  the 200 ms deadline.
- Fix: derive the list from the schema's protocol enum, or keep it in `LinkSchema` with a
  test comparing it to `schema/fakenet-link-v1.schema.json`.

## BUG-13

**`--report FILE` ignores rotated logs** · Low · Confirmed

- Where: `nucleus/crates/cli/src/main.rs` (`--report` passes one file to `write_report`).
- What: the report written at stop reads `events.N.jsonl` and `events.jsonl`; the
  stand-alone `--report` and `--indicators` read only the file named.
- Fix: when given `events.jsonl`, also read its rotated siblings, or accept several files.

## BUG-14

**Custom Response `HttpURIs` and query strings** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/http.rs:212` (`match_http(host, &parts.uri.to_string())`),
  `custom.rs` (`uri.ends_with(u)`).
- What: the URI is matched by suffix including the query string, so `HttpURIs: /gate.php`
  doesn't match `/gate.php?id=1`.
- Fix: match on the path, or on both, and document which.

## BUG-15

**HttpDynamic: request write outside the timeout** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/custom.rs:246`.
- What: `stdin.write_all` of the JSON request (up to `max_body_bytes`, base64) runs before
  the 30 s `PROVIDER_TIMEOUT` starts. A provider that never reads stdin blocks the HTTP
  session indefinitely.
- Fix: put the write inside the timeout, or write from a spawned task.

## BUG-16

**`nxdomain_random` false positives** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/dns.rs:48` (`looks_random`).
- What: any first label of 10+ characters with a run of 5 consonants counts as random, for
  example `strengthsfinder`, `schwarzschild`, `nightscripts`. They get NXDOMAIN.
- Fix: use a character n-gram or entropy score with a threshold tuned on a top-sites list,
  and add those names to the tests.

## BUG-17

**IMAP literals** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/imap.rs` (`parse_arguments`).
- What: `{n}` literals are not supported. For `a LOGIN {5}`, the handler logs the username
  as `{5}` with no password and answers `OK` at once. The client, still waiting for a `+`
  continuation, then sends the literal, which is parsed as a new command. The real
  credential never appears in a `credentials` record.
- Fix: on a trailing `{n}`, send `+ Ready`, read `n` bytes, and continue the line.

## BUG-18

**CA validity starts after its leaf certificates'** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/tls.rs:60` (CA `not_before = now - 1 day`) and
  `:119` (leaf `not_before = now - 30..200 days`).
- What: leaf certificates claim to be issued months before their issuer existed. Most TLS
  stacks accept it; a sandbox check comparing the dates would not.
- Fix: back-date the CA by more than the oldest leaf (for example 2-3 years), which also
  fits the realism goal.

## BUG-19

**The report's Credentials section leaves out captured hashes** · Low · Confirmed

- Where: `nucleus/crates/capture/src/report.rs` (the `"credentials"` arm of
  `render_with_map` lists `username`, `password`, `mechanism` and `apop_digest` only).
- What: NTLM (SMB, LDAP, RDP) and VNC credential records carry their crackable line in
  `hash` (with `hash_type`). The key-indicator summary shows the user name but not the
  hash; it's only visible in the per-record details further down.
- Fix: add `hash_type` and `hash` to the summary keys.
