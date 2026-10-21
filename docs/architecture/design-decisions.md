# Design decisions and trade-offs

The original design notes are in `docs/ARCHITECTURE.md`. This page summarises each
decision with what it costs, and links the related flaws.

| # | Decision | Why | Cost |
|---|---|---|---|
| 1 | The nucleus never depends on the daemon: defaults first, a 200 ms deadline | The sample sees timely answers whatever happens to the daemon | A scripted reply slower than the deadline is lost for that request. `delay_ms` exists so deliberate slowness doesn't count |
| 2 | One WebSocket carries all requests, correlated by `request_id` | Few sockets, a simple daemon | Correlation logic in the nucleus |
| 3 | Per-protocol response encodings (raw HTTP, DNS text lines, raw bytes) | Groovy can write exactly what malware expects; DNS wire format in Groovy is error-prone | Each protocol has its own rule format to learn |
| 4 | Parsed `meta` next to the raw `payload` | Rules switch on `meta.host` or `meta.qname` without parsing | Payloads travel and are stored in full (ARCH-04, PERF-03) |
| 5 | Linux: iptables REDIRECT plus NFQUEUE marking, not NFQUEUE rewriting | The kernel does NAT robustly and fast; NFQUEUE only sees first packets | Needs the `nat` table and `nfnetlink_queue`. The block comes from a separate filter chain (`block_rules`) |
| 6 | Synthesized `traffic.pcap` | Analysts see plaintext, TLS already decrypted | Not byte-exact; `wire.pcap` covers that |
| 7 | Stock Camel only | Analysts use documented components; upgrades are easy | Workarounds such as the warm-up |
| 8 | Lab-only exposure: the control plane on loopback, enforced | The analysis network can't reach it | Malware in the same VM can still reach loopback (hence 12) |
| 9 | Two route files, reloaded separately | Saving rules never drops the WebSocket | A rule file can't redefine link route IDs |
| 10 | Warm up, then open the channels | Groovy's first compile can take seconds | Scripts run once on placeholder data; `WarmUpTest` keeps the protocol list equal to the schema |
| 11 | An empty body means "default" | Rules describe only what's interesting; a failing rule degrades to the default | None significant |
| 12 | The link is authenticated with a shared secret | Malware on loopback can't impersonate either side | Partial coverage (SEC-04), the HTTP channel (SEC-05), the secret reused as a cookie (SEC-03) |
| 16 | Live manual mode and hooks may hold a client past the deadline | Reverse engineering needs the analyst (or a debugger) in the loop | Opt-in and filtered; held requests time out to the proposed answer |
| 13 | The CA is saved once (`ca_cert`/`ca_key`) and reused | The VM trusts it across restarts and snapshots | Its private key sits on disk (mode 0600); without the two keys, a fresh CA per start |
| 14 | SMB, LDAP, RDP and VNC capture credentials, then fail the logon | A fake server can't derive real session keys; worms then try their next credential, which is captured too | No post-logon behaviour is observed |
| 15 | The explorer only changes answers the rules left at the default | The analyst stays in control; nothing is sent proactively | Its reward signal is noisy for scanning samples (ARCH-02) |

## Verification status

| Part | How it's verified |
|---|---|
| Sniffer, schema, link, capture, listeners | `cargo test`: real protocol clients, TLS, STARTTLS, HTTP/2, tunnels, Custom Responses, filters, fallbacks, forged actions |
| Daemon | `mvn test`: HMAC vectors, processors, the shipped rules, the rules library, session state, SIEM documents |
| Rust–Camel link | `camel_link.rs` against the real jar: handshake, both channels, scripted replies, hot reload, Wire Tap, kill and restart |
| Fuzzing | Five cargo-fuzz targets. Found and fixed: an out-of-bounds read on IHL < 5, control characters in the INI importer's output, a report escaping case |
| Explorer | Unit tests, a simulated bot on real REA output, and the demo on a real binary |
| Interop | `scripts/interop.sh`: 42 checks with real clients |
| Linux diverter | Rule generation unit-tested; end-to-end test in a private network namespace in CI |
| Windows diverter | Pure logic unit-tested; WinDivert glue never executed in CI (ARCH-01) |
