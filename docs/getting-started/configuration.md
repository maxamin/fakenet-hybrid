# Configuration reference

The nucleus reads one TOML file (`fakenet-nucleus -c FILE`, default
`config/fakenet.toml`). The sample is `nucleus/config/fakenet.toml`; the container's is
`deploy/docker/fakenet.container.toml`.

Every table uses `deny_unknown_fields`, so a misspelt key is a start-up error. Relative
paths resolve against **the config file's directory** (`Config::resolve_paths` in
`nucleus/crates/cli/src/lib.rs`). That covers `capture_dir`, `fingerprints`, `yara.rules`,
`daemon.secret_file`, `defaults.http.webroot`, `defaults.ftp.root`, `defaults.tftp.root`,
each listener's `custom`, and the explorer's `templates`, `samples`, `rea` and
`coverage_dir`.

`fakenet-nucleus --check -c FILE` loads and validates the config, loads the fingerprint
lists and compiles the YARA rules, then exits. It doesn't load Custom Response INI files;
those fail only at start.

## Validation rules

`Config::validate` refuses to start when:

- `nucleus.health` is not a loopback address,
- a daemon URL's host is not `127.0.0.1`, `::1` or `localhost`,
- `deadline_ms` or `backoff_initial_ms` is 0, or `backoff_max_ms < backoff_initial_ms`,
- there is no `[[listener]]`, or two listeners share a name,
- a UDP listener has `tls = true`.

It doesn't check that an `auto` listener exists for each transport when the diverter is on.
Without one, unmatched traffic is not redirected at all (flaw LEAK-04).

## `[nucleus]`

| Key | Default | Meaning |
|---|---|---|
| `bind` | `0.0.0.0` | Address every listener binds to. `0.0.0.0` is IPv4 only, so IPv6 diversion reaches nothing unless you bind `::` |
| `capture_dir` | `capture` | Output folder. `--run` appends `<UTC time>-<name>-<sha256[:12]>` |
| `timeout_ms` | 30000 | Idle read timeout per connection. Also the TLS handshake timeout, the UDP session expiry and the QUIC idle timeout |
| `first_data_timeout_ms` | 500 | How long an `auto` listener waits for the client's first bytes before choosing a protocol by port |
| `health` | `127.0.0.1:8099` | Control server (`/health`, `/dashboard`, `/api/*`). Must be loopback |
| `max_events_mb` | 256 | Rotate `events.jsonl` past this size. 0 = never |
| `max_pcap_mb` | 1024 | Rotate `traffic.pcap` and `wire.pcap`. 0 = never, and then the previous run's `traffic.pcap` is overwritten at start (flaw BUG-03) |
| `keep_rotations` | 4 | Rotated files kept (`events.1.jsonl` is the newest) |
| `max_files_mb` | 2048 | Budget for `files/`. Past it, payloads are logged but not saved. Existing files count towards it |
| `wire_capture` | false | Record every real packet into `wire.pcap` (AF_PACKET on Linux, a WinDivert sniff handle on Windows) |
| `fingerprints` | `[]` | CSV lists of known JA3/JA4/HASSH fingerprints: first field the fingerprint, last field the label, `#` comments. Later files win |
| `tls_keylog` | true | Write TLS secrets (TCP and QUIC) to `capture/tls-keys.log` in NSS key-log format |

## `[daemon]`

| Key | Default | Meaning |
|---|---|---|
| `websocket_url` | `ws://127.0.0.1:8090/link` | Primary channel. `""` disables it |
| `http_url` | `http://127.0.0.1:8091/decide` | Secondary channel, used while the WebSocket is down. `""` disables it |
| `deadline_ms` | 200 | How long a listener waits for a decision before using its default |
| `backoff_initial_ms`, `backoff_max_ms` | 100, 10000 | WebSocket reconnect back-off. It doubles each time, plus up to 100 ms of jitter |
| `secret_file` | none | Shared secret (contents trimmed, at least 32 bytes). Authenticates the link both ways and protects `/health` details and the dashboard. Without it the link is unauthenticated and only a warning is logged |

## `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `max_sessions` | 4096 | Concurrent TCP connections, UDP client addresses and QUIC connections. 0 = unlimited. New sessions past it are dropped; existing ones are never cut |
| `per_source_per_second` | 0 (off) | Token-bucket rate of new sessions per source IP. At most 65,536 sources are tracked |
| `per_source_burst` | 200 | Bucket size |
| `memory_budget_mb` | 1024 | Shared budget for buffered payloads: HTTP bodies, SMTP DATA, FTP/TFTP uploads, Redis values, HTTP/3 bodies. It does not count the copies made for events, logging and the link (flaw PERF-03) |

Refusals are counted in `/health` and on the dashboard, and logged at most once a second.

## `[yara]`

| Key | Default | Meaning |
|---|---|---|
| `rules` | `[]` | Rule files, or folders searched recursively for `*.yar` / `*.yara` |
| `yara`, `yarac` | `yara`, `yarac` | The YARA tools |

The rules compile at start into `capture/yara-rules.compiled`; a broken rule stops the start.
Each saved file is scanned by `yara -w -a 30 -C` in one background thread.

## `[diverter]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | false | Never on by default. The INI importer never turns it on |
| `mode` | `single_host` | `single_host`: divert this host's own traffic (iptables `OUTPUT`, WinDivert outbound). `gateway`: divert traffic this host routes (`PREROUTING`, WinDivert forward layer) |
| `ignore_ports` | `[]` | Destination ports never diverted, TCP and UDP. **Traffic to them reaches the real network** |
| `excluded_processes` | `[]` | Process names never diverted. Linux matches the `comm` name (15 characters), Windows the image file name. Single-host mode only. A sample can claim one of these names (flaw LEAK-02) |
| `queue_num` | 4242 | Linux NFQUEUE number, used only with `excluded_processes` |
| `ipv6` | true | Also install ip6tables rules. A failure is only a warning, and IPv6 then leaves undiverted (flaw LEAK-03) |
| `answer_ping` | true | ICMP echo to any address gets a reply |
| `gateway_address` | `[]` | Windows gateway mode: this host's addresses on the analysis network |
| `fix_dns`, `fix_dns_server` | false, `192.0.2.53` | Windows: point every interface's DNS at this server while running (FakeNet-NG ModifyLocalDNS); restored on stop |
| `fix_gateway` | false | Windows: add a default route if there is none (FakeNet-NG FixGateway); removed on stop |

## `[defaults]`: the built-in answers

Sending **SIGHUP** (Unix) reloads only this table, live, and logs `config_reloaded`.
Listeners, `bind`, the diverter, the link, `[limits]`, the fingerprint lists, YARA and the
explorer need a restart.

| Key | Default | Meaning |
|---|---|---|
| `latency_ms` | `[0, 0]` | Random delay `[min, max]` before every answer |
| `http.webroot` | none | Files served by request path. A missing file gets FakeNet-NG's default file of its type (`FakeNetMini.exe` for `.exe`, and so on) |
| `http.server_header` | `Microsoft-IIS/10.0` | The `Server` header. `auto` picks a plausible one per host |
| `http.max_body_bytes` | 16 MiB | Larger request bodies get a 413 |
| `http.save_bodies` | true | Save non-empty request bodies under `files/` |
| `http.connectivity_checks` | true | Answer Windows NCSI, Android/Chrome `generate_204`, Apple, Firefox, Ubuntu and GNOME connectivity probes like the real services |
| `dns.a` | `192.0.2.123` | Address for every A (and ANY) query |
| `dns.per_domain` | false | Give each name a stable address from `dns.pool` (FNV-1a hash), with matching PTR answers |
| `dns.pool` | `198.18.0.0/15` | IPv4 CIDR for `per_domain` (prefix /30 or shorter) |
| `dns.nxdomain_random` | false | NXDOMAIN for names whose first label looks random (DGA-style) |
| `dns.aaaa` | none | Address for AAAA queries. None means an empty answer (NODATA) |
| `dns.mx` | `mail.fakenet.local` | MX answer, preference 10 |
| `dns.txt` | `FAKENET` | TXT answer. Keep it under 256 bytes (flaw BUG-01) |
| `dns.ttl` | 60 | TTL of every answer |
| `raw.mode`, `raw.response` | `echo`, `""` | Raw listeners echo, or (`static`) send `response` |
| `mail.hostname` | `mail.fakenet.local` | SMTP greeting and EHLO name |
| `ftp.root` | none | Files served by RETR and listed by LIST |
| `ftp.banner` | `FTP Server Ready` | 220 greeting |
| `ftp.passive_ports` | `[0, 0]` | Passive data port range. **Set a range when diverting**: the diverter keeps that range's ports, while `[0, 0]` picks random ports that the diverter sends to the `auto` listener instead (flaw BUG-06). The sample config uses `[60000, 60010]` |
| `irc.server_name` | `irc.fakenet.local` | Server prefix |
| `tftp.root` | none | Files served on RRQ |
| `ssh.banner` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | Version string |
| `telnet.banner` | `Ubuntu 20.04.6 LTS` | Pre-login banner |
| `ntp.time_offset` | 0 | Seconds added to the time served |

## `[[listener]]`

| Key | Meaning |
|---|---|
| `name` | Unique. Appears in every record. Matches FakeNet-NG's `InstanceName` in Custom Response files |
| `protocol` | One of `http dns raw smtp pop3 ftp tftp irc imap ssh telnet redis ntp socks syslog echo discard daytime chargen time qotd finger whois mqtt coap vnc rdp ldap smb websocket`, or `auto` (sniff each connection) |
| `transport` | `tcp` (default) or `udp`. `http` over UDP means HTTP/3 |
| `port` | Port to bind. 0 picks a free one |
| `tls` | Terminate TLS before the protocol (TCP only). On an `auto` listener it forces TLS |
| `custom` | A FakeNet-NG Custom Response INI. Only for `http` and `raw` listeners |
| `process_whitelist`, `process_blacklist` | Process names or exe basenames, case-insensitive. Connections that fail the filter are closed and logged as `filtered` |
| `host_whitelist`, `host_blacklist` | Destination **IP addresses** only. Host names never match |

The diverter's plan comes from the listeners (`Config::plan`): ports of fixed-protocol
listeners keep their port, the FTP passive range keeps its ports, and everything else goes
to the first `auto` listener of its transport.

## `[explorer]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | false | Turn the explorer on |
| `rate` | 0.8 | Probability of answering an undecided request with a template |
| `seed` | `0x5eed` | RNG seed; runs are deterministic for a seed |
| `window_ms` | 3000 | How long after an answer new behaviour is credited to it |
| `coverage_weight` | 5.0 | Reward per newly reached function |
| `templates` | `[]` | Extra template files, added to the built-in `templates/default.toml` |
| `samples` | `[]` | Binaries to extract hint strings from. `--run` adds the sample when empty |
| `rea` | `[]` | REA (Reverse Engineer Anything) JSON/JSONL analyses |
| `coverage_dir` | none | Folder a tracer writes drcov logs or JSONL coverage into |
| `module`, `image_base` | none, `0x400000` | Map coverage addresses to REA functions |
| `protocols` | `[]` (all with templates) | Restrict exploration to these protocols |

See {doc}`../usage/explorer`.

## Daemon properties

Set them in `daemon/src/main/resources/application.properties`, with `-Dname=value`, or
with `CAMEL_*` environment variables.

| Property | Default | Meaning |
|---|---|---|
| `camel.main.routes-include-pattern` | `file:routes/*.yaml` | Relative to the working directory: start the daemon from `daemon/` |
| `camel.main.routes-reload-*` | enabled, dir `routes`, `*.yaml`, remove-all false | Hot reload, file by file |
| `camel.server.host`, `.port` | `127.0.0.1`, 8091 | `POST /decide` |
| `camel.management.host`, `.port` | `127.0.0.1`, 8092 | `/observe/health` |
| `fakenet.link.secret-file` | blank (unauthenticated) | Same file as the nucleus's `secret_file` |
| `fakenet.link.host`, `.port` | `127.0.0.1`, 8090 | WebSocket `/link` |
| `fakenet.audit.dir` | `audit` | Wire Tap JSONL, `events-YYYYMMDD.jsonl` |
| `fakenet.siem.ecs-uris`, `fakenet.siem.splunk-uris`, `fakenet.siem.splunk-token`, `fakenet.siem.syslog-uris` | blank | SIEM outputs; comma-separated Camel URIs. See {doc}`../usage/siem` |
| `fakenet.library.*` | see the rules library | Parameters of `daemon/rules-library/` routes |
