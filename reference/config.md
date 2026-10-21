# Configuration reference

The nucleus reads TOML (`fakenet-nucleus -c FILE`). Every table uses
`deny_unknown_fields`, so a typo is a startup error. Relative paths resolve against
the config file's directory (`Config::resolve_paths`, `cli/src/lib.rs`). That covers
`capture_dir`, `fingerprints`, `yara.rules`, `daemon.secret_file`, `defaults.http.webroot`,
`defaults.ftp.root`, `defaults.tftp.root`, `listener.custom` and the explorer's `templates`,
`samples`, `rea` and `coverage_dir`.

`Config::validate` enforces the following:

- `nucleus.health` is a loopback address.
- Daemon URLs point at 127.0.0.1, ::1 or localhost.
- `deadline_ms` > 0, `backoff_initial_ms` > 0, and `backoff_max_ms` >= `backoff_initial_ms`.
- There is at least one `[[listener]]`.
- Listener names are unique.
- No `tls = true` on a UDP listener.

## `[nucleus]` (`NucleusConfig`)

| Key | Default | Meaning |
|---|---|---|
| `bind` | `0.0.0.0` | Address every listener binds to |
| `capture_dir` | `capture` | Output folder. `--run` appends `<time>-<name>-<sha12>` |
| `timeout_ms` | 30000 | Idle read timeout per connection. Also used as the TLS handshake timeout and the UDP session expiry |
| `first_data_timeout_ms` | 500 | How long an auto listener waits for the client's first bytes before choosing by port |
| `health` | `127.0.0.1:8099` | Control server (`/health`, `/dashboard`, `/api/*`). Must be loopback |
| `max_events_mb` | 256 | Rotate `events.jsonl` past this size (0 = never) |
| `max_pcap_mb` | 1024 | Rotate `traffic.pcap` / `wire.pcap`. 0 = never, **and the previous run's pcap is truncated** (flaw `BUG-09`) |
| `keep_rotations` | 4 | Rotated files kept |
| `max_files_mb` | 2048 | Budget for `files/`. Past it, payloads are logged but not saved |
| `wire_capture` | false | AF_PACKET (Linux) or WinDivert sniff (Windows) into `wire.pcap` |
| `fingerprints` | `[]` (sample config: `["fingerprints/sslbl-ja3.csv"]`) | CSV lists: fingerprint first, label last |
| `tls_keylog` | true | NSS key log at `capture/tls-keys.log` |

## `[daemon]` (`DaemonConfig`)

| Key | Default | Meaning |
|---|---|---|
| `websocket_url` | `ws://127.0.0.1:8090/link` | Primary channel. `""` disables it |
| `http_url` | `http://127.0.0.1:8091/decide` | Fallback channel. `""` disables it |
| `deadline_ms` | 200 | Per-decision wait. After it, the default answer is used |
| `backoff_initial_ms` / `backoff_max_ms` | 100 / 10000 | WebSocket reconnect backoff (doubles each time, with up to 100 ms of jitter) |
| `secret_file` | none | Shared HMAC secret (trimmed, at least 32 bytes). Also the dashboard and `/health` token |

## `[limits]` (`listeners::LimitsConfig`)

| Key | Default | Meaning |
|---|---|---|
| `max_sessions` | 4096 | Concurrent TCP connections + UDP clients + QUIC connections. 0 = unlimited |
| `per_source_per_second` | 0 (off) | Token bucket of new sessions per source IP |
| `per_source_burst` | 200 | Bucket size |
| `memory_budget_mb` | 1024 | Shared budget for buffered payloads (HTTP bodies, SMTP DATA, FTP/TFTP uploads, Redis values) |

## `[yara]`

`rules` (files or folders, scanned recursively for `*.yar`/`*.yara`), `yara` (default
`yara`), `yarac` (default `yarac`). The rules compile at start into
`capture/yara-rules.compiled`.

## `[diverter]` (`diverter::DiverterConfig`)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | false | Never on by default. Imports never turn it on |
| `mode` | `single_host` | `single_host` (iptables OUTPUT / WinDivert outbound) or `gateway` (PREROUTING / forward layer) |
| `ignore_ports` | `[]` | Destination ports that are never diverted (both transports). **They go to the real network** |
| `excluded_processes` | `[]` | Process names that are never diverted. Linux matches the `comm` name, Windows the image file name. Single-host only |
| `queue_num` | 4242 | Linux NFQUEUE number (only used with `excluded_processes`) |
| `ipv6` | true | Also install ip6tables rules. If that fails, only a warning is logged |
| `answer_ping` | true | ICMP echo to any address gets a reply |
| `gateway_address` | `[]` | Windows gateway mode: this host's analysis-network IPs |
| `fix_dns`, `fix_dns_server` | false, `192.0.2.53` | Windows: repoint every interface's DNS server while running |
| `fix_gateway` | false | Windows: add a default route if there is none |

## `[defaults]` (`listeners::Defaults`): built-in answers, reloadable with SIGHUP

| Key | Default |
|---|---|
| `latency_ms` | `[0, 0]`: random delay before each answer |
| `http.webroot` | none. `http.server_header` `Microsoft-IIS/10.0` (or `auto`), `http.max_body_bytes` 16 MiB, `http.save_bodies` true, `http.connectivity_checks` true |
| `dns.a` | `192.0.2.123`. `dns.per_domain` false, `dns.pool` `198.18.0.0/15`, `dns.nxdomain_random` false, `dns.aaaa` none, `dns.mx` `mail.fakenet.local`, `dns.txt` `FAKENET`, `dns.ttl` 60 |
| `raw.mode` | `echo` or `static`, with `raw.response` |
| `mail.hostname` | `mail.fakenet.local` |
| `ftp.root` | none. `ftp.banner` `FTP Server Ready`, `ftp.passive_ports` `[0, 0]` |
| `irc.server_name` | `irc.fakenet.local` |
| `tftp.root` | none |
| `ssh.banner` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` |
| `telnet.banner` | `Ubuntu 20.04.6 LTS` |
| `ntp.time_offset` | 0 seconds |

SIGHUP swaps only `[defaults]` (`ctx.defaults`, an `ArcSwap`). Fingerprint lists,
listeners, limits, the link and the explorer are not reloaded (flaw `DOC-02`).

## `[[listener]]` (`listeners::ListenerConfig`)

| Key | Meaning |
|---|---|
| `name` | Unique. Shown in records. Matches FakeNet-NG `InstanceName` in Custom Responses |
| `protocol` | One of `http dns raw smtp pop3 ftp tftp irc imap ssh telnet redis ntp socks syslog echo discard daytime chargen time qotd finger whois mqtt coap vnc rdp ldap smb websocket`, or `auto` |
| `transport` | `tcp` (default) or `udp`. `http` on UDP means HTTP/3 |
| `port` | Port to bind. 0 picks a free one |
| `tls` | Terminate TLS first (TCP only) |
| `custom` | FakeNet-NG Custom Response INI (`http` or `raw` listeners only) |
| `process_whitelist`, `process_blacklist`, `host_whitelist`, `host_blacklist` | Per-listener filters. Process entries match the name or the exe basename, case-insensitively. Host entries match IPs only |

The diverter plan comes from the listeners (`Config::plan`): fixed-protocol ports keep
their port, everything else goes to the first `auto` listener of its transport, and the
FTP passive range keeps its port.

## `[explorer]` (`explorer::ExplorerConfig`)

`enabled` (false), `rate` (0.8), `seed` (0x5eed), `window_ms` (3000), `coverage_weight`
(5.0), `templates`, `samples`, `rea`, `coverage_dir`, `module`, `image_base` (default
0x400000 when drcov is parsed), `protocols` (empty = all). See [explorer.md](explorer.md).

## Daemon properties (`daemon/src/main/resources/application.properties`)

Set them with `-Dname=value` or `CAMEL_*` environment variables.

| Property | Default | Meaning |
|---|---|---|
| `camel.main.routes-include-pattern` | `file:routes/*.yaml` | Relative to the working directory |
| `camel.main.routes-reload-*` | enabled, dir `routes`, `*.yaml`, remove-all false | Hot reload, file by file |
| `camel.server.host`/`port` | 127.0.0.1:8091 | `POST /decide` |
| `camel.management.host`/`port` | 127.0.0.1:8092 | `/observe/health` |
| `fakenet.link.secret-file` | blank (unauthenticated) | Same file as the nucleus |
| `fakenet.link.host`/`port` | 127.0.0.1:8090 | WebSocket `/link` |
| `fakenet.audit.dir` | `audit` | Wire Tap JSONL (`events-YYYYMMDD.jsonl`) |
| `fakenet.siem.ecs-uris`, `fakenet.siem.splunk-uris`, `fakenet.siem.splunk-token`, `fakenet.siem.syslog-uris` | blank | SIEM outputs (comma-separated Camel URIs) |
| `fakenet.library.tasks`, `fakenet.library.irc-command`, `fakenet.library.kill-switch-domains`, `fakenet.library.kill-switch-mode` | see rules library | Rules-library parameters |
