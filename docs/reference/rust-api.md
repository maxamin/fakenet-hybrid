# Rust API reference

Every public item of the nucleus crates, by module, with what it does. Paths are relative
to `nucleus/crates/`. `cargo doc --workspace --no-deps --open` renders the doc comments.

## `schema` (`schema/src/lib.rs`)

| Item | Description |
|---|---|
| `VERSION` | Link schema version (1) |
| `Protocol`, `Protocol::name` | The 30 protocols, serialised lowercase |
| `Transport` | `Tcp`, `Udp` |
| `ProcessInfo` | `{pid, name, exe}` |
| `Event`, `EventKind` | Nucleus → daemon message (see {doc}`../architecture/link-protocol`) |
| `Action`, `ActionKind`, `Action::validate_for(&Event)` | Daemon → nucleus message; checks version, IDs and `delay_ms ≤ MAX_DELAY_MS` |
| `Hello`, `HelloKind` | Handshake message |
| `MAX_DELAY_MS` | 60,000 |
| `auth::Secret::{new, sign, verify}` | HMAC-SHA256 key; hex signing; constant-time verification of a hex signature |
| `auth::random_hex(n)` | `n` random bytes as hex (nonces, secrets) |
| `auth::{hello_text, event_text, action_text}` | The canonical signed texts |
| `EventBuilder::{new, event}` | Per-session builder: new `request_id` per event, `seq` counter, endpoints, process, TLS flag |
| `new_session_id(transport)` | `tcp-0000000000000007`, from a process-wide counter |
| `now_rfc3339`, `encode_base64`, `decode_base64` | Helpers |

## `sniffer` (`sniffer/src/`)

| Item | Description |
|---|---|
| `DEFAULT_ORDER` | Candidate protocols in tie-break order |
| `supports(protocol, transport)` | Whether the protocol exists on that transport |
| `default_ports(protocol)` | The protocol's usual ports |
| `server_speaks_first(protocol)` | Protocols whose server greets first |
| `score(protocol, data, port, transport)` | Port +1, recognised content +2 (FTP/POP3-only commands +1); raw 1 |
| `sniff(candidates, data, port, transport)` | Best-scoring protocol, ties to the earlier candidate |
| `sniff_silent(candidates, port)` | Protocol for a client that sent nothing |
| `is_dns_query`, `is_imap`, `is_redis`, `is_telnet`, `is_ntp`, `is_socks`, `is_syslog`, `is_tftp`, `looks_like_tls` | Recognisers (MQTT, CoAP, RDP, LDAP and SMB recognisers are private) |
| `syslog_priority(text)` | `<PRI>rest` → (facility, severity, rest) |
| `tls::ClientHello::{parse, ja3_string, ja3, ja4}` | ClientHello parsing (multi-record) and fingerprints |
| `tls::is_grease`, `tls::MAX_HELLO`, `tls::hello_wants_more` | GREASE test; 20 KiB bound; completeness check |
| `tls::parse_known(csv)` | Fingerprint list → `HashMap<fingerprint, label>` |

## `link` (`link/src/lib.rs`)

| Item | Description |
|---|---|
| `LinkConfig` | URLs, deadline, back-off, optional `Secret` |
| `Link::start(config)` | Builds the HTTP client and spawns the WebSocket maintainer (needs a tokio runtime) |
| `Link::decide(&Event) -> Decision` | Never fails; within the deadline; verifies the Action |
| `Link::notify(&Event)` | Fire-and-forget over the WebSocket; dropped when disconnected or the queue is full |
| `Link::health() -> Health`, `Link::deadline()` | Counters and state; the configured deadline |
| `Decision` | `Action(Action)` or `Fallback(Fallback)` |
| `Fallback` | `Disabled`, `Unavailable`, `Timeout`, `Error(String)`, `Invalid(String)` |
| `Health` | `websocket_configured`, `websocket_connected`, `http_configured`, `decisions`, `fallbacks`, `reconnects` |

## `capture` (`capture/src/`)

| Item | Description |
|---|---|
| `Limits` | `max_events_bytes`, `max_pcap_bytes`, `max_files_bytes`, `keep` (0 = unlimited) |
| `Capture::{open, open_with}` | Create the folder (first moving a previous run's outputs to `previous/<time>/`, `archive_previous`), open `events.jsonl` and a new `traffic.pcap` |
| `archive_previous(dir)`, `with_rotations(events)` | Archive a previous run; a log and its rotated siblings, oldest first |
| `Capture::log(kind, fields)` | Append and flush one record; keep it in the 5,000-record ring |
| `Capture::recent(after, limit)` | Ring records after a sequence number, and the latest number |
| `Capture::event_files()` | Rotated logs oldest first, then the current one |
| `Capture::save_file(prefix, name, data)` | Save under `files/` within the budget; queue YARA |
| `Capture::{tcp_flow, udp_datagram, wire_packet}` | Write synthesized or real packets |
| `Capture::{enable_yara, finish_scans, dir}` | YARA control; the folder |
| `TcpFlow::{client_data, server_data}` | Synthesized TCP data; `Drop` writes the FIN exchange |
| `pcap::PcapWriter::{create, write}` | Classic pcap, link type 101, flushed per packet |
| `pcap::TcpConversation::{new, open, client_data, server_data, close}` | Sequence-tracked TCP synthesis |
| `pcap::udp_packet` | One UDP packet |
| `report::{escape, render, render_with_map, render_file}` | The HTML report |
| `indicators::{Kind, Indicator, collect, to_csv, to_stix, to_misp, is_global}` | Indicator extraction and exports |
| `yara::{rule_files, compile, scan}`, `yara::Scanner::{start, queue, finish}` | YARA through the stock tools |

## `listeners` (`listeners/src/`)

Framework:

| Item | Description |
|---|---|
| `Server::start(ctx, bind, listeners)`, `Server::address(name)`, `server::Listener` | Bind and run every listener; the bound addresses |
| `Context` | Shared state: link, capture, `defaults` (`ArcSwap`), CA, timeouts, `original` lookup, explorer, limits, fingerprints |
| `Session::{new, set_protocol, protocol, log, client_data, server_data, decide, decide_with_default, answer, notify}` | Per-connection state and the decide-or-default step (hooks, then the daemon/explorer, then live manual mode) |
| `manual::{ManualConfig, Manual::{new, wants, hold, pending, resolve, release_all}, Verdict, parse_verdict}` | Live manual mode |
| `hooks::{HookConfig, HookAction, Hooks::{new, fire, paused, resume}}` | Reverse-engineering hooks (pause, dump, command) |
| `event_filter::{EventFilter, host_of, request_text}` | The protocol/host/text filter both use |
| `Original`, `OriginalLookup` | Real endpoints from a rewriting diverter (Windows) |
| `dispatch::{handle_tcp, serve, serve_tunnel, terminate_tls, udp_protocol, handle_udp}` | Handler selection, TLS, tunnels |
| `limits::{LimitsConfig, Limits::{new, admit, hold, stats}, SessionPermit, Held::grow}` | Resource limits |
| `process::{find_process, parse_socket_table, SocketEntry}` | Linux process attribution |
| `original_dst::{original_destination, enable_udp_original_destination, recv_with_original}` | Pre-NAT destinations |
| `stream::{Stream, BoxStream, MAX_LINE, read_line, read_raw_line, send, PrefixedStream}` | Stream helpers |
| `lines::{Lines::{new, read, read_raw, read_exact, send, respond, starttls}, split_command, preview}` | Line-protocol helpers |
| `custom::{parse_ini, Section, CustomResponses::{load, match_http}, HttpCustom::matches, HttpResponse, RawResponse, replace_date, run_http_provider, run_tcp_provider, run_udp_provider, filter}` | FakeNet-NG Custom Responses and listener filters |
| `tls::{TlsAuthority::{generate, load_or_create, certificate_for, config_for, server_config, log_keys_to, ca_pem, ca_der}, random_bytes, DEFAULT_HOSTNAME}` | The interception CA (new, or saved and reused) and certificates |
| `config::{ListenerConfig, ListenerProtocol, AutoKeyword, Defaults, *Defaults, RawMode, bind_any}` | Configuration types |
| `fuzzing::{tcp, udp, TCP, UDP}` (feature `fuzzing`) | Drive a handler with bytes in memory |

Protocol modules (each `handle` serves one session; see {doc}`protocols`):

| Module | Public helpers |
|---|---|
| `http` | `handle`, `answer` (shared by h1/h2/h3), `from_raw`, `connectivity_check`, `server_for`, `default_content`, `safe_join`, `mime_type`, `default_file`, `PendingUpgrade` |
| `http3` | `serve` |
| `websocket` | `is_upgrade`, `accept` |
| `dns` | `Answer`, `answer`, `handle_tcp`, `default_answer_for`, `default_answer`, `parse_answer`, `pool_address`, `looks_random` |
| `smtp`, `mqtt`, `smb`, `vnc`, `socks`, `redis` | `handle` |
| `pop3` | `handle`, `MESSAGE`, `dot_stuffed` |
| `imap` | `handle`, `parse_arguments` |
| `ftp` | `handle`, `resolve_virtual`, `parse_port_argument`, `parse_eprt_argument` |
| `tftp` | `handle`, `parse_request`, `error_packet`, opcodes `RRQ` … `ERROR` |
| `irc` | `handle`, `parse_message` |
| `ssh` | `handle`, `KexInit::{parse, hassh}` |
| `telnet` | `handle`, `strip_commands`, `shell_response` |
| `ntp` | `handle`, `reply`, `ntp_timestamp` |
| `syslog` | `handle_tcp`, `handle_udp` |
| `simple` | `handle_tcp`, `handle_udp`, `daytime_string`, `rfc868_time`, `chargen_line` |
| `raw` | `handle_tcp`, `handle_udp` |
| `ldap` | `handle`, `render_filter` (BER filter → RFC 4515 text) |
| `rdp` | `handle`, `ConnectionRequest::parse`, `client_core_data` |
| `coap` | `handle`, `Request::{parse, method}` |
| `ntlm` | `find`, `message_type`, `challenge`, `filetime_now`, `Authenticate::{parse, anonymous, hash, record}`, `der`, `spnego_init`, `spnego_response`, constants `SIGNATURE`, `DOMAIN`, `COMPUTER`, `DNS_DOMAIN` |

## `diverter` (`diverter/src/`)

| Item | Description |
|---|---|
| `DiverterConfig`, `Mode` | `[diverter]` settings |
| `Plan` | Ports and catch-all listeners, built by `Config::plan` |
| `Diverter::{start, original_lookup, stop}`, `restore()` | Platform-independent front; `Drop` restores |
| `linux::{Family, rules, cleanup_commands, cleanup, Active::{start, stop}, is_excluded}` | iptables and NFQUEUE |
| `windows::Active::{start, original_lookup, stop}` | WinDivert threads |
| `reflect::{Mode, Verdict, Reflector::{new, handle, original, is_gateway, len}}` | Pure reflection state |
| `packet::{Flow, parse, rewrite, echo_reply, internet_checksum}` | Packet decoding and rewriting |
| `host_settings::{QUERY_DNS, QUERY_DEFAULT_ROUTES, QUERY_PRIMARY, DnsSetting, PrimaryAddress, parse_dns, set_dns_script, restore_dns_script, add_route_script, remove_route_script}` | Windows DNS and route changes as generated PowerShell |
| `wire::{Sink, WireCapture::start}` | Real-packet capture |

## `explorer` (`explorer/src/`)

| Item | Description |
|---|---|
| `ExplorerConfig` | `[explorer]` settings |
| `Explorer::{load, new, config}` | Load templates and hints; build from parts |
| `Explorer::observe(&Event)` | Learn tokens, record behaviour signatures, credit recent proposals |
| `Explorer::propose(&Event) -> Option<Proposal>` | Choose and render a template (UCB1) |
| `Explorer::{reached, reached_at, ingest_drcov, ingest_coverage_line}` | Coverage input |
| `Explorer::map()` | The `explorer-map.json` value |
| `Proposal` | `response`, `close`, `template`, `tokens` |
| `signatures(&Event)` | Behaviour signatures of an event |
| `templates::{DEFAULT_TEMPLATES, Template::applies, parse, Source, render_with, mutate, mz_stub}` | Template language |
| `hints::{Hints::{merge, classify, from_binary, from_rea, from_rea_all, learn_from_traffic}, Function, name_words, sha256, extract_strings}` | Hint extraction |
| `coverage::{Drcov::{parse, addresses}, Module, CoverageEvent, FunctionMap::{new, function_at, functions_for, names, is_empty}, parse_hex}` | Coverage formats and address mapping |
| `rng::Rng::{new, next_u64, below, unit, pick}` | SplitMix64 |

## `cli` (`cli/src/`)

| Item | Description |
|---|---|
| `Config`, `NucleusConfig`, `DaemonConfig`, `YaraConfig` | The TOML model |
| `Config::{load, resolve_paths, validate, plan, secret, known_fingerprints, capture_limits, link}` | Loading, checks and conversions |
| `write_report(files, out)`, `write_indicators(files, dir, sample)` | Outputs at stop and for `--report` / `--indicators` |
| `watch_coverage(explorer, dir, capture)` | Polls `coverage_dir` every second |
| `generate_secret(path)` | `--generate-secret` |
| `Control`, `serve_control(listener, control)` | The control server |
| `run::{Sample::{inspect, folder_name}, Outcome, execute, summary}` | `--run` |
| `replay::replay(link, records)` | `--replay` |
| `har::{exchanges, rules}` | `--rules-from-har` |
| `import::convert(ini, base)` | `--import-fakenet-ini` |
| `read_records(files)` | Parse event files |
| `diff::{capture_files, behaviour, compare, render}` | `--diff` |
| `infer::{group_messages, analyse, dissector, infer, Transform, parse_transform, apply, decode}` | `--infer`, `--decode` |
