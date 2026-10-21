# Listeners (`nucleus/crates/listeners/src`)

## Framework

| Module | Key items | What it does |
|---|---|---|
| `server.rs` | `Server::start(ctx, bind, listeners)`, `Listener`, `serve_tcp`, `serve_udp`, `is_http3` | Binds each listener, loads Custom Responses, and admits sessions through `Limits::admit`. Each UDP client address is one session, with 1024 datagrams in flight at most and expiry after `timeout_ms` idle. Dropping the server stops everything |
| `session.rs` | `Context`, `Session::new`, `decide`, `answer`, `notify`, `log`, `client_data`/`server_data`, `set_protocol`, `Original`, `OriginalLookup` | Per-connection state. `decide` logs the `event`, feeds it to the explorer, asks the link, applies `delay_ms` and the latency jitter, then lets the explorer answer whatever the daemon left at the default. `answer` = the decision's bytes, or else the default. `Drop` sends a closed notify and logs `session_end` |
| `dispatch.rs` | `handle_tcp`, `serve`, `serve_tunnel`, `terminate_tls`, `read_client_hello`, `peek`, `udp_protocol`, `handle_udp` | Picks the handler. A fixed listener with TLS terminates TLS first. An auto listener does one read of up to 4 KiB, unwraps TLS if it looks like TLS and peeks again, then calls `sniff` (or `sniff_silent` after `first_data_timeout`). Proxy CONNECT and SOCKS tunnels become new auto sessions. `terminate_tls` logs `tls_handshake` with SNI, certificate name, ALPN, JA3, the JA3 string, JA4 and any known label |
| `limits.rs` | `LimitsConfig`, `Limits::{new, admit, hold, stats}`, `SessionPermit`, `Held::grow` | Session semaphore, per-source token bucket (at most 65536 sources tracked), shared memory budget. Warnings are rate-limited to one per second |
| `process.rs` | `find_process`, `parse_socket_table`, `SocketEntry` | Linux: finds the socket in `/proc/net/{tcp,tcp6,udp,udp6}`, then scans every `/proc/<pid>/fd` for `socket:[inode]`, newest PID first. Only for local client IPs. Non-Linux returns None |
| `original_dst.rs` | `original_destination`, `enable_udp_original_destination`, `recv_with_original` | `SO_ORIGINAL_DST` (TCP) and `IP(V6)_RECVORIGDSTADDR` with `recvmsg` (UDP) |
| `stream.rs` | `BoxStream`, `read_line`, `read_raw_line` (8 KiB max), `send`, `PrefixedStream` | Bounded line I/O, and replaying peeked bytes |
| `lines.rs` | `Lines::{read, read_raw, read_exact, send, respond, starttls}`, `split_command`, `preview` | Line protocols. `starttls` throws away pipelined bytes and logs `starttls_injection_discarded` (CVE-2011-0411 class) |
| `custom.rs` | `parse_ini`, `Section`, `CustomResponses::{load, match_http}`, `HttpCustom::matches`, `HttpResponse`, `RawResponse`, `replace_date`, `run_http_provider`, `run_tcp_provider`, `run_udp_provider`, `filter` | FakeNet-NG Custom Responses. Python providers run as `python3 -I -c providers.py`. HTTP providers get the request as JSON on stdin with a 30 s timeout. TCP providers get the socket as fd 3. UDP providers get the listener's socket as fd 3 and the datagram in environment variables. `filter` applies the process and host white/blacklists |
| `providers.py` | `Handler`, `load`, `main` | Shim that imitates `BaseHTTPRequestHandler` for unmodified FakeNet-NG providers |
| `tls.rs` | `TlsAuthority::{generate, certificate_for, config_for, server_config, log_keys_to, ca_pem, ca_der}`, `random_bytes`, `DEFAULT_HOSTNAME = "fakenet.local"` | Per-run CA. Leaf certificates are minted per SNI or IP and cached: random serial, backdated 30–200 days, lifetime of 90, 365 or 397 days. NSS key log |
| `config.rs` | `ListenerConfig`, `ListenerProtocol::{Fixed, Auto}`, `Defaults` and the `*Defaults` | See [config.md](config.md) |
| `fuzzing.rs` (feature `fuzzing`) | `tcp(protocol, input)`, `udp(protocol, input)`, `TCP`, `UDP` | In-memory harness for cargo-fuzz |

## Protocol handlers

For every handler: **Event** is what goes to the daemon with its `meta` fields.
**Default** is what is sent without a decision. **Records** are the extra
`events.jsonl` kinds the handler logs.

| Protocol (module) | Event / `meta` | Default | Records |
|---|---|---|---|
| **http** (`http.rs`): HTTP/1.1 and h2 through hyper `auto`, with upgrades | One per request. `method`, `path` (path+query; the absolute URI when proxied), `host`, `proxy`, `version`, `headers` (all of them), `body_bytes`, `saved_body` | Matching Custom Response, then the connectivity check (NCSI, `generate_204`, Apple, Firefox, Ubuntu/GNOME), then the webroot file, then the typed default file (`FakeNetMini.exe` for `.exe`, and so on), then `DEFAULT_PAGE`. `server_for("auto")` picks a plausible `Server` header | `bad_request`, `custom_response`, `custom_failed`, `connectivity_check` |
| ↳ CONNECT (`connect`) | `method: CONNECT`, `path`/`host` = target, `proxy` | A 200 starts `serve_tunnel` (a new sniffed session to the target) | `proxy_connect`, `proxy_tunnel` |
| ↳ DoH (`doh_query`, `doh`) | `/dns-query`: a POST with `application/dns-message`, or a GET with `?dns=` | Handled as DNS (see below) | `doh` |
| ↳ helpers | `from_raw`, `build`, `serialize`, `default_content`, `safe_join`, `mime_type`, `default_file`, `connectivity_check`, `server_for`, `PendingUpgrade` | | |
| **http/3** (`http3.rs`): an `http` listener on UDP | One QUIC connection is one session. Every request goes through `http::answer` | Same as HTTP | `tls_handshake` (SNI, ALPN h3) |
| **websocket** (`websocket.rs`) | Upgrade request: HTTP event with `websocket: true`, `protocols`, `headers{user-agent, origin}`. Then a child session (protocol `websocket`) with one event per message: `path`, `opcode` (text/binary), `message`, `message_bytes` | 101. Empty answer = nothing is sent | `websocket_open`, `websocket_message` |
| **dns** (`dns.rs`): UDP, and TCP with 2-byte framing | One per query. `qname`, `qtype`. The first question only. Responses are never answered | NCSI names get their real IPs. With `nxdomain_random`, DGA-looking names get NXDOMAIN (`looks_random`). With `per_domain`, a stable FNV address from `pool` (`pool_address`) plus a PTR map. Otherwise `a`, `aaaa`, `mx`, `txt` by qtype, else NODATA | `malformed`, `invalid_answer` |
| **smtp** (`smtp.rs`) | One per command: `command`, `argument`. A finished message: `command: MESSAGE`, `from`, `to`, `subject`, `size`, `saved` | `220 … ESMTP FakeNet`, EHLO caps (SIZE, 8BITMIME, AUTH PLAIN LOGIN, STARTTLS, HELP). Every message is accepted (at most 32 MiB) | `credentials` (AUTH PLAIN/LOGIN), `email` (+ `.eml` saved) |
| **pop3** (`pop3.rs`) | `command`, `argument` | One fake message. USER, PASS, APOP, CAPA, STLS, STAT, LIST, UIDL, RETR, TOP, DELE, NOOP, RSET, QUIT | `credentials` |
| **imap** (`imap.rs`) | `tag`, `command` (UID stripped), `argument` | CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE PLAIN, SELECT/EXAMINE, LIST, STATUS, FETCH (`fetch`), SEARCH, ID, LOGOUT. Literals (`{n}`) are not supported | `credentials` |
| **ftp** (`ftp.rs`) | `command`, `argument`. RETR adds `path`, `file: true` (response = the file content). STOR/APPE/STOU: payload = the upload, `size`, `saved` | Any login is accepted. PASV/EPSV within `passive_ports` (then any port), PORT/EPRT only to the client's own IP, LIST/NLST/MLSD of `root` or `readme.txt`, virtual CWD (`resolve_virtual`). Uploads at most 64 MiB | `credentials`, `rename`, `download`, `upload`, `upload_too_large` |
| **tftp** (`tftp.rs`): UDP | RRQ: `opcode`, `filename`, `mode`, `file: true`. WRQ is a notify only | RRQ serves the file from `root` or a typed default, on a new port (the TID), 512-byte blocks, 5 retries. WRQ is saved (at most 32 MiB) | `download`, `upload`, `transfer_failed` |
| **irc** (`irc.rs`) | `command`, `params`, `nick`, `registered` | Registration replies 001–004 and MOTD. JOIN gets topic `FakeNet`, NAMES `@botmaster`. Also PING/PONG, CAP LS, MODE, WHO, USERHOST, ISON, QUIT | `credentials` (PASS), `join`, `message`, `quit`, `registered` |
| **ssh** (`ssh.rs`) | Once per connection: `client_version`, `hassh`, `kexinit{kex, host_key, encryption, mac, compression}` | Server banner, then silence | `ssh_client` (with `known`), `no_version` |
| **telnet** (`telnet.rs`) | One per shell line: `command`, `username` | `login:` / `Password:` then a fake root shell (`shell_response`: busybox applet probes, uname, id, ls, echo…). Commands chained with `;`, `&` or `\|` are split | `credentials` |
| **redis** (`redis.rs`) | `command`, `arguments` (previews), `suspicious` | RESP replies (PING, ECHO, AUTH, INFO, CONFIG GET, GET…, SET…) | `credentials`, `suspicious_command` (CONFIG, SLAVEOF, MODULE, EVAL, SAVE…) |
| **ntp** (`ntp.rs`): UDP | `version`, `default_offset` | A stratum-2 reply shifted by `time_offset` | `time_request`, `malformed`, `invalid_answer` |
| **socks** (`socks.rs`) | `version`, `target`, `host`, `port` | SOCKS5 (no-auth, or user/pass captured) and SOCKS4/4a CONNECT accepted, then a sniffed tunnel. BIND and UDP ASSOCIATE are refused | `credentials`, `socks_refused`, `unsupported_command` |
| **syslog** (`syslog.rs`) | Notify only: `facility`, `severity`, `format`, `message` | Never answers. TCP takes octet-counted or newline framing | `syslog_message` |
| **echo, discard, daytime, chargen, time, qotd, finger, whois** (`simple.rs`) | daytime, qotd, finger and whois ask the daemon: `service`, `query` | As in the RFCs. Chargen stops after 1 MiB (TCP) or 512 bytes (UDP). Finger refuses forwarding | `echo`/`discard`/… (protocol name), `chargen`, `query` |
| **raw** (`raw.rs`) | TCP: one per read chunk (≤16 KiB). UDP: one per datagram. `bytes` | Echo, or `raw.response`, or a Custom Response static. A TcpDynamic/UdpDynamic provider takes over | `custom_response`, `custom_failed` |
| **smb** (`smb.rs`) | Notify only. NEGOTIATE (`dialects`, `client_guid`), SESSION_SETUP NTLM negotiate/authenticate | NetBIOS session, SMB1 negotiate moved to SMB2 (0x02ff), SMB2 NEGOTIATE (3.0.2 at best), NTLM CHALLENGE, then `STATUS_LOGON_FAILURE` | `netbios_session`, `smb_negotiate`, `credentials` (NetNTLMv1/v2 line), `smb_command` |
| **ldap** (`ldap.rs`) | Notify only: `operation`, `name`, `mechanism`, `result`, plus search `base`, `scope`, `filter` (RFC 4515 text via `render_filter`), `attributes` | Simple bind succeeds (and is captured). Sicily and SASL GSS-SPNEGO NTLM get a challenge, then invalidCredentials. Root DSE for `DC=fakenet,DC=local`. StartTLS. Writes are acknowledged | `credentials`, `ldap_search`, `ldap_change` |
| **rdp** (`rdp.rs`) | Notify only: `cookie`, `requested_protocols`, `client` | X.224 confirm. For NLA: TLS, then CredSSP (`ts_request`) to capture NTLM. Otherwise TLS/RDP, reading the MCS client core data (`client_core_data`) | `rdp_connect`, `credentials` (cookie, NTLM), `rdp_client` |
| **vnc** (`vnc.rs`) | Notify only | RFB 3.8, VNC auth challenge, then a failure | `vnc_client`, `credentials` (`$vnc$*CH*RESP`) |
| **ntlm** (`ntlm.rs`): shared helper | `find`, `message_type`, `challenge`, `Authenticate::{parse, hash, record, anonymous}`, `der`, `spnego_init`, `spnego_response`, `filetime_now` | Fake server identity: domain `FAKENET`, host `FILESRV01`, DNS `fakenet.local` | |
| **mqtt** (`mqtt.rs`) | PUBLISH: `packet`, `topic`, `qos`, `retain`, `message`, `message_bytes`. SUBSCRIBE: `topics`. CONNECT is a notify | CONNACK, PUBACK/PUBREC/PUBCOMP, SUBACK, UNSUBACK, PINGRESP. A non-empty decision is published to the first non-wildcard subscribed topic | `credentials`, `mqtt_connect`, `mqtt_publish`, `mqtt_subscribe` |
| **coap** (`coap.rs`): UDP | `method`, `path`, `query`, `host`, `content_format`, `confirmable` | 2.05 / 2.04 / 2.02, a `/.well-known/core` listing, a piggybacked ACK, ping → RST | `coap_request` |

Records every session gets: `session_start`, `detected`, `event`, `decision`,
`fallback`, `explored`, `filtered`, `session_end`.
