# Protocol handlers

One module per protocol in `nucleus/crates/listeners/src/`. For each handler:

- **Event and `meta`**: what goes to the daemon (as `FakenetMeta`). "Notify" means the event
  expects no reply.
- **Default**: what the sample gets without a decision.
- **Records**: the extra `events.jsonl` kinds it logs (beyond `session_start`, `detected`,
  `event`, `decision`, `fallback`, `explored`, `filtered` and `session_end`, which every
  session can produce).

Response formats for rules are in {doc}`../usage/writing-rules`.

## Web

### `http` (`http.rs`)

HTTP/1.1 and HTTP/2 on one connection (hyper's `auto` builder, with upgrades), after TLS
when the listener or sniffer found it.

- Event: one per request. `meta`: `method`, `path` (path and query; the absolute URI for
  proxy requests), `host`, `proxy`, `version`, `headers` (all), `body_bytes`, `saved_body`.
  Payload: the request as text (request line, headers, body).
- Default, in order: a matching Custom Response; a connectivity-check answer (Windows
  NCSI and `connecttest`, Android/Chrome `generate_204`, Apple `hotspot-detect` and
  `success.html`, Firefox `success.txt`, Ubuntu and GNOME checks); the webroot file; the
  typed default file (`FakeNetMini.exe` for executables and unknown types, `FakeNet.png`,
  `.jpg`, `.gif`, `.ico`, `.pdf`, `.txt`, `.html`); the built-in page. `server_for("auto")`
  picks `Microsoft-IIS/10.0`, `gws`, `Apache`, `cloudflare`, `AmazonS3` or `nginx` by host.
- A daemon response is parsed as raw HTTP/1.1 (`from_raw`, up to 64 headers); framing
  headers are recomputed; unparseable text becomes a 200 body.
- Records: `bad_request` (body too large or over budget: 413), `custom_response`,
  `custom_failed`, `connectivity_check`.

**CONNECT** (`connect`): `meta` `method: CONNECT`, `path` and `host` = the target,
`proxy: true`. A daemon response refuses the tunnel. Otherwise 200, and the tunnel is
served as a new `auto` session to the target (`serve_tunnel`). Records: `proxy_connect`,
`proxy_tunnel`.

**DNS over HTTPS** (`doh_query`, `doh`): `/dns-query`, POST with
`application/dns-message` or GET with `?dns=` (base64url). Answered by the DNS handler and
logged as DNS. Record: `doh`.

### `http` over UDP: HTTP/3 (`http3.rs`)

quinn + h3, TLS 1.3 with ALPN `h3`, certificates from the same CA. One QUIC connection is
one session; each request goes through `http::answer`, so events and defaults are the
same. Records: `tls_handshake` (`sni`, `alpn: "h3"`). The original destination is not
recovered (flaw BUG-10).

### `websocket` (`websocket.rs`)

After an HTTP/1.1 upgrade request:

- The upgrade is an `http` event with `websocket: true`, `protocols`, `headers`
  (`user-agent`, `origin`). A daemon response refuses it.
- Otherwise 101 (with the first offered subprotocol), and a child session with protocol
  `websocket`: one event per text or binary message, `meta` `path`, `opcode`, `message`
  (512-byte preview), `message_bytes`. Default: no reply. A non-empty response is sent as a
  text message if it's UTF-8, else binary. Messages and frames up to 1 MiB.
- Records: `websocket_open`, `websocket_message`.

## Names and time

### `dns` (`dns.rs`)

UDP, and TCP with the 2-byte length prefix (several queries per connection). Also DoT
(a TLS listener running `dns`) and DoH.

- Event: one per query, first question only. `meta`: `qname` (no trailing dot), `qtype`.
  Responses (QR set) are never answered, so the nucleus can't be used as a reflector.
- Default (`default_answer_for`): `dns.msftncsi.com` gets its real A/AAAA; with
  `nxdomain_random`, random-looking names get NXDOMAIN; with `per_domain`, PTR queries for
  handed-out addresses get the name, and A/ANY get a stable address from `pool`;
  otherwise `a` (A, ANY), `aaaa`, `mx`, `txt` by type; other types get an empty answer.
  Answers are authoritative, with `recursion_available` set and TTL `dns.ttl`.
- Records: `malformed`, `invalid_answer`.

### `ntp` (`ntp.rs`, UDP)

- Event: `version`, `default_offset`.
- Default: a stratum-2 server reply, reference ID `127.127.1.0`, shifted by
  `ntp.time_offset`, with the client's transmit time as origin.
- Records: `time_request`, `malformed`, `invalid_answer`.

## Mail

### `smtp` (`smtp.rs`)

- Greeting `220 <hostname> ESMTP FakeNet`. EHLO advertises `SIZE 33554432`, `8BITMIME`,
  `AUTH PLAIN LOGIN`, `STARTTLS` (outside TLS) and `HELP`.
- Event: one per command (`command`, `argument`). A finished message is one event with the
  message as payload and `meta` `command: "MESSAGE"`, `from`, `to`, `subject`, `size`,
  `saved`.
- Every message is accepted (up to 32 MiB) and saved as `.eml`. Dot-stuffing is undone.
  STARTTLS resets the envelope and discards pipelined bytes.
- Records: `credentials` (AUTH PLAIN and LOGIN, decoded), `email` (with a 512-byte
  preview), `starttls_injection_discarded`.
- See flaw BUG-07 about non-UTF-8 content.

### `pop3` (`pop3.rs`)

- `+OK` greeting; any login accepted; one fake message. Commands: USER, PASS, APOP, CAPA,
  STLS, STAT, LIST, UIDL, RETR, TOP, DELE, NOOP, RSET, QUIT.
- Event: `command`, `argument`. Records: `credentials` (`username`, `password` or
  `apop_digest`).

### `imap` (`imap.rs`)

- Greeting with `IMAP4rev1 IMAP4rev2 STARTTLS AUTH=PLAIN`. Any login accepted; one message
  in INBOX. `UID` commands behave like their plain versions.
- Commands: CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE PLAIN, SELECT, EXAMINE, LIST, LSUB,
  STATUS, FETCH (the items asked for; any body item returns the whole message), SEARCH, ID,
  LOGOUT; NOOP, CHECK, CLOSE, EXPUNGE, STORE, COPY, CREATE, DELETE, RENAME, (UN)SUBSCRIBE,
  APPEND, ENABLE answer OK.
- Event: `tag`, `command`, `argument`. Records: `credentials`. Literals (`{n}`) are not
  supported (flaw BUG-17).

## Files

### `ftp` (`ftp.rs`)

- Greeting `220 <banner>`. Any login accepted. Virtual current directory (`resolve_virtual`,
  never touching the filesystem).
- Event: `command`, `argument` per command. RETR adds `path` and `file: true` (the response
  is the file content). STOR/APPE/STOU: payload = the upload, `size`, `saved`; the response
  replaces the final 226.
- Data connections: PASV/EPSV on `passive_ports` (any port when unset or exhausted);
  PORT/EPRT only to the client's own IP (no FTP bounce). LIST/NLST/MLSD list `root`, or a
  `readme.txt`. Uploads up to 64 MiB.
- Records: `credentials`, `rename`, `download`, `upload`, `upload_too_large`.

### `tftp` (`tftp.rs`, UDP)

- RRQ: event `opcode: "RRQ"`, `filename`, `mode`, `file: true`; the response (default: from
  `root` or a typed default file) is sent from a new port (the transfer ID) in 512-byte
  blocks, 5 retries with 1 s timeouts.
- WRQ: accepted (up to 32 MiB), saved, and sent as a notification.
- Other packets to the listener port get an error packet.
- Records: `download`, `upload`, `transfer_failed`.

## C2 and honeypots

### `irc` (`irc.rs`)

- Registration replies 001–004 and an MOTD once NICK and USER have both arrived. JOIN gets
  the JOIN echo, topic `FakeNet` (332) and NAMES with `@botmaster`. Also PING/PONG,
  CAP LS, PART, MODE, WHO, USERHOST, ISON, QUIT; anything else gets 421.
- Event: `command`, `params`, `nick`, `registered`.
- Records: `credentials` (PASS), `join`, `message` (PRIVMSG/NOTICE), `quit`, `registered`.

### `ssh` (`ssh.rs`)

- Sends the banner, reads the client's version (skipping up to 10 earlier lines) and its
  KEXINIT packet, then stays silent. No key exchange happens.
- Event (once): `client_version`, `hassh`, `kexinit` (`kex`, `host_key`, `encryption`,
  `mac`, `compression`).
- Records: `ssh_client` (`version`, `hassh`, `known`), `no_version`.

### `telnet` (`telnet.rs`)

- Sends `IAC WILL SUPPRESS-GO-AHEAD`, the banner, `login:`, `Password:`, then a fake root
  shell. Option negotiation is stripped from input.
- Event: one per shell line (`command`, `username`). Commands chained with `;`, `&` or `|`
  are answered part by part (`shell_response`: busybox applet probes get
  `applet not found`; `uname`, `whoami`, `id`, `pwd`, `echo`, `ls`; others `not found`).
- Records: `credentials`.

### `redis` (`redis.rs`)

- RESP arrays or inline commands. Defaults for PING, ECHO, AUTH, INFO, CONFIG GET, GET-like,
  list-like, counter-like and write commands; others get `-ERR unknown command`.
- Event: `command`, `arguments` (256-byte previews), `suspicious`.
- Records: `credentials` (AUTH), `suspicious_command` (CONFIG, SLAVEOF, REPLICAOF, MODULE,
  EVAL, EVALSHA, SCRIPT, FLUSHALL, SAVE, BGSAVE, DEBUG, MIGRATE).

### `socks` (`socks.rs`)

- SOCKS5 (no auth preferred; username/password captured if the client insists) and
  SOCKS4/4a CONNECT. BIND and UDP ASSOCIATE are refused.
- Event: `version`, `target`, `host`, `port`. `FakenetClose = true` refuses the tunnel.
  Otherwise success, and the tunnel is served as a new `auto` session.
- Records: `credentials`, `socks_refused`, `unsupported_command`.

### `syslog` (`syslog.rs`)

UDP, or TCP with octet counting or newline framing (RFC 6587). Never answers.
Notification with `facility`, `severity`, `format` (`rfc5424`/`rfc3164`), `message`.
Record: `syslog_message`.

### `mqtt` (`mqtt.rs`)

- MQTT 3.1, 3.1.1 and 5. CONNACK, PUBACK/PUBREC/PUBCOMP, SUBACK, UNSUBACK, PINGRESP.
  Packets up to 1 MiB.
- CONNECT: notification with `packet`, `protocol`, `level`, `client_id`, `keep_alive`,
  `will_topic`, `will_message`, `username`. PUBLISH: event with `packet`, `topic`, `qos`,
  `retain`, `message`, `message_bytes`. SUBSCRIBE: event with `topics`.
- A non-empty decision is published to the client on its first non-wildcard subscribed
  topic.
- Records: `credentials`, `mqtt_connect`, `mqtt_publish`, `mqtt_subscribe`.

### `coap` (`coap.rs`, UDP)

- Event: `method`, `path`, `query`, `host`, `content_format`, `confirmable`.
- Default: 2.05 Content (GET), 2.04 Changed, 2.02 Deleted; `/.well-known/core` lists fake
  sensors and firmware; a piggybacked ACK for confirmable requests; an empty ping gets RST.
- Record: `coap_request`.

## Windows and remote access (credential capture)

These negotiate far enough to capture a credential, then fail the logon. Shared NTLM code
(`ntlm.rs`) plays a fake server (`FAKENET` domain, host `FILESRV01`, DNS `fakenet.local`)
and turns responses into hashcat/john lines (NetNTLMv1: mode 5500; NetNTLMv2: 5600).
Credential records carry `mechanism`, `username`, `domain`, `workstation`, `anonymous`,
`hash_type` and `hash`.

| Protocol | Flow | Records |
|---|---|---|
| `smb` (`smb.rs`) | NetBIOS session; SMB1 negotiate answered by moving to SMB2 (0x02ff); SMB2 NEGOTIATE (up to 3.0.2); SESSION_SETUP with NTLM in SPNEGO; then `STATUS_LOGON_FAILURE`. Notifications only | `netbios_session`, `smb_negotiate`, `credentials`, `smb_command` |
| `ldap` (`ldap.rs`) | Simple binds succeed and are captured; Sicily and SASL GSS-SPNEGO NTLM get a challenge, then invalidCredentials; searches answered with a root DSE for `DC=fakenet,DC=local`; StartTLS; writes acknowledged. Notifications with `operation`, `name`, `mechanism`, `result`, and for searches `base`, `scope`, `filter` (RFC 4515 text), `attributes` | `credentials`, `ldap_search`, `ldap_change` |
| `rdp` (`rdp.rs`) | X.224 connection confirm. NLA clients: TLS, then CredSSP far enough to capture NTLM. Others: TLS or standard RDP, reading the MCS client core data (computer name, build, keyboard, screen). Notification with `cookie`, `requested_protocols` | `rdp_connect`, `credentials` (the `mstshash` cookie, NTLM), `rdp_client` |
| `vnc` (`vnc.rs`) | RFB 3.8, VNC authentication challenge, then failure | `vnc_client`, `credentials` (`$vnc$*CHALLENGE*RESPONSE` for john) |

## Small services (`simple.rs`)

| Service | TCP | UDP | Asks the daemon |
|---|---|---|---|
| echo (7) | Echoes until idle | Echoes | No |
| discard (9) | Reads and drops | Drops | No |
| daytime (13) | `Weekday, Month Day, Year HH:MM:SS-UTC` | Same | Yes |
| chargen (19) | RFC 864 pattern, stops after 1 MiB | 512 bytes | No |
| time (37) | 4-byte seconds since 1900 | Same | No |
| qotd (17) | A quotation | Same | Yes |
| finger (79) | User listing or a user; forwarding (`user@host`) refused | n/a | Yes |
| whois (43) | A fake registration for the query | n/a | Yes |

Event `meta`: `service`, `query`. Records: the protocol name (`echo`, `discard`, ...),
`chargen`, `query`.

## `raw` (`raw.rs`)

- TCP: one event per read (up to 16 KiB), `meta.bytes`. UDP: one per datagram.
- Default: echo, or `raw.response` in `static` mode, or the Custom Response's static bytes.
  A `TcpDynamic`/`UdpDynamic` provider takes over instead (no events).
- Records: `custom_response`, `custom_failed`.

## TLS termination (`dispatch.rs`, `tls.rs`)

Whenever TLS is unwrapped (a `tls = true` listener, a sniffed ClientHello, STARTTLS, STLS,
LDAP StartTLS, RDP): `tls_handshake` with `sni`, `certificate` (the name used), `alpn`,
`ja3`, `ja3_string`, `ja4` and `known` (a label from the fingerprint lists), or
`tls_failed` with the error (for example when the client doesn't trust the CA).
