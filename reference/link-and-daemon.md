# The link, its schema, and the Camel daemon

## Wire schema v1 (`schema/fakenet-link-v1.schema.json`, `nucleus/crates/schema/src/lib.rs`)

**Event** (nucleus to daemon):

| Field | Meaning |
|---|---|
| `version` | 1 |
| `type` | `"event"` |
| `request_id` | UUIDv4 |
| `session_id` | `tcp-0000000000000007` / `udp-…` |
| `seq` | Per-session counter |
| `protocol` | Lowercase protocol name |
| `transport` | `tcp` / `udp` |
| `tls` | Bool |
| `src`, `dst` | `"ip:port"`. `dst` is the original destination |
| `dport` | Destination port |
| `process` | Optional `{pid, name, exe}` |
| `timestamp` | RFC 3339 UTC |
| `payload` | Base64 |
| `meta` | Parsed fields, depending on the protocol |
| `expects_reply` | Bool |
| `auth` | HMAC, when a secret is configured |

**Action** (daemon to nucleus):

| Field | Meaning |
|---|---|
| `version`, `type: "action"`, `request_id`, `session_id` | Must match the event |
| `response` | Base64, or `null` = use the default |
| `close` | Bool |
| `delay_ms` | ≤ 60000 |
| `route` | Label for logs |
| `auth` | HMAC |

**Hello** (handshake): `{version, type: "hello", nonce, auth}`.

Rust items:

- `Protocol` (30 variants, `name()`), `Transport`, `ProcessInfo`, `Event`, `Action`,
  `Hello`.
- `EventBuilder::new/event` numbers `seq` and creates a fresh `request_id` for each
  event.
- `new_session_id`, `now_rfc3339`, `encode_base64`, `decode_base64`.
- `Action::validate_for(event)` checks the version, that the IDs match, and that
  `delay_ms` ≤ `MAX_DELAY_MS`.

### Authentication (`schema::auth`, `daemon/.../LinkAuth.java`)

Each signature is lowercase hex HMAC-SHA256, keyed with the secret file's trimmed
contents, over one of these texts:

```
hello:  "fakenet-link-v1 hello\n{nonce}"
event:  "fakenet-link-v1 event\n{request_id}\n{session_id}\n{payload base64}"
action: "fakenet-link-v1 action\n{request_id}\n{session_id}\n{response b64 or -}\n{close}\n{delay_ms or -}"
```

`Secret::sign`, `Secret::verify` (constant-time through `ring`), `random_hex`. Both
sides share test vectors (`signatures_match_the_shared_vectors` and `LinkAuthTest`).
The MAC does not cover `protocol`, `src`, `dst`, `process`, `meta`, `expects_reply` or
`route` (flaw `SEC-05`).

## The `link` crate (`nucleus/crates/link/src/lib.rs`)

| Item | What it does |
|---|---|
| `LinkConfig` | URLs, deadline (200 ms), backoff (100 ms to 10 s), secret |
| `Link::start(config)` | Build a reqwest client with `no_proxy`, and spawn `maintain_websocket` if a WS URL is set |
| `Link::decide(event) -> Decision` | Never fails. Within the deadline it sends over the WS (correlated by `request_id` in the `pending` map), otherwise over HTTP POST. It then validates (`validate_for`) and verifies the action's HMAC. Any problem gives `Fallback::{Disabled, Unavailable, Timeout, Error, Invalid}` |
| `Link::notify(event)` | Fire-and-forget over the WS (for example session close, uploads, syslog). Dropped if not connected |
| `Link::health()` | `websocket_configured`, `websocket_connected`, `http_configured`, plus counters `decisions`, `fallbacks`, `reconnects` |
| `handshake` | Send a hello with a random nonce. The daemon has 3 s to return the signed hello |
| `maintain_websocket` | Connect with a 5 s timeout, reconnect with exponential backoff and jitter |
| `run_connection` | Writer task with an mpsc of 1024. The reader routes each Action to its waiter and answers pings. On disconnect, every pending request fails at once |

## Daemon Java (`daemon/src/main/java/lab/fakenet/daemon/`)

| Class | Role |
|---|---|
| `FakenetDaemon` | `camel-main` entry point. Adds `DaemonConfiguration` |
| `DaemonConfiguration` | Loads `LinkAuth` from `fakenet.link.secret-file` and binds the beans `eventIn`, `actionOut`, `warmUp`, `state` |
| `LinkAuth` | `load` (blank path = unauthenticated, otherwise at least 32 chars), `sign`, `verify` (`MessageDigest.isEqual`), `helloText`/`eventText`/`actionText` |
| `EventIn` (processor) | Parse JSON and check the version. A hello gets the signed hello as its body (`FakenetKind=hello`). Anything else malformed or unsigned gets `rejected`. An event gets `FakenetKind=event` with every `Fakenet*` header set and an empty body. `FakenetActor` = `pid:N` when the process is known, otherwise `ip:ADDR` |
| `ActionOut` (processor) | Body to `response`. Null or empty means the default. Text, including Groovy GStrings, is UTF-8. Clamps `FakenetDelayMs` to 0–60000, reads `FakenetClose` and `FakenetRoute` (default `"default"`), signs |
| `SessionState` (bean `state`) | Per-actor `Map` with `get`, `get(default)`, `put`, `increment`, `all`, `forget`. Idle actors expire after 1 h. Pruning happens only when there are at least 10k actors (flaw `DOS-07`) |
| `WarmUp` (processor) | Compiles and evaluates every Groovy expression in every route on a placeholder exchange, then sends 20 placeholder protocols through `direct:decide` |
| `LinkSchema` | Header-name constants, `VERSION`, `MAX_DELAY_MS`, the shared `ObjectMapper` |

### Headers available to rules

Set by `EventIn`:

| Header | Content |
|---|---|
| `FakenetProtocol`, `FakenetTransport`, `FakenetTls` | From the event |
| `FakenetSessionId`, `FakenetRequestId`, `FakenetSeq` | From the event |
| `FakenetSrc`, `FakenetDst`, `FakenetDport` | From the event |
| `FakenetProcess`, `FakenetPid`, `FakenetActor` | Process and actor identity |
| `FakenetPayload` | `byte[]` |
| `FakenetText` | UTF-8 decoding of the payload |
| `FakenetMeta` | Map |
| `FakenetExpectsReply` | Bool |
| `FakenetMethod`, `FakenetPath`, `FakenetHost` | HTTP convenience copies of `meta` |
| `FakenetQname`, `FakenetQtype` | DNS convenience copies of `meta` |

Set by rules: `FakenetClose`, `FakenetDelayMs`, `FakenetRoute`.

### <a name="response-formats"></a>Response formats by protocol

| Protocol | Body a rule sets |
|---|---|
| http (also h2, h3, websocket upgrade, CONNECT) | A full raw HTTP/1.1 response. Framing headers are recomputed. If it does not parse, it becomes a 200 with the text as body. For CONNECT and WebSocket, any response refuses the tunnel |
| dns (also DoT, DoH) | Lines: `A ip`, `AAAA ip`, `MX [pref] name`, `TXT text` (≤255 bytes, flaw `BUG-01`), `CNAME`/`NS`/`PTR name`, or the single word `NXDOMAIN`, `SERVFAIL` or `REFUSED` |
| raw, websocket, mqtt (message payload), coap (payload), telnet, finger, whois, daytime, qotd | Bytes sent as they are |
| smtp, pop3, imap, ftp, irc, redis | The full reply lines (RESP for redis) that replace the default reply |
| ftp RETR, tftp RRQ (`meta.file = true`) | The file content |
| ntp | `+N`/`-N` seconds of offset, or a complete 48-byte packet |
| socks | Only `FakenetClose=true` matters: it refuses the tunnel |
| ssh | Any bytes after the version exchange |

## Routes (`daemon/routes/`)

**`link.yaml`** (transport; not hot-edited):

- `link-websocket-in`: the `vertx-websocket` consumer on `/link`, feeding
  `seda:link-events` (queue of 10k, `blockWhenFull=false`). Starts with
  `autoStartup: false`.
- `link-websocket-decide`: `seda` with 16 consumers, then `eventIn`, then a choice.
  A hello is sent back to the same connection. A rejected message is logged. Anything
  else goes to `decide-safely` and, if a reply is expected, back over the WS.
- `link-http`: `platform-http:/decide` (POST, JSON). Anything that is not an event gets
  401. Removes `Fakenet*` headers from the response.
- `decide-safely`: `doTry direct:decide`. On an exception the body becomes null with
  `FakenetRoute=rule-error`. Then `actionOut`, then `wireTap direct:audit`.
- `audit`: Groovy builds `{event, action}`, then multicasts to
  `file:audit/events-YYYYMMDD.jsonl`, to the log, and to `direct:siem`.

**`decisions.yaml`** (the analyst's rules; hot-reloaded):

- `decide`: a content-based router on `FakenetProtocol` to `decide-http`,
  `decide-dns` or `decide-raw`.
- `decide-http`:
  - `/gate.php`: Groovy tasking.
  - `/checkin`: a staged C2 through the `state` bean.
  - `*update.example.com`: a Simple-language JSON template.
- `decide-dns`: `*c2.example` answers `A 10.6.6.6`. `killswitch.example` answers
  `NXDOMAIN`.
- `decide-raw`: `HELLO <name>` gets a Groovy handshake with `FakenetClose`. `PING` gets
  `PONG\n` (`trim: false`).
- `decide-warm-up`: a one-shot timer, then `warmUp`, then `controlbus` starts both link
  routes.

**`siem.yaml`**: Groovy builds the ECS document and a CEF line, then a `recipientList`
for each of `fakenet.siem.ecs-uris`, `splunk-uris` (with an `Authorization: Splunk`
header) and `syslog-uris`.

## Rules library (`daemon/rules-library/`)

| Route | Behaviour | Properties |
|---|---|---|
| `direct:library-staged-http-c2` | The first GET registers the bot (UUIDv3 of the actor). Later GETs return the next task as JSON. A POST counts a result and returns `ok` | `fakenet.library.tasks` |
| `direct:library-dns-txt-tasking` | A TXT query returns the next task, base64-encoded, cycling. Any other qtype returns `A 10.0.0.2` while tasks remain, otherwise `A 10.0.0.1` | `fakenet.library.tasks` |
| `direct:library-irc-botnet` | On JOIN: echo the JOIN, a 332 topic and an operator PRIVMSG carrying the command | `fakenet.library.irc-command` |
| `direct:library-kill-switch` | Listed domains get `A 10.0.0.250`, or `NXDOMAIN` in `nxdomain` mode | `fakenet.library.kill-switch-domains`, `-mode` |
| `direct:decide-recorded` | HAR replay (generated by `--rules-from-har`) | |

To use one, copy the file into `routes/` and add `- to: direct:library-…` to a branch.
