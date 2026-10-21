# Writing rules

Rules live in `daemon/routes/decisions.yaml`. They are stock Camel YAML routes. Save the
file and Camel reloads only that file, re-runs the warm-up, and keeps the nucleus's
WebSocket connected.

## The contract

- Every request arrives at `direct:decide` with `Fakenet*` headers and an **empty body**.
- A rule answers by **setting the body**. The body's format depends on the protocol
  (table below).
- A rule that leaves the body empty sends `response: null`, and the nucleus uses its
  built-in default. Only describe what's interesting.
- A rule that throws is caught by `decide-safely`: the default is used and the route is
  logged as `rule-error`.
- The answer must reach the nucleus within `deadline_ms` (200 ms by default), or the
  default is used for that request.

## Headers available to rules

Set by `EventIn` (`daemon/src/main/java/lab/fakenet/daemon/EventIn.java`):

| Header | Content |
|---|---|
| `FakenetProtocol` | `http`, `dns`, `raw`, `smtp`, … (all 30 names; the comment at the top of `decisions.yaml` lists only 8) |
| `FakenetTransport`, `FakenetTls` | `tcp`/`udp`, boolean |
| `FakenetSessionId`, `FakenetRequestId`, `FakenetSeq` | Identifiers |
| `FakenetSrc`, `FakenetDst`, `FakenetDport` | `ip:port` strings and the destination port. `FakenetDst` is the original destination |
| `FakenetProcess`, `FakenetPid` | Process name and PID, when known |
| `FakenetActor` | `pid:N` when the process is known, else `ip:ADDRESS`. Key for the `state` bean |
| `FakenetPayload` | The raw bytes |
| `FakenetText` | The payload decoded as UTF-8 |
| `FakenetMeta` | The parsed fields, as a map (see {doc}`../reference/protocols`) |
| `FakenetExpectsReply` | False for notifications |
| `FakenetMethod`, `FakenetPath`, `FakenetHost` | Copies of `meta` for HTTP |
| `FakenetQname`, `FakenetQtype` | Copies of `meta` for DNS |

Headers a rule may set:

| Header | Effect |
|---|---|
| `FakenetClose` | `true`: close the connection after replying |
| `FakenetDelayMs` | Wait before replying, clamped to 0–60000. Doesn't count against the deadline |
| `FakenetRoute` | The name shown in `decision` records, the audit log and the report (default `default`) |

## Response formats

| Protocol | Body to set |
|---|---|
| `http` (HTTP/1.1, h2, h3) | A complete raw HTTP/1.1 response: `HTTP/1.1 200 OK\r\nHeader: v\r\n\r\nbody`. `Content-Length`, `Transfer-Encoding` and `Connection` are recomputed. Text that doesn't parse becomes the body of a 200 |
| `http` CONNECT, WebSocket upgrade | Any response refuses the tunnel or upgrade and is sent instead |
| `dns` (UDP, TCP, DoT, DoH) | Lines: `A ip`, `AAAA ip`, `MX [pref] name`, `TXT text` (longer than 255 bytes: split into several strings), `CNAME name`, `NS name`, `PTR name`; or one of `NXDOMAIN`, `SERVFAIL`, `REFUSED`. Bad lines are skipped and logged as `invalid_answer` |
| `raw`, `websocket`, `mqtt` (PUBLISH), `coap`, `telnet`, `finger`, `whois`, `daytime`, `qotd` | The bytes to send |
| `smtp`, `pop3`, `imap`, `ftp`, `irc` | The complete reply line(s), replacing the default reply |
| `redis` | A RESP reply (`+OK\r\n`, `$3\r\nfoo\r\n`) |
| `ftp` RETR, `tftp` RRQ (`meta.file = true`) | The file content |
| `smtp` finished message (`meta.command == "MESSAGE"`) | The reply to the end of DATA |
| `ntp` | `+N` or `-N` seconds of offset, or a complete 48-byte packet |
| `socks` | Body ignored; `FakenetClose = true` refuses the tunnel |
| `ssh` | Any bytes, sent after the version exchange |

## Examples

A Groovy C2 tasking for `/gate.php`:

```yaml
- simple: "${header.FakenetPath} startsWith '/gate.php'"
  steps:
    - setHeader:
        name: FakenetRoute
        constant: c2-gate
    - setBody:
        groovy: |
          def bot = request.headers.FakenetSessionId
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nid=${bot};task=sleep;interval=3600"
```

A DNS sinkhole and a kill switch:

```yaml
- simple: "${header.FakenetQname} endsWith 'c2.example'"
  steps:
    - setBody:
        constant: "A 10.6.6.6"
- simple: "${header.FakenetQname} == 'killswitch.example'"
  steps:
    - setBody:
        constant: NXDOMAIN
```

A multi-step conversation with the `state` bean (per actor, forgotten after an hour idle):

```groovy
def state = camelContext.registry.lookupByName('state')
def actor = request.headers.FakenetActor
def count = state.increment(actor, 'checkins')        // 1 the first time
if (count == 1) {
  state.put(actor, 'bot_id', 'BOT-' + Integer.toHexString(actor.hashCode() & 0xffff))
  return "HTTP/1.1 200 OK\r\n\r\nregistered ${state.get(actor, 'bot_id')}"
}
```

`state` methods: `get(actor, key)`, `get(actor, key, fallback)`, `put(actor, key, value)`,
`increment(actor, key)`, `all(actor)`, `forget(actor)`.

## Camel behaviours to know

- `constant` and `simple` text is trimmed. Add `trim: false` to keep a trailing `\n`.
- Groovy `GString` results have no Camel converter to bytes; `ActionOut` handles any
  `CharSequence` itself (UTF-8).
- Each Groovy script compiles on first use, which can take seconds on a cold JVM. The
  warm-up (`WarmUp.java`) compiles every Groovy expression in every route and sends one
  placeholder event per protocol through `direct:decide` before the link opens. Scripts
  therefore run once on placeholder data: keep them free of side effects. Every protocol
  of the schema gets one.
- `link.yaml` and `decisions.yaml` reload independently
  (`routes-reload-remove-all-routes = false`). A rule file can't redefine the link routes'
  IDs.

## The rules library

`daemon/rules-library/` holds ready-made routes. Copy a file into `routes/` and add its
`- to: direct:library-...` line to a branch.

| File | Route | Behaviour | Properties |
|---|---|---|---|
| `staged-http-c2.yaml` | `direct:library-staged-http-c2` | First GET registers the bot (a UUIDv3 of the actor); later GETs get the next task as JSON; a POST counts a result and gets `ok` | `fakenet.library.tasks` |
| `dns-txt-tasking.yaml` | `direct:library-dns-txt-tasking` | TXT answers carry the next task, base64-encoded, cycling; other types get `A 10.0.0.2` while tasks remain, else `A 10.0.0.1` | `fakenet.library.tasks` |
| `irc-botnet.yaml` | `direct:library-irc-botnet` | On JOIN: echo the JOIN, a 332 topic, and an operator PRIVMSG carrying the command | `fakenet.library.irc-command` |
| `kill-switch.yaml` | `direct:library-kill-switch` | Listed domains get `A 10.0.0.250`, or NXDOMAIN in `nxdomain` mode | `fakenet.library.kill-switch-domains`, `fakenet.library.kill-switch-mode` |
| `recorded-example.yaml` | `direct:decide-recorded` | Example output of `--rules-from-har` (from `recorded-example.har`) | |

## Testing rules

- `cd daemon && mvn test` runs `DecisionRulesTest` and `LibraryRulesTest` against the
  shipped rules.
- `fakenet-nucleus -c my.toml --replay capture/events.jsonl` shows what the current rules
  decide for every recorded event.
