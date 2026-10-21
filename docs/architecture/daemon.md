# The daemon

A `camel-main` application (Java 21, Apache Camel 4.18 LTS, Maven). Everything it does is
stock Camel components plus a few small processors. Start it from `daemon/` so that the
relative `routes/` and `audit/` paths resolve.

## Java classes (`daemon/src/main/java/lab/fakenet/daemon/`)

| Class | Role |
|---|---|
| `FakenetDaemon` | Entry point: a `Main` with `DaemonConfiguration` |
| `DaemonConfiguration` | Loads `LinkAuth` from `fakenet.link.secret-file` and binds the beans `eventIn`, `actionOut`, `warmUp` and `state` |
| `LinkAuth` | `load` (blank path: unauthenticated, which `DaemonConfiguration` refuses unless `fakenet.link.insecure=true`; otherwise at least 32 characters), `sign`, `verify`, `helloText`, `seal`, `unseal`. `EventIn` also refuses stale timestamps (±5 min) and seen `request_id`s (100,000 kept) |
| `EventIn` | Processor. Parses the JSON and checks the version. A hello gets the signed hello as body (`FakenetKind=hello`). Anything malformed or unsigned gets `FakenetKind=rejected` with a reason. An event gets `FakenetKind=event`, every `Fakenet*` header, and an empty body |
| `ActionOut` | Processor. The body becomes `response` (null or empty means default; text, including Groovy GStrings, is UTF-8); `FakenetClose`, `FakenetDelayMs` (clamped to 0–60000) and `FakenetRoute` (default `"default"`) become the other fields; signs the Action |
| `SessionState` | Bean `state`: per-actor maps with `get`, `put`, `increment`, `all`, `forget`. At 10,000 actors, idle ones (an hour) are pruned, then the least recently used tenth; 1,000 keys per actor |
| `WarmUp` | Processor. Compiles and evaluates every Groovy expression in every route on a placeholder exchange, then sends placeholder events for 20 protocols through `direct:decide` |
| `LinkSchema` | Header names, `VERSION`, `MAX_DELAY_MS`, the shared Jackson `ObjectMapper` |

## Routes

`link.yaml` (transport; not meant to be edited during a run):

| Route | From | Does |
|---|---|---|
| `link-websocket-in` | `vertx-websocket:{host}:{port}/link` (`autoStartup: false`) | Puts each message on `seda:link-events` (10,000 slots, `blockWhenFull=false`) |
| `link-websocket-decide` | `seda:link-events?concurrentConsumers=16` | `eventIn`; a hello goes back to the same connection; a rejected message is logged; an event goes to `decide-safely` and, if a reply is expected, back over the WebSocket |
| `link-http` | `platform-http:/decide` (POST, JSON; `autoStartup: false`) | `eventIn`; anything but an event gets 401; otherwise `decide-safely`. Removes `Fakenet*` headers from the HTTP response |
| `decide-safely` | `direct:decide-safely` | `doTry direct:decide`; on an exception the body becomes null and the route `rule-error`. Then `actionOut` and a Wire Tap to `direct:audit` |
| `audit` | `direct:audit` | `AuditRecord.of` builds `{event, action}`, the payload cut to `fakenet.audit.payload-bytes` with its length and SHA-256; multicast to `file:{audit.dir}?fileName=events-YYYYMMDD.jsonl` (append), the log, and `direct:siem` |

`decisions.yaml` (the analyst's rules; hot-reloaded): `decide` routes by protocol to
`decide-http`, `decide-dns` and `decide-raw`, which hold the sample rules; the last route,
`decide-warm-up`, is a one-shot timer running `warmUp` and then `controlbus` to start both
link routes.

`siem.yaml`: see {doc}`../usage/siem`.

## Start-up and reload sequence

1. Camel loads every `routes/*.yaml`. The link routes don't start (`autoStartup: false`).
2. The warm-up timer fires: `WarmUp` compiles the Groovy scripts and runs the
   placeholder events, then `controlbus` starts `link-websocket-in` and `link-http`. The
   log says `Rules warmed up; link channels started`. Until then, the nucleus can't connect
   and uses its defaults.
3. Saving `decisions.yaml` reloads that file only
   (`routes-reload-remove-all-routes = false`): the warm-up route is part of it, so it
   runs again; the WebSocket stays connected.

## Stock components

| Need | Component |
|---|---|
| WebSocket server | `camel-vertx-websocket` (replies go to the sender through its connection key) |
| HTTP endpoint and health | `camel-platform-http-main` (embedded Vert.x server, `/observe/health`) |
| YAML routes and reload | `camel-yaml-dsl`, `camel-main` |
| JSON | `camel-jackson` |
| Scripted answers | `camel-groovy`, Simple |
| Router, Wire Tap, multicast | core EIPs |
| Audit sinks | `camel-file`, `camel-log` |
| Warm-up, then start the channels | `camel-timer`, `camel-controlbus` |
| Concurrency off the event loop | `camel-seda` |
| SIEM | `camel-http`, `camel-netty` (and any other component you add) |

Camel's embedded servers default to `0.0.0.0`; `application.properties` pins
`camel.server.host` and `camel.management.host` to `127.0.0.1`.
