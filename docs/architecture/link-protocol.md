# The link protocol (v1)

Defined by `schema/fakenet-link-v1.schema.json`; implemented by
`nucleus/crates/schema/src/lib.rs` and the daemon's `EventIn`, `ActionOut` and `LinkAuth`.
Examples: `schema/examples/`. Unknown fields are ignored on input, so either side may add
fields.

## Event (nucleus → daemon)

| Field | Type | Meaning |
|---|---|---|
| `version` | 1 | |
| `type` | `"event"` | |
| `request_id` | string (UUIDv4) | Correlates the Action |
| `session_id` | string | `tcp-0000000000000007` or `udp-…`, unique within a nucleus run |
| `seq` | integer | Per-session counter from 0 |
| `protocol` | string | One of the 30 protocol names |
| `transport` | `tcp` / `udp` | |
| `tls` | bool | The session is inside TLS |
| `src`, `dst` | `"ip:port"` | `dst` is the original destination |
| `dport` | integer | Destination port |
| `process` | `{pid, name, exe?}` | When known |
| `timestamp` | RFC 3339, UTC | |
| `payload` | base64 | The raw step (request, query, line, chunk) |
| `meta` | object | Parsed fields, per protocol (see {doc}`../reference/protocols`) |
| `expects_reply` | bool | False for notifications (session end, uploads, syslog, ...) |
| `auth` | hex string | HMAC, when a secret is configured |

## Action (daemon → nucleus)

| Field | Type | Meaning |
|---|---|---|
| `version`, `type: "action"` | | |
| `request_id`, `session_id` | string | Must equal the Event's |
| `response` | base64 or `null` | `null`: use the nucleus's default |
| `close` | bool | Close after replying |
| `delay_ms` | integer ≤ 60000 | Wait before replying |
| `route` | string | Label for logs |
| `auth` | hex string | HMAC |

## Hello (handshake)

`{"version": 2, "type": "hello", "nonce": "<32 hex chars>", "auth": "<hmac>"}`. The nucleus
sends it without `auth`; the daemon returns it signed. On the WebSocket the nucleus waits at
most 3 s and sends nothing else on the connection until the signature checks out. On the
HTTP channel it POSTs a fresh hello to `/decide` before each event, and sends the event only
if the reply is signed.

## Authentication

Signatures are lowercase hex HMAC-SHA256, keyed with the secret file's trimmed contents.

- **Events and actions are sealed whole.** The sender serialises the message without
  `auth`, computes the MAC over `"fakenet-link-v2\n"` followed by that exact JSON text, and
  appends `,"auth":"<mac>"` as the last member. The receiver strips that suffix and checks
  the MAC over the text before it. Every field is covered (`protocol`, `meta`, `src`, `dst`,
  `process`, `expects_reply`, `route`...), and neither side has to reproduce the other's JSON
  formatting (`auth::seal` / `auth::unseal`, `LinkAuth.seal` / `LinkAuth.unseal`).
- **Hello:** the MAC over `"fakenet-link-v2 hello\n{nonce}"`.

Both sides check the same test vectors, computed independently (`signatures_match_the_shared_vectors`
in Rust, `LinkAuthTest` in Java). Verification is constant-time on both sides
(`ring::hmac::verify`, `MessageDigest.isEqual`).

What it guarantees:

- the peer holds the secret before any event is sent to it (WebSocket handshake per
  connection, HTTP hello per event), so a process that takes a port while the daemon is
  down receives nothing;
- the daemon drops events that are unsigned, altered in any field, more than 5 minutes off
  in `timestamp`, or carry a `request_id` it has seen (`rejected`; HTTP returns 401);
- the nucleus ignores unsigned or altered actions (`invalid` fallback), and only accepts one
  for a request it is waiting on;
- neither side starts a link without a secret unless told to (`--insecure-link`,
  `fakenet.link.insecure=true`).

What it doesn't: anyone who can read the secret file can do anything (it is readable by
SYSTEM/Administrators or root and the `fakenet` group only).

## Transport details

- WebSocket: one long-lived connection carries many concurrent requests. The writer queue
  holds 1,024 messages; notifications are dropped when it's full. Pings are answered.
  When the connection drops, every waiting request fails at once (`error`), instead of each
  waiting for its deadline.
- Reconnection: 5 s connect timeout; back-off from `backoff_initial_ms` doubling to
  `backoff_max_ms`, plus 0–99 ms of jitter; `reconnects` counts successful reconnections.
- HTTP: `POST http_url` with the signed Event as JSON; the response body is the Action.
  The client ignores system proxies (`no_proxy`).

## Versioning

`version` is 1 on both sides; the nucleus rejects Actions of another version and the daemon
rejects Events of another version.
