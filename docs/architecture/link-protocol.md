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

## Hello (WebSocket handshake)

`{"version": 1, "type": "hello", "nonce": "<32 hex chars>", "auth": "<hmac>"}`. The nucleus
sends it without `auth`; the daemon returns it signed. The nucleus waits at most 3 s and
sends nothing else on the connection until the signature checks out.

## Authentication

Each signature is lowercase hex HMAC-SHA256, keyed with the secret file's trimmed contents,
over:

```text
hello:  "fakenet-link-v1 hello\n{nonce}"
event:  "fakenet-link-v1 event\n{request_id}\n{session_id}\n{payload base64}"
action: "fakenet-link-v1 action\n{request_id}\n{session_id}\n{response base64 or -}\n{close}\n{delay_ms or -}"
```

Both sides check the same test vectors (`signatures_match_the_shared_vectors` in Rust,
`LinkAuthTest` in Java). Verification is constant-time on both sides (`ring::hmac::verify`,
`MessageDigest.isEqual`).

What it guarantees:

- the WebSocket peer holds the secret (handshake) before any event is sent on it;
- the daemon drops unsigned or forged events (`rejected`; HTTP returns 401);
- the nucleus ignores unsigned or forged actions (`invalid` fallback).

What it doesn't:

- fields outside the signed texts (`protocol`, `meta`, `src`, `dst`, `process`,
  `expects_reply`, `route`) can be altered, and messages can be replayed (flaw SEC-04);
- the HTTP channel has no handshake: whoever holds port 8091 receives the events
  (flaw SEC-05);
- anyone who can read the secret file can do anything.

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
