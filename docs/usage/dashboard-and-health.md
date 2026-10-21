# Health and the live dashboard

The nucleus's control server listens on `[nucleus] health` (default `127.0.0.1:8099`,
loopback enforced). Source: `serve_control` and `control_response` in
`nucleus/crates/cli/src/lib.rs`.

## Authentication

When `[daemon] secret_file` is set, everything beyond a bare "ok" needs the secret,
either as `Authorization: Bearer <secret>` or as the `fakenet_token` cookie, compared in
constant time. Without a secret, everything is open.

## Routes

| Route | Without the secret | With it |
|---|---|---|
| `GET /health` | `{"status":"ok"}` | Also `daemon` (link health), `listeners`, `limits` |
| `GET /dashboard?token=SECRET` | | 303 to `/dashboard`, setting `fakenet_token=<secret>; HttpOnly; SameSite=Strict; Path=/` |
| `GET /dashboard` | 401 with a hint | The page |
| `GET /dashboard.js`, `/dashboard.css` | Served | Served |
| `GET /api/records?after=N&limit=L` | 401 | Up to `L` (default 1000, at most 5000) records newer than sequence `N`, from a 5,000-record ring in memory, plus the latest sequence number |
| `GET /api/summary` | 401 | Link health, listeners, limits, and an explorer summary (top 8 templates by reward) |
| `GET /api/manual` | 401 | Live manual mode: `enabled`, `timeout_ms`, and the held requests (`id`, request line, host, process, payload and proposed answer in base64, `expires_at_ms`) |
| `POST /api/manual/<id>` | 401 | Answer a held request: `{"action":"proposed"}`, `{"action":"send","response":"text"}` or `"response_base64"`, optional `"close":true`, or `{"action":"close"}`. 410 when no longer held |
| `GET /api/paused` | 401 | Processes paused by hooks |
| `POST /api/paused/<pid>/resume` | 401 | Resume (SIGCONT) a process a hook paused |

POSTs must be `application/json`, which a cross-site form can't send, on top of the
`SameSite=Strict` cookie. Bodies are limited to 16 MiB.

Every response carries a strict CSP (`default-src 'none'; script-src 'self'; ...`),
`nosniff`, `no-store` and `no-referrer`.

```{warning}
The cookie value is the link secret itself, and the token travels in the URL once (flaw
SEC-03). Close the browser and clear its data before running samples in the same VM.
```

### Link health fields

| Field | Meaning |
|---|---|
| `websocket_configured`, `http_configured` | Channels with a URL |
| `websocket_connected` | The WebSocket is up and passed the handshake |
| `decisions` | Valid, verified Actions received |
| `fallbacks` | Requests that used the default |
| `reconnects` | WebSocket reconnections after the first |

### Limits fields

`sessions_active`, `max_sessions`, `memory_bytes`, `refused_max_sessions`,
`refused_rate`, `refused_memory`.

## The dashboard

`dashboard/index.html`, `dashboard.js` and `dashboard.css` are compiled into the binary.
The script polls `/api/records` every second and `/api/summary` every 2 s, keeps up to
5,000 records in the browser, and renders everything with `textContent` (sample data is
never interpreted as HTML). It shows sessions, DNS names, URLs, credentials, files,
fallbacks, the daemon state and, when on, the explorer's progress.

## Daemon health

`GET http://127.0.0.1:8092/observe/health` is Camel's built-in health check. It needs no
secret.
