# Health and the live dashboard

The nucleus's control server listens on `[nucleus] health` (default `127.0.0.1:8099`,
loopback enforced). Source: `serve_control` and `control_response` in
`nucleus/crates/cli/src/lib.rs`.

## Authentication

When `[daemon] secret_file` is set, everything beyond a bare "ok" needs either the secret
as `Authorization: Bearer <secret>` (scripts; compared in constant time) or a dashboard
session cookie. Open `/dashboard`, enter the secret in the login form, and the nucleus sets
`fakenet_session=<random 256-bit token>; HttpOnly; SameSite=Strict; Path=/`. The secret
itself is never put in a URL or a cookie. Sessions last 12 hours (64 at most, in memory);
**Log out** ends one. Without a secret (`--insecure-link`), everything is open.

## Routes

| Route | Without the secret | With it |
|---|---|---|
| `GET /health` | `{"status":"ok"}` | Also `daemon` (link health), `listeners`, `limits` |
| `GET /dashboard` | 401 with the login form (a `?token=` in the URL is refused) | The page |
| `POST /dashboard/login` | Form field `token` = the secret: 303 to `/dashboard` with a session cookie; else 401 | |
| `POST /dashboard/logout` | Ends the session, clears the cookie | |
| `GET /dashboard.js`, `/dashboard.css` | Served | Served |
| `GET /api/records?after=N&limit=L` | 401 | Up to `L` (default 1000, at most 5000) records newer than sequence `N`, from a 5,000-record ring in memory, plus the latest sequence number |
| `GET /api/summary` | 401 | Link health, listeners, limits, and an explorer summary (top 8 templates by reward) |
| `GET /api/manual` | 401 | Live manual mode: `enabled`, `timeout_ms`, and the held requests (`id`, request line, host, process, payload and proposed answer in base64, `expires_at_ms`) |
| `POST /api/manual/<id>` | 401 | Answer a held request: `{"action":"proposed"}`, `{"action":"send","response":"text"}` or `"response_base64"`, optional `"close":true`, or `{"action":"close"}`. 410 when no longer held |
| `GET /api/paused` | 401 | Processes paused by hooks |
| `POST /api/paused/<pid>/resume` | 401 | Resume (SIGCONT) a process a hook paused |

POSTs to `/api/` must be `application/json`, which a cross-site form can't send, on top of the
`SameSite=Strict` cookie. Bodies are limited to 16 MiB (4 KiB for the login).

Every response carries a strict CSP (`default-src 'none'; script-src 'self'; ...`),
`nosniff`, `no-store` and `no-referrer`.

```{note}
The session cookie lets a sample that reads the browser's cookie store use the dashboard
API (as the analyst could) until the session ends, but not the link. Log out, or close the
browser, before running samples in the same VM.
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
