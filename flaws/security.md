# Security flaws (`SEC-*`)

The threat model: the sample under analysis runs on the same VM as the nucleus and daemon.
It can reach loopback, read world-readable files and the process list, and race for
ports. It cannot read root-only files.

## SEC-03

**The dashboard cookie is the link secret** · Medium · Confirmed

- Where: `nucleus/crates/cli/src/lib.rs:445-460` (`fakenet_token={secret}`); the token is
  also passed in the URL (`/dashboard?token=...`).
- What: the same value is the HMAC key for the link, the `/health` bearer token and the
  browser cookie. Opening the dashboard puts the key in browser history and the cookie
  store of the analysis VM's browser profile.
- Impact: a sample running as the browser user can read the cookie database and get the
  link key. It can then pose as the daemon (forge Actions) whenever it can take the
  daemon's port.
- Fix: derive separate keys from the secret (for example HMAC(secret, "dashboard")), or
  issue a random session token on `/dashboard?token=` and keep a server-side map. Prefer a
  POST form over a query string.

## SEC-04

**Most link fields are not authenticated, and nothing prevents replay** · Medium · Confirmed

- Where: `nucleus/crates/schema/src/lib.rs` (`auth::event_text`, `auth::action_text`),
  `daemon/src/main/java/lab/fakenet/daemon/LinkAuth.java`, `EventIn.java`.
- What: the event MAC covers `request_id`, `session_id` and the payload only. `protocol`,
  `meta`, `src`, `dst`, `dport`, `process`, `tls`, `seq` and `expects_reply` can be changed
  without breaking the signature. The action MAC omits `route`. The daemon doesn't remember
  which `request_id`s it has seen.
- Impact: whoever obtains a signed event (see SEC-05) can resend it to the real daemon
  with a different protocol, host or process. That steers rule decisions, advances `state`
  counters (staged C2), and injects forged records into the audit log and the SIEM.
- Fix: sign the canonical JSON of the whole message (minus `auth`), or add every field to
  the signed text, in both implementations with new shared test vectors. Add a timestamp
  window and a bounded seen-`request_id` cache on the daemon.

## SEC-05

**The HTTP fallback channel has no handshake** · Medium · Confirmed

- Where: `nucleus/crates/link/src/lib.rs`, `ask()` (the `http_url` branch).
- What: the WebSocket proves the daemon's identity with a signed nonce before any event
  is sent on it. The HTTP fallback POSTs the signed event to whatever listens on
  `127.0.0.1:8091`. When the daemon is stopped or restarting, a local process can bind that
  port and receive every event, including payloads and captured credentials. It can't
  answer (the actions would fail verification). `docs/ARCHITECTURE.md` notes the missing
  handshake; the consequence is that the whole event stream is readable while the daemon
  is down.
- Impact: confidentiality of the whole capture stream while the daemon is down; enables
  SEC-04.
- Fix: send no payload until the server proves itself: for example a `GET /decide/hello?nonce=`
  round trip per connection, cached for the keep-alive connection. Alternatively disable
  the HTTP channel when a secret is set, or encrypt the payload.

## SEC-06

**The link is unauthenticated by default** · Medium · Confirmed

- Where: `daemon/src/main/resources/application.properties`
  (`fakenet.link.secret-file =`), `nucleus/config/fakenet.toml` (`# secret_file = ...`),
  `main.rs` (only a warning).
- What: from a source checkout, both sides run without a secret. Any local process can
  connect to `:8090`, read events or, by taking the port first, answer them.
- Fix: refuse to start without a secret unless `--insecure-link` is given; have
  `--generate-secret` print the two config lines to add.

## SEC-09

**Splunk HEC token on the command line** · Low · Confirmed

- Where: `daemon/routes/siem.yaml` (header comment and `fakenet.siem.splunk-token`).
- What: the documented way to configure it is a `-D` system property, which appears in
  `/proc/<pid>/cmdline` and in `ps` for every user.
- Impact: the sample can read the token and write to the SIEM.
- Fix: read it from a file (`fakenet.siem.splunk-token-file`) or an environment
  variable, and document `application.properties` with restricted permissions.
