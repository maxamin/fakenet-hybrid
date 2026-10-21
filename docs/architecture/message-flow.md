# Message flow

This follows one HTTPS request to an arbitrary port, on Linux in single-host mode.

## 1. Diversion

The sample connects to `203.0.113.7:8443`. The `nat OUTPUT` chain jumps to `FAKENET`; no
fixed listener uses port 8443, so the catch-all rule REDIRECTs the connection to the
`auto` TCP listener's port. The kernel performs the NAT (conntrack keeps it for the rest of
the connection).

With `excluded_processes`, the first packet of each new connection first goes through the
`mangle` NFQUEUE rule; the nucleus's queue thread finds the owning process and marks the
packet when it's excluded, and the NAT chain returns marked packets untouched.

## 2. Accept and session

`server::serve_tcp` accepts the connection and asks `Limits::admit` for a permit (session
count and optional per-source rate). `dispatch::handle_tcp`:

1. reads `SO_ORIGINAL_DST` to recover `203.0.113.7:8443` (`original_dst.rs`);
2. creates a `Session` (`session.rs`): event builder, session ID, `find_process` from
   `/proc`, a synthetic TCP flow in `traffic.pcap`, and a `session_start` record;
3. applies the listener's process and host filters.

## 3. Detection

`dispatch::serve` for an `auto` listener:

1. `peek`: one read of up to 4 KiB, waiting at most `first_data_timeout_ms`.
2. The bytes look like a TLS ClientHello, so `terminate_tls` reads the whole hello,
   computes JA3/JA4, picks the certificate name (SNI, else the tunnel host, else the
   destination IP), has the CA mint or reuse a certificate, offers `h2`/`http/1.1` if asked,
   completes the handshake and logs `tls_handshake`.
3. `peek` again inside TLS, then `sniffer::sniff` scores every candidate protocol; `GET `
   wins for HTTP. (No data at all: `sniff_silent` picks the server-speaks-first protocol of
   the port, or raw.)
4. `set_protocol` logs `detected`, and the stream (with the peeked bytes replayed through
   `PrefixedStream`) goes to `http::handle`.

## 4. The protocol step

`http::answer` reads the request (bounded by `max_body_bytes` and the memory budget),
saves the body, and builds `meta` (`method`, `path`, `host`, `headers`, ...). Then
`Session::decide`:

1. builds the Event (new `request_id`, next `seq`) and logs it as an `event` record;
2. feeds it to the explorer (`observe`), if enabled;
3. `Link::decide` sends it and waits at most `deadline_ms`;
4. on an Action: logs `decision`, sleeps `delay_ms` if any. On a problem: logs `fallback`
   with the reason;
5. sleeps the configured latency jitter;
6. if there is no response yet, asks the explorer for a proposal (`explored`).

## 5. Inside the daemon

1. `link-websocket-in` (vertx-websocket on `/link`) puts the text on
   `seda:link-events` (10,000 slots, never blocking the event loop).
2. `link-websocket-decide` (16 consumers) runs `EventIn`: parse, check the version, verify
   the HMAC, set the `Fakenet*` headers and an empty body.
3. `decide-safely` calls `direct:decide` (the analyst's router) inside `doTry`.
4. `ActionOut` turns the body and headers into a signed Action.
5. A Wire Tap sends a copy to `direct:audit` (file, log, SIEM) without delaying the reply.
6. If `FakenetExpectsReply`, the Action goes back to the same WebSocket connection (the
   `CamelVertxWebsocket.connectionKey` header survives the seda hand-off).

## 6. The answer

Back in the nucleus, the link's reader task matches the Action to the waiting request by
`request_id`, then `decide` validates it (version, IDs, `delay_ms ≤ 60000`) and verifies its
HMAC. `http::answer` uses the daemon's raw response (`from_raw`), or else the default: a
matching Custom Response, a connectivity-check answer, the webroot file, the typed default
file, or the default page. The response is recorded into the pcap and sent by hyper.

## 7. The end

When the connection closes, the `Session` is dropped: it notifies the daemon
(`{"closed": true}`, no reply expected), logs `session_end`, writes the pcap FIN exchange,
and releases its permit.

## Fallback reasons

| Reason | When |
|---|---|
| `disabled` | Both daemon URLs are empty |
| `unavailable` | The WebSocket is down and there is no HTTP URL |
| `timeout` | No valid answer within `deadline_ms` |
| `error` | The WebSocket closed while waiting, or HTTP failed or returned a non-2xx status |
| `invalid` | The answer isn't an Action for this event, or its signature is missing or wrong |
