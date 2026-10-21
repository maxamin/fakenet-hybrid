# Migrating from FakeNet-NG

## Converting `default.ini`

```sh
fakenet-nucleus --import-fakenet-ini default.ini -o fakenet.toml
```

Source: `nucleus/crates/cli/src/import.rs` (`convert`). It also reads fakenet-rs's
extended `default.ini`.

| FakeNet-NG | Becomes |
|---|---|
| `[Diverter] NetworkMode` | `[diverter] mode` |
| `BlackListPortsTCP`, `BlackListPortsUDP` | merged into `ignore_ports` |
| `ProcessBlackList` | `excluded_processes` |
| `ModifyLocalDNS`, `FixGateway` | `fix_dns`, `fix_gateway` |
| Each enabled listener section | a `[[listener]]` with `name`, `protocol` (from the listener class, `protocol_for`), `transport`, `port`, `tls` (`UseSSL`), `custom`, and the process/host white- and blacklists |
| A `Port` range `a-b` | `[defaults.ftp] passive_ports` |
| `Webroot`, `FTPRoot`, `TFTPRoot` | the defaults' roots |
| Anything without an equivalent | an escaped `# NOTE:` comment |

The importer never enables the diverter. Review the result, add an `auto` listener per
transport if you divert (flaw LEAK-04), and set `passive_ports` (flaw BUG-06).

## Custom Responses

Point a listener at an existing Custom Response INI:

```toml
[[listener]]
name = "HTTPListener80"
protocol = "http"
port = 80
custom = "custom_responses.ini"
```

Source: `nucleus/crates/listeners/src/custom.rs`.

- Sections apply when their `InstanceName` equals the listener's `name`, or their
  `ListenerType` is `HTTP`, `TCP` or `UDP` matching the listener. Only `http` and `raw`
  listeners take a `custom` file.
- HTTP sections: `HttpHosts` (case-insensitive, with or without a port) and/or `HttpURIs`
  (suffix match on the full URI, including the query string, flaw BUG-14); both must match
  when both are set. Exactly one of `HttpRawFile`, `HttpStaticString` (with an optional
  `ContentType`) or `HttpDynamic`.
- Raw sections: exactly one of `TcpRawFile`/`TcpStaticString`/`TcpStaticBase64`/`TcpDynamic`
  (or the `Udp*` equivalents). At most one raw section per listener.
- `<RAW-DATE>` in raw and static responses is replaced by the current HTTP date.
- A Custom Response is the listener's **default**: the daemon can still override it.

Dynamic providers run unmodified, on Unix only, through an embedded shim
(`providers.py`) started as `python3 -I -c <shim> MODE PROVIDER`:

| Mode | How the provider is called |
|---|---|
| `HttpDynamic` | `HandleHttp(handler, method, body)` or `HandleRequest`. The request comes as JSON on stdin; the handler imitates `BaseHTTPRequestHandler`; what it writes is the raw response. 30 s timeout |
| `TcpDynamic` | `HandleTcp(socket)` with the client connection on fd 3. It takes over the whole connection (no per-chunk events) |
| `UdpDynamic` | `HandleUdp(socket, data, peer)` with the listener's socket on fd 3; one process per datagram |

## Behaviour differences

- FakeNet-NG's `TFTPListener.taste()` raises for anything but read requests; here every
  TFTP packet type is recognised.
- Silent clients on an `auto` port get the greeting of that port's server-speaks-first
  protocol (for example SMTP on 25) instead of waiting forever.
- Sniffing scores content +2 and port +1, so content beats port (FakeNet-NG scores FTP +1,
  which ties with HTTP on port 80).
- Listener filters close the connection (`filtered` record); host filters accept IP
  addresses only (flaw ARCH-06).
- Process attribution: events carry `process` on Linux (`/proc`) and on Windows (WinDivert's
  socket layer).
