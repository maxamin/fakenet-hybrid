# Event record catalogue

Every line of `events.jsonl` is a JSON object with `timestamp` and `kind`. Session records
also carry `listener`, `session_id`, `protocol`, `transport`, `tls`, `src`, `dst` and,
when known, `process`. Records without `protocol` appear in the report's "Nucleus & daemon
link" group.

| Group | Kind | Main fields | Logged by |
|---|---|---|---|
| Lifecycle | `nucleus_started` | `listeners`, `daemon` (link health) | `main.rs` |
| | `nucleus_stopped` | `daemon` | `main.rs` |
| | `config_reloaded` | `source` | SIGHUP task |
| | `session_start`, `session_end` | | `Session::new`, `Drop` |
| | `detected` | `detected`, `tls` | `Session::set_protocol` |
| | `filtered` | `reason` | `dispatch`, `server` |
| Link | `event` | The whole Event (`request_id`, `seq`, `payload` base64, `meta`, `expects_reply`) | `Session::decide` |
| | `decision` | `request_id`, `route`, `default`, `close`, `delay_ms`, `response_bytes` | `Session::decide` |
| | `fallback` | `request_id`, `fallback.reason`, `fallback.detail` | `Session::decide` |
| | `explored` | `request_id`, `template`, `tokens`, `close`, `response_bytes` | `Session::decide` |
| | `manual` | `request_id`, `verdict` (`send`, `close`), `close`, `response_bytes` | `Session::decide_with_default` |
| | `hook` | `hook`, `request_id`, `pid`, `process`, `dir`, `results` (`dump`: `regions`, `bytes`, `truncated`; `pause`; `command`: `argv`, `pid`, `exit`), or `error` | `Hooks::fire` |
| TLS | `tls_handshake` | `sni`, `certificate`, `alpn`, `ja3`, `ja3_string`, `ja4`, `known` | `terminate_tls`, `http3` |
| | `tls_failed` | `error` | `terminate_tls` |
| | `starttls_injection_discarded` | `bytes` | `Lines::starttls` |
| HTTP | `bad_request` | `error` | `http` |
| | `connectivity_check` | `host`, `path` | `http` |
| | `custom_response`, `custom_failed` | `section`, `provider`, `error` | `http`, `raw` |
| | `proxy_connect`, `proxy_tunnel` | `target`, `parent_session` | `http`, `dispatch` |
| | `tunnel_refused` | `target`, `reason` (`nesting`: over 4 deep; `limits`) | `dispatch::serve_tunnel` |
| | `doh` | `method`, `host` | `http` |
| | `websocket_open`, `websocket_message` | `parent_session`, `path`, `host`, `protocols`; `opcode`, `message`, `message_bytes` | `websocket` |
| DNS, NTP | `malformed` | `bytes` | `dns`, `ntp` |
| | `invalid_answer` | `errors` / `error` | `dns`, `ntp` |
| | `time_request` | `version`, `time_offset` | `ntp` |
| Credentials and data | `credentials` | `username`, `password`, `mechanism`, `apop_digest`, `domain`, `workstation`, `hash_type`, `hash` | many |
| | `email` | `from`, `to`, `subject`, `size`, `saved`, `preview` | `smtp` |
| | `upload` | `name`/`filename`, `size`, `saved`, `preview` | `ftp`, `tftp` |
| | `upload_too_large` | `name` | `ftp` |
| | `download` | `path`/`filename`, `size` | `ftp`, `tftp` |
| | `rename` | `from`, `to` | `ftp` |
| | `transfer_failed` | `filename`, `error` | `tftp` |
| Protocols | `ssh_client`, `no_version` | `version`, `hassh`, `known` | `ssh` |
| | `join`, `message`, `quit`, `registered` | `nick`, `channels`, `target`, `text` | `irc` |
| | `suspicious_command` | `command`, `arguments` | `redis` |
| | `socks_refused`, `unsupported_command` | `target`; `command`, `host`, `port` | `socks` |
| | `syslog_message` | `facility`, `severity`, `format`, `message` | `syslog` |
| | `echo`, `discard`, `daytime`, `time`, `qotd`, `chargen`, `query` | `total_bytes`, `text`, `service`, `query` | `simple` |
| | `netbios_session`, `smb_negotiate`, `smb_command` | `dialects`, `client_guid`, `chosen`, `command` | `smb` |
| | `ldap_search`, `ldap_change` | `base`, `filter`, `operation`, `dn` | `ldap` |
| | `rdp_connect`, `rdp_client` | `cookie`, `requested_protocols`, client core data | `rdp` |
| | `vnc_client` | `version` | `vnc` |
| | `mqtt_connect`, `mqtt_publish`, `mqtt_subscribe` | see {doc}`protocols` | `mqtt` |
| | `coap_request` | `method`, `path` | `coap` |
| Runs | `sample_started`, `sample_exited`, `sample_killed`, `sample_failed` | `path`, `sha256`, `pid`, `args`, `status`, `runtime_ms`, `reason`, `error` | `run.rs` |
| Analysis | `yara_match`, `yara_error` | `file`, `rules` / `error` | `capture::yara` |
| | `yara_summary` | `skipped_queue_full`, `unscanned_at_stop` (only when non-zero) | `Scanner::finish` |
| | `coverage` | `source`, `new_functions` | coverage watcher |

To list the kinds actually present in a capture:

```sh
jq -r .kind events.jsonl | sort | uniq -c | sort -rn
```
