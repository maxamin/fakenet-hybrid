# Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `binding DNS to udp 0.0.0.0:53: address in use` (Linux) | systemd-resolved holds `127.0.0.53:53`. Set `DNSStubListener=no`, or bind the nucleus to the VM's own address (`[nucleus] bind`). Resolved's upstream queries are diverted either way |
| `reading fingerprints .../sslbl-ja3.csv` at start | The fingerprint list isn't next to the config. Copy `config/fingerprints/` there or remove the `fingerprints` line |
| Every request falls back with `timeout` | The daemon is overloaded or a rule is slow. Check `daemon/audit/` and the daemon log. Raise `deadline_ms` if the sample tolerates it. Use `FakenetDelayMs` for deliberate slowness |
| `unavailable` fallbacks | The daemon isn't running, is still warming up, or failed the handshake. Both sides must use the same secret file. The nucleus logs `Daemon failed authentication`; the daemon logs `Dropped a link message` |
| `invalid` fallbacks: `unsigned or forged action` | The daemon runs without the secret, or with a different one |
| HTTPS clients fail (`tls_failed`) | The VM doesn't trust `ca.pem`. Without `[nucleus] ca_cert`/`ca_key` it changes at every start; with them, install it once. Pinned clients always fail |
| FTP passive transfers hang | `[defaults.ftp] passive_ports` must be a range the diverter keeps (default `[60000, 60010]`; `[0, 0]` is refused when diverting) |
| A TCP protocol shows up as `raw` | The protocol isn't recognisable from its first bytes (fragments are collected for up to 150 ms between pieces, within `first_data_timeout_ms`). Use a fixed-protocol listener for that port |
| Events have no `process` | Remote client, or Windows without diversion |
| DNS query answered SERVFAIL | The answer couldn't be encoded (an `invalid_answer` record says why) |
| Python Custom Response providers don't run (Windows) | Dynamic providers are Unix-only; static ones work everywhere |
| The nucleus was killed and the VM has no network | Run `sudo fakenet-nucleus --restore-network` |
| No report after stop | Render one with `--report capture/events.jsonl` (rotated `events.N.jsonl` are read too) |

Useful checks:

```sh
curl -H "Authorization: Bearer $(cat link.secret)" http://127.0.0.1:8099/health | jq .daemon
sudo iptables -t nat -S FAKENET          # the active diversion rules
RUST_LOG=debug fakenet-nucleus -c my.toml
jq -r 'select(.kind=="fallback") | .fallback.reason' capture/events.jsonl | sort | uniq -c
```
