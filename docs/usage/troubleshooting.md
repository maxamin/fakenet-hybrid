# Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `binding DNS to udp 0.0.0.0:53: address in use` (Linux) | systemd-resolved holds `127.0.0.53:53`. Set `DNSStubListener=no`, or bind the nucleus to the VM's own address (`[nucleus] bind`). Resolved's upstream queries are diverted either way |
| `reading fingerprints .../sslbl-ja3.csv` at start | The package didn't ship `config/fingerprints/` (flaw DEP-01). Copy it next to the config or remove the `fingerprints` line |
| Every request falls back with `timeout` | The daemon is overloaded or a rule is slow. Check `daemon/audit/` and the daemon log. Raise `deadline_ms` if the sample tolerates it. Use `FakenetDelayMs` for deliberate slowness |
| `unavailable` fallbacks | The daemon isn't running, is still warming up, or failed the handshake. Both sides must use the same secret file. The nucleus logs `Daemon failed authentication`; the daemon logs `Dropped a link message` |
| `invalid` fallbacks: `unsigned or forged action` | The daemon runs without the secret, or with a different one |
| HTTPS clients fail (`tls_failed`) | The VM doesn't trust this start's `ca.pem`: it changes at every start (flaw BUG-05). Pinned clients always fail |
| FTP passive transfers hang | Set `[defaults.ftp] passive_ports` to a range (flaw BUG-06) |
| A TCP protocol shows up as `raw` | The client's first `read` was a fragment (flaw BUG-08), or the protocol isn't recognisable from its first bytes. Use a fixed-protocol listener for that port |
| Events have no `process` | Remote client, Windows without diversion, or a UDP client on a wildcard-bound socket (flaw BUG-09) |
| DNS TXT query never answered | The TXT string is over 255 bytes (flaw BUG-01) |
| Python Custom Response providers don't run (Windows) | Dynamic providers are Unix-only; static ones work everywhere |
| The nucleus was killed and the VM has no network | Run `sudo fakenet-nucleus --restore-network` |
| No report after stop | Check the log for an error from removing the diversion (flaw BUG-02); render one with `--report capture/events.jsonl` |

Useful checks:

```sh
curl -H "Authorization: Bearer $(cat link.secret)" http://127.0.0.1:8099/health | jq .daemon
sudo iptables -t nat -S FAKENET          # the active diversion rules
RUST_LOG=debug fakenet-nucleus -c my.toml
jq -r 'select(.kind=="fallback") | .fallback.reason' capture/events.jsonl | sort | uniq -c
```
