# Use cases and workflows

## Who uses it, and for what

| Use case | What happens | Components |
|---|---|---|
| **Dynamic malware triage** in an isolated VM | All outbound traffic gets plausible answers. You see the sample's DNS names, URLs, C2 protocol, credentials and dropped files | diverter, listeners, capture |
| **One run per sample** with a summary | `--run sample.exe --timeout N` starts everything, runs the sample, then writes `run.json` (hashes, exit status), the report and IOCs into a folder for that run | `cli::run`, capture |
| **C2 emulation / tasking** | Camel rules answer specific requests: a staged check-in, DNS TXT tasks, an IRC JOIN that carries a command, a kill-switch domain | daemon routes, rules library, `state` bean |
| **Kill-switch testing** | Resolve or NXDOMAIN the kill-switch domain and compare behaviour | `rules-library/kill-switch.yaml` |
| **Unlocking hidden capabilities** | The explorer answers undecided requests with templates filled from the sample's strings and REA/Ghidra analysis. It learns which answers lead to new behaviour or new functions | explorer, coverage watcher |
| **Record and replay a live C2** | Turn a HAR from a period when the C2 was alive into a replay rule | `--rules-from-har` |
| **Regression-testing rules** | Send a capture's events to the current rules without running any traffic | `--replay` |
| **Credential and hash capture** | SMB/LDAP/RDP produce NetNTLMv1/v2 hashcat lines, VNC produces `$vnc$`, plus FTP/POP3/IMAP/SMTP/Telnet/Redis/MQTT/SOCKS/LDAP-simple cleartext | ntlm, smb, ldap, rdp, vnc, mail and other handlers |
| **IoT botnet observation** | Telnet (Mirai probes), MQTT, CoAP, IRC | telnet, mqtt, coap, irc |
| **Fingerprinting client libraries** | JA3, JA4 and HASSH are matched against known lists (abuse.ch SSLBL) | `sniffer::tls`, ssh, `[nucleus] fingerprints` |
| **Threat-intel export** | CSV, STIX 2.1 and MISP JSON (with `to_ids=false`) | `capture::indicators` |
| **SIEM feed** | Each event and its decision goes out as ECS to Elastic or a webhook, to Splunk HEC, or as syslog CEF | `daemon/routes/siem.yaml` |
| **YARA on dropped and uploaded payloads** | Every saved file is scanned in the background | `capture::yara` |
| **Migrating from FakeNet-NG** | Convert `default.ini`. Custom Response INIs and Python providers run unchanged | `cli::import`, `listeners::custom` |
| **Standalone fake-services box (container)** | Run the services on published ports with no diversion | `deploy/docker` |

## Workflow A: interactive analysis on Linux

1. `fakenet-nucleus --generate-secret link.secret` creates a hex secret with mode 0600.
2. Start the daemon from `daemon/`:
   `java -Dfakenet.link.secret-file=... -jar target/fakenet-daemon.jar`. Its `WarmUp`
   compiles the Groovy rules, then `controlbus` starts the link routes.
3. Edit `config/fakenet.toml`: set `[diverter] enabled = true`, point `[defaults.dns] a`
   at the VM's address, and set `[daemon] secret_file`.
4. `fakenet-nucleus --check -c my.toml` validates the config, the fingerprint lists and
   the YARA rules.
5. `sudo fakenet-nucleus -c my.toml`. On startup it opens the capture, writes `ca.pem`,
   installs iptables, starts the listeners, the link and the control server on
   `127.0.0.1:8099`.
6. Install `capture/ca.pem` as a trusted root in the VM, then run the sample.
7. Watch `http://127.0.0.1:8099/dashboard?token=<secret>`.
8. Ctrl+C removes iptables, finishes the YARA scans, and writes `report.html` and
   `indicators.*`.

## Workflow B: batch run per sample

`sudo fakenet-nucleus -c my.toml --run ./sample --timeout 300 --sample-arg -q`. The
capture folder becomes `capture/<UTC time>-<name>-<sha256[:12]>/`. Read
[cli.md](cli.md#run) for the exact lifecycle, and, on Windows, flaws `SEC-01` and `SEC-02`
before relying on it.

## Workflow C: writing a C2 rule

1. Find the request in `events.jsonl` (`kind: "event"`) and note `protocol` and `meta`.
2. Add a `when` branch in the matching `decide-<protocol>` route of
   `daemon/routes/decisions.yaml`. Set the body in that protocol's response format (see
   [link-and-daemon.md](link-and-daemon.md#response-formats)) and set `FakenetRoute`.
3. Save the file. Camel hot-reloads it and re-runs the warm-up without dropping the
   WebSocket.
4. `fakenet-nucleus -c my.toml --replay capture/events.jsonl` prints what the new rules
   decide for each recorded event.

## Workflow D: exploration with REA

1. `nucleus/scripts/rea-hints.sh sample.exe rea.jsonl ghidra`
2. In the config: `[explorer] enabled = true`, plus `samples`, `rea`, and optionally
   `coverage_dir`, `module` and `image_base`.
3. Optionally run under drcov or Frida so they write coverage into `coverage_dir`.
4. Read `capture/explorer-map.json` and the report's Explorer section to see which
   answer unlocked which behaviour or function.

## Workflow E: migrating from FakeNet-NG

`fakenet-nucleus --import-fakenet-ini default.ini -o fakenet.toml`. Anything without an
equivalent is listed as `# NOTE:` comments. Point `[[listener]] custom = "..."` at an
existing Custom Response INI. The listener must be an `http` or `raw` listener.

## Out of scope (by design)

- Real session completion for SMB, LDAP, RDP or VNC. These handlers capture credentials,
  then fail the logon.
- Outbound traffic generated by the nucleus itself. The explorer never sends anything.
- Strong isolation. The diverter is a redirector, not a firewall (see `flaws/` `LEAK-*`).
