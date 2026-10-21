# Overview

## What it is for

| Use case | What happens | Components |
|---|---|---|
| Dynamic malware triage | Every outbound connection gets a plausible answer. You see the sample's DNS names, URLs, C2 protocol, credentials and dropped files | diverter, listeners, capture |
| One run per sample | `--run sample.exe --timeout N` starts everything, runs the sample, and writes `run.json`, the report and the indicators into a folder for that run | `cli::run`, capture |
| C2 emulation and tasking | Camel rules answer chosen requests: a staged check-in, DNS TXT tasks, an IRC JOIN carrying a command, a kill-switch domain | daemon routes, rules library, `state` bean |
| Unlocking hidden capabilities | The explorer answers undecided requests with templates filled from the sample's strings and REA/Ghidra analysis, and learns which answers lead to new behaviour | explorer |
| Record and replay a live C2 | Turn a HAR recorded while the C2 was alive into a replay rule | `--rules-from-har` |
| Regression-testing rules | Send a capture's events to the current rules without generating traffic | `--replay` |
| Credential and hash capture | SMB, LDAP and RDP produce NetNTLMv1/v2 lines for hashcat/john; VNC produces `$vnc$`; cleartext logins from FTP, POP3, IMAP, SMTP, Telnet, Redis, MQTT, SOCKS and LDAP simple binds | `ntlm`, `smb`, `ldap`, `rdp`, `vnc` and the mail/line handlers |
| IoT botnet observation | Telnet (Mirai-style probes), MQTT, CoAP, IRC | `telnet`, `mqtt`, `coap`, `irc` |
| Client fingerprinting | JA3, JA4 and HASSH matched against known lists such as abuse.ch SSLBL | `sniffer::tls`, `ssh` |
| Threat-intel export | CSV, STIX 2.1 and MISP JSON | `capture::indicators` |
| SIEM feed | Every event and decision as ECS JSON, Splunk HEC or syslog CEF | `daemon/routes/siem.yaml` |
| YARA on payloads | Every saved file is scanned in the background | `capture::yara` |
| Migrating from FakeNet-NG | Convert `default.ini`; Custom Response INIs and Python providers run unchanged | `cli::import`, `listeners::custom` |
| Fake-services box | A container serving the fake services on published ports, with no diversion | `deploy/docker` |

## What it fakes

| Family | Protocols |
|---|---|
| Web | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), HTTPS with certificates minted per host name or IP, proxy `CONNECT`, SOCKS4/4a/5 tunnels, WebSocket |
| Names and time | DNS over UDP and TCP, DNS over TLS, DNS over HTTPS (`/dns-query`), NTP |
| Mail | SMTP (STARTTLS, AUTH), POP3 (STLS), IMAP (STARTTLS) |
| Files | FTP (passive and active), TFTP (both directions) |
| C2 and honeypots | IRC, SSH (HASSH), Telnet, Redis, syslog, MQTT, CoAP |
| Windows and remote access | SMB, LDAP, RDP, VNC (credential capture only) |
| Small services | echo, discard, daytime, chargen, time, qotd, finger, whois |
| Everything else | raw TCP and UDP (echo or a static reply) |

## Repository layout

```text
schema/fakenet-link-v1.schema.json   Event / Action / Hello wire schema (both sides)
nucleus/                             Rust workspace
  crates/schema                      wire types and HMAC texts
  crates/link                        WebSocket + HTTP client with a deadline
  crates/sniffer                     protocol scoring, TLS ClientHello, JA3/JA4
  crates/capture                     events.jsonl, pcaps, files, report, IOCs, YARA
  crates/listeners                   the server and 30 protocol handlers
  crates/diverter                    iptables/NFQUEUE (Linux), WinDivert (Windows)
  crates/explorer                    template bandit, hints, coverage
  crates/cli                         the fakenet-nucleus binary and dashboard
  config/                            sample config, default files, fingerprint lists
  fuzz/                              cargo-fuzz targets (own workspace)
  scripts/, examples/                interop tests, REA hints, diversion test, demo
daemon/                              Java 21 / Camel (Maven)
  routes/                            link.yaml, decisions.yaml, siem.yaml
  rules-library/                     ready-made rules
  src/main/java/lab/fakenet/daemon/  entry point and processors
deploy/                              systemd, Windows tasks + MSI, Docker
scripts/package.sh                   release tarball
docs/                                this documentation
flaws/                               known bugs, risks and improvement ideas
```

## Network endpoints

All control endpoints listen on loopback only. The nucleus refuses to start with anything
else.

| Endpoint | Owner | Purpose |
|---|---|---|
| `ws://127.0.0.1:8090/link` | daemon | Primary link channel |
| `http://127.0.0.1:8091/decide` | daemon | Secondary link channel (one POST per event) |
| `http://127.0.0.1:8092/observe/health` | daemon | Camel health |
| `http://127.0.0.1:8099/health` | nucleus | Health, link state, counters |
| `http://127.0.0.1:8099/dashboard` | nucleus | Live dashboard |
