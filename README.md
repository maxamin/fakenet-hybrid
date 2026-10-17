# FakeNet hybrid

A FakeNet-NG-style network simulator for **isolated malware-analysis VMs**. A Rust
**nucleus** intercepts all outbound traffic, detects each connection's protocol, answers it
convincingly, and records everything. A Java **daemon** built on stock Apache Camel decides
how to answer, using YAML routes that analysts edit live.

The nucleus never depends on the daemon. If the daemon is stopped, slow or restarting, every
request still gets the built-in default within the deadline (200 ms by default), and the
event log records the fallback.

> **Lab use only.** Run it inside an isolated analysis VM. Diversion takes over the
> host's traffic, so it's off until you enable it. The daemon, the health endpoint and the
> link bind to 127.0.0.1 only, and the nucleus refuses any other address.

Design, trade-offs and verification status: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What it fakes

| | |
|---|---|
| Web | HTTP/1.1, HTTP/2 and HTTP/3 (QUIC), HTTPS with certificates minted per hostname (or per IP for clients without SNI), proxy `CONNECT` and SOCKS4/4a/5 tunnels (sniffed and served inside) |
| Name & time | DNS (UDP & TCP), NTP (with a time offset) |
| Mail | SMTP (STARTTLS, AUTH, messages saved as `.eml`), POP3 (STLS), IMAP (STARTTLS) |
| Files | FTP (passive & active, uploads saved), TFTP (both directions) |
| C2 & honeypots | IRC, SSH (client fingerprinting with HASSH), Telnet (Mirai-style login & busybox probes), Redis (flags `CONFIG SET`-style attacks), syslog |
| Small services | echo, discard, daytime, chargen, time, qotd, finger, whois |
| Everything else | raw TCP/UDP (echo or a static reply); "auto" listeners detect any of the above on any port |

FakeNet-NG compatibility: its Custom Response files (static and Python providers),
per-listener process/host white/blacklists, typed default files, and its `default.ini`
(convert with `fakenet-nucleus --import-fakenet-ini default.ini -o fakenet.toml`).

## Layout

```
schema/fakenet-link-v1.schema.json   Event/Action message schema (shared by both sides)
nucleus/                             Rust workspace
  crates/schema  sniffer  link  capture  listeners  diverter  cli  explorer
  crates/explorer/templates/         the explorer's response templates (default.toml)
  fuzz/                              cargo-fuzz targets for every parser (own workspace)
  examples/explorer-demo/            a harmless instrumented bot: the explorer end to end
  scripts/rea-hints.sh               REA (Reverse Engineer Anything) analysis -> explorer hints
  config/fakenet.toml                sample config (relative paths: from this file's folder)
  config/default-files/              FakeNet-NG's typed default files (served for missing files)
  scripts/test-linux-diversion.sh    diverter end-to-end test (private network namespace)
daemon/                              Java 21 / Camel 4.18 LTS (Maven)
  routes/link.yaml                   transport: WebSocket, POST /decide, Wire Tap
  routes/decisions.yaml              the analyst's rules (hot-reloaded)
  routes/siem.yaml                   SIEM outputs: ECS, Splunk HEC, syslog CEF (off until configured)
  rules-library/                     ready-made rules: staged HTTP C2, DNS TXT tasking, IRC, kill switch
  src/main/java/lab/fakenet/daemon/  entry point, link auth, processors, automatic warm-up
deploy/                              systemd units & installers (Linux), scheduled tasks (Windows)
scripts/package.sh                   release package
upstream/                            reference only, git-ignored: the FakeNet-NG clone and the
                                     archived fakenet-rs source (see upstream/README.md)
```

| Endpoint (all 127.0.0.1) | Owner | Purpose |
|---|---|---|
| `ws://127.0.0.1:8090/link` | daemon | Primary channel (Events in, Actions out) |
| `http://127.0.0.1:8091/decide` | daemon | Secondary channel (one POST per Event) |
| `http://127.0.0.1:8092/observe/health` | daemon | Camel health |
| `http://127.0.0.1:8099/health` | nucleus | Nucleus health, link state, fallback counters |
| `http://127.0.0.1:8099/dashboard` | nucleus | Live dashboard (open `/dashboard?token=<link secret>` once) |

## Requirements

- Rust 1.85+ (stable)
- Java 21 and Maven 3.9 (for the daemon)
- Linux diversion: root, `iptables` / `ip6tables` with the `nat` table (REDIRECT, addrtype),
  plus `nfnetlink_queue` if you use `excluded_processes`
- Windows diversion: Administrator, and [WinDivert 2.2](https://reqrypt.org/windivert.html)
  (`WinDivert.dll`, `WinDivert.lib`, `WinDivert64.sys` from the release zip's `x64` folder)

## Build

Linux:

```sh
cd nucleus && cargo build --release           # target/release/fakenet-nucleus
cd ../daemon && mvn package                    # target/fakenet-daemon.jar + target/lib/
```

Windows (PowerShell):

```powershell
$env:WINDIVERT_PATH = "C:\tools\WinDivert-2.2.2-A\x64"   # where WinDivert.dll/.lib/.sys are
cd nucleus; cargo build --release
Copy-Item "$env:WINDIVERT_PATH\WinDivert.dll", "$env:WINDIVERT_PATH\WinDivert64.sys" target\release\
cd ..\daemon; mvn package
```

## Run

0. **Create the link secret** (once). It authenticates the nucleus and the daemon to each
   other, so other local processes, including the malware, can't pose as either side:

   ```sh
   ./target/release/fakenet-nucleus --generate-secret link.secret   # readable by its owner only
   ```

   Set `[daemon] secret_file = "link.secret"` in the nucleus config, and give the daemon the
   same file.

1. **Start the daemon** (from `daemon/`, so it finds `routes/`; the audit log goes to
   `daemon/audit/`):

   ```sh
   java -Dfakenet.link.secret-file=../nucleus/link.secret -jar target/fakenet-daemon.jar
   ```

   It logs `Rules warmed up; link channels started` once it accepts the nucleus. Until then
   the nucleus answers with its defaults.

2. **Configure the nucleus.** Copy `nucleus/config/fakenet.toml` and review it. Inside the
   analysis VM, set `[diverter] enabled = true`. Point `[defaults.dns] a` at an address the
   malware should reach (e.g. the VM's own IP). To serve FakeNet-NG's typed default files
   (a real .exe for `*.exe` and so on), set `webroot`, `[defaults.ftp] root` and
   `[defaults.tftp] root`. `fakenet-nucleus --check -c my.toml` validates the config.
   Coming from FakeNet-NG? `fakenet-nucleus --import-fakenet-ini default.ini -o my.toml`
   converts its config, listing anything without an equivalent as comments.

   Windows extras in `[diverter]`: `fix_dns` and `fix_gateway` (FakeNet-NG's
   ModifyLocalDNS and FixGateway, restored on stop), and `mode = "gateway"` with
   `gateway_address` when this host routes the analysis network.

3. **Start the nucleus**:

   ```sh
   sudo ./target/release/fakenet-nucleus -c config/fakenet.toml      # Linux
   .\target\release\fakenet-nucleus.exe -c config\fakenet.toml       # Windows, as Administrator
   ```

   Install `capture/ca.pem` as a trusted root in the analysis VM, so intercepted HTTPS,
   SMTPS and STARTTLS look valid.

4. **Stop** with Ctrl+C. This removes the diversion: on Linux, the `FAKENET` iptables
   chains; on Windows, the WinDivert handles close with the process. If the nucleus was
   killed (`kill -9`, power loss), run `sudo fakenet-nucleus --restore-network` on Linux.
   Windows needs nothing.

Check both sides at any time:

```sh
curl -H "Authorization: Bearer $(cat link.secret)" http://127.0.0.1:8099/health   # nucleus: listeners, link, fallbacks
curl http://127.0.0.1:8092/observe/health                                           # daemon
```

Without the token, the nucleus's `/health` only says `{"status":"ok"}`.

### What you get

`capture/` (the nucleus's `capture_dir`):

- `events.jsonl`: one JSON line per session start and end, detected protocol, TLS
  handshake (with SNI), event sent to the daemon, decision or fallback (with its reason),
  credentials, email, upload and download. Each line carries the session ID, source,
  original destination and the client process (Linux, and Windows when diverting).
- `traffic.pcap`: decrypted conversations, synthesized per session (open with Wireshark).
- `wire.pcap`: with `[nucleus] wire_capture = true`, every real packet as it crossed the
  wire (including traffic that was never diverted).
- `files/`: HTTP request bodies, emails (`.eml`), FTP and TFTP uploads.
- `report.html`: written at every stop. It shows the key indicators (DNS, URLs, SNI,
  credentials, emails, files, SSH clients, IRC, suspicious commands, tunnels, daemon
  decisions, fallbacks), then everything by process. `fakenet-nucleus --report
  events.jsonl -o report.html` renders one at any time.
- `ca.pem`: the interception CA.

The event log and pcaps rotate by size (`max_events_mb`, `max_pcap_mb`, `keep_rotations`),
and `files/` stops growing at `max_files_mb`. Past that budget new payloads are logged but
not saved, so existing evidence is never deleted.

`daemon/audit/events-YYYYMMDD.jsonl`: the Wire Tap's copy of every event with its action.

### Live dashboard

`http://127.0.0.1:8099/dashboard?token=<contents of link.secret>` sets an HttpOnly cookie
and opens a live view: sessions, DNS names, URLs, credentials, files, fallbacks, daemon
state and, when it's on, the explorer's progress. It's served on the health address
(loopback only) and needs the secret, like `/health`'s details.

### One run per sample

```sh
sudo ./target/release/fakenet-nucleus -c my.toml --run ./sample.exe --timeout 300 --sample-arg -q
```

starts everything, runs the sample, and stops when it exits (plus 5 s for its last
connections) or at `--timeout`. Each run gets its own folder under `capture_dir`
(`<time>-<name>-<sha256 prefix>/`) with the usual outputs and `run.json`: the sample's SHA-256 and MD5,
arguments, exit status and duration. **This executes the sample**: only inside the analysis VM.

### Realism

Some samples check whether they're in a sandbox before doing anything. The defaults help
them conclude they're not:

- TLS certificates look issued 30–200 days ago, with random serials.
- `[defaults.http] connectivity_checks` answers Windows NCSI (`connecttest.txt`, `ncsi.txt`
  and its DNS name), Android/Chrome `generate_204`, Apple's and Firefox's captive-portal
  checks exactly as the real services do. `server_header = "auto"` picks a plausible
  `Server` per host.
- `[defaults.dns] per_domain = true` gives each name its own stable address from `pool`
  (198.18.0.0/15) with matching PTR answers, instead of one address for everything.
  `nxdomain_random = true` answers NXDOMAIN for random-looking (DGA) names, as the Internet
  would.
- `[defaults] latency_ms = [20, 120]` adds a random delay to each answer.

## Exploring a sample

Defaults show a sample's first move. Many samples only reveal their capabilities when the
C2 answers with something they understand: a task they parse, a command name they compare
against. The **explorer** finds such answers automatically.

When the daemon doesn't decide a request, the explorer (with probability `rate`) answers
with one of ~60 protocol templates (HTTP JSON tasks, key-value bodies, redirects, PE
downloads, DNS TXT/CNAME/A answers, IRC PRIVMSG, raw TCP, SMTP/FTP replies...) and fills
its slots with *hints*:

- strings from the sample's binary (`samples`);
- **REA's analysis** (`rea`): function names, strings and imports from Ghidra, via
  [Reverse Engineer Anything](https://github.com/morluto/rea). Words from the sample's own
  function names (`cmd_download` -> `download`) are favoured, since command handlers are
  usually named after their commands;
- what the sample itself sent (echoed, mutated, or its parameters).

Each answer is scored by what follows within `window_ms`: new kinds of behaviour (new
protocols, hosts, paths, credentials, files...) and, with a coverage tracer, newly reached
functions. A bandit (UCB1 per kind of request) learns which templates pay off, and the
hint words that paid off are reused more. Everything is logged (`explored` events, route
`explorer:<template>`) and summarised in `capture/explorer-map.json` and the report's
Explorer section: which answer led to which behaviour and which functions.

Typical use:

```sh
nucleus/scripts/rea-hints.sh sample.exe rea.jsonl ghidra   # REA + Ghidra: functions, strings, imports
```

then in the config:

```toml
[explorer]
enabled = true
samples = ["sample.exe"]
rea = ["rea.jsonl"]
coverage_dir = "coverage"     # optional: a tracer's output (see below)
module = "sample.exe"
image_base = "0x400000"
```

Coverage makes the map precise: a tracer such as DynamoRIO's drcov
(`drrun -t drcov -logdir coverage -- sample.exe`) or Frida writes to `coverage_dir`;
the explorer reads drcov logs and JSONL lines (`{"pid":..,"time":..,"functions":[..]}` or
`"addresses"`) and maps addresses to REA's functions. The explorer warns if REA analysed a
different build (SHA-256 mismatch) than `samples`.

`nucleus/examples/explorer-demo/run-demo.sh` shows it end to end on a harmless instrumented
bot (localhost, high ports, no diversion): with defaults it reaches none of the bot's five
command handlers; with the explorer, four, each attributed to the answer that triggered it.

The explorer only answers what the analyst's rules leave undecided, and it changes answers,
nothing else: it never sends traffic of its own.

## Writing rules

Edit `daemon/routes/decisions.yaml` and save it. Camel reloads only that file, re-runs the
warm-up, and keeps the WebSocket connected. The file's header lists the headers available to
rules (`FakenetProtocol`, `FakenetDst`, `FakenetPath`, `FakenetQname`, `FakenetText`...), the
response format for each protocol, and the headers a rule can set (`FakenetClose`,
`FakenetDelayMs`, `FakenetRoute`). A rule answers by setting the body. A rule that leaves the
body empty gets the nucleus's default, so you only describe what's interesting.

The sample rules include:
- a Groovy-scripted C2 tasking for `/gate.php`;
- a Simple template for a fake update check;
- DNS sinkholing and an NXDOMAIN for a kill-switch domain;
- a Groovy-scripted raw TCP handshake that closes the connection.

Two Camel behaviours to know:
- `constant` and `simple` text is trimmed, so use `trim: false` to keep a trailing `\n`.
- Each Groovy script compiles on first use. The warm-up route at the end of
  `decisions.yaml` exercises each rule before the link opens; add a sample there for each
  new scripted rule.

Multi-step conversations: the `state` bean keeps per-client state (by process, else by
source address; header `FakenetActor`) for an hour, so a rule can register a bot on its
first check-in and hand out tasks on later ones. See the `/checkin` rule in
`decisions.yaml`.

**Rules library:** `daemon/rules-library/` has ready-made rules (staged HTTP C2, DNS TXT
tasking, IRC botnet channel, kill-switch domains); see its README.

**Record & replay:**
- `fakenet-nucleus --rules-from-har c2.har -o routes/recorded.yaml` turns a recorded
  exchange (a HAR from a browser, mitmproxy or HTTP Toolkit) into a rule that answers each
  recorded request with its recorded response.
- `fakenet-nucleus -c my.toml --replay capture/events.jsonl` sends a capture's events to the
  running daemon and prints what the current rules decide for each, without any traffic:
  a regression test for rule changes.

**SIEM outputs:** every event and its decision can also go out as Elastic Common Schema
JSON (HTTP to Elasticsearch, any webhook, a file, Kafka), to Splunk's HTTP Event
Collector, or as syslog CEF. They're off until configured; see the header of
`daemon/routes/siem.yaml` for the `fakenet.siem.*` properties. Other sinks: add them to the
`audit` route in `link.yaml` with their stock Camel component.

## Tests

| What | Command |
|---|---|
| Unit and integration tests: every protocol with real protocol clients, TLS/STARTTLS/HTTP/2, proxy & SOCKS tunnels, Custom Responses, filters, link authentication, rotation, the report, and **fallback when the daemon is stopped or too slow** | `cd nucleus && cargo test` |
| Daemon: link authentication (HMAC vectors shared with the nucleus), event/action processing, the shipped rules | `cd daemon && mvn test` |
| Rust–Camel link against the real daemon: authenticated handshake, both channels, scripted replies, hot reload, Wire Tap, **fallback while the daemon is stopped**, reconnect after restart | `cd daemon && mvn package`, then `cd nucleus && cargo test -p fakenet-cli --test camel_link -- --ignored` (uses `JAVA_HOME` or `java` on PATH) |
| Real clients (curl, dig, OpenSSH, redis-cli, swaks, logger, nc, Python): 42 checks | `cd nucleus && cargo build && scripts/interop.sh` |
| Fuzzing: every protocol handler, parser, packet decoder, link message, the report and the INI importer face hostile input | `cd nucleus/fuzz && ./run-all.sh 300` (cargo-fuzz; nightly, or `RUSTC_BOOTSTRAP=1` as the script does). Crashes land in `fuzz/artifacts/`; `seeds/` holds the starting corpus |
| The explorer on a real binary with REA's Ghidra analysis | `nucleus/examples/explorer-demo/run-demo.sh` (needs gcc, and REA with Ghidra unless you pass REA JSON) |
| Linux diversion & wire capture end to end, in a throwaway network namespace (never touches the host's iptables) | `nucleus/scripts/test-linux-diversion.sh` (needs a kernel with the NAT modules and unprivileged user namespaces; or run the test binary with `sudo unshare --net`, as CI does) |

CI (`.github/workflows/ci.yml`) runs all of these on Linux, including the diversion test as
root in a private namespace, and builds and tests the nucleus on Windows with WinDivert.

The fallback tests to look at first:
- `falls_back_to_defaults_when_the_daemon_is_stopped` and
  `a_slow_daemon_misses_the_deadline_and_defaults_apply` in
  `nucleus/crates/listeners/tests/listeners.rs`;
- the daemon-kill section of `nucleus/crates/cli/tests/camel_link.rs`.

The WinDivert diverter itself has no automated test: CI can't divert a runner's own
traffic. Try it in a VM: enable the diverter, then `curl http://example.com`, `nslookup
example.com` and `ping 8.8.8.8` should all be answered by the nucleus.

## Differences from FakeNet-NG

- Fixed: FakeNet-NG's `TFTPListener.taste()` raises for anything but read requests, so its
  proxy can't route TFTP writes, data or acks. Here every packet type is recognized.
- Silent clients on an auto port are answered by port (e.g. a greeting on 25), rather than
  waiting forever.
- Custom Responses work with the same INI files, including unmodified Python providers
  (HttpDynamic, TcpDynamic, UdpDynamic; Unix only), via
  `nucleus/crates/listeners/src/providers.py`.
- Process attribution: events from local clients carry `process` {pid, name, exe} (Linux
  via /proc; Windows via WinDivert's socket layer).
- More protocols (IMAP, SSH with HASSH, Telnet, Redis, SOCKS, syslog, NTP, the small
  services), HTTP/2, certificates per hostname or IP, and every response can be decided by
  the Camel daemon.
- This project supersedes fakenet-rs, an earlier Rust port of FakeNet-NG's listeners: its
  protocols, Custom Responses, filters, report and interop tests all live here now, and
  `--import-fakenet-ini` reads its extended `default.ini` too.

## Install as a service

From a package (`scripts/package.sh` builds `dist/fakenet-hybrid-<version>-<target>.tar.gz`),
inside the analysis VM:

- **Linux:** `sudo deploy/linux/install.sh` installs to `/opt/fakenet-hybrid`, the config
  to `/etc/fakenet/fakenet.toml`, a generated link secret (readable by root and the
  daemon's `fakenet` group only), and two systemd units. The daemon runs unprivileged and
  sandboxed; the nucleus runs as root and runs `--restore-network` after every stop. Then
  `systemctl enable --now fakenet-daemon fakenet-nucleus`.
- **Windows:** `deploy\windows\install.ps1` (as Administrator) installs to
  `C:\FakeNetHybrid` with startup scheduled tasks running as SYSTEM, and the secret
  readable by SYSTEM and Administrators only. `uninstall.ps1` removes the tasks.

Neither script enables diversion: review the config first.

## Troubleshooting

- **`binding DNS to udp 0.0.0.0:53`: address in use (Linux):** systemd-resolved holds
  127.0.0.53:53. Either set `DNSStubListener=no`, or bind the nucleus to the VM's own address
  (`[nucleus] bind`). Upstream DNS from resolved is diverted to the nucleus either way.
- **FTP passive transfers hang:** keep `[defaults.ftp] passive_ports` set to a range. The
  diverter sends that range to the nucleus unchanged.
- **Every request falls back with `timeout`:** the daemon is overloaded or its rules are
  slow. Check `daemon/audit/` and its log. Raise `deadline_ms` if the malware tolerates it.
- **`unavailable` fallbacks:** the daemon isn't running, or is still warming up, or it
  failed the link handshake. Check both sides use the same secret file (the nucleus logs
  "Daemon failed authentication"; the daemon logs "Dropped a link message").
- **Python Custom Response providers don't run (Windows):** only static custom responses
  are supported there; the Python providers need Unix.
