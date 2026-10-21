# The `fakenet-nucleus` binary (`nucleus/crates/cli`)

## Flags (`main.rs`, `Args`)

Modes are checked in this order. The first one that matches runs and the program exits.

| Flag | Function | Use case |
|---|---|---|
| `--import-fakenet-ini INI [-o FILE]` | `import::convert` | Convert a FakeNet-NG `default.ini` (including fakenet-rs's extended one) to TOML. Prints to stdout without `-o` |
| `--rules-from-har HAR [-o FILE]` | `har::rules` | Generate a Camel YAML route (`direct:decide-recorded`) that replays a HAR |
| `--replay EVENTS` (uses `-c`) | `replay::replay` | Send recorded events to the running daemon. Prints one JSON line per decision or fallback |
| `--report EVENTS [-o report.html]` | `write_report` | Render an HTML report from any `events.jsonl` |
| `--indicators EVENTS [-o DIR]` | `write_indicators` | Write `indicators.csv`, `indicators.stix.json` and `indicators.misp.json` |
| `--generate-secret PATH` | `generate_secret` | 32 random bytes as hex, `create_new`, mode 0600 on Unix |
| `--restore-network` | `diverter::restore` | Remove the iptables `FAKENET` chains a killed run left behind (Linux), or the firewall block (Windows) |
| `-c, --config FILE` | `Config::load` | Default `config/fakenet.toml` |
| `--check` | | Validate the config, load the fingerprint lists and compile the YARA rules, then exit. A `--run` sample is also hashed |
| `--run SAMPLE [--timeout 120] [--sample-arg A]...` | `run::Sample::inspect`, `run::execute`, `run::summary` | One run per sample, in a capture folder of its own |

## Startup sequence (`main`)

1. Load the config. With `--run`, set the capture dir to
   `<capture_dir>/<YYYYMMDD-HHMMSS>-<name>-<sha12>`. If the explorer has no samples,
   add the sample to it.
2. `config.secret()`. With no secret file, a warning is logged and the link is
   unauthenticated.
3. `Capture::open_with`, then the optional `WireCapture::start`, then optional YARA
   (`enable_yara`).
4. `TlsAuthority::generate()` creates a fresh CA for each run and writes it to
   `capture/ca.pem`. The optional TLS key log goes to `tls-keys.log`.
5. `Diverter::start` (only if enabled). Dropping the diverter restores the network.
6. `Explorer::load` (only if enabled).
7. `Link::start`, then `Limits::new`, then `Context`, then `Server::start` binds every
   listener.
8. Bind the control server on `nucleus.health` and run `serve_control`.
9. Background tasks: the coverage watcher (`watch_coverage`), `explorer-map.json`
   every 10 s, and the SIGHUP `[defaults]` reload (Unix).
10. Wait for Ctrl+C or SIGTERM, or for the sample to finish.

Shutdown runs in this order: abort the control server, drop the listeners, stop the
diverter, abort the background tasks, write the final explorer map, `finish_scans`
(YARA), log `nucleus_stopped`, write `report.html`, write `run.json` (for `--run`),
then write `indicators.*`. If `diverter.stop()` fails, the outputs are still written and the exit status is
non-zero.

## `lib.rs`

| Item | What it does |
|---|---|
| `Config`, `NucleusConfig`, `DaemonConfig`, `YaraConfig` | The TOML model (see [config.md](config.md)) |
| `Config::load(path)` | Read, parse, `resolve_paths`, `validate` |
| `Config::resolve_paths(base)` | Make relative paths relative to the config file |
| `Config::known_fingerprints()` | Merge the CSV lists into `HashMap<fingerprint, label>`. Later files win |
| `Config::validate()` | The lab-safety rules (loopback-only control plane, and so on) |
| `Config::plan()` | Build the `diverter::Plan` from the listeners |
| `Config::secret()` | Read and trim the secret file. Fails if it is shorter than 32 bytes |
| `Config::capture_limits()`, `Config::link(secret)` | Turn config into `capture::Limits` and `LinkConfig` |
| `loopback_url(url)` | Host part is `localhost` or a loopback IP |
| `write_report(files, out)` | Read the records and an `explorer-map.json` next to the last file, then render |
| `write_indicators(files, dir, sample)` | IOC exports. The sample comes from the argument or from `dir/run.json` |
| `watch_coverage(explorer, dir, capture)` | Poll every 1 s. Tails new complete lines of `*.jsonl` files. Ingests each `*.log` (drcov) once its size is stable across two polls |
| `generate_secret(path)` | See the flags table |
| `Control` | State for the control server |
| `serve_control(listener, control)` | HTTP/1.1 accept loop |
| `authorized(control, req)` | Bearer token or `fakenet_token` cookie, compared in constant time. Always true when there is no secret |
| `control_response` | The routes below |
| `constant_time_eq`, `query_param` | Helpers (no URL decoding) |

### Control server routes

| Route | Without auth | With auth |
|---|---|---|
| `GET /health` | `{"status":"ok"}` | Adds `daemon` (link health), `listeners`, `limits` |
| `GET /dashboard?token=SECRET` | | 303 to `/dashboard` with the cookie `fakenet_token=<secret>; HttpOnly; SameSite=Strict; Path=/` |
| `GET /dashboard` | 401 with a hint | The page (`dashboard/index.html`) |
| `GET /dashboard.js`, `/dashboard.css` | Always served | |
| `GET /api/records?after=N&limit=L` | 401 | Up to 5000 recent records (in-memory ring) with sequence numbers |
| `GET /api/summary` | 401 | Daemon, listeners, limits, explorer summary |

Every response carries a strict CSP, `nosniff`, `no-store` and `no-referrer`. The
dashboard JS (`dashboard/dashboard.js`) renders everything with `textContent`, polls
`/api/records` every 1 s and `/api/summary` every 2 s, and keeps 5000 records in the
browser.

## <a name="run"></a>`run.rs` (`--run`)

| Item | What it does |
|---|---|
| `Sample::inspect(path, args)` | Canonicalize the path, read the whole file, compute SHA-256 and MD5 |
| `Sample::folder_name()` | `YYYYMMDD-HHMMSS-<sanitized name, at most 40 chars>-<sha256[:12]>` |
| `execute(sample, timeout, capture, interrupt)` | Spawn the sample with the working directory set to its folder and `kill_on_drop`. The run ends when the sample exits plus 5 s of grace, on timeout (kill), or on interrupt (kill). Logs `sample_started`, `sample_exited`, `sample_killed`, `sample_failed` |
| `summary(sample, outcome, capture)` | The `run.json` content: sample, run, record counts by kind, events by protocol, file names |

On Unix the sample runs as `--run-as USER` (required when the nucleus is root), in its own
session and (Linux) cgroup; the whole tree is tracked and killed. On Windows it runs in a Job
Object (kill on close, no breakaway) with a restricted token unless `--run-as administrator`
(`run_windows.rs`).

## `replay.rs`

`replay(link, records)` handles records with `kind == "event"` and
`expects_reply != false`. It parses each one as a `schema::Event` (the record's
`request_id` and `session_id` are kept) and calls `Link::decide`. Each output line has
the protocol, a summary of method/host/path/qname/qtype/command/argument, the route,
`default`, `close`, and the first 160 bytes of the response, or the fallback reason.

## `har.rs`

- `exchanges(har)` maps `"METHOD host /path"` to a list of raw HTTP/1.1 responses in
  order. It drops pseudo-headers and the framing headers (`content-length`,
  `transfer-encoding`, `content-encoding`, `connection`, `keep-alive`), skips headers
  containing CR/LF, and base64-decodes `content.encoding = "base64"` bodies.
- `rules(har, source)` emits the YAML route with a Groovy map of base64 responses. Each
  response is played in order per `FakenetActor`, then the last one repeats, with
  `FakenetRoute = recorded`.
- `groovy_string` escapes `\` and `'` only (flaw `SEC-12`).

## `import.rs`

`convert(ini, base)` handles the sections as follows:

- `[Diverter]`: `NetworkMode` becomes `mode`. `BlackListPortsTCP/UDP` merge into
  `ignore_ports`. `ProcessBlackList` becomes `excluded_processes`. `ModifyLocalDNS`
  becomes `fix_dns`. `FixGateway` becomes `fix_gateway`.
- Each enabled listener section becomes a `[[listener]]` with `name`, `protocol`
  (from `protocol_for`), `transport`, `port`, `tls` (`UseSSL`), `custom`, and the
  white/blacklists.
- A `Port` of `a-b` becomes `defaults.ftp.passive_ports`.
- `Webroot`, `FTPRoot` and `TFTPRoot` become the defaults' roots.
- Anything unsupported becomes an escaped `# NOTE:` comment.

`protocol_for` maps FakeNet-NG and fakenet-rs listener class names to protocols.
