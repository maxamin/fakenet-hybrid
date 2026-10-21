# The `fakenet-nucleus` command

Source: `nucleus/crates/cli/src/main.rs` (`Args`).

```text
fakenet-nucleus [-c CONFIG] [--check]
                [--run SAMPLE [--timeout SECS] [--sample-arg ARG]...]
fakenet-nucleus --generate-secret PATH
fakenet-nucleus --restore-network
fakenet-nucleus --report EVENTS [-o report.html]
fakenet-nucleus --indicators EVENTS [-o DIR]
fakenet-nucleus --import-fakenet-ini INI [-o FILE]
fakenet-nucleus --rules-from-har HAR [-o FILE]
fakenet-nucleus --replay EVENTS [-c CONFIG]
```

The one-shot modes are checked in this order; the first present one runs and the program
exits: `--import-fakenet-ini`, `--rules-from-har`, `--replay`, `--report`, `--indicators`,
`--generate-secret`, `--restore-network`. Otherwise the config is loaded and, with
`--check`, validated, or the nucleus runs.

Logging uses `RUST_LOG` (`tracing-subscriber` env filter; default `info`), for example
`RUST_LOG=fakenet_link=debug,info`.

## Options

| Option | Default | Effect |
|---|---|---|
| `-c, --config FILE` | `config/fakenet.toml` | The TOML config |
| `--check` | | Validate the config, load the fingerprint lists, compile the YARA rules (to a temporary file), hash the `--run` sample, then exit |
| `--run SAMPLE` | | Analyse one sample in a capture folder of its own (below) |
| `--timeout SECS` | 120 | `--run` only: kill the sample and end the run after this long |
| `--sample-arg ARG` | | `--run` only: an argument for the sample; repeat for several |
| `--generate-secret PATH` | | Write 32 random bytes as 64 hex characters plus a newline. Fails if the file exists. Mode 0600 on Unix |
| `--restore-network` | | Linux: remove the `FAKENET` iptables/ip6tables chains a killed run left. Windows: nothing to do |
| `--report EVENTS` | | Render an HTML report from one `events.jsonl` (to `-o`, default `report.html`). Includes `explorer-map.json` from the same folder if present. Reads only the file given (flaw BUG-13) |
| `--indicators EVENTS` | | Write `indicators.csv`, `indicators.stix.json` and `indicators.misp.json` to `-o DIR` (default: the events file's folder). Uses `DIR/run.json` for the sample if present |
| `--import-fakenet-ini INI` | | Convert a FakeNet-NG (or fakenet-rs) `default.ini` to TOML (to `-o`, default stdout) |
| `--rules-from-har HAR` | | Generate a Camel route replaying a HAR recording (to `-o`, default stdout) |
| `--replay EVENTS` | | Send a capture's events to the running daemon (using `-c`'s `[daemon]` section and secret) and print each decision |
| `-o, --output PATH` | | Output for the modes above |

## Normal run: start-up and shutdown

Start-up (`main`):

1. Load the config (`Config::load`: parse, resolve relative paths, validate). With `--run`,
   append `<YYYYMMDD-HHMMSS>-<name>-<sha256[:12]>` to `capture_dir`, and add the sample to
   `[explorer] samples` if that list is empty.
2. Read the secret. Without one, log a warning: the link is unauthenticated.
3. Open the capture (`Capture::open_with`), start the optional wire capture and YARA.
4. Generate the TLS CA and write `capture/ca.pem`; open `tls-keys.log` if enabled.
5. Start the diverter (if enabled). From here, dropping it restores the network.
6. Load the explorer (if enabled).
7. Start the link, the limits, the shared `Context`, then bind every listener
   (`Server::start`).
8. Bind the control server on `nucleus.health`.
9. Start background tasks: the coverage watcher, `explorer-map.json` every 10 s, and the
   SIGHUP reload of `[defaults]` (Unix).
10. Log `nucleus_started`, then wait for Ctrl+C or SIGTERM, or for the `--run` sample.

Shutdown: stop the control server, drop the listeners, stop the diverter, stop the
background tasks, write the final `explorer-map.json`, wait for YARA scans, log
`nucleus_stopped`, write `report.html`, write `run.json` (`--run`), write the indicators.

If removing the diversion fails, the steps after it are skipped (flaw BUG-02).

## `--run`: one sample per capture folder

Source: `nucleus/crates/cli/src/run.rs`.

```sh
sudo fakenet-nucleus -c my.toml --run ./sample.exe --timeout 300 --sample-arg -q
```

- `Sample::inspect` canonicalises the path, reads the file, and computes SHA-256 and MD5.
- `execute` spawns the sample with its own folder as working directory, after every
  listener is up. The run ends when:
  - the sample exits, plus a 5 s grace period for its last connections (`exited`),
  - `--timeout` passes: the sample is killed (`timeout`),
  - Ctrl+C or SIGTERM: the sample is killed (`interrupted`).
- Records: `sample_started`, `sample_exited`, `sample_killed`, `sample_failed`.
- `run.json` (`summary`): the sample (path, name, hashes, size, arguments), the run (pid,
  `ended_by`, exit status, start, duration), record counts by kind, events by protocol, and
  the output file names.

```{warning}
`--run` executes the sample with the nucleus's privileges (root or Administrator), and only
the direct child is killed. Descendants survive the run, and then the diversion is gone.
Read flaws SEC-01, SEC-02 and LEAK-01 before relying on it; revert the VM after each run.
```

## `--replay`: test rules without traffic

Source: `nucleus/crates/cli/src/replay.rs`.

```sh
fakenet-nucleus -c my.toml --replay capture/events.jsonl
```

Each record with `kind == "event"` and `expects_reply != false` is parsed back into an
Event (keeping its `request_id` and `session_id`) and sent through `Link::decide`, after a
500 ms pause to let the WebSocket connect. Each output line is JSON: the protocol, a short
summary (method, host, path, qname, qtype, command, argument), the route, whether the
answer is the default, the close flag, and the first 160 bytes of the response, or the
fallback reason. Use it as a regression test after editing `decisions.yaml`.

## `--rules-from-har`: replay a recorded C2

Source: `nucleus/crates/cli/src/har.rs`.

```sh
fakenet-nucleus --rules-from-har c2.har -o daemon/routes/recorded.yaml
```

- `exchanges` groups the HAR's entries by `"METHOD host /path"` (query and fragment
  dropped) and turns each response into raw HTTP/1.1. Pseudo-headers and framing headers
  (`content-length`, `transfer-encoding`, `content-encoding`, `connection`, `keep-alive`)
  are dropped, headers containing CR/LF are skipped, and base64 bodies are decoded.
- `rules` writes a route `direct:decide-recorded` holding a Groovy map of base64 responses.
  Responses are played in order per `FakenetActor`, then the last one repeats. The route
  sets `FakenetRoute = recorded`.
- To use it, add `- to: direct:decide-recorded` to `decide-http`. Requests it doesn't know
  keep whatever the other rules set.

See flaw SEC-08 about untrusted HAR files.

## `--import-fakenet-ini`

Source: `nucleus/crates/cli/src/import.rs`. See {doc}`fakenet-ng-migration`.
