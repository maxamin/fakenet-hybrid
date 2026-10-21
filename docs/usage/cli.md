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
| `--generate-secret PATH` | | Write 32 random bytes as 64 hex characters plus a newline, and print the two settings that use it. Fails if the file exists. Mode 0600 on Unix |
| `--insecure-link` | | Allow a daemon link without `secret_file` (otherwise start-up stops). Any local process could then read events or pose as the daemon |
| `--restore-network` | | Remove what a run left: Linux, the `FAKENET` iptables/ip6tables chains (with `--keep-block`, only the diversion); Windows, the firewall block, restoring the firewall and forwarding state it changed |
| `--run-as USER` | | `--run` only. Unix: the account the sample runs as (required when the nucleus runs as root; `root` keeps root). Windows: `restricted` (default: Administrators deny-only, no privileges, medium integrity) or `administrator` |
| `--report EVENTS` | | Render an HTML report from one `events.jsonl` (to `-o`, default `report.html`). Includes `explorer-map.json` from the same folder if present. Also reads its rotated siblings (`events.N.jsonl`), as does `--indicators` |
| `--indicators EVENTS` | | Write `indicators.csv`, `indicators.stix.json` and `indicators.misp.json` to `-o DIR` (default: the events file's folder). Uses `DIR/run.json` for the sample if present |
| `--import-fakenet-ini INI` | | Convert a FakeNet-NG (or fakenet-rs) `default.ini` to TOML (to `-o`, default stdout) |
| `--rules-from-har HAR` | | Generate a Camel route replaying a HAR recording (to `-o`, default stdout) |
| `--replay EVENTS` | | Send a capture's events to the running daemon (using `-c`'s `[daemon]` section and secret) and print each decision |
| `--diff A B` | | Compare two runs (capture folders or `events.jsonl` files): destinations, DNS names, HTTP requests, commands, raw messages, credentials, TLS/SSH clients, saved files and detections only one run has, plus record counts. JSON to `-o` if given. See [reverse engineering](reverse-engineering.md) |
| `--infer EVENTS` | | Per destination, the structure of unparsed (`raw`) client messages: magic, constant bytes, length field, per-session counter, encodings, single-byte XOR key. With `-o DIR`, a Wireshark Lua dissector per destination |
| `--decode EVENTS` | | Run client payloads through `--transform` steps into `-o DIR` (default `decoded/` next to the events), with `index.json` |
| `--transform STEP` | | `--decode` step, applied in order: `base64`, `hex`, `xor:KEY`, `rc4:KEY` (KEY as hex, or `text:...`), `skip:N` |
| `--only TEXT` | | `--decode`: only destinations containing TEXT (e.g. `:4444`) |
| `--learn PCAP...` | | Learn a model pack from pcap files or capture folders (their `traffic*.pcap`, `wire*.pcap`, recursively) into `-o` (default `model.json`). See [learned models](learning-and-responders.md) |
| `--model-info PACK` | | Summarise a model pack: protocols, exchanges, most frequent request keys |
| `--all-protocols` | | `--infer`, `--decode`: every protocol, not only `raw` |
| `-o, --output PATH` | | Output for the modes above |

## Normal run: start-up and shutdown

Start-up (`main`):

1. Load the config (`Config::load`: parse, resolve relative paths, validate). With `--run`,
   append `<YYYYMMDD-HHMMSS>-<name>-<sha256[:12]>` to `capture_dir`, and add the sample to
   `[explorer] samples` if that list is empty.
2. Read the secret. Without one, stop unless `--insecure-link` (or no daemon URL is set).
3. Open the capture (`Capture::open_with`), start the optional wire capture and YARA.
4. Load the TLS CA from `ca_cert`/`ca_key` (creating and saving it on first use) or generate one, and write `capture/ca.pem`; open `tls-keys.log` if enabled.
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

If removing the diversion fails, the outputs are still written and the exit status is non-zero.

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
`--run` executes the sample. Unix: as `--run-as USER`, in its own session and (Linux)
cgroup. Windows: with a restricted token, in a Job Object that kills the whole tree and
allows no breakaway. Either way the run ends when the whole tree has exited, and what is left
is killed. Revert the VM after each run all the same.
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

Keys are written as single-quoted Groovy strings with control characters escaped (`\uXXXX`), so HAR text can't end them.

## `--import-fakenet-ini`

Source: `nucleus/crates/cli/src/import.rs`. See {doc}`fakenet-ng-migration`.
