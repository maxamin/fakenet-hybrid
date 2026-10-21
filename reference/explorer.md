# Explorer (`nucleus/crates/explorer`)

The explorer answers requests that the daemon left at the default. It is off by
default. It never sends traffic of its own: it only changes the content of answers.

## Flow

1. Every event, including notifies, goes to `Explorer::observe`. The explorer learns
   tokens from the traffic, computes `signatures(event)` (protocol and transport,
   destination, plus one protocol-specific signature), and credits every new signature
   to the actor's recent proposals inside `window_ms`. The latest proposal gets the full
   reward. Older ones get ½, ¼, and so on.
2. A request the daemon left at the default goes to `Explorer::propose`. The explorer
   filters templates by protocol and `when` (`Template::applies`), returns nothing with
   probability `1 - rate`, then picks one with `select`: UCB1 per `context(event)`,
   trying untried arms first. It renders the template with `Filler`, records the
   `Pending` proposal for the actor, and returns a `Proposal { response, close, template, tokens }`.
3. Coverage arrives through `ingest_drcov(data, file)` or `ingest_coverage_line(json)`,
   which map addresses to REA functions (`FunctionMap::functions_for`). That calls
   `reached_at(pid, functions, when)` and adds `coverage_weight` per new function.
4. `map()` returns `explorer-map.json`: proposals, behaviours, templates ranked by
   reward (with their behaviours, functions and best tokens), the top tokens,
   `first_seen_after`, reached and unreached functions, and hint statistics.

The actor (`Explorer::actor`) is `pid:N` when the process is known. Otherwise it is
whichever process was last seen at that IP, and failing that `ip:ADDR`.

## Modules

| Module | Items |
|---|---|
| `explorer.rs` | `ExplorerConfig` (defaults: rate 0.8, seed 0x5eed, window 3000 ms, coverage weight 5.0), `Explorer::{load, new, config, observe, propose, reached, reached_at, ingest_drcov, ingest_coverage_line, map}`, `select` (UCB1, exploration constant 1.4), `context`, `signatures`, `pattern` (abstracts digits and long hex/random runs), `shape` |
| `templates.rs` | `Template { name, protocol, body, close, when }`, `parse(toml)`, `Template::applies`, `render_with(body, source)` (the slot language), `slot`, `apply` (functions), `mutate(payload, rng)`, `mz_stub()` (a tiny PE), `Source` trait, `Probe` (validates templates at load) |
| `hints.rs` | `Hints { commands, keys, urls, domains, functions, … }`, `Hints::{merge, classify, from_binary, from_rea, from_rea_all, learn_from_traffic}`, `extract_strings` (ASCII and UTF-16LE), `name_words` (`cmd_download` → `download`), `sha256`, plus REA parsing (`collect_rea`, `parse_address`, `find_digests`, `is_runtime_function`, `is_metadata_section`) |
| `coverage.rs` | `Drcov::{parse, addresses}` (module table v1/v2 plus binary block table; the PID comes from the file name), `CoverageEvent` (JSONL with `pid`, `time` in ms, `functions`, `addresses`), `FunctionMap::{new, function_at, functions_for, names, is_empty}`, `parse_hex` |
| `rng.rs` | `Rng` (SplitMix64): `new`, `next_u64`, `below`, `unit`, `pick` |

## Template language (`templates/default.toml`)

Slots:

| Slot | Value |
|---|---|
| `{command} {key} {token} {string} {url} {domain} {path}` | Words from the hints |
| `{int} {ip} {port} {random}` | Generated values |
| `{offset}` | NTP time shift |
| `{mirror}` | The request's payload |
| `{mutate}` | A mutated copy of the payload |
| `{mz}` | A tiny PE stub |
| `{session}` | The session ID |
| `{param}` | The first IRC parameter |
| `{meta:FIELD}` | A field of the event's `meta` |

Functions, applied right to left: `b64`, `hex`, `json`, `urlenc`, `upper`, `lower`,
`len8`, `len16be`, `len16le`, `len32be`, `len32le`, `bulk`. Write `{{` and `}}` for
literal braces.

Built-in templates, about 60:

| Protocol | Templates |
|---|---|
| http | `http-token`, `-kv`, `-json`, `-json-task`, `-b64`, `-url`, `-redirect`, `-exe`, `-not-found`, `-server-error`, `-unavailable`, `-auth`, `-cookie`, `-header`, `-mirror`, `-mutate`, `-empty` |
| dns | `dns-a-random`, `-a-loopback`, `-a-zero`, `-txt-command`, `-txt-b64`, `-cname`, `-nxdomain`, `-mx` |
| raw | `raw-echo`, `-mutate`, `-command`, `-command-line`, `-command-url`, `-len8`, `-len16be`/`le`, `-len32be`/`le`, `-json`, `-kv`, `-b64`, `-close` |
| irc (on JOIN) | `irc-privmsg-command`, `-privmsg-command-url`, `-topic`, `-notice` |
| ftp | `ftp-file-exe`, `-file-command`, `-file-script`, `-reject` |
| others | `smtp-reject`, `smtp-tempfail`, `pop3-message`, `imap-no`, `telnet-output`, `telnet-url`, `redis-status`, `-bulk`, `-error`, `ntp-offset`, `tftp-exe`, `tftp-command`, `socks-refuse` |

None of the HTTP templates has a `when`. They apply to CONNECT, to WebSocket upgrades
and to OS connectivity checks too (flaw `BUG-02`).

## Demo

`nucleus/examples/explorer-demo/` builds `bot.c` with `-finstrument-functions`, which
writes coverage JSONL with the addresses of `cmd_download`, `cmd_keylog`, `cmd_scan`,
`cmd_update` and `cmd_sleep`. It runs the nucleus twice, explorer off and then on, and
reports which handlers each run reached.
