# The explorer

Defaults show a sample's first move. Many samples only reveal their capabilities when the
C2 answers with something they understand: a task they parse, a command name they compare
against. The explorer looks for such answers automatically. It is off by default, it only
answers what the analyst's rules leave undecided, and it never sends traffic of its own.

Source: `nucleus/crates/explorer/src/`.

## Enabling it

```sh
nucleus/scripts/rea-hints.sh sample.exe rea.jsonl ghidra   # optional: REA + Ghidra analysis
```

```toml
[explorer]
enabled = true
samples = ["sample.exe"]       # strings are extracted from it
rea = ["rea.jsonl"]            # functions, strings, imports from REA
coverage_dir = "coverage"      # optional: a tracer writes here
module = "sample.exe"
image_base = "0x400000"
```

## How it works

1. **Observe.** Every event, including notifications, goes to `Explorer::observe`. The
   explorer learns tokens from the traffic and computes behaviour signatures
   (`signatures(event)`: protocol and transport, destination, and one protocol-specific
   signature such as the HTTP route and query keys). Each new signature is credited to the
   same actor's recent proposals within `window_ms`: the latest gets the full reward, older
   ones ½, ¼ and so on.
2. **Propose.** When the daemon leaves a request at the default, `Explorer::propose`
   filters the templates by protocol and `when`, returns nothing with probability
   `1 - rate`, then picks a template with UCB1 per request context (`context(event)`:
   HTTP method and path pattern, DNS qtype, raw transport and port, or the command). Untried
   templates go first; the exploration constant is 1.4. It fills the template's slots with
   hints and returns the response. The session logs `explored` and the route is
   `explorer:<template>`.
3. **Coverage.** A tracer writes drcov logs or JSONL lines into `coverage_dir`. The CLI's
   watcher feeds them in (`ingest_drcov`, `ingest_coverage_line`). Addresses are mapped to
   REA functions, and each newly reached function adds `coverage_weight` to the reward of
   the proposals in the window.
4. **Map.** `explorer-map.json` (every 10 s and at stop) lists proposals, behaviours,
   templates ranked by reward (with their behaviours, functions and best tokens), the top
   tokens, which behaviour first appeared after which template, reached and unreached
   functions, and hint statistics. The report has an Explorer section built from it.

The actor is `pid:N` when the process is known; otherwise the process last seen at that
IP; otherwise `ip:ADDRESS`.

```{note}
Destinations count as behaviour, so a scanning sample makes every answer look rewarding
(flaw ARCH-02). Restrict `protocols` or ignore the map's rankings for such samples.
```

## Hints

`hints.rs` builds the word lists the templates draw from:

- strings from `samples`: ASCII and UTF-16LE, classified into commands, keys, URLs,
  domains, paths;
- REA's analysis: procedure names, strings, imports and segments. Words from the
  sample's own function names are favoured (`cmd_download` gives `download`), since
  command handlers are usually named after their commands. Runtime and library functions
  are filtered out;
- traffic: words the sample itself sent (`learn_from_traffic`).

The explorer warns when REA analysed a different build (SHA-256 mismatch) than `samples`.

## Templates

`nucleus/crates/explorer/templates/default.toml` holds about 60 templates. Each has a
`name`, a `protocol`, a `body`, an optional `close`, and an optional `when` condition.

Slots:

| Slot | Value |
|---|---|
| `{command}`, `{key}`, `{token}`, `{string}`, `{url}`, `{domain}`, `{path}` | Words from the hints |
| `{int}`, `{ip}`, `{port}`, `{random}` | Generated values |
| `{offset}` | An NTP time shift |
| `{mirror}` | The request's payload |
| `{mutate}` | A mutated copy of the payload |
| `{corpus}` | A mutated copy of a rewarded answer from the corpus (picked in proportion to its reward); without one, of the payload |
| `{mz}` | A tiny PE stub |
| `{session}` | The session ID |
| `{param}` | The first IRC parameter |
| `{meta:FIELD}` | A field of the event's `meta` |

**Corpus.** An answer whose proposal earns a reward (new behaviour or coverage) joins the
corpus, as in coverage-guided fuzzers: later proposals of the `http-corpus` and `raw-corpus`
templates mutate what already worked instead of starting from nothing. Up to 256 entries
(64 KiB each) are kept, the least rewarded dropped first. With `corpus_dir`, the corpus is
loaded at start and saved at stop (one `<protocol>-<hash>.bin` file per answer; loaded
answers start with a reward of 1), so it grows across runs and samples. The map's `corpus`
field counts its answers by protocol.

Functions, applied right to left: `b64`, `hex`, `json`, `urlenc`, `upper`, `lower`, `len8`,
`len16be`, `len16le`, `len32be`, `len32le`, `bulk`. Write `{{` and `}}` for literal braces.
Templates are validated at load (`Probe`), so a broken one fails the start.

Built-in families: HTTP (token, key-value, JSON, JSON task, base64, URL, redirect, `.exe`,
error codes, auth, cookie, header, mirror, mutate, empty), DNS (random/loopback/zero A,
TXT command, TXT base64, CNAME, NXDOMAIN, MX), raw (echo, mutate, command variants,
length-prefixed, JSON, key-value, base64, close), IRC on JOIN (PRIVMSG command, topic,
notice), FTP (file as exe/command/script, reject), and SMTP, POP3, IMAP, Telnet, Redis,
NTP, TFTP and SOCKS answers. The HTTP templates have no `when`, so they also apply to
CONNECT, WebSocket upgrades and connectivity checks.

## Coverage formats

- **drcov** logs (`*.log`): module table v1/v2 and the binary basic-block table; the PID
  comes from the file name. A file is read once its size is stable across two polls.
- **JSONL** (`*.jsonl`): `{"pid": N, "time": ms, "functions": ["name", ...]}` or
  `"addresses": [...]`. New complete lines are read each second.

## The demo

`nucleus/examples/explorer-demo/run-demo.sh` builds `bot.c` with
`-finstrument-functions` (it writes coverage JSONL for `cmd_download`, `cmd_keylog`,
`cmd_scan`, `cmd_update` and `cmd_sleep`), runs the nucleus on localhost high ports with no
diversion, first without and then with the explorer, and reports which handlers each run
reached. With defaults none are reached; with the explorer, four. It needs gcc, and REA
with Ghidra unless you pass REA JSON files.
