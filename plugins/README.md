# Responder plugins

A responder plugin is a program, in any language, that answers requests the analyst's rules
and the explorer left to the default. The nucleus starts it from a `[[responder]]` entry,
keeps it running, and talks to it in JSON lines over stdin and stdout.

| File | What it is |
|---|---|
| `fakenet_plugin.py` | Helper: the protocol in one function call (`run(respond)`), standard library only |
| `template.py` | A plugin to copy and fill in |
| `radamsa_mutator.py` | Mutates the handler's default answer with Radamsa (or a built-in mutator) |
| `markov_bodies.py` | Generates new HTTP bodies from a model pack with a character Markov chain |
| `tests/` | `python3 -m unittest discover plugins/tests` |

Scaffold a new plugin with `python3 scripts/scaffold.py plugin NAME`.

## Configuration

```toml
[[responder]]
name = "radamsa"                 # logged as the route's prefix
kind = "plugin"
command = ["python3", "-I", "plugins/radamsa_mutator.py", "--rate", "0.3"]   # no shell
timeout_ms = 150                 # answers later than this are dropped
rate = 1.0                       # share of matching requests offered to it
protocols = ["http", "raw"]      # optional filter: protocols, hosts, contains
```

Responders are tried in config order; the first answer wins. A `kind = "model"` responder
(`packs = ["model.json"]`) answers from a learned traffic model without a plugin.

## Protocol

To the plugin, one line per request:

```json
{"type": "respond", "id": 7, "protocol": "http", "event": {...}, "default_base64": "SFRUUC8xLjEg..."}
```

- `id`: echo it back; answers may come in any order.
- `event`: the full link Event (`schema/fakenet-link-v1.schema.json`): `payload` (base64),
  `meta` (what the handler parsed), `src`, `dst`, `process`, `session_id`, `seq`...
- `default_base64`: the handler's built-in answer, when known (HTTP, raw). For HTTP this is
  the whole raw response; for DNS an answer is text lines (`A 1.2.3.4`, `TXT ...`, `NXDOMAIN`).

From the plugin, one line per request:

```json
{"id": 7, "response_base64": "...", "close": false, "route": "radamsa seed=42"}
{"id": 7, "skip": true}
```

The plugin's stderr goes to the nucleus's log. If it exits it is restarted, at most every
5 seconds. Lines longer than 16 MiB are cut.

## Rules for plugins

- Requests come from the malware: treat payloads and metadata as hostile data. Never `eval`
  them, put them in a shell command, or write them to paths built from them.
- Answer within `timeout_ms`: slow work (training, LLM calls) belongs before the run or in
  a background thread, with answers precomputed.
- Record what made an answer (a seed, a template) in `route`: it appears in `events.jsonl`
  as the `responded` record, so a finding can be reproduced.
