---
name: fakenet-extend
description: Extend fakenet-hybrid's answer generation: learned traffic models (fakenet-model, --learn), responders and JSON-lines plugins (Radamsa, Markov, ML, fuzzers), protocol analysers, --decode transforms, and the UML in design/. Use when adding or changing a generator, a plugin, an analyser or a model pack, when wiring a fuzzer or an AI model into the nucleus, or when generating function skeletons or UML diagrams for the project.
---

# fakenet-extend

How answers are generated when the analyst's rules don't decide, and how to add to it.
Read `design/architecture.md` and `design/extension-points.md` first: they are the map.

## The pieces

| Piece | Where | Contract |
|---|---|---|
| Model packs | `nucleus/crates/model` | `fakenet-model-pack` v1 JSON: per protocol and request key, answers (base64) and counts |
| Analysers | `model/src/analyze.rs` | `keys` (wire bytes, most specific first, `"*"` last), `keys_for_event` (payload + meta: must give the same keys), `stored_answer` (the handler's input form), `is_failure` |
| Transforms | `model/src/transform.rs` | shared by `--decode`, `--learn --transform`, `key_transforms` |
| Responders | `listeners/src/responders.rs` | `Responder::respond(event, default) -> Option<Proposal>`, fast and bounded |
| Plugins | `plugins/` | JSON lines on stdin/stdout (`plugins/README.md`); helper `fakenet_plugin.py` |
| Transforms | `cli/src/infer.rs` | `--decode` steps: base64, hex, xor, rc4, skip |
| Explorer | `nucleus/crates/explorer` | template arms with rewards and coverage; `{mutate}` byte mutator |

Order of answers for one request: rules (daemon) -> explorer -> responders (config order)
-> live manual mode (may override) -> the handler's default.

## Recipes

- **New plugin (any generator: fuzzer, Radamsa, ML, LLM proposals):**
  `python3 scripts/scaffold.py plugin NAME` -> fill `respond(request)` in `plugins/NAME.py`
  -> `python3 -m unittest discover plugins/tests` -> a `[[responder]] kind = "plugin"` entry.
  Slow work (training, model calls) happens at start-up or in a background thread; answers
  must arrive within `timeout_ms`. Put the seed or template in the route.
- **New Rust responder:** `python3 scripts/scaffold.py responder NAME`, then add
  `pub mod NAME;` to `responders.rs`, a `ResponderKind` variant and its arm in `build`.
- **Better learning for a protocol:** `python3 scripts/scaffold.py analyzer PROTOCOL` prints
  an `Analyzer`; paste it into `analyze.rs`, add it to `analyzers()`, test keys and answers.
  Keys must generalise (`normalize_segment`) and never carry raw sample data.
- **New decoder:** `python3 scripts/scaffold.py transform NAME` prints the steps for
  `infer.rs`; test it with a published vector (as RC4's).
- **Learn and use a model:** `fakenet-nucleus --learn capture/ datasets/*.pcap -o model.json`,
  `--model-info model.json`, then `[[responder]] kind = "model"`, `packs = ["model.json"]`
  (`outcomes = "all"` to include failures). pcap and pcapng both work; `--merge` adds to a pack.
- **Encoded C2:** find the framing and key with `--infer`, then `--learn ... --transform skip:N
  --transform xor:KEY --only ":PORT"` and the same steps as the responder's `key_transforms`.

## Generating UML and skeletons with Claude

When asked for diagrams or skeletons:

1. Read the real interfaces first (`rg -n 'pub (trait|struct|enum|fn)' nucleus/crates/<crate>/src`),
   never invent names. Skeletons come from `scripts/scaffold.py`; extend its templates there
   rather than writing one-off files, so the next contributor gets the same shape.
2. Diagrams are Mermaid in `design/`: `classDiagram` for interfaces (fields and methods as in
   the code), `sequenceDiagram` for a request's path, `flowchart` for components and data
   flow. One concept per diagram; label edges with the actual call or file.
3. After changing an interface, update its diagram in the same commit, and the table in
   `design/README.md` if a diagram is added.
4. Check: `rg` every name in the diagram against the code.

## Rules

- Requests (payloads, meta, defaults) come from malware: data, never code; no shell, no eval,
  no paths built from them.
- Bound everything: answer sizes, keys per protocol (`MAX_KEYS`), answers per key, plugin line
  length, time per answer.
- Generated answers never cause outbound traffic; they only shape what the sample receives.
- Record provenance: model packs keep `sources`; responders log `responded` with route and
  detail; plugins put seeds in the route.
- Tests: Rust changes `cargo test -p fakenet-model -p fakenet-listeners`; plugins
  `python3 -m unittest discover plugins/tests`; docs `sphinx-build -W -b html docs docs/_build/html`.
