# Learned models and responders

When the analyst's rules and the explorer leave a request to the default, **responders**
can answer it instead: a model learned from real traffic, or a plugin program (Radamsa,
a Markov generator, a machine-learning model, a fuzzer). They are tried in config order; the
first answer wins, and the handler's built-in default applies only when none answers.

| Step | Command or config |
|---|---|
| Learn a model from captures | `fakenet-nucleus --learn capture/ datasets/*.pcap -o model.json` |
| ...including encrypted sessions | `--learn capture/ --keylog capture/tls-keys.log` |
| Learn while running | `[learn] into = "live-model.json"` |
| Generate new answers instead of replaying | `[[responder]] kind = "model"`, `generate = true` |
| Look at it | `fakenet-nucleus --model-info model.json` |
| Answer from it | `[[responder]] kind = "model"`, `packs = ["model.json"]` |
| Answer from a program | `[[responder]] kind = "plugin"`, `command = [...]` (see `plugins/README.md`) |
| Write a plugin | `python3 scripts/scaffold.py plugin NAME` |

Diagrams: `design/architecture.md` and `design/extension-points.md` in the repository.

## Learning a model

`--learn` reads pcap and pcapng files: this project's captures (`traffic.pcap`, `wire.pcap`),
captures from fuzzing or REA runs, and public datasets. A folder is searched recursively for
`.pcap`, `.pcapng` and `.cap` files (capture folders and their `previous/` archives included).
Link types: raw IP, Ethernet (with VLAN tags), Linux cooked v1 and v2. `--merge pack.json`
adds what is learned to an existing pack instead of starting a new one.

For each TCP connection (reassembled per direction) and UDP flow, it pairs what the client
sent with what the server answered, identifies the protocol from the first client bytes and
the port (as the nucleus's sniffer does), and files the answer under a **request key**:

| Protocol | Key | Answer stored as |
|---|---|---|
| HTTP | method and normalised path (`GET /api/bots/{n}/task`; numbers, hex, UUIDs, tokens and `name=value` values typed) | the complete raw response (chunked or truncated ones are skipped) |
| DNS | query type (`A`, `TXT`...) | answer lines the DNS handler takes (`A 1.2.3.4`, `TXT ...`, `NXDOMAIN`) |
| SMTP, POP3, FTP, IRC, Telnet, IMAP | the command (IMAP: after the tag) | the server's reply |
| Redis | the command name | the reply |
| MQTT | packet type and topic (`PUBLISH bots/{n}/tasks`) | the body of the server's first PUBLISH (what the MQTT handler sends a subscriber) |
| CoAP | method and Uri-Path (`GET /sensors/{n}`) | the response payload |
| Anything else, text | `text:` and the leading word (`text:UPTIME`) | the reply |
| Anything else, binary | first two bytes and size class (`dead:len64`) | the reply |
| All | `<greeting>` for what a server sends before any request | the banner |

The result is a **model pack**: JSON (`fakenet-model-pack`, version 1) listing, per protocol
and key, the distinct answers (base64, up to 64 KiB each, 16 per key) and how often each was
seen, plus the source file names. Packs are meant to be shared and combined: list several in
`packs` and their counts add up.

SMB and LDAP aren't learned: their handlers build each answer from protocol state, so a
recorded one can't be replayed.

### Encrypted traffic: `--keylog`

With an NSS key log (what browsers write to `SSLKEYLOGFILE`, and the nucleus to its
capture's `tls-keys.log`), TLS sessions are decrypted and learned from their plaintext, so
HTTPS C2 yields HTTP keys and answers instead of an opaque `tls` stream:

```sh
fakenet-nucleus --learn capture/ datasets/https.pcapng --keylog capture/tls-keys.log -o model.json
```

| Version | Secrets used | Suites |
|---|---|---|
| TLS 1.3 (RFC 8446) | `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| TLS 1.2 | `CLIENT_RANDOM` (the master secret) | ECDHE/DHE/RSA with AES-GCM (RFC 5288) or ChaCha20-Poly1305 (RFC 7905) |

Sessions are matched to secrets by the ClientHello's random. Sessions without secrets, CBC
suites, TLS 1.3 drafts, and records that fail authentication stay encrypted. The pack's
`decrypted` field counts the sessions learned from plaintext. Code: `nucleus/crates/model/src/tls.rs`.

### Encoded C2: keying by the decoded command

A C2 protocol that encodes its messages gives every request a different look. Learn with the
same decoding steps as `--decode` (find them with `--infer`), and requests are keyed by
their decoded content while answers are stored as sent:

```sh
fakenet-nucleus --learn capture/ --transform skip:9 --transform xor:5a --only ":4444" -o c2.json
```

`--only` limits the decoding to flows whose `"<protocol> :<port>"` contains the text. The
responder must decode live requests the same way, with `key_transforms`:

```toml
[[responder]]
name = "c2"
kind = "model"
packs = ["c2.json"]
key_transforms = ["skip:9", "xor:5a"]
protocols = ["raw"]
```

A request that doesn't decode is looked up as sent.

## Answering from a model

```toml
[[responder]]
name = "model"
kind = "model"
packs = ["model.json"]          # relative to the config file
protocols = ["http", "dns"]     # optional filter: protocols, hosts, contains
rate = 1.0                      # share of matching requests it answers
outcomes = "successful"         # or "all": include NXDOMAIN, HTTP 4xx/5xx... as recorded
generate = false                # true: new text answers from a Markov model of the recorded ones
```

For a request, the most specific key with answers wins (`GET /gate/{n}`, then `GET *`,
then the protocol as a whole), and an answer is picked at random **in proportion to how often
it was seen**. With `outcomes = "successful"` (the default) failures are left out, so the
sample keeps going; `all` reproduces the recorded distribution, failures included. Each
answer is logged as a `responded` record with the key and the answer's probability.

Packs are reloaded when their files change (checked every 2 seconds), so a pack that grows
during the run (online learning, below) or is replaced by a new `--learn` takes effect
without a restart.

### Generating instead of replaying

A sample that compares successive answers (a beacon that waits for a new task) sees a loop
when every answer is a replay. With `generate = true`, text answers come from an order-4
byte Markov chain trained on the key's recorded answers: new text with the same words,
punctuation and line endings.

| Answer | Generated |
|---|---|
| HTTP | the body; the recorded status line and headers are kept, `Content-Length` set to match, chunking dropped |
| Other text (line protocols, text C2) | the whole answer, ending like the recorded ones (`\r\n` or `\n`) |
| DNS, binary | never: replayed as recorded |

A key needs at least one text answer longer than 4 bytes; otherwise the answer is replayed.
The `responded` record's detail carries `"generated": true`.

## Learning online

`[learn]` turns the answers of a running analysis into a model as they are given:

```toml
[learn]
into = "live-model.json"                    # relative to the config file
sources = ["rules", "manual", "plugins"]    # plus "explorer"
save_every_s = 30
```

| Source | Answers from |
|---|---|
| `rules` | the daemon's rules (and the handler's defaults they leave) |
| `manual` | live manual mode |
| `plugins` | plugin responders |
| `explorer` | the explorer's proposals (off by default: they're experiments, not ground truth) |

Model responders' own answers are never learned (that would only reinforce the pack). The
pack's earlier contents are kept; this run is added under the source `live:<capture dir>`.
It is written every `save_every_s` seconds when something was added, and at stop. A model
responder whose `packs` include the same file answers from it during the run.

## Plugins

A plugin is a long-lived program speaking JSON lines (protocol: `plugins/README.md`):

```toml
[[responder]]
name = "radamsa"
kind = "plugin"
command = ["python3", "-I", "plugins/radamsa_mutator.py", "--rate", "0.3"]
protocols = ["raw", "http"]
timeout_ms = 150
```

| Plugin | What it does |
|---|---|
| `radamsa_mutator.py` | Mutates the handler's default answer (or, without one, the client's bytes) with Radamsa, or a built-in mutator; the seed is in the route |
| `markov_bodies.py` | New HTTP answers from a model pack: a recorded status line and headers, a body generated by a character Markov chain |
| `template.py` | The starting point for your own |

Answers later than `timeout_ms` are dropped (keep it under `[daemon] deadline_ms`). A plugin
that exits is restarted at most every 5 seconds; its stderr goes to the nucleus's log.

## Order and interplay

1. Hooks fire. 2. The daemon's rules decide. 3. The explorer may answer what they left.
4. Responders, in config order. 5. Live manual mode shows the chosen answer as its proposal
and may replace it. 6. Otherwise, the handler's default.

The answers a run gives end up in its `traffic.pcap`, so later `--learn` runs can include
them: a feedback loop from rules, fuzzing and manual sessions into the next model. `[learn]`
closes that loop during the run itself.
