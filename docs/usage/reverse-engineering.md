# Reverse engineering

FakeNet hybrid records what a sample does on the network. These features help work out
**why**: answer the sample by hand, stop it in a debugger at the right request, map its
network calls to its code, and take apart protocols no handler understands.

| Feature | Use it to | How |
|---|---|---|
| Live manual mode | Work out a C2 protocol interactively | `[manual]` in the config; answer in the dashboard |
| Hooks | Land a debugger in the reply-handling code; dump decrypted configs and keys | `[[hook]]` with `pause`, `dump`, `command` |
| Network-to-code | Find the function that opened a connection or sent a message | `hooks/net-backtrace.js` with Frida, from a hook |
| Protocol inference | Find the framing of an unknown protocol; get a Wireshark dissector | `--infer EVENTS -o DIR` |
| Decoding | Apply keys from static analysis or memory to captured payloads | `--decode EVENTS --transform ...` |
| Run diff | See what one answer changed, or how two variants differ | `--diff RUN_A RUN_B` |

## Live manual mode

```toml
[manual]
enabled = true
timeout_ms = 120000
protocols = ["http", "raw"]
hosts = ["c2.example"]          # optional
contains = "/gate"              # optional
```

Open the dashboard (`/dashboard?token=<secret>`). Each held request shows the client, its
process, the request line, the payload (control bytes escaped) and the **proposed** answer:
the daemon rule's, the explorer's, or the handler's built-in default (shown for HTTP and raw;
for other protocols the handler's default is used without being shown). Then:

- **Send proposed**: what would have been sent anyway.
- **Send edited** (optionally **then close**): the text, or base64 for binary answers. For
  HTTP this is the whole raw response, status line and headers included.
- **Close connection**: no answer.

A request nobody answers gets the proposed answer after `timeout_ms`. At most 256 requests
are held at once; later ones are answered at once. Each manual answer is logged as a
`manual` record. The same actions are available to scripts through `POST /api/manual/<id>`
(see [the dashboard routes](dashboard-and-health.md)).

```{warning}
Held requests wait past the daemon deadline by design. Keep the filter narrow: a held DNS
query blocks the sample's resolver.
```

## Hooks: pause, dump, instrument

```toml
[[hook]]
name = "first-beacon"
protocols = ["http"]
hosts = ["c2.example"]
actions = ["dump", "pause"]
once = true
```

When an event matches, before its answer is computed, the hook acts on the process that
owns the connection (from process attribution: local clients on Linux, diverted ones on
Windows):

- `dump` (Linux): the process is stopped, every readable mapping is copied from
  `/proc/<pid>/mem` to `capture/hooks/<hook>-<request>-<pid>/` (`maps.txt`,
  `regions.json`, one `.bin` per region), then it resumes unless it was already stopped.
  Search them for decrypted strings, configs and keys.
- `pause`: SIGSTOP. The sample stops with the answer waiting in its socket buffer. Attach
  `gdb -p PID` or x64dbg, set a breakpoint on `recv`/`read`, then press **Resume** in the
  dashboard (or `POST /api/paused/<pid>/resume`): the debugger stops in the code that reads
  the answer. Paused processes stay paused when the nucleus stops (`kill -CONT PID`).
- `command`: runs `command` as an argv, without a shell, with `{pid}`, `{session_id}`,
  `{request_id}`, `{protocol}`, `{event}` and `{dir}` replaced. Only the nucleus's own values
  are substituted, never anything the sample controls. Output goes to `command.stdout` and
  `command.stderr` in the hook folder. `wait_ms` holds the answer until the command exits.

Every firing is a `hook` record. Hooks need the nucleus to be allowed to signal and read the
sample: run as root, or as the same user with `kernel.yama.ptrace_scope` at 0 or 1.

## Network-to-code with Frida

`hooks/net-backtrace.js` (installed next to the config) hooks `connect`, `send`, `sendto`,
`recv` (plus `write` on Linux; `WSAConnect`, `WSASend`, `WSARecv`, `WinHttpSendRequest`,
`HttpSendRequestW` on Windows) and prints one JSON line per call with the call stack as
`module` + `offset`:

```toml
[[hook]]
name = "trace-sockets"
once = true
actions = ["command"]
command = ["frida", "-p", "{pid}", "-l", "/opt/fakenet-hybrid/hooks/net-backtrace.js", "-q", "-t", "inf"]
wait_ms = 3000
```

In Ghidra, with the image base set as loaded, **Navigation > Go To** `module+offset`
reaches the calling code. Stripped samples without unwind information fall back to a
stack scan (`"fuzzy": true`), which can include stale frames. The script works with
Frida 16 and 17.

## Protocol inference

```sh
fakenet-nucleus --infer capture/events.jsonl -o dissectors/
```

For each destination of unparsed (`raw`) messages, or every protocol with
`--all-protocols`, it reports:

| Field | Meaning |
|---|---|
| `magic` | Bytes every message starts with (up to the first field found) |
| `constant` | Other byte ranges equal in every message |
| `length_field` | A 1, 2 or 4-byte field, either endianness, equal to the message length minus `adjust` |
| `counter` | A field that grows by a constant `step` from message to message in each session |
| `encodings` | `text`, `base64`, `hex`, `gzip`/`zlib`/`zip`/`zstd`, high entropy |
| `xor_key` | A single-byte key that turns the body (from `from_offset`) into text |

With `-o`, each destination gets a Wireshark Lua dissector skeleton with those fields.
These are heuristics that point at what to verify in the code.

## Decoding

```sh
fakenet-nucleus --decode capture/events.jsonl --only :4444 \
  --transform skip:9 --transform xor:5a -o decoded/
```

Transforms apply in order: `base64`, `hex`, `xor:KEY` (repeating key), `rc4:KEY`, `skip:N`.
Keys are hex (`deadbeef`) or text (`text:secret`). Each payload is saved as
`<n>_<session>.bin`; `index.json` lists them with a preview and failures.

## Comparing runs

```sh
fakenet-nucleus --diff capture/previous/20261021-101500 capture
```

Lists, for destinations, DNS names, HTTP requests, line-protocol commands, raw messages,
credentials, TLS/SSH clients, saved files and detections, what only run A (`-`) or only run B
(`+`) has, and record counts that differ. Saved-file counters and DNS case are ignored.
Restarting the nucleus archives the previous run into `capture/previous/`, so consecutive
runs are ready to compare. For repeatable runs, revert the VM snapshot between them.
