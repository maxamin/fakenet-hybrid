#!/usr/bin/env python3
"""Generates skeletons for FakeNet hybrid extensions, so people and AI assistants start from
code that already fits the project's interfaces:

    scripts/scaffold.py plugin NAME      plugins/NAME.py: a responder plugin (any protocol)
    scripts/scaffold.py responder NAME   nucleus/crates/listeners/src/responders/NAME.rs: a Rust responder
    scripts/scaffold.py analyzer NAME    a protocol analyser for fakenet-model (printed: add it to analyze.rs)
    scripts/scaffold.py transform NAME   a decoding step (printed: add it to model/src/transform.rs)

Never overwrites a file. NAME: letters, digits and underscores. Prints what to do next.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLUGIN = '''#!/usr/bin/env python3
"""{title}: a FakeNet hybrid responder plugin.

    [[responder]]
    name = "{name}"
    kind = "plugin"
    command = ["python3", "-I", "plugins/{name}.py"]
    protocols = ["http"]        # optional filter (also: hosts, contains)
    timeout_ms = 150            # keep under [daemon] deadline_ms

Protocol and rules: plugins/README.md. Requests come from malware: treat them as data.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fakenet_plugin import run  # noqa: E402


def respond(request):
    """Return the answer bytes, None to skip, or (bytes, close, route)"""
    # request.protocol, request.meta (parsed fields), request.payload (client bytes),
    # request.default (the handler's built-in answer, when known), request.event (all of it)
    return None


if __name__ == "__main__":
    run(respond)
'''

PLUGIN_TEST = '''"""Tests for plugins/{name}.py (run: python3 -m unittest discover plugins/tests)"""

import base64
import json
import os
import subprocess
import sys
import unittest

PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "{name}.py")


def ask(lines):
    process = subprocess.run([sys.executable, "-I", PLUGIN], input="\\n".join(lines) + "\\n", capture_output=True, text=True, timeout=30)
    return [json.loads(l) for l in process.stdout.splitlines() if l.strip()]


class {klass}(unittest.TestCase):
    def test_answers_every_request(self):
        request = {{"type": "respond", "id": 1, "protocol": "http", "event": {{"payload": base64.b64encode(b"GET / HTTP/1.1\\r\\n\\r\\n").decode(), "meta": {{"method": "GET", "path": "/"}}}}}}
        replies = ask([json.dumps(request)])
        self.assertEqual(replies[0]["id"], 1)


if __name__ == "__main__":
    unittest.main()
'''

RESPONDER = '''//! {title}: a Rust responder (see `responders`). Register it in `responders::build` with a
//! new `ResponderKind`, document the kind in docs/usage/learning-and-responders.md, and test
//! it like `responders::tests`.

use fakenet_schema::Event;

use super::{{Proposal, Respond, Responder}};

pub struct {klass} {{
    name: String,
}}

impl {klass} {{
    pub fn new(name: String) -> {klass} {{
        {klass} {{ name }}
    }}
}}

impl Responder for {klass} {{
    fn name(&self) -> &str {{
        &self.name
    }}

    fn respond<'a>(&'a self, event: &'a Event, default: Option<&'a [u8]>) -> Respond<'a> {{
        Box::pin(async move {{
            // Fast (under the daemon deadline) and bounded: the event comes from malware
            let _ = (event, default);
            None::<Proposal>
        }})
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[tokio::test]
    async fn skips_until_implemented() {{
        let event: Event = serde_json::from_value(serde_json::json!({{
            "version": 2, "type": "event", "request_id": "r", "session_id": "s", "seq": 1, "protocol": "http",
            "transport": "tcp", "src": "10.0.0.5:1", "dst": "198.51.100.7:80", "dport": 80,
            "timestamp": "2026-01-01T00:00:00Z", "payload": "", "meta": {{}}, "expects_reply": true,
        }}))
        .unwrap();
        assert!({klass}::new("{name}".into()).respond(&event, None).await.is_none());
    }}
}}
'''

ANALYZER = '''// {title}: add to nucleus/crates/model/src/analyze.rs, register in `analyzers()`, and test in
// its `tests` module (keys for typical requests; stored_answer for good and bad answers).

struct {klass};

impl Analyzer for {klass} {{
    fn protocol(&self) -> &'static str {{
        "{name}" // A fakenet_schema::Protocol name
    }}

    /// Most specific first; "*" last. Keep keys short and normalised (no raw sample bytes).
    fn keys(&self, request: &[u8]) -> Vec<String> {{
        if request.is_empty() {{
            return vec![GREETING.into()];
        }}
        vec!["*".into()]
    }}

    /// The answer in the form the nucleus's {name} handler takes; None when unusable
    fn stored_answer(&self, response: &[u8]) -> Option<Vec<u8>> {{
        Some(response.to_vec())
    }}

    fn is_failure(&self, _answer: &[u8]) -> bool {{
        false
    }}
}}
'''

TRANSFORM = '''// {title}: a decoding step (--decode, --learn --transform, key_transforms). In
// nucleus/crates/model/src/transform.rs:
// 1. add a variant to `enum Transform`, e.g. `{klass}(Vec<u8>)`;
// 2. parse it in `parse_transform` ("{name}:KEY");
// 3. apply it in `apply`:
//        Transform::{klass}(key) => {name}_decode(key, &data)?,
// 4. test it with a known vector in transform.rs's tests, and list it in docs/usage/reverse-engineering.md.

fn {name}_decode(key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {{
    let _ = key;
    Ok(data.to_vec())
}}
'''


def write(path, text):
    if os.path.exists(path):
        sys.exit(f"{os.path.relpath(path, ROOT)} exists: not overwritten")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(path, ROOT)}")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("plugin", "responder", "analyzer", "transform"):
        sys.exit(__doc__)
    kind, name = sys.argv[1], sys.argv[2]
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", name):
        sys.exit("NAME: lowercase letters, digits and underscores, starting with a letter")
    klass = "".join(part.capitalize() for part in name.split("_"))
    title = name.replace("_", " ").capitalize()
    fields = {"name": name, "klass": klass, "title": title}
    if kind == "plugin":
        write(os.path.join(ROOT, "plugins", f"{name}.py"), PLUGIN.format(**fields))
        write(os.path.join(ROOT, "plugins", "tests", f"test_{name}.py"), PLUGIN_TEST.format(**fields))
        print("next: fill in respond(); python3 -m unittest discover plugins/tests; add a [[responder]] entry")
    elif kind == "responder":
        write(os.path.join(ROOT, "nucleus", "crates", "listeners", "src", "responders", f"{name}.rs"), RESPONDER.format(**fields))
        print("next: `pub mod " + name + ";` in responders.rs (as a folder module), a ResponderKind variant, then cargo test -p fakenet-listeners")
    elif kind == "analyzer":
        print(ANALYZER.format(**fields))
    else:
        print(TRANSFORM.format(**fields))


if __name__ == "__main__":
    main()
