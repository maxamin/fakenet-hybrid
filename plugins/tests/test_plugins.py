"""Runs each plugin as the nucleus would: a subprocess fed JSON lines"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGINS = os.path.dirname(HERE)


def request(rid, protocol, payload=b"", default=None, meta=None):
    message = {"type": "respond", "id": rid, "protocol": protocol,
               "event": {"payload": base64.b64encode(payload).decode(), "meta": meta or {}}}
    if default is not None:
        message["default_base64"] = base64.b64encode(default).decode()
    return json.dumps(message)


def exchange(args, lines):
    process = subprocess.run([sys.executable, "-I"] + args, input="\n".join(lines) + "\n",
                             capture_output=True, text=True, timeout=30)
    return [json.loads(l) for l in process.stdout.splitlines() if l.strip()]


class Plugins(unittest.TestCase):
    def test_template_skips_everything(self):
        replies = exchange([os.path.join(PLUGINS, "template.py")], [request(1, "http"), "not json", request(2, "dns")])
        self.assertEqual(replies, [{"id": 1, "skip": True}, {"id": 2, "skip": True}])

    def test_radamsa_mutator_changes_the_default_reproducibly(self):
        default = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntask"
        args = [os.path.join(PLUGINS, "radamsa_mutator.py"), "--seed", "3"]
        first = exchange(args, [request(1, "http", default=default), request(2, "raw", payload=b"\x01\x02\x03")])
        again = exchange(args, [request(1, "http", default=default), request(2, "raw", payload=b"\x01\x02\x03")])
        self.assertEqual([r["id"] for r in first], [1, 2])
        self.assertTrue(first[0]["route"].endswith(tuple("0123456789")))
        self.assertEqual(first[0]["route"], again[0]["route"])  # Same seeds
        # Without Radamsa, the built-in mutator always changes something
        builtin = exchange(args + ["--radamsa", ""], [request(1, "http", default=default)])
        self.assertNotEqual(base64.b64decode(builtin[0]["response_base64"]), default)
        self.assertIn("builtin", builtin[0]["route"])
        # Nothing to mutate: skip
        self.assertEqual(exchange(args, [request(3, "raw")]), [{"id": 3, "skip": True}])

    def test_markov_bodies_generate_well_formed_http(self):
        body = (b"<html><body>Welcome to the update server. Your client is up to date. " * 8) + b"</body></html>"
        answer = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(body) + body
        pack = {"format": "fakenet-model-pack", "version": 1, "protocols": {"http": {"exchanges": 1, "keys": {
            "GET /update": {"count": 1, "answers": [{"count": 1, "bytes": base64.b64encode(answer).decode()}]}}}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(pack, f)
        try:
            replies = exchange([os.path.join(PLUGINS, "markov_bodies.py"), "--pack", f.name, "--seed", "1"],
                               [request(1, "http", meta={"method": "GET", "path": "/update"}), request(2, "dns")])
        finally:
            os.unlink(f.name)
        generated = base64.b64decode(replies[0]["response_base64"])
        head, _, new_body = generated.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK"))
        self.assertIn(b"Content-Length: %d" % len(new_body), head)
        self.assertIn(b"Server: nginx", head)
        self.assertTrue(len(new_body) > 0)
        self.assertEqual(replies[1], {"id": 2, "skip": True})


if __name__ == "__main__":
    unittest.main()
