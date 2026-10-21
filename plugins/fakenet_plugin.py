"""Helper for FakeNet hybrid responder plugins (Python 3.8+, standard library only).

A plugin is a long-lived program the nucleus starts from a `[[responder]] kind = "plugin"`
entry. It reads one JSON request per line on stdin and writes one JSON answer per line on
stdout (see plugins/README.md). With this module a plugin is one function:

    from fakenet_plugin import run

    def respond(request):
        if request.protocol != "http":
            return None                      # skip: the next responder, or the default
        return b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok"

    run(respond)

The request's payload and the handler's default come from the malware's traffic: treat them
as hostile data, never as code.
"""

import base64
import json
import sys
import traceback


class Request:
    """One request from the nucleus"""

    def __init__(self, message):
        self.raw = message
        self.id = message["id"]
        self.protocol = message.get("protocol", "")
        self.event = message.get("event", {})
        self.meta = self.event.get("meta") or {}
        self.payload = base64.b64decode(self.event.get("payload", "") or "")
        default = message.get("default_base64")
        self.default = base64.b64decode(default) if default else None


def answer(request_id, response, close=False, route=None):
    """The answer line for `response` (bytes), or a skip when it is None"""
    if response is None:
        return {"id": request_id, "skip": True}
    message = {"id": request_id, "response_base64": base64.b64encode(response).decode(), "close": bool(close)}
    if route:
        message["route"] = str(route)[:80]
    return message


def run(respond, stdin=None, stdout=None):
    """Answers requests until stdin closes. `respond(request)` returns bytes, None (skip),
    or (bytes, close, route). An exception skips that request and is logged to stderr."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = Request(json.loads(line))
        except (ValueError, KeyError):
            continue
        try:
            result = respond(request)
            if isinstance(result, tuple):
                reply = answer(request.id, *result)
            else:
                reply = answer(request.id, result)
        except Exception:  # A plugin bug must not stop the plugin
            traceback.print_exc(file=sys.stderr)
            reply = answer(request.id, None)
        stdout.write(json.dumps(reply) + "\n")
        stdout.flush()
