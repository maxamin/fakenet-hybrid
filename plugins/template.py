#!/usr/bin/env python3
"""Template responder plugin: copy it, then fill in `respond`.

Config:
    [[responder]]
    name = "my-plugin"
    kind = "plugin"
    command = ["python3", "-I", "/path/to/plugins/my_plugin.py"]
    protocols = ["http"]        # optional filter (also: hosts, contains)
    timeout_ms = 150            # keep under [daemon] deadline_ms
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fakenet_plugin import run  # noqa: E402


def respond(request):
    """Return the answer bytes, None to skip, or (bytes, close, route)"""
    # request.protocol: "http", "dns", "raw", ...
    # request.meta: what the handler parsed (HTTP: method, path, host...; DNS: qname, qtype)
    # request.payload: the client's bytes; request.default: the built-in answer, if known
    return None


if __name__ == "__main__":
    run(respond)
