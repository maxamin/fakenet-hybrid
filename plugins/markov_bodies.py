#!/usr/bin/env python3
"""Responder plugin: generates new HTTP answers from a model pack (fakenet-nucleus --learn)
instead of replaying recorded ones. The status line and headers come from a recorded answer
for the same request key (weighted by how often it was seen); the body is new text from a
character Markov chain trained on the pack's text bodies.

    [[responder]]
    name = "markov"
    kind = "plugin"
    command = ["python3", "-I", "plugins/markov_bodies.py", "--pack", "model.json", "--order", "4"]
    protocols = ["http"]

An example of a statistical generator: plausible, varied content with the observed shape.
"""

import argparse
import base64
import collections
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fakenet_plugin import run  # noqa: E402

MAX_BODY = 16 * 1024


def split(answer):
    head, _, body = answer.partition(b"\r\n\r\n")
    return head, body


def text_like(body):
    if not body:
        return False
    printable = sum(1 for b in body[:4096] if 32 <= b < 127 or b in b"\r\n\t")
    return printable / min(len(body), 4096) > 0.95


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", required=True)
    parser.add_argument("--order", type=int, default=4)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    with open(args.pack, encoding="utf-8") as f:
        pack = json.load(f)
    keys = pack.get("protocols", {}).get("http", {}).get("keys", {})

    # Heads per key, weighted; one Markov chain over every text body
    heads = {}
    chain = collections.defaultdict(collections.Counter)
    starts = []
    for key, model in keys.items():
        for answer in model.get("answers", []):
            raw = base64.b64decode(answer["bytes"])
            head, body = split(raw)
            if not head.startswith(b"HTTP/"):
                continue
            heads.setdefault(key, []).append((answer.get("count", 1), head))
            if text_like(body) and len(body) > args.order:
                text = body.decode("latin-1")
                starts.append(text[:args.order])
                for i in range(len(text) - args.order):
                    chain[text[i:i + args.order]][text[i + args.order]] += 1

    def generate(length):
        if not starts:
            return b""
        state = rng.choice(starts)
        out = [state]
        for _ in range(length):
            following = chain.get(state)
            if not following:
                break
            letters, weights = zip(*following.items())
            letter = rng.choices(letters, weights)[0]
            out.append(letter)
            state = state[1:] + letter
        return "".join(out).encode("latin-1")[:MAX_BODY]

    def weighted(options):
        total = sum(w for w, _ in options)
        point = rng.uniform(0, total)
        for weight, value in options:
            point -= weight
            if point <= 0:
                return value
        return options[-1][1]

    def respond(request):
        if request.protocol != "http" or not heads:
            return None
        method = str(request.meta.get("method", "GET"))
        key = None
        for candidate in heads:
            if candidate.startswith(method + " "):
                path_pattern = candidate.split(" ", 1)[1]
                if path_pattern.split("/")[:2] == str(request.meta.get("path", "/")).split("/")[:2]:
                    key = candidate
                    break
        options = heads.get(key) or [h for hs in heads.values() for h in hs]
        head = weighted(options)
        body = generate(rng.randint(64, 2048))
        lines = [l for l in head.split(b"\r\n") if not l.lower().startswith((b"content-length:", b"transfer-encoding:"))]
        lines.append(b"Content-Length: %d" % len(body))
        return b"\r\n".join(lines) + b"\r\n\r\n" + body, False, "markov order=%d" % args.order

    run(respond)


if __name__ == "__main__":
    main()
