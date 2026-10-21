#!/usr/bin/env python3
"""Responder plugin: answers with a Radamsa mutation of the handler's default answer (or, for
raw protocols without one, of the client's own bytes), to push the sample's parsers into
error paths and hidden branches.

    [[responder]]
    name = "radamsa"
    kind = "plugin"
    command = ["python3", "-I", "plugins/radamsa_mutator.py", "--rate", "0.3"]
    timeout_ms = 150

Options: --rate R (share of requests mutated, default 1), --seed N (reproducible runs),
--radamsa PATH. Without Radamsa installed, a small built-in byte mutator is used instead.
Each answer's route records the seed used, so a finding can be replayed.
"""

import argparse
import os
import random
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fakenet_plugin import run  # noqa: E402

MAX_INPUT = 256 * 1024


def builtin_mutation(data, rng):
    data = bytearray(data or b"\x00")
    for _ in range(rng.randint(1, 4)):
        i = rng.randrange(len(data))
        kind = rng.randrange(5)
        if kind == 0:
            data[i] ^= 1 << rng.randrange(8)
        elif kind == 1:
            data[i] = rng.choice([0x00, 0xFF, 0x7F, 0x80, 0x0A, 0x25])
        elif kind == 2 and len(data) > 1:
            del data[i:i + rng.randint(1, 16)]
        elif kind == 3:
            data[i:i] = data[i:i + rng.randint(1, 16)] * rng.randint(1, 8)
        else:
            data[i:i] = bytes([rng.randrange(256)])
    return bytes(data[:MAX_INPUT * 2])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rate", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--radamsa", default=shutil.which("radamsa"))
    args = parser.parse_args()
    rng = random.Random(args.seed)

    def respond(request):
        if rng.random() >= args.rate:
            return None
        base = request.default if request.default is not None else request.payload
        if not base:
            return None
        seed = rng.randrange(2**31)
        if args.radamsa:
            try:
                mutated = subprocess.run([args.radamsa, "-s", str(seed)], input=base[:MAX_INPUT], capture_output=True, timeout=0.1).stdout
            except (OSError, subprocess.TimeoutExpired):
                mutated = builtin_mutation(base[:MAX_INPUT], random.Random(seed))
            tool = "radamsa"
        else:
            mutated = builtin_mutation(base[:MAX_INPUT], random.Random(seed))
            tool = "builtin"
        return mutated, False, "%s seed=%d" % (tool, seed)

    run(respond)


if __name__ == "__main__":
    main()
