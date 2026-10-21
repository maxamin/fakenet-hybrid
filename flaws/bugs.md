# Functional bugs (`BUG-*`)

## BUG-16

**`nxdomain_random` false positives** · Low · Confirmed

- Where: `nucleus/crates/listeners/src/dns.rs:48` (`looks_random`).
- What: any first label of 10+ characters with a run of 5 consonants counts as random, for
  example `strengthsfinder`, `schwarzschild`, `nightscripts`. They get NXDOMAIN.
- Fix: use a character n-gram or entropy score with a threshold tuned on a top-sites list,
  and add those names to the tests.
