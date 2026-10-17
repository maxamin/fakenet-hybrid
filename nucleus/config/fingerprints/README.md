# Known fingerprints

CSV lists for `[nucleus] fingerprints`: the first field is a JA3 MD5, a JA4 or a HASSH,
the last its label; `#` lines are comments. Matches are labelled (`known`) on
`tls_handshake` / `ssh_client` records and in the report.

- `sslbl-ja3.csv`: abuse.ch SSL Blacklist, JA3 fingerprints
  (https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv, downloaded 2026-10-17, list last
  updated 2021-08-03; terms of use: https://sslbl.abuse.ch/blacklist/). Refresh with
  `curl -o sslbl-ja3.csv https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv`.

Add your own lists the same way (e.g. `fingerprint,label` per line). A match is a lead,
not an attribution: fingerprints follow the TLS/SSH library and its options, and are
shared by everything built on it (the SSLBL list also includes adware and generic
libraries).
