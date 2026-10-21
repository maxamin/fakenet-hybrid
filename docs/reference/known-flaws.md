# Known flaws

The full list, with locations, impact and suggested fixes, lives in the repository's
`flaws/` folder (`flaws/README.md` is the index). This page summarises what matters most
when **using** the tool.

## Before you rely on it

| ID | What to know | Workaround |
|---|---|---|
| DEP-01 | Packaged configs reference a fingerprint list no package ships; the nucleus won't start | Copy `nucleus/config/fingerprints/` next to the config, or remove the `fingerprints` line |
| DEP-02, DEP-03 | The Docker image doesn't build (Rust 1.83), and its `/bin/sh` entrypoint exits under `dash` | Bump the builder image; switch the entrypoint and HEALTHCHECK to bash |
| LEAK-01 | Stopping or crashing the nucleus restores the real network while the sample may still run | Revert the VM after each run; isolate the VM's network as well |
| LEAK-03 | Non-TCP/UDP traffic, non-echo ICMP, `ignore_ports`, failed IPv6 and flows established before start leave the VM | Same; add your own drop rules |
| LEAK-02 | `excluded_processes` trusts a name the sample can choose | Keep the list empty during runs |
| SEC-01, SEC-02 | `--run` runs the sample as root and kills only the direct child | Revert the VM after each run |
| BUG-05 | A new CA at every start | Re-install `ca.pem` after each start |
| BUG-04 | Re-using a capture folder overwrites saved files and mixes runs in the report | Use `--run`, or a fresh `capture_dir` per start |
| BUG-06 | `passive_ports = [0, 0]` breaks FTP passive mode under diversion | Set a range |
| BUG-01 | DNS TXT answers over 255 bytes are never sent | Keep TXT strings short |
| SEC-03 | The dashboard cookie is the link secret | Clear the browser before running samples |

## Categories

| Prefix | Category | Count |
|---|---|---|
| `SEC` | Security | 9 |
| `LEAK` | Network containment | 4 |
| `BUG` | Functional bugs | 19 |
| `PERF` | Performance and denial of service | 10 |
| `DEP` | Packaging, container, CI | 6 |
| `ARCH` | Architectural inconveniences | 7 |
| `ENH` | Enhancement ideas | 12 |
