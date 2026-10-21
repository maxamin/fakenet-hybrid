# Known flaws

Bugs, security risks, containment leaks, performance problems, architectural inconveniences
and enhancement ideas found by reading the source at commit `1168ac0`. Each entry gives
the location (`file:line`, which may drift), what happens, the impact and a suggested fix.

**Status** is one of:

- **Confirmed**: read in the code, and reproduced where the note says so.
- **Likely**: follows from the code, but the failing path has not been run.

**Severity**: High (wrong results, a broken install or a containment break in normal use),
Medium (wrong results or risk in specific conditions), Low (edge cases, fidelity, polish).

| File | Covers |
|---|---|
| [security.md](security.md) | `SEC-*`: authentication, secrets, injection, sample execution |
| [network-leaks.md](network-leaks.md) | `LEAK-*`: traffic that can reach the real network |
| [bugs.md](bugs.md) | `BUG-*`: functional defects |
| [performance-and-dos.md](performance-and-dos.md) | `PERF-*`: scalability, blocking I/O, unbounded growth |
| [deployment.md](deployment.md) | `DEP-*`: packaging, container, CI |
| [architecture.md](architecture.md) | `ARCH-*`: design inconveniences |
| [enhancements.md](enhancements.md) | `ENH-*`: improvements that aren't defects |

## Index

| ID | Sev. | Status | Summary |
|---|---|---|---|
| [DEP-01](deployment.md#dep-01) | High | Confirmed | No install path ships `fingerprints/`; the shipped configs need it, so the nucleus doesn't start |
| [DEP-02](deployment.md#dep-02) | High | Confirmed | Dockerfile builds with Rust 1.83; the code needs 1.85 |
| [DEP-03](deployment.md#dep-03) | High | Confirmed | Container entrypoint and HEALTHCHECK use `/dev/tcp` under `dash`; the entrypoint exits at once |
| [LEAK-01](network-leaks.md#leak-01) | High | Confirmed | Diversion is fail-open: stopping or crashing the nucleus puts a running sample online |
| [SEC-02](security.md#sec-02) | High | Confirmed | `--run` kills only the direct child; descendants outlive the run and then reach the real network |
| [BUG-05](bugs.md#bug-05) | High | Confirmed | A new CA on every start: `ca.pem` must be re-trusted in the VM after each restart |
| [LEAK-03](network-leaks.md#leak-03) | High | Confirmed | NAT redirect only, no drop rule: other IP protocols, non-echo ICMP, `ignore_ports`, failed IPv6 and pre-existing flows leave the VM |
| [SEC-01](security.md#sec-01) | Medium | Confirmed | `--run` runs the sample as root/Administrator |
| [LEAK-02](network-leaks.md#leak-02) | Medium | Confirmed | `excluded_processes` matches a name the sample can choose |
| [LEAK-04](network-leaks.md#leak-04) | Medium | Confirmed | Diverting without an `auto` listener leaves unlisted ports undiverted, unchecked |
| [BUG-04](bugs.md#bug-04) | Medium | Confirmed | Re-using a capture folder overwrites earlier saved files and mixes runs in reports |
| [BUG-01](bugs.md#bug-01) | Medium | Confirmed | DNS TXT longer than 255 bytes: the query gets no answer at all |
| [BUG-02](bugs.md#bug-02) | Medium | Confirmed | An error removing the diversion skips the report, indicators and `run.json` |
| [BUG-06](bugs.md#bug-06) | Medium | Confirmed | Default `passive_ports = [0, 0]` breaks FTP passive mode under diversion |
| [BUG-07](bugs.md#bug-07) | Medium | Confirmed | SMTP messages are saved as lossy UTF-8; 8-bit content is corrupted |
| [BUG-08](bugs.md#bug-08) | Medium | Confirmed | Protocol sniffing uses a single `read()`; fragmented first messages are misdetected |
| [BUG-09](bugs.md#bug-09) | Medium | Confirmed | No process attribution for UDP clients on wildcard-bound sockets |
| [BUG-10](bugs.md#bug-10) | Medium | Confirmed | HTTP/3 events record the listener, not the original destination |
| [SEC-03](security.md#sec-03) | Medium | Confirmed | The dashboard cookie is the link's HMAC key |
| [SEC-04](security.md#sec-04) | Medium | Confirmed | The link MAC leaves most fields unsigned and has no replay protection |
| [SEC-05](security.md#sec-05) | Medium | Confirmed | The HTTP fallback channel sends signed events to whoever holds port 8091 |
| [SEC-06](security.md#sec-06) | Medium | Confirmed | Unauthenticated link by default |
| [PERF-01](performance-and-dos.md#perf-01) | Medium | Confirmed | Blocking file I/O under global mutexes on the async runtime |
| [PERF-02](performance-and-dos.md#perf-02) | Medium | Confirmed | `/proc` scan per new connection (and per NFQUEUE packet) |
| [PERF-03](performance-and-dos.md#perf-03) | Medium | Confirmed | The memory budget ignores the many copies of each payload |
| [PERF-04](performance-and-dos.md#perf-04) | Medium | Confirmed | HTTP/2 and HTTP/3 requests on one connection are serialized |
| [PERF-05](performance-and-dos.md#perf-05) | Medium | Confirmed | Unbounded caches keyed by sample-controlled values |
| [ARCH-01](architecture.md#arch-01) | Medium | Confirmed | Windows diverter has never run in CI |
| [ARCH-02](architecture.md#arch-02) | Medium | Confirmed | Explorer rewards scanning as "new behaviour" |
| [BUG-03](bugs.md#bug-03) | Low | Confirmed | `max_pcap_mb = 0` truncates the previous `traffic.pcap` |
| [BUG-11](bugs.md#bug-11) | Low | Likely | TFTP data comes from an un-NATed socket under Linux diversion |
| [BUG-12](bugs.md#bug-12) | Low | Confirmed | Daemon warm-up skips 10 of the 30 protocols |
| [BUG-13](bugs.md#bug-13) | Low | Confirmed | `--report FILE` ignores rotated logs |
| [BUG-14](bugs.md#bug-14) | Low | Confirmed | Custom Response `HttpURIs` never match a URL with a query string |
| [BUG-15](bugs.md#bug-15) | Low | Confirmed | HttpDynamic provider timeout doesn't cover writing the request |
| [BUG-16](bugs.md#bug-16) | Low | Confirmed | `nxdomain_random` flags real names with long consonant runs |
| [BUG-17](bugs.md#bug-17) | Low | Confirmed | IMAP literals unsupported: `LOGIN {n}` credentials are logged wrongly |
| [BUG-18](bugs.md#bug-18) | Low | Confirmed | CA validity starts after its leaf certificates' |
| [BUG-19](bugs.md#bug-19) | Low | Confirmed | Report summary omits NTLM and VNC hash lines |
| [SEC-07](security.md#sec-07) | Low | Confirmed | CSV formula injection in `indicators.csv` |
| [SEC-08](security.md#sec-08) | Low | Confirmed | `--rules-from-har` escaping allows breaking out of the generated Groovy/YAML |
| [SEC-09](security.md#sec-09) | Low | Confirmed | Splunk token as a `-D` property is visible to every local process |
| [PERF-06](performance-and-dos.md#perf-06) | Low | Confirmed | YARA queue unbounded; shutdown waits for every scan |
| [PERF-07](performance-and-dos.md#perf-07) | Low | Confirmed | Coverage watcher re-reads whole JSONL files every second |
| [PERF-08](performance-and-dos.md#perf-08) | Low | Confirmed | One UDP client's datagrams are answered strictly one at a time |
| [PERF-09](performance-and-dos.md#perf-09) | Low | Confirmed | Daemon audit log has no size limit |
| [PERF-10](performance-and-dos.md#perf-10) | Low | Confirmed | Report and indicators load the whole capture into memory |
| [DEP-04](deployment.md#dep-04) | Low | Confirmed | WinDivert downloaded in CI without a checksum |
| [DEP-05](deployment.md#dep-05) | Low | Confirmed | `fuzz/run-all.sh` always exits 0 |
| [DEP-06](deployment.md#dep-06) | Low | Confirmed | Compiled `__pycache__` files are committed |
| [ARCH-03](architecture.md#arch-03) | Low | Confirmed | Schema and HMAC logic duplicated in Rust and Java |
| [ARCH-04](architecture.md#arch-04) | Low | Confirmed | Payloads are stored twice and travel in full everywhere |
| [ARCH-05](architecture.md#arch-05) | Low | Confirmed | Live reload covers `[defaults]` only, and not on Windows |
| [ARCH-06](architecture.md#arch-06) | Low | Confirmed | Listener filters close connections; host filters take IPs only |
| [ARCH-07](architecture.md#arch-07) | Low | Confirmed | Process-wide global state |

Enhancement ideas (`ENH-01` to `ENH-12`) are listed in [enhancements.md](enhancements.md).

## Suggested order of work

1. DEP-01, DEP-02, DEP-03: every packaged install path is currently broken.
2. LEAK-01, SEC-02, LEAK-03: containment. Add a fail-closed drop policy, kill the
   whole process tree, and keep the drop rules after stop until an explicit "release".
3. BUG-05: load or persist the CA, so trust survives restarts.
4. BUG-04 and BUG-02: evidence integrity.
5. The PERF items, before running heavy or scanning samples.
