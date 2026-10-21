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
| [LEAK-02](network-leaks.md#leak-02) | Medium | Confirmed | `excluded_processes` matches a name the sample can choose |
| [PERF-03](performance-and-dos.md#perf-03) | Low | Confirmed | The memory budget counts one of the nucleus's ~4 copies of a large payload |
| [ARCH-01](architecture.md#arch-01) | Medium | Confirmed | The Windows diverter, firewall block and exit guard have never run end to end |
| [ARCH-02](architecture.md#arch-02) | Medium | Confirmed | Explorer rewards scanning as "new behaviour" |
| [BUG-16](bugs.md#bug-16) | Low | Confirmed | `nxdomain_random` flags real names with long consonant runs |
| [SEC-09](security.md#sec-09) | Low | Confirmed | Splunk token as a `-D` property is visible to every local process |
| [PERF-08](performance-and-dos.md#perf-08) | Low | Confirmed | UdpDynamic providers start one interpreter per datagram |
| [ARCH-03](architecture.md#arch-03) | Low | Confirmed | Schema and HMAC logic duplicated in Rust and Java |
| [ARCH-04](architecture.md#arch-04) | Low | Confirmed | Saved payloads are also in their `event` records |
| [ARCH-05](architecture.md#arch-05) | Low | Confirmed | Live reload covers `[defaults]` only, and not on Windows |
| [ARCH-06](architecture.md#arch-06) | Low | Confirmed | Listener filters close connections; host filters take IPs only |
| [ARCH-07](architecture.md#arch-07) | Low | Confirmed | Process-wide global state |

Enhancement ideas (`ENH-04` to `ENH-12`) are listed in [enhancements.md](enhancements.md).

## Suggested order of work

1. ARCH-01: run the Windows containment on a Windows VM.
2. PERF-03 and PERF-08 (minor), LEAK-02, the ARCH items.
