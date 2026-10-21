# Network containment leaks (`LEAK-*`)

The diverter redirects traffic to the listeners. It is not a firewall: nothing drops what
the redirect rules don't match. Run the VM on an isolated network as well; don't rely on
the diverter alone.

## LEAK-01

**Diversion is fail-open** · High · Confirmed

- Where: `nucleus/crates/cli/src/main.rs:265-267` (`diverter.stop()` on shutdown),
  `nucleus/crates/diverter/src/linux.rs` (`Active::stop`, and `Drop` in `lib.rs`),
  `deploy/linux/fakenet-nucleus.service` (`ExecStopPost=... --restore-network`).
- What: every way the nucleus ends (Ctrl+C, SIGTERM, a panic that unwinds, the end of a
  `--run`, a systemd restart after a crash) removes the rules. Whatever is still running in
  the VM then gets the real network. With `Restart=on-failure`, there's a window between
  `ExecStopPost` and the restart in which nothing is diverted. On Windows the WinDivert
  handles close with the process, with the same effect.
- Impact: samples, or their descendants (SEC-02), reach real infrastructure after or
  between runs.
- Fix: install a separate drop policy (an `iptables -P OUTPUT DROP`-style chain allowing
  loopback and the analyst's management ports) that stays in place when the nucleus stops,
  and remove it only with an explicit `--restore-network --release`. Make the systemd
  `ExecStopPost` keep the drop rule.

## LEAK-02

**`excluded_processes` matches a name the sample controls** · Medium · Confirmed

- Where: `nucleus/crates/diverter/src/linux.rs:225` (`is_excluded`, on `comm`),
  `windows.rs:215` (the image file name).
- What: on Linux the name is `/proc/<pid>/comm`, which any process can set with
  `prctl(PR_SET_NAME)`. On Windows it is the image's file name, which a dropper chooses.
- Impact: a sample that names itself like an excluded tool (`python3`, `procmon64.exe`)
  bypasses diversion and talks to the real network.
- Fix: match the full executable path (`/proc/<pid>/exe`, `QueryFullProcessImageNameW`)
  and, better, a hash or the user ID. Document that the list is for trusted tools only.

## LEAK-03

**Only matching traffic is redirected; the rest leaves** · High · Confirmed

- Where: `nucleus/crates/diverter/src/linux.rs`, `rules()`; `Active::start` (IPv6).
- What escapes on Linux:
  - IP protocols other than TCP, UDP and ICMP echo (GRE, SCTP, ESP, raw IP),
  - ICMP other than echo request (for example timestamp requests),
  - TCP/UDP to `ignore_ports`, by design,
  - all IPv6 when ip6tables or its `nat` table is missing: start-up only warns,
  - flows that conntrack already tracked before the rules were added. NAT is decided on
    a connection's first packet, so a long-lived TCP connection, or a UDP flow seen within
    the last 30 s or so, keeps going to its real destination,
  - in gateway mode, the gateway host's own traffic.
- Fix: end the `FAKENET` NAT chain with a filter-table companion that drops everything
  not redirected (`-t filter -A FAKENET-DROP ! -o lo -j DROP` after the allowed cases).
  Flush conntrack (`conntrack -F`) when starting. Make an IPv6 failure fatal unless
  `ipv6 = false`.

## LEAK-04

**No catch-all listener means no catch-all diversion** · Medium · Confirmed

- Where: `nucleus/crates/cli/src/lib.rs`, `Config::plan` and `Config::validate`;
  `linux.rs` (`tcp_default` / `udp_default` are optional).
- What: the REDIRECT for "any other port" exists only if an `auto` listener exists for
  that transport. Validation doesn't require one when `[diverter] enabled = true`.
- Impact: with a config that only lists fixed ports, every other port goes to the real
  network without a warning.
- Fix: when the diverter is enabled, require an `auto` listener per transport, or log a
  loud warning naming the transports left undiverted.
