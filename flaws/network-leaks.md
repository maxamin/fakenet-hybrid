# Network containment leaks (`LEAK-*`)

The diverter redirects traffic to the listeners. It is not a firewall: nothing drops what
the redirect rules don't match. Run the VM on an isolated network as well; don't rely on
the diverter alone.

## LEAK-01

**Windows: diversion is fail-open** · High · Confirmed

- Where: `nucleus/crates/diverter/src/windows.rs` (no counterpart of Linux's
  `block_rules`); `[diverter] block_undiverted` and `block_after_stop` are Linux-only.
- What: on Linux, a filter chain rejects everything the NAT didn't divert and stays after
  the nucleus stops or crashes, until `--restore-network`. On Windows, closing the WinDivert
  handles (stop, crash) restores the real network at once, and traffic WinDivert doesn't
  reflect is not blocked meanwhile (untested: ARCH-01).
- Impact: a sample still running on Windows reaches the real network after the nucleus
  stops.
- Fix: a Windows Filtering Platform block (persistent sublayer, or `netsh advfirewall`
  outbound block policy with exceptions for loopback), installed at start, kept after stop,
  removed by `--restore-network`.

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
