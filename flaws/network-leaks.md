# Network containment leaks (`LEAK-*`)

The diverter redirects traffic to the listeners. It is not a firewall: nothing drops what
the redirect rules don't match. Run the VM on an isolated network as well; don't rely on
the diverter alone.

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
