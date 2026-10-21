# Known flaws

The full list, with locations, impact and suggested fixes, lives in the repository's
`flaws/` folder (`flaws/README.md` is the index). This page summarises what matters most
when **using** the tool.

## Before you rely on it

| ID | What to know | Workaround |
|---|---|---|
| LEAK-01 | Windows: stopping or crashing the nucleus restores the real network while the sample may still run (Linux keeps outbound traffic blocked until `--restore-network`) | Revert the VM after each run; isolate the VM's network as well |
| LEAK-02 | `excluded_processes` trusts a name the sample can choose | Keep the list empty during runs |
| SEC-01, SEC-02 | Windows: `--run` runs the sample as Administrator and tracks only the direct child (Linux uses `--run-as`, a session and a cgroup) | Revert the VM after each run |
| SEC-03 | The dashboard cookie is the link secret | Clear the browser before running samples |

## Categories

| Prefix | Category | Count |
|---|---|---|
| `SEC` | Security | 7 |
| `LEAK` | Network containment | 2 |
| `BUG` | Functional bugs | 1 |
| `PERF` | Performance and denial of service | 10 |
| `DEP` | Packaging, container, CI | 0 |
| `ARCH` | Architectural inconveniences | 7 |
| `ENH` | Enhancement ideas | 11 |
