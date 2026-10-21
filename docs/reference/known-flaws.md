# Known flaws

The full list, with locations, impact and suggested fixes, lives in the repository's
`flaws/` folder (`flaws/README.md` is the index). This page summarises what matters most
when **using** the tool.

## Before you rely on it

| ID | What to know | Workaround |
|---|---|---|
| LEAK-02 | `excluded_processes` trusts a name the sample can choose | Keep the list empty during runs |

## Categories

| Prefix | Category | Count |
|---|---|---|
| `SEC` | Security | 1 |
| `LEAK` | Network containment | 1 |
| `BUG` | Functional bugs | 1 |
| `PERF` | Performance and denial of service | 2 |
| `DEP` | Packaging, container, CI | 0 |
| `ARCH` | Architectural inconveniences | 7 |
| `ENH` | Enhancement ideas | 9 |
