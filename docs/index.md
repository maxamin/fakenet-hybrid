# FakeNet hybrid

FakeNet hybrid is a network simulator for **isolated malware-analysis VMs**, in the style of
FakeNet-NG. It has two halves:

- the **nucleus** (Rust, `nucleus/`) owns the network. It diverts the VM's outbound traffic to
  local listeners, works out each connection's protocol, answers it convincingly and
  records everything. It runs on its own.
- the **daemon** (Java 21 and stock Apache Camel 4.18, `daemon/`) owns the decisions. Each
  request the nucleus sees becomes an *Event*. Analyst-written YAML routes may answer it
  with an *Action*. If the daemon is slow or absent, the nucleus uses its built-in default
  within a deadline (200 ms by default).

An optional **explorer** answers the requests the rules leave undecided. It uses learned
templates to coax hidden capabilities out of a sample.

```{warning}
Lab use only. Run it inside an isolated analysis VM. Diversion is a redirector, not a
firewall: some traffic still reaches the real network (see {doc}`reference/known-flaws`).
`--run` executes the sample.
```

```{toctree}
:maxdepth: 2
:caption: Getting started

getting-started/overview
getting-started/installation
getting-started/quickstart
getting-started/configuration
```

```{toctree}
:maxdepth: 2
:caption: Usage

usage/cli
usage/outputs
usage/writing-rules
usage/explorer
usage/reverse-engineering
usage/learning-and-responders
usage/dashboard-and-health
usage/siem
usage/fakenet-ng-migration
usage/deployment
usage/troubleshooting
```

```{toctree}
:maxdepth: 2
:caption: Architecture

architecture/overview
architecture/message-flow
architecture/link-protocol
architecture/nucleus
architecture/daemon
architecture/diverter
architecture/design-decisions
```

```{toctree}
:maxdepth: 2
:caption: Reference

reference/protocols
reference/event-records
reference/rust-api
reference/daemon-api
reference/scripts-and-files
reference/known-flaws
```

```{toctree}
:maxdepth: 2
:caption: Development

development/building
development/testing
development/contributing
```
