# Security flaws (`SEC-*`)

The threat model: the sample under analysis runs on the same VM as the nucleus and daemon.
It can reach loopback, read world-readable files and the process list, and race for
ports. It cannot read root-only files.

## SEC-09

**Splunk HEC token on the command line** · Low · Confirmed

- Where: `daemon/routes/siem.yaml` (header comment and `fakenet.siem.splunk-token`).
- What: the documented way to configure it is a `-D` system property, which appears in
  `/proc/<pid>/cmdline` and in `ps` for every user.
- Impact: the sample can read the token and write to the SIEM.
- Fix: read it from a file (`fakenet.siem.splunk-token-file`) or an environment
  variable, and document `application.properties` with restricted permissions.
