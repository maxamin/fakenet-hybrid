# Enhancement ideas (`ENH-*`)

Improvements that aren't defects, roughly by value to analysts.

| ID | Idea | Why |
|---|---|---|
| ENH-04 | Per-start capture sub-folders (as `--run` does), plus a `latest` symlink | Makes runs comparable (a restart already archives the previous run to `previous/`) |
| ENH-05 | Save Redis `SET`/`CONFIG SET` values and Telnet `echo`/`wget` payloads as files | Attack payloads (cron lines, SSH keys, droppers) today exist only as truncated previews and base64 in events |
| ENH-06 | DNS: EDNS(0), TC bit for UDP answers over 512 bytes, all questions, per-domain AAAA from an IPv6 pool | Fidelity with real resolvers; some samples probe these |
| ENH-07 | Protocol fidelity fixes: Redis `INCR` returns 0, SSH stops after the banner (no KEXINIT), IMAP has one fixed message | Samples that check responses notice |
| ENH-08 | Daemon: a `FakenetText` limit, structured rule unit tests (`--replay` with expected outputs), and a rules linter | Faster, safer rule writing |
| ENH-09 | Report: per-run summary at the top (sample, duration, top talkers), payload truncation, links into `files/` | Usable reports for large captures (the report already caps listings at 20,000 records) |
| ENH-10 | `--check` also loads Custom Response INIs, the explorer's templates and REA files, and warns about risky diverter settings | Fail before the sample runs, not during |
| ENH-11 | Prometheus-style `/metrics` on the control port | Watch fallbacks, refusals and latency over time |
| ENH-12 | Windows: SIGHUP-equivalent reload, and the Windows diverter in CI (ARCH-01, ARCH-05) | Parity between platforms |
