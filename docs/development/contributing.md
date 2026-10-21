# Contributing

## Invariants to keep

1. **The nucleus never waits on the daemon beyond the deadline.** Any new handler step must
   go through `Session::answer` / `decide` with a default ready.
2. **Control interfaces stay on loopback.** `Config::validate` enforces it for the nucleus;
   `application.properties` pins Camel's servers.
3. **Everything from the sample is hostile.** Bound every read (`MAX_*` constants, the
   memory budget), escape everything rendered (report, dashboard), never execute or
   interpolate it.
4. **Link changes are made on both sides.** Signed texts, header names and the protocol list
   live in Rust (`schema`) and Java (`LinkAuth`, `LinkSchema`, `WarmUp`); update the shared
   test vectors and `schema/fakenet-link-v1.schema.json` together.
5. **Stock Camel only.** Rules use documented components; Java stays limited to small
   processors.
6. **Diversion is off by default** and no tool or importer turns it on.

## Adding a protocol handler

1. Add the variant to `schema::Protocol` (and `name()`), the JSON Schema enum, the Java
   `WarmUp` list, and the sniffer tables (`supports`, `default_ports`, `DEFAULT_ORDER`, a
   recogniser in `score`, `server_speaks_first` if applicable).
2. Write `listeners/src/<protocol>.rs` with `handle(stream, session)` (TCP) or a function
   called from `dispatch::handle_udp`, and wire it in `dispatch::serve`.
3. Bound reads; log credentials with `session.log("credentials", ...)`; use
   `session.answer` for every reply that a rule might change.
4. Add a test in `listeners/tests/protocols.rs`, a seed in `fuzz/seeds/handlers/`, the
   handler to `fuzzing.rs`, and a check in `scripts/interop.sh` if a real client exists.
5. Document it in `docs/reference/protocols.md` and the response format in
   `docs/usage/writing-rules.md`.

## Adding a config key

Add it to the right struct (`cli::NucleusConfig`, `listeners::config::*Defaults`,
`DiverterConfig`, ...), with a default and a doc comment; resolve it in
`Config::resolve_paths` if it's a path; validate it in `Config::validate`; add it to
`nucleus/config/fakenet.toml` and `deploy/docker/fakenet.container.toml`; document it in
`docs/getting-started/configuration.md`.

## Fixing a flaw

Each entry in `flaws/` gives a location and a suggested fix. When you fix one, delete its
section, remove it from the index in `flaws/README.md`, and update any page in `docs/`
that mentions its ID (`rg -n 'BUG-04' docs flaws`).
