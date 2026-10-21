# Progress: learned traffic models and pluggable generators

Goal: answers learned from real traffic (every protocol the nucleus speaks), a modular
chain of answer sources the community can extend in any language, and Claude tooling
(skills, scaffolding, UML) so fuzzers, Radamsa, AI models and future generators share one
interface.

## Milestones

- [x] M1 `fakenet-model` crate: pcap reader (raw, Ethernet/VLAN, Linux cooked), TCP
      reassembly, exchanges, protocol analysers (HTTP, DNS, line protocols, Redis,
      generic), shareable JSON model packs, weighted sampling
- [x] M2 Responder chain in the nucleus (`[[responder]]`): `model` and `plugin` (JSON
      lines over stdin/stdout), after the rules and the explorer, before manual mode
- [x] M3 CLI: `--learn` (pcaps or capture folders -> pack), `--model-info`
- [x] M4 Plugins folder: protocol reference, Python template, Radamsa mutator plugin
- [x] M5 Claude tooling: project skill updated, `fakenet-extend` skill with templates,
      `scripts/scaffold.py` (plugin, responder, analyser skeletons), UML in `design/`
- [x] M6 Docs: learning and responders page, config, CLI, records, Rust API
- [x] M7 Tests end to end (learn from a capture, answer from the model, plugin), full
      suites, Windows check, docs build; commit and push

## Notes

- Verified on real data: Wireshark's public dns.cap (Ethernet) and http_with_jpegs.cap, plus
  this project's own captures. DNS answers that were failures in the data (NXDOMAIN) are
  left out by default (`outcomes = "successful"`), since a mock should keep the sample going.
- Radamsa 0.8a built from source (gitlab.com/akihe/radamsa) into ~/.local/bin for the tests;
  the plugin falls back to a built-in mutator without it.

- Fuzzing (`nucleus/fuzz`, target `model`) found a panic in the pcap reader (an IP header
  longer than the packet); fixed, kept as a seed and a unit test; 143,300 runs clean after.
- Results: 199 Rust tests, 22 daemon tests, 3 plugin tests, Windows cross-check, docs -W.

## Later

- Online learning (update packs from live traffic), decoders applied while learning
  (TLS key log, XOR/RC4 from `--infer`), pcapng input
- Grammar-aware synthesis from pack statistics (not only replay), coverage-guided corpus
- More analysers (SMB, LDAP, MQTT, CoAP fields)
