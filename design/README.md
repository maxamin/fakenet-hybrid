# Design diagrams

UML for contributors and AI assistants, as Mermaid (GitHub renders it; so do most editors).
Keep them in step with the code: the `fakenet-extend` skill (`.claude/skills/fakenet-extend`)
says how to regenerate them from source.

| File | Shows |
|---|---|
| [architecture.md](architecture.md) | Components, the answer pipeline (sequence), the learning loop |
| [extension-points.md](extension-points.md) | Class diagrams of every interface meant to be extended: responders, analysers, model packs, the plugin protocol, transforms |
