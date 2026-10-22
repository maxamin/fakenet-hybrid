//! The coverage-guided corpus: an answer that earned reward is kept, saved, reloaded next
//! run, and mutated by the `{corpus}` slot

use fakenet_explorer::templates::Template;
use fakenet_explorer::{Explorer, ExplorerConfig, Hints};
use fakenet_schema::{Event, EventBuilder, ProcessInfo, Protocol, Transport};
use serde_json::json;

fn event(protocol: Protocol, payload: &[u8], meta: serde_json::Value) -> Event {
    let mut builder = EventBuilder::new(protocol, Transport::Tcp, "10.0.2.15:50000".parse().unwrap(), "203.0.113.10:4444".parse().unwrap());
    builder.process = Some(ProcessInfo { pid: 4242, name: "bot.exe".into(), exe: None });
    builder.event(payload.to_vec(), meta, true)
}

fn raw_template(name: &str, body: &str) -> Template {
    Template { name: name.into(), protocol: "raw".into(), body: body.into(), close: false, when: Default::default() }
}

#[test]
fn rewarded_answers_join_the_corpus_and_survive_runs() {
    let dir = std::env::temp_dir().join(format!("fakenet-corpus-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = ExplorerConfig { enabled: true, rate: 1.0, corpus_dir: Some(dir.clone()), ..ExplorerConfig::default() };
    let explorer = Explorer::new(config.clone(), vec![raw_template("raw-task", "TASK-1")], Hints::default());
    let request = event(Protocol::Raw, b"hello", json!({ "bytes": 5 }));
    assert_eq!(explorer.propose(&request).unwrap().response, b"TASK-1");
    // Right after the answer the bot does something new: the answer earns reward
    explorer.observe(&event(Protocol::Dns, b"", json!({ "qname": "stage2.example", "qtype": "A" })));
    assert_eq!(explorer.corpus_sizes()["raw"], 1);
    assert_eq!(explorer.map()["corpus"]["raw"], 1);
    assert_eq!(explorer.save_corpus().unwrap(), 1);
    assert_eq!(explorer.save_corpus().unwrap(), 0); // Already written

    // Next run: loaded from disk, and {corpus} mutates it
    let next = Explorer::new(config, vec![raw_template("raw-corpus", "{corpus}")], Hints::default());
    assert_eq!(next.load_corpus().unwrap(), 1);
    let mut mutated = 0;
    for _ in 0..20 {
        let answer = next.propose(&request).unwrap().response;
        assert!(!answer.is_empty());
        mutated += usize::from(answer != b"TASK-1");
    }
    assert!(mutated > 10, "{mutated} of 20 mutated");
    // Without a corpus for the protocol, {corpus} mutates the request instead
    let empty = Explorer::new(ExplorerConfig { enabled: true, rate: 1.0, ..ExplorerConfig::default() }, vec![raw_template("raw-corpus", "{corpus}")], Hints::default());
    assert!(!empty.propose(&request).unwrap().response.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
