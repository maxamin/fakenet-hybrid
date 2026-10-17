//! Messages from the other side of the link (a daemon, or an impostor): parsing,
//! validation and signature checks must never panic, and a forged signature never passes
#![no_main]
use fakenet_schema::auth::{action_text, event_text, Secret};
use fakenet_schema::{Action, Event, EventBuilder, Hello, Protocol, Transport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let secret = Secret::new(b"fuzzing-secret-fuzzing-secret-00");
    let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap());
    let event = builder.event(b"x".to_vec(), serde_json::Value::Null, true);
    if let Ok(action) = serde_json::from_slice::<Action>(data) {
        let _ = action.validate_for(&event);
        // A random signature must not verify (2^-256), and a correct one must
        let text = action_text(&action);
        if let Some(auth) = &action.auth {
            if secret.verify(&text, Some(auth)) {
                assert_eq!(*auth, secret.sign(&text));
            }
        }
        assert!(secret.verify(&text, Some(&secret.sign(&text))));
    }
    if let Ok(event) = serde_json::from_slice::<Event>(data) {
        let _ = secret.verify(&event_text(&event), event.auth.as_deref());
    }
    let _ = serde_json::from_slice::<Hello>(data);
});
