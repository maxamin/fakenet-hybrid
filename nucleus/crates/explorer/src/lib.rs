//! Response exploration for fakenet-hybrid: when the analyst's rules don't decide an
//! answer, propose one from protocol templates, filled with what the sample suggests (its
//! strings, REA's analysis of it, what it sends), and learn which answers unlock new
//! behaviour or new code, so a sample is driven down more of its paths. The result is a
//! map of answer -> behaviour -> functions.

pub mod coverage;
pub mod explorer;
pub mod hints;
pub mod rng;
pub mod templates;

pub use explorer::{Explorer, ExplorerConfig, Proposal};
pub use hints::Hints;
