//! Convenience node operations within `atomic_lib`, the component boundary.
//!
//! [`AtomicNode`](crate::runtime::AtomicNode) groups selected writes, outbox delivery, queries, search,
//! and commit ingestion policies. It is not a separate product or a mandatory
//! layer for every operation inside the library. The `Db` implementation and
//! the facade's `from_db` / `db` helpers are documented as internal, while their
//! Rust paths remain available for existing first-party adapters.
//!
//! The initial slice wrapped existing store operations
//! (`planning/atomic-lib-runtime.md`, `planning/completed/runtime-boundary-decision.md`).
//! Current convenience methods also group local writes with outbox bookkeeping.
//! The surface is used by the WASM `ClientDb` and Flutter's per-call node accessor. It includes
//! `from_db`, `db`, agent accessors, indexed `query`, full-text `search`, local
//! writes (`save_locally`, `apply_local_commit`), outbox access and delivery,
//! and `apply_commit` under an [`IngestPolicy`](crate::runtime::IngestPolicy).

mod node;

pub use node::{AtomicNode, IngestPolicy};
