//! The node runtime boundary: [`AtomicNode`] is the one surface adapters
//! (HTTP, WebSocket, Iroh, WASM, FFI, Flutter) bind to instead of wrapping
//! [`crate::Db`] themselves.
//!
//! Slice 1 (`planning/atomic-lib-runtime.md`, `planning/completed/runtime-boundary-decision.md`)
//! is a thin wrapper: every method delegates to code that already existed, so
//! there is no behaviour change — only a named place for it. The surface is
//! used by the WASM `ClientDb` and Flutter's per-call node accessor. It includes
//! `from_db`, `db`, agent accessors, indexed `query`, full-text `search`, local
//! writes (`save_locally`, `apply_local_commit`), outbox access and delivery,
//! and `apply_commit` under an [`IngestPolicy`].

mod node;

pub use node::{AtomicNode, IngestPolicy};
