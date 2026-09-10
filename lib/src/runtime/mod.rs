//! The node runtime boundary: [`AtomicNode`] is the one surface adapters
//! (HTTP, WebSocket, Iroh, WASM, FFI, Flutter) bind to instead of wrapping
//! [`crate::Db`] themselves.
//!
//! WASM binds existing storage through `from_db`. Native adapters can open
//! local storage, load a persisted identity and own a durable-flush worker
//! here without a server crate, HTTP origin or Actix executor.

mod node;

pub use node::{AtomicNode, IngestPolicy};

#[cfg(not(target_arch = "wasm32"))]
mod durable_flush;
#[cfg(not(target_arch = "wasm32"))]
pub use durable_flush::DurableFlush;
#[cfg(all(feature = "config", not(target_arch = "wasm32")))]
mod identity;
