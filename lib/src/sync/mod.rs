//! Sync protocol — transport-agnostic drive synchronization.
//!
//! Contains the v2 binary frame protocol and the sync engine.
//! Used by WebSocket (server), Iroh QUIC (native peers), and WASM clients.

// `policy`, `protocol`, and `rbsr` are std-only; the rest needs the `db`
// feature. The module itself stays ungated so `Storelike::sync_policy`
// (always compiled) can reference `sync::policy` in a no-features build.
#[cfg(feature = "db")]
pub mod engine;
#[cfg(all(test, feature = "iroh", feature = "db-redb"))]
mod iroh_e2e;
#[cfg(feature = "iroh")]
pub mod peer;
pub mod policy;
pub mod protocol;
pub mod rbsr;
/// Pushing a whole drive to a remote server, as a client. Needs the WS client.
#[cfg(feature = "ws")]
pub mod replicate;
#[cfg(feature = "db")]
pub mod session;
#[cfg(all(test, feature = "iroh"))]
mod tests;
#[cfg(feature = "db")]
pub mod tombstones;
#[cfg(feature = "db")]
pub mod transport;
#[cfg(feature = "db")]
pub mod ws_apply;
