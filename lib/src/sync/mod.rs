//! Sync protocol — transport-agnostic drive synchronization.
//!
//! Contains the v2 binary frame protocol and the sync engine.
//! Used by WebSocket (server), Iroh QUIC (native peers), and WASM clients.

// `policy` and `protocol` are std-only; the rest needs the `db`
// feature. The module itself stays ungated so `Storelike::sync_policy`
// (always compiled) can reference `sync::policy` in a no-features build.
#[cfg(feature = "iroh")]
pub mod discover;
#[cfg(feature = "db")]
pub mod engine;
#[cfg(all(test, feature = "iroh", feature = "db"))]
mod iroh_e2e;
/// The durable dirty-subject queue a device drains to a hub.
#[cfg(feature = "db")]
pub mod outbox;
#[cfg(feature = "iroh")]
pub mod peer;
#[cfg(feature = "iroh")]
mod peer_verification;
pub mod policy;
pub mod protocol;
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

#[cfg(feature = "db")]
pub mod browser_peer;
