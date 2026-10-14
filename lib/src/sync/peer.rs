//! Iroh peer-to-peer transport for the v2 binary protocol.
//!
//! Any device running atomic-lib with the `iroh` feature becomes a peer node.
//! Peers connect via NodeID — no port forwarding, DNS, or TLS needed.
//!
//! Addressing (relay URL, direct addresses) is handled by Iroh's `discovery_n0()`.
//! Peer discovery (agent → NodeID) is handled by pkarr in `discovery.rs`.
//!
//! Wire format is the same v2 protocol used over WebSocket; see
//! `docs/src/websockets.md` (canonical spec) and [`super::protocol`] for
//! tags / encoders. The one extension peer streams add on top of the
//! browser-WS subset is the `HELLO (0x37)` device-name handshake sent
//! immediately after `AUTH_OK` — see `encode_hello` / `decode_hello` in
//! [`super::protocol`].

use crate::{agents::ForAgent, Db, Storelike};
use iroh::{protocol::Router, Endpoint, NodeId};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Map Iroh I/O errors to AtomicError.
fn io_err(e: impl std::fmt::Display) -> crate::errors::AtomicError {
    format!("Iroh I/O error: {e}").into()
}

/// ALPN protocol identifier for Atomic Data over Iroh.
pub(crate) const ATOMIC_ALPN: &[u8] = b"atomic/1";

use super::{discover, engine, protocol, ws_apply};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

mod endpoint;
mod events;
mod handler;
mod identity;
mod known_peers;
mod live_broadcast;
mod live_registry;
mod live_session;
mod sync_outgoing;

pub use endpoint::*;
pub use events::*;
pub use handler::*;
pub use identity::*;
pub use known_peers::*;
pub use live_broadcast::*;
pub use live_registry::*;
#[cfg(test)]
pub(crate) use live_session::admitted_for_drive_for_test;
use live_session::*;
pub use sync_outgoing::*;

#[cfg(all(test, feature = "db"))]
mod accept_gate_tests;
#[cfg(test)]
mod initiator_trust_tests;
#[cfg(test)]
mod live_peer_registry_tests;
#[cfg(test)]
mod live_write_admission_tests;
#[cfg(all(test, feature = "db"))]
mod peer_sync_volume_tests;
