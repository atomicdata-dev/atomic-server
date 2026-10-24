//! Everything that talks to other machines: the WebSocket session to a server,
//! Iroh peers, finding where a drive lives. Ported from `flutter/rust`; the
//! HTTPS parts only use `atomic_lib::client` (whose TLS setup is
//! `lib/src/client/tls.rs`, the one that works on Android).

pub(crate) mod discovery;
pub(crate) mod peers;
pub(crate) mod ws;
