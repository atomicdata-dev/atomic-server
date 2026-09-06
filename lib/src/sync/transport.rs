//! Byte-pipe a [`super::session::SyncSession`] runs over.
//!
//! Semantics stay in the engine; a transport only sends and receives
//! complete v2 frames (tag byte included). WebSocket, Iroh QUIC, and the
//! in-process [`ChannelTransport`] are all `AtomicTransport`s.

use crate::errors::AtomicResult;

/// Send and receive one protocol frame at a time.
///
/// Not object-safe: implementors use async fn. Callers are generic over
/// `T: AtomicTransport` (`SyncSession::serve`, a future `drain_outbox`).
pub trait AtomicTransport: Send {
    fn send(
        &mut self,
        frame: Vec<u8>,
    ) -> impl std::future::Future<Output = AtomicResult<()>> + Send;
    /// `Ok(None)` is a clean close (the other end dropped).
    fn recv(&mut self) -> impl std::future::Future<Output = AtomicResult<Option<Vec<u8>>>> + Send;
}

/// In-process pair for tests and for wiring two `SyncSession`s in one
/// process. `pair()` yields two ends of the same pipe.
pub struct ChannelTransport {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl ChannelTransport {
    pub fn pair() -> (Self, Self) {
        let (a_tx, a_rx) = tokio::sync::mpsc::channel(32);
        let (b_tx, b_rx) = tokio::sync::mpsc::channel(32);
        (Self { tx: a_tx, rx: b_rx }, Self { tx: b_tx, rx: a_rx })
    }
}

impl AtomicTransport for ChannelTransport {
    async fn send(&mut self, frame: Vec<u8>) -> AtomicResult<()> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| "sync transport closed".into())
    }

    async fn recv(&mut self) -> AtomicResult<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
}
