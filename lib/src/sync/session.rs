//! [`SyncSession`]: one connection's engine loop over an [`AtomicTransport`].
//!
//! First slice (`planning/serverless-p2p.md` P2): the responder loop that
//! already exists inline in `peer.rs` `handle_stream` and the WebSocket
//! handler. Connect / mutual AUTH / VV reconcile / live / outbox drain
//! still live in those call sites; they collapse onto this type once the
//! outbox port and the remaining `sync_drive_with_peer*` entries fold in.

use super::engine::{handle_frame_full, HandleOutput};
use super::transport::AtomicTransport;
use crate::agents::ForAgent;
use crate::errors::AtomicResult;
use crate::Db;

/// One authenticated (or still-`Public`) sync conversation over a
/// transport. Cheap to create; the store is shared.
pub struct SyncSession {
    store: Db,
    agent: ForAgent,
}

impl SyncSession {
    pub fn new(store: Db) -> Self {
        Self {
            store,
            agent: ForAgent::Public,
        }
    }

    /// Identity this session has proven via `AUTH`, or `Public`.
    pub fn agent(&self) -> &ForAgent {
        &self.agent
    }

    /// Apply one inbound frame and return what the engine produced. The
    /// caller writes `frames` on the wire; a hub also honours
    /// `subscribe` / `unsubscribe`. Exposed so a transport that is not a
    /// simple request/response loop (WebSocket + actor mailbox) can still
    /// share the engine.
    pub async fn handle(&mut self, frame: &[u8]) -> HandleOutput {
        handle_frame_full(frame, &self.store, &mut self.agent).await
    }

    /// Responder loop: recv → engine → send replies, until the transport
    /// closes. Does not register `SUB` (this is not a hub). AUTH is the
    /// engine's unbound arm — a transport that binds `requestedSubject`
    /// should call [`handle_frame_full`] itself with [`super::engine::handle_auth_frame`].
    pub async fn serve<T: AtomicTransport>(&mut self, transport: &mut T) -> AtomicResult<()> {
        loop {
            let Some(frame) = transport.recv().await? else {
                return Ok(());
            };
            let out = self.handle(&frame).await;
            for reply in out.frames {
                transport.send(reply).await?;
            }
        }
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod tests {
    use super::*;
    use crate::sync::protocol::{self, tag};
    use crate::sync::transport::ChannelTransport;

    #[tokio::test]
    async fn session_holds_auth_across_frames() {
        let db = Db::init_temp("sync_session_auth").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();

        let (mut client, mut server_end) = ChannelTransport::pair();
        let mut session = SyncSession::new(db);
        let serve = tokio::spawn(async move { session.serve(&mut server_end).await });

        // Unauthenticated GET of a private drive is refused.
        client.send(protocol::encode_get(1, &drive)).await.unwrap();
        let reply = client.recv().await.unwrap().expect("GET answer");
        assert_eq!(
            reply.first(),
            Some(&tag::ERROR),
            "Public GET of a private drive must ERROR"
        );

        let auth = protocol::encode_auth(&alice, &drive).unwrap();
        client.send(auth).await.unwrap();
        let reply = client.recv().await.unwrap().expect("AUTH answer");
        assert_eq!(reply.first(), Some(&tag::AUTH_OK));

        client.send(protocol::encode_get(2, &drive)).await.unwrap();
        let reply = client.recv().await.unwrap().expect("GET answer after AUTH");
        assert_eq!(
            reply.first(),
            Some(&tag::UPDATE),
            "Alice's GET after AUTH must return the drive snapshot"
        );

        drop(client);
        serve.await.unwrap().unwrap();
    }
}
