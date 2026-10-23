//! The bridge's binding of `atomic_lib::host` to a store handle: each
//! [`AtomicStore`] has its recents index, conversation and chat-room caches,
//! profile cache and sync session, and a local write is pushed through the
//! handle's own session (`push_write`). The functions below are those of the
//! default store, for the free functions of the bridge.

use crate::api::resources::AtomicStore;
use crate::api::simple::state::default_store;
use crate::api::simple::ws_sync::SyncSession;
use atomic_lib::{
    commit::CommitResponse,
    host::{
        chat_rooms::ChatRooms, conversations::Conversations, profiles::AgentProfiles, recents::RecentsIndex,
        AgentProfileFetcher, LocalWritePusher,
    },
    Storelike,
};
use std::sync::Arc;

/// Hands a local write of one handle to its WebSocket session, and for the
/// store the app syncs, to live peers and paired devices.
pub(crate) struct BridgePusher {
    pub(crate) db: Arc<atomic_lib::Db>,
    pub(crate) sync: Arc<SyncSession>,
}

#[async_trait::async_trait]
impl LocalWritePusher for BridgePusher {
    async fn push(&self, response: &CommitResponse) {
        crate::api::simple::push_write(response, self.db.as_ref(), &self.sync).await;
    }
}

/// Asks the server a handle's session is on for an agent, with the library's
/// HTTP client (which carries the Android TLS setup). The cache in front of
/// it bounds the time and remembers failures.
pub(crate) struct ServerProfileFetcher {
    pub(crate) db: Arc<atomic_lib::Db>,
    pub(crate) sync: Arc<SyncSession>,
}

#[async_trait::async_trait]
impl AgentProfileFetcher for ServerProfileFetcher {
    async fn fetch_agent_resource(&self, member: &str) -> Option<String> {
        let Some(origin) = self.sync.origin() else {
            tracing::debug!("[profile] no connected server for {member}");
            return None;
        };
        let agent = self.db.get_default_agent().ok();
        let url = format!("{origin}/{member}");
        let started = std::time::Instant::now();
        let fetched =
            atomic_lib::client::fetch_body(&url, atomic_lib::parse::JSON_AD_MIME, agent.as_ref())
                .await;
        match &fetched {
            Ok(body) => tracing::debug!(
                "[profile] {url}: {} bytes in {} ms",
                body.len(),
                started.elapsed().as_millis()
            ),
            Err(e) => tracing::debug!(
                "[profile] {url} failed after {} ms: {e}",
                started.elapsed().as_millis()
            ),
        }
        fetched.ok()
    }

    async fn fetch_history_attribution(&self, subject: &str) -> Option<String> {
        let origin = self.sync.origin()?;
        let agent = self.db.get_default_agent().ok();
        atomic_lib::host::fetch_history_attribution(&origin, subject, agent.as_ref()).await
    }
}

fn default() -> &'static AtomicStore {
    // Every caller has already used the default store (`db()?`, `node()?`).
    default_store().expect("the default store is open")
}

/// The profiles of agents this device does not hold, fetched from the
/// connected server and kept in memory (the default store's).
pub(crate) fn profiles() -> AgentProfiles {
    default().profiles.clone()
}

/// The pusher every default-store write goes through.
pub(crate) fn pusher() -> Arc<dyn LocalWritePusher> {
    default().pusher()
}

/// The recents index of the store `open_db` opened.
pub(crate) fn recents() -> &'static Arc<RecentsIndex> {
    &default().recents
}

/// Conversations of the default store, with their caches of agent names and
/// opened messages.
#[allow(dead_code)]
pub(crate) fn conversations() -> &'static Conversations {
    &default().conversations
}

/// Chat rooms and meetings of the default store.
#[allow(dead_code)]
pub(crate) fn chat_rooms() -> &'static ChatRooms {
    &default().chat_rooms
}

/// A value as the JSON string the Dart side reads.
pub(crate) fn to_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}
