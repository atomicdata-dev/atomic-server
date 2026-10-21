//! The bridge's binding of `atomic_lib::host` to this process: the store,
//! recents index and conversation caches live in statics here, a local write
//! is pushed with [`push_local_write`](crate::api::simple::push_local_write),
//! and the profiles of agents this device does not hold come from the
//! connected server (one cache, shared by the lists and the embedded page).

use crate::api::simple::state::{connected_server, db};
use atomic_lib::{
    commit::CommitResponse,
    host::{
        chat_rooms::ChatRooms, conversations::Conversations, profiles::AgentProfiles, recents::RecentsIndex,
        AgentProfileFetcher, LocalWritePusher,
    },
    Storelike,
};
use std::sync::{Arc, OnceLock};

/// Hands a local write to the WebSocket session, live peers and paired
/// devices (`push_local_write`).
pub(crate) struct BridgePusher;

#[async_trait::async_trait]
impl LocalWritePusher for BridgePusher {
    async fn push(&self, response: &CommitResponse) {
        if let Ok(store) = db() {
            crate::api::simple::push_local_write(response, store.as_ref()).await;
        }
    }
}

/// Asks the connected server for an agent, with the library's HTTP client
/// (which carries the Android TLS setup). The cache in front of it bounds the
/// time and remembers failures.
struct ServerProfileFetcher;

#[async_trait::async_trait]
impl AgentProfileFetcher for ServerProfileFetcher {
    async fn fetch_agent_resource(&self, member: &str) -> Option<String> {
        let Some(origin) = connected_server() else {
            tracing::debug!("[profile] no connected server for {member}");
            return None;
        };
        let agent = db().ok()?.get_default_agent().ok();
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
        let origin = connected_server()?;
        let agent = db().ok()?.get_default_agent().ok();
        atomic_lib::host::fetch_history_attribution(&origin, subject, agent.as_ref()).await
    }
}

/// The profiles of agents this device does not hold, fetched from the
/// connected server and kept in memory.
pub(crate) fn profiles() -> AgentProfiles {
    static PROFILES: OnceLock<AgentProfiles> = OnceLock::new();
    PROFILES
        .get_or_init(|| AgentProfiles::new(Arc::new(ServerProfileFetcher)))
        .clone()
}

/// The pusher every bridge write goes through.
pub(crate) fn pusher() -> Arc<dyn LocalWritePusher> {
    static PUSHER: OnceLock<Arc<dyn LocalWritePusher>> = OnceLock::new();
    PUSHER.get_or_init(|| Arc::new(BridgePusher)).clone()
}

/// The recents index of the store `open_db` opened.
pub(crate) fn recents() -> &'static Arc<RecentsIndex> {
    static RECENTS: OnceLock<Arc<RecentsIndex>> = OnceLock::new();
    RECENTS.get_or_init(Default::default)
}

/// Conversations, with their caches of agent names and opened messages.
pub(crate) fn conversations() -> &'static Conversations {
    static CONVERSATIONS: OnceLock<Conversations> = OnceLock::new();
    CONVERSATIONS.get_or_init(|| Conversations::new(profiles()))
}

/// Chat rooms and meetings, sharing the profile cache.
pub(crate) fn chat_rooms() -> &'static ChatRooms {
    static CHAT_ROOMS: OnceLock<ChatRooms> = OnceLock::new();
    CHAT_ROOMS.get_or_init(|| ChatRooms::new(profiles()))
}

/// Load the recents index from `dir`, and keep it current for as long as the
/// store lives.
pub(crate) fn start_recents(dir: &std::path::Path, store: Arc<atomic_lib::Db>) {
    recents().load(dir);
    recents().clone().spawn_listener(store);
}

/// A value as the JSON string the Dart side reads.
pub(crate) fn to_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}
