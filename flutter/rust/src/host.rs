//! The bridge's binding of `atomic_lib::host` to this process: the store,
//! recents index and conversation caches live in statics here, a local write
//! is pushed with [`push_local_write`](crate::api::simple::push_local_write),
//! and agent names come from the connected server.

use crate::api::simple::state::{connected_server, db};
use atomic_lib::{
    commit::CommitResponse,
    host::{
        conversations::Conversations, recents::RecentsIndex, AgentNameFetcher, LocalWritePusher,
    },
    Storelike,
};
use std::sync::{Arc, OnceLock};

/// How long a background lookup of one agent's name may take.
const AGENT_NAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
/// (which carries the Android TLS setup).
struct ServerNameFetcher;

#[async_trait::async_trait]
impl AgentNameFetcher for ServerNameFetcher {
    async fn fetch(&self, member: &str) -> Option<String> {
        let origin = connected_server()?;
        let agent = db().ok()?.get_default_agent().ok();
        let url = format!("{origin}/{member}");
        let body = tokio::time::timeout(
            AGENT_NAME_TIMEOUT,
            atomic_lib::client::fetch_body(&url, atomic_lib::parse::JSON_AD_MIME, agent.as_ref()),
        )
        .await
        .ok()?
        .ok()?;
        atomic_lib::host::conversations::name_from_json_ad(&body)
    }
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
    CONVERSATIONS.get_or_init(|| Conversations::new(Arc::new(ServerNameFetcher)))
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
