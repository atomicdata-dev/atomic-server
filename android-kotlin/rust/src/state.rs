//! Process-wide state: one store per process.

use atomic_lib::{
    commit::CommitResponse,
    host::{
        conversations::Conversations, profiles::AgentProfiles, recents::RecentsIndex, AgentProfileFetcher,
        LocalWritePusher,
    },
    Storelike,
};
use std::sync::{Arc, Mutex, OnceLock};

use crate::{error::CoreResult, types::StoreRecovery};

static DB: OnceLock<Arc<atomic_lib::Db>> = OnceLock::new();

/// Serialises `open_store`: two engines starting at once must not both open the
/// file.
pub(crate) static OPEN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

static RECOVERY: Mutex<Option<StoreRecovery>> = Mutex::new(None);

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn db() -> CoreResult<&'static Arc<atomic_lib::Db>> {
    Ok(DB.get().ok_or("Call open_store() first.")?)
}

pub(crate) fn is_open() -> bool {
    DB.get().is_some()
}

pub(crate) fn set_db(store: atomic_lib::Db) {
    let _ = DB.set(Arc::new(store));
}

pub(crate) fn node() -> CoreResult<atomic_lib::runtime::AtomicNode> {
    Ok(atomic_lib::runtime::AtomicNode::from_db((**db()?).clone()))
}

pub(crate) fn set_recovery(recovery: StoreRecovery) {
    *RECOVERY.lock().unwrap_or_else(|e| e.into_inner()) = Some(recovery);
}

pub(crate) fn recovery() -> Option<StoreRecovery> {
    RECOVERY.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The recents index of the store `open_store` opened.
pub(crate) fn recents() -> &'static Arc<RecentsIndex> {
    static RECENTS: OnceLock<Arc<RecentsIndex>> = OnceLock::new();
    RECENTS.get_or_init(Default::default)
}

/// Hands a local write to the WebSocket session, live peers and paired
/// devices (`sync::peers::push_local_write`): what makes an edit reach the
/// server instead of waiting in the outbox.
pub(crate) struct RealPusher;

#[async_trait::async_trait]
impl LocalWritePusher for RealPusher {
    async fn push(&self, response: &CommitResponse) {
        if let Ok(store) = db() {
            crate::sync::peers::push_local_write(response, store.as_ref()).await;
        }
    }
}

/// The pusher every write of this app goes through.
pub(crate) fn pusher() -> Arc<dyn LocalWritePusher> {
    static PUSHER: OnceLock<Arc<dyn LocalWritePusher>> = OnceLock::new();
    PUSHER.get_or_init(|| Arc::new(RealPusher)).clone()
}

static SERVER_ORIGIN: Mutex<Option<String>> = Mutex::new(None);

/// Remember the server the WebSocket session connected to.
pub(crate) fn set_server_origin(origin: &str) {
    *SERVER_ORIGIN.lock().unwrap_or_else(|e| e.into_inner()) = Some(origin.trim_end_matches('/').to_string());
}

pub(crate) fn connected_server() -> Option<String> {
    SERVER_ORIGIN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Asks the connected server for an agent, with the library's HTTP client
/// (which carries the Android TLS setup). The cache in front bounds the time
/// and remembers failures.
struct ServerProfileFetcher;

#[async_trait::async_trait]
impl AgentProfileFetcher for ServerProfileFetcher {
    async fn fetch_agent_resource(&self, member: &str) -> Option<String> {
        let origin = connected_server()?;
        let agent = db().ok()?.get_default_agent().ok();
        atomic_lib::client::fetch_body(&format!("{origin}/{member}"), atomic_lib::parse::JSON_AD_MIME, agent.as_ref())
            .await
            .ok()
    }
}

/// The profiles of agents this device does not hold, fetched from the
/// connected server and kept in memory (shared by lists and the embedded page).
pub(crate) fn profiles() -> AgentProfiles {
    static PROFILES: OnceLock<AgentProfiles> = OnceLock::new();
    PROFILES.get_or_init(|| AgentProfiles::new(Arc::new(ServerProfileFetcher))).clone()
}

/// Conversations, with their caches of agent names and opened messages.
pub(crate) fn conversations() -> &'static Conversations {
    static CONVERSATIONS: OnceLock<Conversations> = OnceLock::new();
    CONVERSATIONS.get_or_init(|| Conversations::new(profiles()))
}
