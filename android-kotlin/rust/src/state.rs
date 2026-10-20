//! Process-wide state: one store per process.

use atomic_lib::host::{conversations::Conversations, profiles::AgentProfiles, recents::RecentsIndex, NoProfiles};
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

/// Conversations. No server is connected in this stage, so the names of
/// agents this device does not hold stay unknown ([`NoProfiles`]).
pub(crate) fn conversations() -> &'static Conversations {
    static CONVERSATIONS: OnceLock<Conversations> = OnceLock::new();
    CONVERSATIONS.get_or_init(|| Conversations::new(AgentProfiles::new(Arc::new(NoProfiles))))
}
