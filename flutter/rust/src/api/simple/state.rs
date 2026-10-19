use std::sync::{Arc, OnceLock};

static DB: OnceLock<Arc<atomic_lib::Db>> = OnceLock::new();

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn db() -> Result<&'static Arc<atomic_lib::Db>, String> {
    DB.get().ok_or_else(|| "Call openDb() first.".into())
}

/// The runtime the binding writes through (`planning/atomic-lib-runtime.md`):
/// saves and self-signed commits go via the node so they land in the
/// outbox. Cheap: a `Db` is a bundle of `Arc`s.
pub(crate) fn node() -> Result<atomic_lib::runtime::AtomicNode, String> {
    Ok(atomic_lib::runtime::AtomicNode::from_db((**db()?).clone()))
}

pub(super) fn set_db(store: atomic_lib::Db) {
    let _ = DB.set(Arc::new(store));
}

pub(crate) fn err(e: atomic_lib::AtomicError) -> String {
    e.to_string()
}

static SERVER_ORIGIN: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Remember the server `open_ws_sync` connected to (for links into its web app).
pub(crate) fn set_server_origin(origin: &str) {
    *SERVER_ORIGIN.lock().unwrap() = Some(origin.trim_end_matches('/').to_string());
}

pub(crate) fn connected_server() -> Option<String> {
    SERVER_ORIGIN.lock().unwrap().clone()
}
