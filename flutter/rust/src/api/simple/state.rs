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

/// Serialises `open_db`: two engines starting at once must not both open
/// the file.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) static OPEN_DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

static STORE_RECOVERY: std::sync::Mutex<Option<super::StoreRecovery>> = std::sync::Mutex::new(None);

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn set_store_recovery(recovery: super::StoreRecovery) {
    *STORE_RECOVERY.lock().unwrap_or_else(|e| e.into_inner()) = Some(recovery);
}

pub(super) fn store_recovery() -> Option<super::StoreRecovery> {
    STORE_RECOVERY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub(super) fn set_db(store: Arc<atomic_lib::Db>) {
    let _ = DB.set(store);
}

/// Every store opened in this process, by file. A file is opened once per
/// process (a second open of a redb file damaged stores on Android, see
/// `atomic_lib::db::recovery`), so a second handle on a path shares the
/// first one's `Db`. Guarded by [`OPEN_DB_LOCK`] while opening.
static OPEN_STORES: std::sync::Mutex<
    Option<std::collections::HashMap<std::path::PathBuf, Arc<atomic_lib::Db>>>,
> = std::sync::Mutex::new(None);

pub(super) fn registered_store(key: &std::path::Path) -> Option<Arc<atomic_lib::Db>> {
    OPEN_STORES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(key).cloned())
}

pub(super) fn register_store(key: std::path::PathBuf, store: Arc<atomic_lib::Db>) {
    OPEN_STORES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Default::default)
        .insert(key, store);
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

static STORE_DIR: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Remember where `open_db` put the store, to measure it on disk.
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn set_store_dir(dir: &std::path::Path) {
    *STORE_DIR.lock().unwrap_or_else(|e| e.into_inner()) = Some(dir.to_path_buf());
}

pub(crate) fn store_dir() -> Option<std::path::PathBuf> {
    STORE_DIR.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
