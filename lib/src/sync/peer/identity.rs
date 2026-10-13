//! Node identity: canonical NodeID, device name and the persisted Iroh secret key.

use super::*;

/// Canonical 64-char lowercase hex NodeID for map keys and UI matching.
pub fn normalize_node_id(id: &str) -> String {
    let mut s = id.trim().to_string();
    if let Some(rest) = crate::identifiers::node_id(&s) {
        s = rest.split(':').next().unwrap_or(rest).to_string();
    } else if let Some(rest) = s.strip_prefix("iroh:") {
        s = rest.to_string();
    }
    s.to_lowercase()
}

/// Global NodeID, set once on startup.
pub(super) static NODE_ID: OnceLock<String> = OnceLock::new();

/// Resolve the device name this node announces in `HELLO` frames.
///
/// Order of precedence:
///  1. Whatever is persisted via [`set_device_name`] (flutter app UI, server
///     `--device-name` / `ATOMIC_DEVICE_NAME` written at startup).
///  2. The OS hostname (`gethostname()`).
///  3. The literal `"Unknown"`.
///
/// Truncates to [`crate::sync::protocol::HELLO_MAX_CHARS`] scalar values
/// so a misconfigured peer can't drive the on-wire length cap into reject.
pub fn effective_device_name(store: &Db) -> String {
    let from_db = get_device_name(store);
    let raw = if !from_db.trim().is_empty() {
        from_db
    } else {
        hostname::get()
            .ok()
            .and_then(|os| os.into_string().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unknown".to_string())
    };
    let max = super::protocol::HELLO_MAX_CHARS;
    if raw.chars().count() > max {
        raw.chars().take(max).collect()
    } else {
        raw
    }
}

/// Returns the Iroh NodeID if the peer node is running.
pub fn get_node_id() -> Option<&'static str> {
    NODE_ID.get().map(|s| s.as_str())
}

/// Key used to persist the Iroh secret key in the DB.
const IROH_SECRET_KEY: &[u8] = b"_iroh_secret_key";
const DEVICE_NAME_KEY: &[u8] = b"_device_name";

/// Get the persisted device name.
pub fn get_device_name(store: &Db) -> String {
    store
        .kv
        .get(crate::db::trees::Tree::PluginMeta, DEVICE_NAME_KEY)
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

/// Set the device name (persisted in DB).
pub fn set_device_name(store: &Db, name: &str) {
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        DEVICE_NAME_KEY,
        name.as_bytes(),
    );
}

/// Load or generate a persistent Iroh secret key.
/// Stored in the DB so the NodeID survives app restarts.
pub(super) fn load_or_create_secret_key(store: &Db) -> iroh::SecretKey {
    if let Ok(Some(bytes)) = store
        .kv
        .get(crate::db::trees::Tree::PluginMeta, IROH_SECRET_KEY)
    {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return iroh::SecretKey::from_bytes(&arr);
        }
    }
    // Generate and persist. Flush immediately: kv writes use Durability::None
    // (no fsync per commit), which redb rolls back on an unclean kill unless a
    // later durable commit lands. This node's identity is written exactly once
    // and must survive the very next app kill — otherwise every restart mints a
    // new NodeID, the paired server is effectively a stranger again, and the
    // user has to re-scan the QR. A one-time fsync here is well worth that.
    let key = iroh::SecretKey::generate(rand::rngs::OsRng);
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        IROH_SECRET_KEY,
        &key.to_bytes(),
    );
    let _ = store.flush();
    key
}
