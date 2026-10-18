use std::sync::{Arc, OnceLock};

static DB: OnceLock<Arc<atomic_lib::Db>> = OnceLock::new();

pub(super) const CANVAS_STROKE_DATA: &str = "https://atomicdata.dev/ontology/canvas/strokeData";
pub(super) const CANVAS_CLASS: &str = "https://atomicdata.dev/ontology/canvas/Canvas";
pub(super) const CANVAS_FOLDER_ID: &str = "https://atomicdata.dev/ontology/canvas/folderId";
/// Unix milliseconds; updated whenever the canvas is edited (gallery sort key).
pub(super) const CANVAS_DATE_EDITED: &str = "https://atomicdata.dev/ontology/canvas/dateEdited";
pub(super) const FOLDER_CLASS: &str = "https://atomicdata.dev/classes/Folder";

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(super) fn touch_date_edited(resource: &mut atomic_lib::Resource) {
    // `_sys` variant: tags the commit with a `sys:` origin so the user's
    // undo button skips this op. Without it, `push_stroke + touch_date`
    // produces two undo groups and the first tap of the undo button looks
    // like a no-op (reverts the date tick, leaves the stroke).
    let _ = resource
        .patch_loro_property_sys(CANVAS_DATE_EDITED, atomic_lib::Value::Timestamp(now_ms()));
}

/// Read gallery sort timestamp; falls back to legacy `"Canvas {millis}"` names.
pub(super) fn canvas_date_edited_ms(resource: &atomic_lib::Resource) -> i64 {
    if let Ok(v) = resource.get(CANVAS_DATE_EDITED) {
        if let Ok(ms) = v.to_int() {
            return ms;
        }
    }
    if let Ok(name) = resource.get(atomic_lib::urls::NAME) {
        let name = name.to_string();
        if let Some(suffix) = name.strip_prefix("Canvas ") {
            if let Ok(ms) = suffix.parse::<i64>() {
                return ms;
            }
        }
    }
    0
}

pub(crate) fn db() -> Result<&'static Arc<atomic_lib::Db>, String> {
    DB.get().ok_or_else(|| "Call openDb() first.".into())
}

/// The runtime the binding writes through (`planning/atomic-lib-runtime.md`):
/// saves and self-signed commits go via the node so they land in the
/// outbox. Cheap: a `Db` is a bundle of `Arc`s.
pub(super) fn node() -> Result<atomic_lib::runtime::AtomicNode, String> {
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
