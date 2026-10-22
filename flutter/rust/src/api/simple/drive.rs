//! Drives: create, list, and the active drive.

use super::*;

// ── 3. Drive ───────────────────────────────────────────────────────────────

/// Create a new drive. Returns the drive subject.
pub async fn create_drive(name: String) -> Result<String, String> {
    db()?.create_drive(&name).await.map_err(err)
}

/// Get the active drive subject, if one is set.
#[frb(sync)]
pub fn get_active_drive() -> Option<String> {
    db().ok()?.get_active_drive()
}

/// Set the active drive.
pub async fn set_active_drive(subject: String) -> Result<(), String> {
    db()?.set_active_drive(&subject).map_err(err)
}

/// List drives belonging to the current agent, with names.
pub async fn list_drives() -> Result<Vec<String>, String> {
    Ok(drives_by_use()
        .await?
        .into_iter()
        .map(|d| d.subject)
        .collect())
}

/// The agent's drives in the order every drive list shows: the active one,
/// then the most recently used, then the rest by name.
pub(crate) async fn drives_by_use() -> Result<Vec<atomic_lib::db::DriveInfo>, String> {
    let store = db()?;
    let drives = store.list_drives().await.map_err(err)?;
    Ok(atomic_lib::host::lists::order_drives_by_use(
        store,
        crate::host::recents(),
        drives,
        |d| (d.subject.as_str(), d.name.as_str()),
    ))
}

/// List drives with names. Returns JSON-encoded array of {subject, name,
/// emoji?} (`emoji` is the drive's own icon, absent when it has none).
pub async fn list_drives_with_names() -> Result<String, String> {
    let store = db()?;
    let drives = drives_by_use().await?;
    let mut rows = serde_json::to_value(&drives).map_err(|e| e.to_string())?;
    if let Some(rows) = rows.as_array_mut() {
        for row in rows {
            let Some(subject) = row["subject"].as_str() else {
                continue;
            };
            if let Some(drive) = atomic_lib::host::rows::row_resource(store, &subject.into()).await
            {
                *row = atomic_lib::host::rows::with_icon(store, row.take(), &drive);
            }
        }
    }
    serde_json::to_string(&rows).map_err(|e| e.to_string())
}

// ── Legacy stubs (kept for frb_generated.rs compatibility) ─────────────────
// These will be removed when FRB codegen is regenerated.

// Legacy stubs — removed.

#[frb(sync)]
pub fn set_drive(subject: String) {
    if let Ok(store) = db() {
        let _ = store.set_active_drive(&subject);
    }
}

#[frb(sync)]
pub fn get_drive() -> Option<String> {
    db().ok()?.get_active_drive()
}
