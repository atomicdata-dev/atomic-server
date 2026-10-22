//! Device-to-device sync: the Iroh peer, pairing, known peers.

use super::*;

// ── 7. Peer / Sync (explicit, opt-in) ─────────────────────────────────────

/// Start the Iroh peer node. Returns the NodeID.
/// Call this before any sync operations.
pub async fn start_peer() -> Result<String, String> {
    // One endpoint per process: a second caller (the background start after a
    // resume, a sync button) waits for the first instead of binding another.
    // A failed start is not remembered: the next caller tries again.
    let store = db()?;
    let node_id = peer_search::PEER_SEARCH
        .start_with(|| async {
            tracing::info!("[start_peer] called");
            if let Some(existing) = atomic_lib::sync::peer::get_node_id() {
                tracing::info!("[start_peer] already running: {existing}");
                return Ok(existing.to_string());
            }
            tracing::info!("[start_peer] starting Iroh endpoint...");
            let (node_id, _router) = atomic_lib::sync::peer::start(store.as_ref().clone())
                .await
                .map_err(|e| {
                    tracing::error!("[start_peer] failed: {e}");
                    format!("Failed to start Iroh: {e}")
                })?;
            tracing::info!("[start_peer] OK, NodeID: {node_id}");
            Ok(node_id.to_string())
        })
        .await?;
    // Returns at once when the loop already runs.
    peer_search::spawn(store.as_ref().clone(), node_id.clone());
    Ok(node_id)
}

/// What the search for this account's other devices is doing, as JSON:
/// `{"state": "starting" | "searching" | "no_peers_yet" | "connected" |
/// "failed", "message": "…", "detail": "…" | null, "retry_in_secs"?,
/// "devices"?, "reason"?, "last_checked_ms": …, "attempts": …}`.
#[frb(sync)]
pub fn peer_search_status() -> String {
    let mut status =
        serde_json::to_value(peer_search::PEER_SEARCH.status()).unwrap_or(serde_json::json!({}));
    if let Some(map) = status.as_object_mut() {
        // For the Sync page's "N directory lookups in the last hour", and
        // whether the search is paused (the app in the background).
        map.insert(
            "directory_lookups_last_hour".into(),
            directory::lookups_last_hour().into(),
        );
        map.insert("paused".into(), peer_search::PEER_SEARCH.is_paused().into());
    }
    status.to_string()
}

/// Look for the other devices now (a "Search again" button, a network
/// change, the app coming back), dialling the ones that did not answer
/// recently too.
#[frb(sync)]
pub fn peer_search_again() {
    peer_search::search_again_now();
}

/// Tell the bridge whether the app is in the foreground. In the background
/// the device search and the periodic announce stop (no directory requests;
/// live connections stay); coming back looks for devices at once. Call it
/// from the app lifecycle: resumed → true; paused, hidden, detached → false;
/// inactive (a window that merely lost focus) is not a reason to stop.
#[frb(sync)]
pub fn set_app_foreground(foreground: bool) {
    peer_search::set_foreground(foreground);
}

/// Get this device's Iroh NodeID (if peer is running).
#[frb(sync)]
pub fn get_peer_id() -> Option<String> {
    atomic_lib::sync::peer::get_node_id().map(|s| s.to_string())
}

/// Announce this device for a drive via pkarr relay.
/// Publishes the Iroh NodeID so other devices can discover and connect.
pub async fn peer_announce(drive_subject: String) -> Result<(), String> {
    if let Some(node_id) = atomic_lib::sync::peer::get_node_id() {
        atomic_lib::discovery::publish_node_id(&drive_subject, node_id)
            .await
            .map_err(|e| format!("Discovery publish failed: {e}"))?;
        tracing::info!("[announce] published NodeID {node_id} via pkarr");
    }

    Ok(())
}

/// Sync the active drive with a specific peer by Iroh NodeID.
/// Call `start_peer()` first.
/// What a sync did, in both directions. A count of imports alone cannot tell
/// "sent your workspace" or "already up to date" from "nothing happened" —
/// and those are most of what actually occurs.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PeerSyncReport {
    pub imported: i32,
    pub pushed: i32,
    pub in_sync: bool,
    pub peer_name: Option<String>,
}

pub async fn peer_sync(node_id: String) -> Result<String, String> {
    tracing::info!(
        "[peer_sync] called with node_id={}",
        &node_id[..node_id.len().min(16)]
    );
    let store = db()?;
    let drive = store.get_active_drive().ok_or("No active drive")?;
    tracing::info!(
        "[peer_sync] active drive: {}",
        &drive[..drive.len().min(20)]
    );

    let my_id = atomic_lib::sync::peer::get_node_id();
    tracing::info!(
        "[peer_sync] my NodeID: {:?}",
        my_id.map(|s| &s[..s.len().min(16)])
    );

    if my_id.is_none() {
        return Err("Peer not started. Call start_peer() first.".into());
    }

    tracing::info!("[peer_sync] calling sync_drive_with_peer...");
    let outcome =
        atomic_lib::sync::peer::sync_drive_with_peer_outcome(&node_id, &drive, store.as_ref())
            .await
            .map_err(|e: atomic_lib::AtomicError| {
                tracing::error!("[peer_sync] failed: {e}");
                e.to_string()
            })?;
    tracing::info!(
        "[peer_sync] success: imported {}, pushed {}, in_sync {}",
        outcome.count,
        outcome.pushed,
        outcome.in_sync
    );

    serde_json::to_string(&PeerSyncReport {
        imported: outcome.count as i32,
        pushed: outcome.pushed as i32,
        in_sync: outcome.in_sync,
        peer_name: outcome.peer_name,
    })
    .map_err(|e| e.to_string())
}

/// Discover a peer for a drive via pkarr relay and sync. Call `start_peer()` first.
/// Prefer [`sync_connectivity_now`] — tries known peers first, returns clearer errors.
pub async fn peer_discover_sync(drive_subject: String) -> Result<i32, String> {
    let report_json = sync_connectivity_now().await?;
    let report: SyncConnectivityReport =
        serde_json::from_str(&report_json).map_err(|e| e.to_string())?;
    if report.live_peers == 0 && report.imported == 0 && !report.message.is_empty() {
        return Err(report.message);
    }
    Ok(report.imported)
}

// ── 8. Known peers (persisted in DB) ─────────────────────────────────────

/// Get all known peers as JSON: [{"node_id":"...","name":"..."},...]
#[frb(sync)]
pub fn get_known_peers() -> String {
    let Ok(store) = db() else { return "[]".into() };
    let peers = atomic_lib::sync::peer::get_known_peers(store.as_ref());
    serde_json::to_string(&peers).unwrap_or_else(|_| "[]".into())
}

/// Add a peer with optional name.
#[frb(sync)]
pub fn add_known_peer(node_id: String, name: String) {
    let Ok(store) = db() else { return };
    atomic_lib::sync::peer::add_known_peer(store.as_ref(), &node_id, &name);
}

/// Remove a peer by NodeID.
#[frb(sync)]
pub fn remove_known_peer(node_id: String) {
    let Ok(store) = db() else { return };
    atomic_lib::sync::peer::remove_known_peer(store.as_ref(), &node_id);
}

#[frb(sync)]
pub fn live_peer_count() -> i32 {
    atomic_lib::sync::peer::live_peer_count() as i32
}

#[frb(sync)]
pub fn live_peer_ids() -> Vec<String> {
    atomic_lib::sync::peer::live_peer_ids()
}

pub async fn wait_for_peer_count_change(current: i32) -> i32 {
    atomic_lib::sync::peer::wait_for_peer_count_change(current as usize).await as i32
}

#[frb(sync)]
pub fn get_known_peers_json() -> String {
    let Ok(store) = db() else { return "[]".into() };
    let peers = atomic_lib::sync::peer::get_known_peers(store.as_ref());
    serde_json::to_string(&peers).unwrap_or_else(|_| "[]".into())
}

/// Devices connected to us right now that are not paired, as JSON
/// `[{"node_id":"...","name":"..."}]` (name empty when unknown). Display only.
#[frb(sync)]
pub fn live_unsaved_peers_json() -> String {
    let Ok(store) = db() else { return "[]".into() };
    let list: Vec<serde_json::Value> = atomic_lib::sync::peer::live_unsaved_peers(store.as_ref())
        .into_iter()
        .map(|(id, name)| serde_json::json!({"node_id": id, "name": name.unwrap_or_default()}))
        .collect();
    serde_json::to_string(&list).unwrap_or_else(|_| "[]".into())
}
