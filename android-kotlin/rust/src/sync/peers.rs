//! Iroh peers and the glue around them, copied from
//! `flutter/rust/src/api/simple.rs` (that crate cannot be a dependency):
//! pushing a local write, starting the endpoint, announcing on pkarr, syncing
//! with a peer, finding the drives of the person that this device lacks.

use super::ws;
use crate::state::db;

/// Hand a commit this device just signed to whoever can take it: live peers
/// get the state at once, the server gets the queued commit, and a paired
/// device takes it when there is no server in reach.
pub(crate) async fn push_local_write(
    response: &atomic_lib::commit::CommitResponse,
    store: &atomic_lib::Db,
) {
    if let Some(bytes) = &response.commit.loro_update {
        if !bytes.is_empty() {
            let subject_key = response.commit.subject.pure_id();
            atomic_lib::sync::peer::broadcast_live_update(&subject_key, bytes);
        }
    }
    let ws_ok = ws::drain_outbox(store).await;
    // No hub in reach: a paired peer takes the signed commit instead
    // (planning/serverless-p2p.md P4). The raw broadcast above already gave
    // every live peer the state; this is what makes it attributable.
    if !ws_ok {
        atomic_lib::sync::peer::drain_outbox_to_any_live_peer(store).await;
    }
    // Hub unreachable or no WS session: bulk Iroh reconcile. When live peers exist
    // we already broadcast above; still bulk-nudge if P2P-only (no hub).
    if !ws_ok || atomic_lib::sync::peer::live_peer_count() == 0 {
        nudge_peers_after_local_change(store).await;
    }
}

pub(crate) fn is_unreachable_hub_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("localhost") || lower.contains("127.0.0.1")
}

/// Start Iroh (live sync + auto-connect loop) and announce on pkarr.
pub(crate) async fn ensure_sync_connectivity(store: &atomic_lib::Db) -> Result<(), String> {
    let Some(drive) = store.get_active_drive() else {
        return Ok(());
    };
    let _ = start_peer().await?;
    let _ = peer_announce(drive).await;
    Ok(())
}

static LAST_PEER_NUDGE_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// When WS push failed, run a debounced bulk sync with known peers / pkarr discover.
async fn nudge_peers_after_local_change(store: &atomic_lib::Db) {
    // The bridge unit tests assert local cache/store invariants. Standing up a
    // real Iroh endpoint for them would make every save network-dependent and
    // slow for no added coverage — the transport itself is covered by
    // `atomic_lib`'s two-node `sync::iroh_e2e` suite.
    #[cfg(test)]
    {
        let _ = store;
        return;
    }
    #[cfg(not(test))]
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = LAST_PEER_NUDGE_MS.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < 2_000 {
            return;
        }
        LAST_PEER_NUDGE_MS.store(now, std::sync::atomic::Ordering::Relaxed);

        if ensure_sync_connectivity(store).await.is_err() {
            return;
        }
        if let Err(e) = try_auto_peer_sync(store).await {
            tracing::debug!("[save_and_push] peer nudge failed: {e}");
        }
    }
}


const PEER_SYNC_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(22);
const PKARR_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
/// How many of the NodeIDs a drive's pkarr record names are dialled at once.
const PKARR_PEERS_TO_TRY: usize = 4;

fn short_id(node_id: &str) -> &str {
    &node_id[..node_id.len().min(12)]
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SyncConnectivityReport {
    pub imported: i32,
    pub live_peers: u32,
    pub message: String,
    /// The server the drive was found on through pkarr, when it was.
    #[serde(default)]
    pub server: Option<String>,
}

/// Start Iroh, sync known peers (then pkarr). Returns JSON [`SyncConnectivityReport`].
pub async fn sync_connectivity_now() -> Result<SyncConnectivityReport, String> {
    let store = db()?;
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        sync_connectivity_inner(store.as_ref()),
    )
    .await
    .map_err(|_| {
        "Sync timed out. Check Wi‑Fi, keep the other device open, or pair with QR.".to_string()
    })??;
    Ok(report)
}

async fn sync_connectivity_inner(store: &atomic_lib::Db) -> Result<SyncConnectivityReport, String> {
    ensure_sync_connectivity(store).await?;
    let drive = store.get_active_drive().ok_or("No active drive")?;

    let mut imported: i32 = 0;
    let mut errors: Vec<String> = Vec::new();

    // Known peers first (fast path after QR pairing)
    let peers_json = get_known_peers();
    let peers: Vec<serde_json::Value> = serde_json::from_str(&peers_json).unwrap_or_default();
    for peer in &peers {
        let Some(node_id) = peer.get("node_id").and_then(|v| v.as_str()) else {
            continue;
        };
        if node_id.is_empty() {
            continue;
        }
        match tokio::time::timeout(
            PEER_SYNC_ATTEMPT_TIMEOUT,
            atomic_lib::sync::peer::sync_drive_with_peer_if_needed(node_id, &drive, store),
        )
        .await
        {
            Ok(Ok(count)) => {
                imported += count as i32;
                tracing::info!("[sync_now] peer {}: {count} resources", node_id);
            }
            Ok(Err(e)) => {
                tracing::warn!("[sync_now] peer {} failed: {e}", node_id);
                errors.push(format!("{}: {e}", &node_id[..node_id.len().min(12)]));
            }
            Err(_) => {
                errors.push(format!(
                    "{}: timed out after {}s",
                    &node_id[..node_id.len().min(12)],
                    PEER_SYNC_ATTEMPT_TIMEOUT.as_secs()
                ));
            }
        }
    }

    // pkarr discover, also when some peer is live already: a live server
    // used to stop this lookup, and then the account's other devices were
    // never dialled. The record also names replicas that are gone (an
    // uninstalled app, an old laptop), so several are dialled at once and
    // the first that answers wins; live ones are skipped
    // (`sync_drive_with_peer_if_needed`). As in the Flutter bridge, the
    // active and the private drive are both looked up.
    {
        match tokio::time::timeout(PKARR_RESOLVE_TIMEOUT, async {
            let my_node_id = atomic_lib::sync::peer::get_node_id()
                .ok_or("Peer not started")?
                .to_string();
            // Only other devices: a drive on this device alone names none,
            // which is nothing to report (it toasted "No peer on network:
            // Found 1 NodeID(s) but all are ours (…)" on every start).
            let mut drives = vec![drive.clone()];
            if let Ok(private) = store.private_drive_subject() {
                if !drives.contains(&private) {
                    drives.push(private);
                }
            }
            let mut others = Vec::new();
            for search in drives {
                for id in atomic_lib::discovery::resolve_other_node_ids(&search, Some(&my_node_id)).await? {
                    if !others.contains(&id) {
                        others.push(id);
                    }
                }
            }
            Ok::<_, atomic_lib::AtomicError>(others)
        })
        .await
        {
            Ok(Ok(node_ids)) if node_ids.is_empty() => {}
            Ok(Ok(node_ids)) => {
                let tried = node_ids.len().min(PKARR_PEERS_TO_TRY);
                let drive = drive.as_str();
                let attempts = node_ids.iter().take(PKARR_PEERS_TO_TRY).map(|node_id| {
                    Box::pin(async move {
                        tokio::time::timeout(
                            PEER_SYNC_ATTEMPT_TIMEOUT,
                            atomic_lib::sync::peer::sync_drive_with_peer_if_needed(
                                node_id, drive, store,
                            ),
                        )
                        .await
                        .map_err(|_| format!("{}: timed out", short_id(node_id)))?
                        .map_err(|e| format!("{}: {e}", short_id(node_id)))
                    })
                });
                match futures::future::select_ok(attempts).await {
                    Ok((count, _)) => imported += count as i32,
                    Err(last) => errors.push(format!(
                        "None of the {tried} devices that announced your drive answered ({last})"
                    )),
                }
            }
            Ok(Err(e)) => errors.push(format!("Could not look for devices: {e}")),
            Err(_) => errors.push("Could not look for devices: the directory (pkarr) timed out".into()),
        }
    }

    if crate::session::drive_exists(store).await {
        tokio::spawn(follow_listed_drives(drive.clone()));
    }

    let live = atomic_lib::sync::peer::live_peer_count() as u32;
    let live_ids: std::collections::HashSet<String> = atomic_lib::sync::peer::live_peer_ids()
        .into_iter()
        .collect();
    let live_names: Vec<String> = peers
        .iter()
        .filter_map(|p| {
            let id = p.get("node_id")?.as_str()?;
            if live_ids.contains(&atomic_lib::sync::peer::normalize_node_id(id)) {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name.is_empty() {
                    Some(format!("{}…", &id[..id.len().min(8)]))
                } else {
                    Some(name.to_string())
                }
            } else {
                None
            }
        })
        .collect();
    let message = if live > 0 {
        if live_names.is_empty() {
            format!(
                "Connected to {live} device{}",
                if live == 1 { "" } else { "s" }
            )
        } else {
            format!("Connected to {}", live_names.join(", "))
        }
    } else if imported > 0 {
        "Synced data but no live connection — try again".to_string()
    } else if errors.is_empty() {
        "No other device found yet. Open the app on another device signed in with this account, or pair with QR.".to_string()
    } else {
        errors.join(" · ")
    };

    Ok(SyncConnectivityReport {
        imported,
        live_peers: live,
        message,
        server: None,
    })
}


/// Node ids of the live peers, then the known (paired) ones, minus `skip`.
fn peer_ids_to_try(skip: &std::collections::HashSet<String>) -> Vec<String> {
    let mut ids = atomic_lib::sync::peer::live_peer_ids();
    let known: Vec<serde_json::Value> =
        serde_json::from_str(&get_known_peers()).unwrap_or_default();
    for peer in known {
        if let Some(id) = peer.get("node_id").and_then(|v| v.as_str()) {
            if !id.is_empty() && !ids.iter().any(|i| i == id) {
                ids.push(id.to_string());
            }
        }
    }
    ids.retain(|id| !skip.contains(id));
    ids
}

static OTHER_DRIVES_RUNNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The drives the personal drive lists that this device does not hold yet:
/// fetched from the server the session is on, or else from a live paired
/// device. Each drive is tried once per run and a drive nobody here has is
/// skipped, not an error. One run at a time, in the background.
pub(crate) async fn follow_listed_drives(home: String) {
    use std::sync::atomic::Ordering;
    if OTHER_DRIVES_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let Ok(store) = db() else {
        OTHER_DRIVES_RUNNING.store(false, Ordering::SeqCst);
        return;
    };
    let drives = match store.list_drives().await {
        Ok(drives) => drives,
        Err(e) => {
            tracing::warn!("[home] cannot list drives: {e}");
            OTHER_DRIVES_RUNNING.store(false, Ordering::SeqCst);
            return;
        }
    };
    let key = |s: &str| {
        s.trim_start_matches("did:ad:")
            .trim_start_matches("atomic:")
            .split('?')
            .next()
            .unwrap_or("")
            .to_string()
    };
    let mut seen = std::collections::HashSet::new();
    seen.insert(key(&home));
    let wanted: Vec<String> = drives
        .into_iter()
        .filter(|d| seen.insert(key(&d.subject)) && !store.has_resource_locally(&d.subject))
        .map(|d| d.subject)
        .collect();
    tracing::info!("[home] fetching {} other drives", wanted.len());
    let dead_peers = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut followed = 0;
    // A few at a time: each one is a round trip or a dial.
    for chunk in wanted.chunks(OTHER_DRIVES_PARALLEL) {
        let mut tasks = tokio::task::JoinSet::new();
        for drive in chunk {
            tasks.spawn(fetch_other_drive(drive.clone(), dead_peers.clone()));
        }
        while let Some(done) = tasks.join_next().await {
            if matches!(done, Ok(true)) {
                followed += 1;
            }
        }
    }
    tracing::info!(
        "[home] other drives: {followed} followed, {} not available here",
        wanted.len() - followed
    );
    OTHER_DRIVES_RUNNING.store(false, Ordering::SeqCst);
}

const OTHER_DRIVES_PARALLEL: usize = 4;

/// One drive of the person that this device lacks, tried where it is most
/// likely to be: the server the session is connected to, then the paired
/// devices, then whatever pkarr says hosts this drive (its announced Iroh
/// nodes). Whether it arrived is whether it is stored here afterwards.
async fn fetch_other_drive(
    drive: String,
    dead_peers: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
) -> bool {
    let Ok(store) = db() else { return false };
    let store = store.as_ref();

    // 1. The connected server.
    match ws::follow_drive(&drive).await {
        Ok(()) if store.has_resource_locally(&drive) => return true,
        Ok(()) => tracing::info!("[home] {drive}: the server sent nothing"),
        Err(e) => tracing::info!("[home] {drive}: not on the connected server: {e}"),
    }

    // 2. Paired devices, then 3. pkarr's nodes for this drive.
    let mut candidates = peer_ids_to_try(&dead_peers.lock().map(|d| d.clone()).unwrap_or_default());
    let own = atomic_lib::sync::peer::get_node_id().map(|n| n.to_string());
    match tokio::time::timeout(
        PKARR_RESOLVE_TIMEOUT,
        atomic_lib::discovery::resolve_drive_record(&drive),
    )
    .await
    {
        Ok(Ok(record)) => {
            for node in record.node_ids {
                if own.as_deref() != Some(node.as_str()) && !candidates.contains(&node) {
                    candidates.push(node);
                }
            }
        }
        Ok(Err(e)) => tracing::info!("[home] {drive}: pkarr: {e}"),
        Err(_) => tracing::info!("[home] {drive}: pkarr timed out"),
    }
    for node_id in candidates.into_iter().take(6) {
        let attempt = tokio::time::timeout(
            PEER_SYNC_ATTEMPT_TIMEOUT,
            atomic_lib::sync::peer::sync_drive_with_peer_if_needed(&node_id, &drive, store),
        )
        .await;
        match attempt {
            Ok(Ok(_)) if store.has_resource_locally(&drive) => return true,
            Ok(Ok(_)) => {}
            // Did not answer: not dialled again for the next drive.
            Ok(Err(e)) if e.to_string().contains("timed out") => {
                if let Ok(mut dead) = dead_peers.lock() {
                    dead.insert(node_id);
                }
            }
            Ok(Err(e)) => tracing::info!(
                "[home] {drive} at {}: {e}",
                &node_id[..node_id.len().min(12)]
            ),
            Err(_) => {
                if let Ok(mut dead) = dead_peers.lock() {
                    dead.insert(node_id);
                }
            }
        }
    }
    false
}

/// Iroh: known peers, then pkarr discover. Returns true if any sync ran.
async fn try_auto_peer_sync(store: &atomic_lib::Db) -> Result<bool, String> {
    let report = sync_connectivity_inner(store).await?;
    Ok(report.imported > 0 || report.live_peers > 0)
}


/// Start the Iroh peer node. Returns the NodeID.
/// Call this before any sync operations.
pub async fn start_peer() -> Result<String, String> {
    // One endpoint per process: a second caller (the background start after a
    // resume, a sync button) waits for the first instead of binding another.
    static STARTING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _starting = STARTING.lock().await;
    tracing::info!("[start_peer] called");
    let store = db()?;
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
}

/// Get this device's Iroh NodeID (if peer is running).
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

pub async fn peer_sync(node_id: &str) -> Result<PeerSyncReport, String> {
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
        atomic_lib::sync::peer::sync_drive_with_peer_outcome(node_id, &drive, store.as_ref())
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

    Ok(PeerSyncReport {
        imported: outcome.count as i32,
        pushed: outcome.pushed as i32,
        in_sync: outcome.in_sync,
        peer_name: outcome.peer_name,
    })
}


/// Get all known peers as JSON: [{"node_id":"...","name":"..."},...]
pub fn get_known_peers() -> String {
    let Ok(store) = db() else { return "[]".into() };
    let peers = atomic_lib::sync::peer::get_known_peers(store.as_ref());
    serde_json::to_string(&peers).unwrap_or_else(|_| "[]".into())
}

/// Add a peer with optional name.
pub fn add_known_peer(node_id: String, name: String) {
    let Ok(store) = db() else { return };
    atomic_lib::sync::peer::add_known_peer(store.as_ref(), &node_id, &name);
}

/// Remove a peer by NodeID.
pub fn remove_known_peer(node_id: String) {
    let Ok(store) = db() else { return };
    atomic_lib::sync::peer::remove_known_peer(store.as_ref(), &node_id);
}

