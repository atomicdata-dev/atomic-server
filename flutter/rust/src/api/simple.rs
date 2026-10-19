use atomic_lib::Storelike;
use flutter_rust_bridge::frb;

#[cfg(test)]
mod peer_tests;
pub(crate) mod state;
#[cfg(test)]
pub(crate) mod tests;
pub mod types;
pub mod ws_sync;

pub use atomic_lib::{Commit, Db};

use state::{db, err, node, set_db};
pub use types::{AgentInfo, SetupResult, VersionMetadata};

/// Save resource locally, record it in the durable outbox, and drain the
/// outbox over WS when a session is open. Offline edits wait on disk.
async fn save_and_push(
    resource: &mut atomic_lib::Resource,
    store: &atomic_lib::Db,
) -> Result<(), String> {
    let response = node()?.save_locally(resource).await.map_err(err)?;
    push_local_write(&response, store).await;
    Ok(())
}

/// Hand a commit this device just signed to whoever can take it: live peers
/// get the state at once, the server gets the queued commit, and a paired
/// device takes it when there is no server in reach.
/// Apply a commit this device signed itself and queue it for the server, like
/// `save_locally` does for an edit.
pub(crate) async fn node_apply_local(
    commit: atomic_lib::Commit,
    opts: &atomic_lib::commit::CommitOpts,
) -> Result<atomic_lib::commit::CommitResponse, String> {
    node()?.apply_local_commit(commit, opts).await.map_err(err)
}

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
    let ws_ok = ws_sync::drain_outbox(store).await;
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

fn is_unreachable_hub_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("localhost") || lower.contains("127.0.0.1")
}

/// Start Iroh (live sync + auto-connect loop) and announce on pkarr.
async fn ensure_sync_connectivity(store: &atomic_lib::Db) -> Result<(), String> {
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

/// Local-first Atomic Data SDK for Flutter.
///
/// API groups:
///   1. Database  — open_db()
///   2. Agent     — setup(), load_agent(), get_active_agent(), clear_agent()
///   3. Drive     — create_drive(), list_drives(), get_active_drive(), set_active_drive()
///   4. Resource  — create_resource(), set_property(), get_property()
///   5. History   — warm_resource_history(), get_resource_history()
///   6. Peer      — start_peer(), get_peer_id(), peer_announce(), peer_sync(), peer_discover_sync()
///
/// Networking (group 6) is explicit and opt-in. Nothing in groups 1-5 touches the network.

// ── 1. Database ────────────────────────────────────────────────────────────

/// Open a local database. Call once on app start.
pub async fn open_db(path: String) -> Result<(), String> {
    // Set up log filtering — suppress noisy TLS/mDNS/iroh internals
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("atomic").unwrap())
            .with(tracing_subscriber::filter::EnvFilter::new(
                "info,swarm_discovery=error",
            ))
            .try_init();
    }
    #[cfg(not(target_arch = "wasm32"))]
    let store = {
        let base_path = std::path::Path::new(&path);
        let db_path = base_path.join("atomic.redb");
        let uploads_path = base_path.join("uploads");
        match atomic_lib::Db::init_redb_file(base_path, None, &uploads_path).await {
            Ok(s) => s,
            Err(e) if is_corruption_error(&e) => {
                tracing::warn!("DB corrupted, deleting and recreating: {e}");
                let _ = std::fs::remove_file(&db_path);
                atomic_lib::Db::init_redb_file(base_path, None, &uploads_path)
                    .await
                    .map_err(err)?
            }
            Err(e) => return Err(err(e)),
        }
    };

    #[cfg(target_arch = "wasm32")]
    let store = atomic_lib::Db::init_redb_opfs(None, "atomic.redb")
        .await
        .map_err(err)?;

    set_db(store);
    #[cfg(not(target_arch = "wasm32"))]
    {
        catch_up_search_index(db()?.clone()).await;
        crate::host::start_recents(std::path::Path::new(&path), db()?.clone());
    }
    Ok(())
}

/// Make sure every stored resource is searchable. An index written by an older
/// build can lack resources that arrived by sync, and nothing else notices: the
/// library only rebuilds an empty index. Rebuilds once per install (a marker
/// records it, so later starts cost one key read), then drains resources filed
/// for deferred indexing.
#[cfg(not(target_arch = "wasm32"))]
async fn catch_up_search_index(store: std::sync::Arc<atomic_lib::Db>) {
    let rebuilder = store.clone();
    let rebuilt = tokio::task::spawn_blocking(move || {
        atomic_lib::search::rebuild_search_index_once(&rebuilder, "flutter-1")
    })
    .await;
    match rebuilt {
        Ok(Ok(true)) => tracing::info!("search index rebuilt"),
        Ok(Ok(false)) => {}
        Ok(Err(e)) => tracing::warn!("search index rebuild failed: {e}"),
        Err(e) => tracing::warn!("search index rebuild panicked: {e}"),
    }
    while let Ok(done) = atomic_lib::search::index_pending(&store, 500).await {
        if done == 0 {
            break;
        }
    }
}

/// Whether an open error means the file itself is damaged. redb reports that
/// as `StorageError::Corrupted` ("DB corrupted: …"), and atomic_lib's own
/// deserialisation failures say the DB is "possibly corrupt". Anything else —
/// the file locked by another process, a permission problem, a redb version
/// that needs an upgrade — is not a reason to throw the user's data away.
#[cfg(not(target_arch = "wasm32"))]
fn is_corruption_error(e: &atomic_lib::errors::AtomicError) -> bool {
    e.to_string().to_ascii_lowercase().contains("corrupt")
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();

    // Initialize tracing → logcat on Android, stderr elsewhere
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("atomic").ok())
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .try_init();
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .try_init();
    }
}

// ── 2. Agent ───────────────────────────────────────────────────────────────

/// Create an agent and a personal drive in one call. Pure local — no networking.
/// Call `start_peer()` + `peer_announce()` afterwards if you want to be discoverable.
pub async fn setup(name: String) -> Result<SetupResult, String> {
    let store = db()?;
    let (agent, drive_subject) = store.setup(&name).await.map_err(err)?;
    let secret = agent.build_secret().map_err(err)?;
    Ok(SetupResult {
        agent_secret: secret,
        agent_subject: agent.subject.to_string(),
        drive_subject,
    })
}

/// Load an existing agent from a secret. Pure local — no networking.
/// If the secret contains a drive DID, it becomes the active drive.
///
/// Returns "needs_sync" if the drive doesn't exist locally (needs QR pairing).
/// Returns the agent subject if everything is available.
pub async fn load_agent(secret: String) -> Result<String, String> {
    let result = db()?.load_agent_from_secret(&secret).await.map_err(err)?;
    if result.drive_needs_sync {
        Ok("needs_sync".to_string())
    } else {
        Ok(result.agent.subject.to_string())
    }
}

/// Get the currently active agent, if any.
pub async fn get_active_agent() -> Result<Option<AgentInfo>, String> {
    let store = db()?;
    match store.get_default_agent() {
        Ok(agent) => {
            let secret = agent.build_secret().map_err(err)?;
            Ok(Some(AgentInfo {
                secret,
                subject: agent.subject.to_string(),
                public_key: agent.public_key.clone(),
                name: agent.name.clone(),
            }))
        }
        Err(_) => Ok(None),
    }
}

/// Clear the active agent.
pub fn clear_agent() -> Result<(), String> {
    if let Ok(store) = db() {
        store.clear_default_agent();
    }
    Ok(())
}

#[frb(sync)]
pub fn create_agent(name: String) -> Result<AgentInfo, String> {
    let agent = atomic_lib::agents::Agent::new(Some(&name)).map_err(err)?;
    let secret = agent.build_secret().map_err(err)?;
    if let Ok(store) = db() {
        store.set_default_agent(agent.clone());
    }
    Ok(AgentInfo {
        secret,
        subject: agent.subject.to_string(),
        public_key: agent.public_key.clone(),
        name: agent.name.clone(),
    })
}

#[frb(sync)]
pub fn agent_from_secret(secret: String) -> Result<AgentInfo, String> {
    let agent = atomic_lib::agents::Agent::from_secret(&secret).map_err(err)?;
    Ok(AgentInfo {
        secret,
        subject: agent.subject.to_string(),
        public_key: agent.public_key.clone(),
        name: agent.name.clone(),
    })
}

/// The profile of this device's agent as JSON `{subject, name, description,
/// emoji?, imageUrl?}`: what the store holds, else what the connected server
/// has (`atomic_lib::host::own_profile`).
pub async fn get_own_profile() -> Result<String, String> {
    let profile = atomic_lib::host::own_profile::own_profile(db()?, &crate::host::profiles())
        .await
        .map_err(err)?;
    crate::host::to_json(&profile)
}

/// Save this device's agent's profile: a commit by the agent on its own
/// resource, stored here and synced like any other edit. An empty
/// `description` removes it; `icon` is the subject of a File for the picture
/// (empty removes it, `None` leaves it as it is).
pub async fn set_agent_profile(
    name: String,
    description: String,
    icon: Option<String>,
) -> Result<(), String> {
    atomic_lib::host::own_profile::set_own_profile(
        &node()?,
        crate::host::pusher().as_ref(),
        &name,
        &description,
        icon.as_deref(),
    )
    .await
    .map_err(err)
}

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
    let drives = db()?.list_drives().await.map_err(err)?;
    Ok(drives.iter().map(|d| d.subject.clone()).collect())
}

/// List drives with names. Returns JSON-encoded array of {subject, name,
/// emoji?} (`emoji` is the drive's own icon, absent when it has none).
pub async fn list_drives_with_names() -> Result<String, String> {
    let store = db()?;
    let drives = store.list_drives().await.map_err(err)?;
    let mut rows = serde_json::to_value(&drives).map_err(|e| e.to_string())?;
    if let Some(rows) = rows.as_array_mut() {
        for row in rows {
            let Some(subject) = row["subject"].as_str() else {
                continue;
            };
            if let Some(drive) = atomic_lib::host::rows::row_resource(store, &subject.into()).await
            {
                *row = atomic_lib::host::rows::with_emoji(row.take(), &drive);
            }
        }
    }
    serde_json::to_string(&rows).map_err(|e| e.to_string())
}

// ── 4. Resource ────────────────────────────────────────────────────────────

pub async fn create_resource(parent_subject: String, name: String) -> Result<String, String> {
    db()?
        .create_resource(atomic_lib::urls::CLASS, &parent_subject, &name, None)
        .await
        .map_err(err)
}

pub async fn set_property(subject: String, property: String, value: String) -> Result<(), String> {
    let store = db()?;
    let mut resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    resource.set_unsafe(property, atomic_lib::Value::String(value));
    save_and_push(&mut resource, store.as_ref()).await
}

pub async fn get_property(subject: String, property: String) -> Result<String, String> {
    let store = db()?;
    let resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    Ok(resource
        .get(&property)
        .map(|v| v.to_string())
        .unwrap_or_default())
}

// ── 6. History ─────────────────────────────────────────────────────────────

/// Load versioned state for history operations.
pub async fn warm_resource_history(subject: String) -> Result<(), String> {
    let store = db()?;
    let mut resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    resource.warm_history().map_err(|e| e.to_string())
}

/// Get the edit history of a resource.
pub async fn get_resource_history(subject: String) -> Result<Vec<VersionMetadata>, String> {
    let store = db()?;
    let mut resource = store
        .get_resource(&subject.as_str().into())
        .await
        .map_err(err)?;
    resource.warm_history().map_err(|e| e.to_string())?;
    Ok(resource
        .get_history()
        .into_iter()
        .map(|m| VersionMetadata {
            id: m.id.bytes().to_vec(),
            timestamp: m.timestamp,
            peer_id: m.peer_id,
            lamport: m.lamport,
            len: m.len as i32,
            message: m.message,
        })
        .collect())
}

// ── 6b. WebSocket sync (server-backed, same as browser) ─────────────────────

/// Open a WebSocket sync session to an Atomic Server. Authenticates, SUBs the active drive,
/// and applies incoming UPDATE / QUERY_UPDATE / COMMIT frames to the local DB.
pub async fn open_ws_sync(server_url: String) -> Result<(), String> {
    ws_sync::open_ws_sync(&server_url).await
}

/// Close the WebSocket sync session.
pub async fn close_ws_sync() -> Result<(), String> {
    ws_sync::close_ws_sync().await;
    Ok(())
}

/// Push the active drive to a server, so it is hosted there as well as here.
///
/// [`open_ws_sync`] fetches a drive this device lacks, and pushes commits made
/// from now on — but a drive made here before any server was connected has
/// never been offered to one. This offers it: the same replication
/// `/replicate-drive` runs, signed as this device's agent, which is the drive's
/// owner and so may write it at the remote.
///
/// This is the only way a workspace made on this device reaches a browser: a
/// browser is not a peer and cannot be paired with — it reads from a server.
///
/// Returns the number of resources pushed.
pub async fn sync_drive_to_server(server_url: String) -> Result<i32, String> {
    use atomic_lib::sync::replicate::{replicate_drive_to_remote, ReplicateAuth};

    let store = db()?;
    let drive = store.get_active_drive().ok_or("No active drive")?;
    let agent = store.get_default_agent().map_err(err)?;
    let ws_url = ws_sync::server_origin_to_ws_url(&server_url)?;

    tracing::info!(
        "[sync_drive_to_server] pushing {} to {ws_url}",
        &drive[..drive.len().min(20)]
    );

    let outcome = replicate_drive_to_remote(
        store.as_ref(),
        &drive,
        &ws_url,
        // Export as the owner: the drive's own agent, whose key this device
        // holds. Anything they can read is theirs to take with them.
        &atomic_lib::agents::ForAgent::AgentSubject(agent.subject.clone()),
        ReplicateAuth::Agent(Box::new(agent)),
    )
    .await
    .map_err(|e: atomic_lib::AtomicError| {
        tracing::error!("[sync_drive_to_server] failed: {e}");
        e.to_string()
    })?;

    // `in_sync` is the receiver's drive hash matching ours on a second probe.
    // Without it the push was acked but dropped — silently, for lack of write
    // rights — and reporting a count would be reporting a lie.
    if !outcome.in_sync {
        return Err(
            "The server accepted the workspace but does not have it. It may not \
             allow this account to write there."
                .into(),
        );
    }

    tracing::info!(
        "[sync_drive_to_server] pushed {} resources, {} blobs",
        outcome.pushed,
        outcome.blobs_served
    );

    Ok(outcome.pushed as i32)
}

/// Restore agent + drive on app start. Opens WS sync, fetches drive from server when missing,
/// then falls back to Iroh discover / known peers (previous "auto pair on boot" behaviour).
/// Returns `"ok"` or `"needs_sync"`.
pub async fn resume_app_session(
    server_url: String,
    secret: String,
    drive_hint: Option<String>,
) -> Result<String, String> {
    let store = db()?;
    store.load_agent_from_secret(&secret).await.map_err(err)?;

    match drive_hint.filter(|s| !s.is_empty()) {
        Some(drive) => {
            let _ = store.set_active_drive(&drive);
        }
        // A secret holds an identity and nothing else — but the one drive that
        // follows from the key alone is the agent's personal drive. Work on
        // that, not on whatever the previous agent left active; the sync
        // screen then finds where it is hosted.
        None => {
            if let Ok(home) = store.private_drive_subject() {
                let _ = store.set_active_drive(&home);
            }
        }
    }

    let origin = server_url.trim();
    if !origin.is_empty() && !is_unreachable_hub_url(origin) {
        if let Err(e) = ws_sync::open_ws_sync(origin).await {
            tracing::warn!("[resume] WS sync failed: {e}");
        }
    } else if !origin.is_empty() {
        tracing::info!(
            "[resume] skipping WS hub at {origin} (localhost is not reachable from devices)"
        );
    }

    // Fast on purpose. If a reachable server already has the drive, the WS
    // sync above brought it — bring the Iroh endpoint up for live sync and
    // answer "ok". If it does not, answer "needs_sync" immediately.
    //
    // What it must NOT do is run Iroh discovery to look for the drive: pkarr
    // resolve and a peer-sync attempt time out in tens of seconds, and a fresh
    // sign-in — about to pair by QR — can succeed at neither yet. Blocking the
    // sign-in on that is the long wait before "sync your drive" appears, and it
    // was run twice: here, and again when that screen calls back in. Discovery
    // now lives only on the needs-sync screen (`sync_connectivity_now`), where
    // there is a loading state for it, not a spinning button.
    if drive_resource_exists(store.as_ref()).await {
        let _ = ensure_sync_connectivity(store.as_ref()).await;
        if let Some(home) = store.get_active_drive() {
            tokio::spawn(follow_listed_drives(home));
        }

        return Ok("ok".into());
    }

    Ok("needs_sync".into())
}

async fn drive_resource_exists(store: &atomic_lib::Db) -> bool {
    let Some(drive) = store.get_active_drive() else {
        return false;
    };
    let subject = atomic_lib::Subject::from_raw(&drive, store.get_base_domain().as_deref());
    store.get_resource(&subject).await.is_ok()
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
pub async fn sync_connectivity_now() -> Result<String, String> {
    let store = db()?;
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        sync_connectivity_inner(store.as_ref()),
    )
    .await
    .map_err(|_| {
        "Sync timed out. Check Wi‑Fi, keep the other device open, or pair with QR.".to_string()
    })??;
    serde_json::to_string(&report).map_err(|e| e.to_string())
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

    // pkarr discover when still not live to any peer. The record also names
    // replicas that are gone (an uninstalled app, an old laptop), so several
    // are dialled at once and the first that answers wins.
    if atomic_lib::sync::peer::live_peer_count() == 0 {
        match tokio::time::timeout(PKARR_RESOLVE_TIMEOUT, async {
            let my_node_id = atomic_lib::sync::peer::get_node_id()
                .ok_or("Peer not started")?
                .to_string();
            atomic_lib::discovery::resolve_node_ids_filtered(&drive, Some(&my_node_id)).await
        })
        .await
        {
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
            Ok(Err(e)) => errors.push(format!("No peer on network: {e}")),
            Err(_) => errors.push("Peer lookup timed out (pkarr)".into()),
        }
    }

    if drive_resource_exists(store).await {
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
        "No peers online. Open the other device or pair with QR.".to_string()
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

/// The https origins the drive's pkarr record names. The record is public and
/// anyone may add to it, so none of them is trusted yet: the host fetches each
/// one's `/genesis` and asks [`genesis_answer_verifies`]. (The fetch is the
/// host's, not Rust's: the platform's own HTTPS stack is the one that is known
/// to trust the device's certificates.)
pub async fn resolve_drive_origins(drive: String) -> Result<Vec<String>, String> {
    let record = tokio::time::timeout(
        PKARR_RESOLVE_TIMEOUT,
        atomic_lib::discovery::resolve_drive_record(&drive),
    )
    .await
    .map_err(|_| "Server lookup timed out (pkarr)".to_string())?
    .map_err(err)?;
    tracing::info!(
        "[home] {drive} names {} origins {:?}",
        record.http_origins.len(),
        record.http_origins
    );
    Ok(record.http_origins)
}

/// Whether `body`, the answer of `GET /genesis?subject=<drive>`, is the drive's
/// own genesis certificate and verifies against the DID.
#[frb(sync)]
pub fn genesis_answer_verifies(body: String, drive: String) -> bool {
    atomic_lib::discovery::genesis_body_verifies(&body, &drive)
}

/// Connect to the server that hosts the active drive: fetches the drive and
/// follows its commits over WS, then, in the background, follows the drives the
/// personal drive lists. Call it only for an origin whose genesis verified.
pub async fn connect_home_server(origin: String) -> Result<(), String> {
    let store = db()?;
    ws_sync::open_ws_sync(&origin).await?;
    let Some(drive) = store.get_active_drive() else {
        return Err("No active drive".into());
    };
    if !drive_resource_exists(store.as_ref()).await {
        return Err(format!("{origin} did not send the drive"));
    }
    tokio::spawn(follow_listed_drives(drive));
    Ok(())
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
async fn follow_listed_drives(home: String) {
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
    match ws_sync::follow_drive(&drive).await {
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

/// Block until a local DB event arrives. Returns JSON, or None on timeout.
pub async fn poll_db_event(timeout_ms: u32) -> Result<Option<String>, String> {
    let store = db()?;
    let mut rx = store.subscribe_events();
    let timeout = std::time::Duration::from_millis(timeout_ms as u64);

    let event = tokio::time::timeout(timeout, async {
        loop {
            match rx.recv().await {
                Ok(e) => return Some(db_event_to_json(e)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    rx = store.subscribe_events();
                }
            }
        }
    })
    .await
    .ok()
    .flatten();

    Ok(event)
}

fn db_event_to_json(event: atomic_lib::DbEvent) -> String {
    use types::DbEventDto;
    let dto = match event {
        atomic_lib::DbEvent::Changed { subject, .. } => DbEventDto {
            kind: "changed".into(),
            subject: subject.to_string(),
            added: None,
        },
        atomic_lib::DbEvent::Destroyed { subject, .. } => DbEventDto {
            kind: "destroyed".into(),
            subject: subject.to_string(),
            added: None,
        },
        atomic_lib::DbEvent::QueryMembershipChanged { subject, added, .. } => DbEventDto {
            kind: "query_membership".into(),
            subject,
            added: Some(added),
        },
    };
    serde_json::to_string(&dto).unwrap_or_else(|_| "{}".into())
}

// ── 7. Peer / Sync (explicit, opt-in) ─────────────────────────────────────

/// Start the Iroh peer node. Returns the NodeID.
/// Call this before any sync operations.
pub async fn start_peer() -> Result<String, String> {
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

// ── 11. New Typed FFI Exports ──────────────────────────────────────────────

#[frb(sync)]
pub fn get_device_name() -> Result<String, String> {
    let store = db()?;
    Ok(atomic_lib::sync::peer::get_device_name(store.as_ref()))
}

#[frb(sync)]
pub fn set_device_name(name: String) -> Result<(), String> {
    let store = db()?;
    atomic_lib::sync::peer::set_device_name(store.as_ref(), &name);
    Ok(())
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

pub fn poll_sync_events() -> String {
    let events = atomic_lib::sync::peer::poll_sync_events();
    serde_json::to_string(&events).unwrap_or_else(|_| "[]".into())
}

pub async fn wait_for_sync_event() -> String {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        atomic_lib::sync::peer::wait_for_sync_event(),
    )
    .await;
    match result {
        Ok(event) => serde_json::to_string(&event).unwrap_or_else(|_| "null".into()),
        Err(_) => "null".into(),
    }
}

pub async fn watch_resource(subject: String) -> Result<String, String> {
    let store = db()?;
    let mut rx = store.subscribe_events();
    let target = atomic_lib::Subject::from_raw(&subject, store.get_base_domain().as_deref())
        .without_params();
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(atomic_lib::DbEvent::Changed { subject, .. }) if subject == target => {
                    return subject.to_string();
                }
                Ok(atomic_lib::DbEvent::Destroyed { subject, .. }) if subject == target => {
                    return format!("!{}", subject);
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    rx = store.subscribe_events();
                }
            }
        }
    })
    .await;
    match result {
        Ok(s) => Ok(s),
        Err(_) => Ok("timeout".into()),
    }
}

pub async fn watch_children(parent: String) -> Result<String, String> {
    let store = db()?;
    let mut rx = store.subscribe_events();
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match rx.recv().await {
                Ok(atomic_lib::DbEvent::Destroyed { subject, .. }) => {
                    return format!("!{}", subject);
                }
                Ok(atomic_lib::DbEvent::Changed { subject, .. }) => {
                    if let Ok(r) = store.get_resource(&subject).await {
                        if let Ok(p) = r.get(atomic_lib::urls::PARENT) {
                            if p.to_string() == parent {
                                return subject.to_string();
                            }
                        }
                    }
                }
                Ok(atomic_lib::DbEvent::QueryMembershipChanged { .. }) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    rx = store.subscribe_events();
                }
            }
        }
    })
    .await;

    match result {
        Ok(subject) => Ok(subject),
        Err(_) => Ok("timeout".into()),
    }
}

#[frb(sync)]
pub fn get_known_peers_json() -> String {
    let Ok(store) = db() else { return "[]".into() };
    let peers = atomic_lib::sync::peer::get_known_peers(store.as_ref());
    serde_json::to_string(&peers).unwrap_or_else(|_| "[]".into())
}
