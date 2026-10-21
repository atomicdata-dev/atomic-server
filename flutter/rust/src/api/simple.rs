use atomic_lib::Storelike;
use flutter_rust_bridge::frb;

#[cfg(not(target_arch = "wasm32"))]
mod compaction_check;
#[cfg(test)]
mod peer_tests;
mod peer_search;
pub(crate) mod state;
#[cfg(test)]
mod store_open_tests;
#[cfg(test)]
pub(crate) mod tests;
pub mod types;
pub mod ws_sync;

pub use atomic_lib::{Commit, Db};

use state::{db, err, node, set_db};
use atomic_lib::host::activity_status::{self, begin as busy, Kind};
pub use types::{AgentInfo, SetupResult, StoreRecovery, VersionMetadata};

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
    let _ = drive;
    // `start_peer` also starts the search loop, which announces this device
    // for the active and the private drive and keeps looking for the others.
    let _ = start_peer().await?;
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

/// Open a local database. Call on app start; a second call in the same
/// process (Android runs `main` again when it recreates the activity) keeps
/// the store that is already open.
///
/// Never panics and never deletes the user's data. A store that cannot be
/// opened because the file is damaged is renamed to
/// `atomic.redb.corrupt-<ms>`, a repaired copy (or, failing that, an empty
/// store) takes its place, and `store_recovery` tells the app so it can say
/// so. Other errors (permissions, a full disk) are returned as they are.
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
    let _opening = state::OPEN_DB_LOCK.lock().await;
    if db().is_ok() {
        // A second store handle on the same file is what damaged stores on
        // Android (see `atomic_lib::db::recovery`).
        tracing::info!("open_db: the store is already open in this process; keeping it");
        return Ok(());
    }

    #[cfg(not(target_arch = "wasm32"))]
    let store = {
        let (store, recovery) = open_native_store(std::path::Path::new(&path)).await?;
        if let Some(recovery) = recovery {
            state::set_store_recovery(recovery);
        }
        store
    };

    #[cfg(target_arch = "wasm32")]
    let store = atomic_lib::Db::init_redb_opfs(None, "atomic.redb")
        .await
        .map_err(err)?;

    set_db(store);
    #[cfg(not(target_arch = "wasm32"))]
    {
        state::set_store_dir(std::path::Path::new(&path));
        catch_up_search_index(db()?.clone()).await;
        crate::host::start_recents(std::path::Path::new(&path), db()?.clone());
    }
    Ok(())
}

/// Set when the last `open_db` had to set a damaged store aside.
#[frb(sync)]
pub fn store_recovery() -> Option<StoreRecovery> {
    state::store_recovery()
}

/// What the host does in the background right now (sync runs, following and
/// catching up on drives, picture downloads, activity lookups and scans,
/// uploads), for a small "busy" mark. Cheap; poll it.
pub struct BackgroundActivity {
    pub total: u32,
    /// Running tasks by kind: `sync`, `drives`, `pictures`, `history`, `scan`,
    /// `upload`.
    pub by_kind: std::collections::HashMap<String, u32>,
    /// The last background failure, cleared by the next success.
    pub last_error: Option<String>,
    /// Unix ms of the last success.
    pub last_ok_ms: Option<i64>,
}

#[frb(sync)]
pub fn background_activity() -> BackgroundActivity {
    let s = atomic_lib::host::activity_status::snapshot();
    BackgroundActivity {
        total: s.total,
        by_kind: s.by_kind.into_iter().collect(),
        last_error: s.last_error,
        last_ok_ms: s.last_ok_ms,
    }
}

/// Make every write so far durable now. The app calls it when it goes to
/// the background, where Android may kill it without warning; the store
/// otherwise makes writes durable on a 100 ms tick.
pub fn flush_db() -> Result<(), String> {
    db()?.flush().map_err(err)
}

#[cfg(not(target_arch = "wasm32"))]
async fn open_native_store(
    base_path: &std::path::Path,
) -> Result<(atomic_lib::Db, Option<StoreRecovery>), String> {
    use atomic_lib::db::recovery;
    let db_path = base_path.join("atomic.redb");
    let before = recovery::inspect(&db_path).ok().flatten();
    let started = std::time::Instant::now();

    let (store, recovered) = match open_store_catching(base_path).await {
        Ok(store) => (store, None),
        Err(e) if recovery::is_damaged_store_error(&e) => {
            tracing::error!("The store could not be opened, setting it aside: {e} ({before:?})");
            let kept = recovery::set_aside(&db_path).map_err(|io| {
                format!("The store could not be opened ({e}) nor moved aside: {io}")
            })?;
            let mut repaired = match recovery::repair_copy(&kept, &db_path) {
                Ok(()) => true,
                Err(repair) => {
                    tracing::warn!("Repairing a copy of the store failed: {repair}");
                    false
                }
            };
            let store = match open_store_catching(base_path).await {
                Ok(store) => store,
                Err(again) if repaired => {
                    // Only the repaired copy goes; the original is `kept`.
                    tracing::warn!("The repaired store did not open either: {again}");
                    let _ = std::fs::remove_file(&db_path);
                    repaired = false;
                    open_store_catching(base_path).await?
                }
                Err(again) => return Err(again),
            };
            let recovery = StoreRecovery {
                kept_path: kept.to_string_lossy().into_owned(),
                reason: e,
                repaired,
            };
            (store, Some(recovery))
        }
        Err(e) => return Err(e),
    };

    let after = recovery::inspect(&db_path).ok().flatten();
    tracing::info!(
        "store self-check: {} opened in {:?}; before {}; now {}; {}",
        db_path.display(),
        started.elapsed(),
        describe_file(before),
        describe_file(after),
        match &recovered {
            None => "no recovery needed".to_string(),
            Some(r) if r.repaired => format!("REPAIRED a damaged store, kept at {}", r.kept_path),
            Some(r) => format!(
                "STARTED EMPTY, the damaged store is kept at {}",
                r.kept_path
            ),
        }
    );
    Ok((store, recovered))
}

#[cfg(not(target_arch = "wasm32"))]
fn describe_file(check: Option<atomic_lib::db::recovery::FileCheck>) -> String {
    match check {
        None => "no store file".into(),
        Some(c) => format!(
            "{} bytes, header describes {}{}{}",
            c.file_len,
            c.layout_len,
            if c.is_short() { " (SHORT)" } else { "" },
            if c.recovery_required {
                ", last run did not close it"
            } else {
                ", closed cleanly"
            }
        ),
    }
}

/// redb's read cache on a phone. Its default (1 GiB) keeps whatever was read,
/// up to the size of the store, in memory (870 MB of RSS after a full walk of
/// a 1 GB store); the lists and the search read little and repeatedly.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const REDB_CACHE_BYTES: usize = 48 * 1024 * 1024;

/// `Db::init_redb_file` with any panic inside it turned into a "damaged"
/// error: a panic must not escape to the app, which then never draws.
#[cfg(not(target_arch = "wasm32"))]
async fn open_store_catching(base_path: &std::path::Path) -> Result<atomic_lib::Db, String> {
    use futures::FutureExt;
    let uploads_path = base_path.join("uploads");
    let now = state::now_ms();
    let policy = compaction_check::startup_policy(base_path, now);
    let checks = policy.enabled;
    let opening = atomic_lib::Db::init_redb_file_with_cache(
        base_path,
        None,
        &uploads_path,
        &policy,
        Some(REDB_CACHE_BYTES),
    );
    match std::panic::AssertUnwindSafe(opening).catch_unwind().await {
        Ok(Ok(store)) => {
            if checks {
                compaction_check::record_check(base_path, now);
            }
            Ok(store)
        }
        Ok(Err(e)) => Err(err(e)),
        Err(panic) => Err(format!(
            "The {}: panic while opening: {}",
            atomic_lib::db::recovery::DAMAGED_STORE,
            atomic_lib::db::recovery::panic_message(&panic)
        )),
    }
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

#[frb(init)]
pub fn init_app() {
    // Before any TLS use: rustls panics without a process default when both of
    // its backends are compiled in (they are: ring and aws-lc-rs).
    #[cfg(not(target_family = "wasm"))]
    atomic_lib::client::install_default_crypto_provider();
    // Not `setup_default_user_utils`: that forwards the `log` crate to logcat
    // at Trace (rustls, reqwest and iroh wrote ~800 formatted lines per app
    // start) and sets RUST_BACKTRACE=1, which also makes every `anyhow` error
    // capture and print a stack (iroh makes them in its retry loops). Panics
    // keep their backtrace; library errors do not capture one.
    #[cfg(not(target_family = "wasm"))]
    if std::env::var_os("RUST_LIB_BACKTRACE").is_none() {
        std::env::set_var("RUST_LIB_BACKTRACE", "0");
    }
    flutter_rust_bridge::setup_backtrace();
    flutter_rust_bridge::setup_log_to_console(log::LevelFilter::Warn);

    // Initialize tracing → logcat on Android, stderr elsewhere. Loro logs
    // every encoded block at info.
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let _ = tracing_subscriber::registry()
            .with(tracing_android::layer("atomic").ok())
            .with(tracing_subscriber::filter::EnvFilter::new(
                "info,loro_internal=warn,swarm_discovery=error",
            ))
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

/// The bytes of a File resource (a profile picture) when this device holds
/// them; `None` when the File or its bytes are not here (yet) or too large.
pub async fn read_file_bytes(file: String) -> Result<Option<Vec<u8>>, String> {
    atomic_lib::host::own_profile::file_bytes(db()?, &file)
        .await
        .map_err(err)
}

/// The bytes of a File resource (a profile picture): from this device when it
/// holds them, else downloaded from the connected server the way the web app
/// does (signed by the agent, checked against the blob's hash, an image of at
/// most 16 MB) and kept in the store. Fails with the reason (HTTP status
/// included) when they cannot be had.
pub async fn fetch_file_bytes(file: String) -> Result<Vec<u8>, String> {
    let origins: Vec<String> = state::connected_server().into_iter().collect();
    atomic_lib::host::own_profile::fetch_file_bytes(db()?, &file, &origins)
        .await
        .map_err(err)
}

/// Keep a picked picture as a File in the active drive (bytes in the local
/// store, the File queued for sync like the web app's upload) and return the
/// File's subject, to pass as `icon` to `set_agent_profile`.
pub async fn upload_agent_picture(
    filename: String,
    mimetype: String,
    bytes: Vec<u8>,
) -> Result<String, String> {
    let drive = db()?
        .get_active_drive()
        .ok_or("No workspace to keep the picture in")?;
    let origin = state::connected_server();
    let _busy = busy(Kind::Upload);
    atomic_lib::host::own_profile::upload_own_picture(
        &node()?,
        crate::host::pusher().as_ref(),
        &drive,
        origin.as_deref(),
        &filename,
        &mimetype,
        &bytes,
    )
    .await
    .map_err(err)
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
    Ok(drives_by_use()
        .await?
        .into_iter()
        .map(|d| d.subject)
        .collect())
}

/// The agent's drives in the order every drive list shows: the active one,
/// then the most recently used, then the rest by name.
async fn drives_by_use() -> Result<Vec<atomic_lib::db::DriveInfo>, String> {
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
        // Bounded: a server that does not answer (offline, a captive portal)
        // held sign-in and every cold start until the OS gave up on the TCP
        // connect, a minute or more, on a spinner.
        match tokio::time::timeout(RESUME_WS_TIMEOUT, ws_sync::open_ws_sync(origin)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("[resume] WS sync failed: {e}"),
            Err(_) => tracing::warn!(
                "[resume] WS sync to {origin} gave no answer in {}s; going on without it",
                RESUME_WS_TIMEOUT.as_secs()
            ),
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
        // Iroh comes up in the background: binding and waiting for the relay
        // (up to 10 s offline) must not hold the home back. Everything that
        // needs the peer calls `start_peer` itself, which waits for this one.
        tokio::spawn(async move {
            let _ = ensure_sync_connectivity(store.as_ref()).await;
        });
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

/// How long a cold start or sign-in waits for the session's server.
const RESUME_WS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Connecting to a verified home server: the WS handshake, auth and the drive.
const HOME_SERVER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const PEER_SYNC_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(22);
const PKARR_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
/// How many of the NodeIDs a drive's pkarr record names are dialled at once.
const PKARR_PEERS_TO_TRY: usize = 4;

fn short_id(node_id: &str) -> &str {
    &node_id[..node_id.len().min(12)]
}

/// The one-line, non-technical summary of a failed sync attempt.
fn failure_summary(peers_failed: bool, lookup_failed: bool) -> &'static str {
    if peers_failed {
        "No other device answered. Open the app on a device that has your drive and keep it on the same network."
    } else if lookup_failed {
        "Could not look for your devices. Check your internet connection and try again."
    } else {
        "Could not reach your other devices."
    }
}

/// The report's message when the lookup worked and named no other device.
/// The app keeps it quiet (no toast): it is the normal state of a new account.
const NO_OTHER_DEVICE_YET: &str =
    "No other device found yet. Open the app on another device signed in with this account, or pair with QR.";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SyncConnectivityReport {
    pub imported: i32,
    pub live_peers: u32,
    pub message: String,
    /// The server the drive was found on through pkarr, when it was.
    #[serde(default)]
    pub server: Option<String>,
    /// The raw lines behind a failure `message`, one per device or lookup that
    /// failed (technical, for a collapsible "Details"). `message` starts with
    /// a short summary line; these lines also follow it, newline separated.
    #[serde(default)]
    pub details: Vec<String>,
    /// `no_peers_answered`, `lookup_failed`, or null when nothing failed.
    #[serde(default)]
    pub kind: Option<String>,
}

/// Start Iroh, sync known peers (then pkarr). Returns JSON [`SyncConnectivityReport`].
pub async fn sync_connectivity_now() -> Result<String, String> {
    let store = db()?;
    let _busy = busy(Kind::Sync);
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        sync_connectivity_inner(store.as_ref()),
    )
    .await
    .map_err(|_| {
        "Sync timed out. Check Wi‑Fi, keep the other device open, or pair with QR.".to_string()
    })
    .and_then(|r| r)
    .inspect_err(|e| activity_status::record_error(e.clone()))?;
    if report.live_peers > 0 || report.imported > 0 {
        activity_status::record_ok();
    } else if !report.message.starts_with("No other device found yet") {
        activity_status::record_error(report.message.lines().next().unwrap_or("Sync failed"));
    }
    serde_json::to_string(&report).map_err(|e| e.to_string())
}

async fn sync_connectivity_inner(store: &atomic_lib::Db) -> Result<SyncConnectivityReport, String> {
    ensure_sync_connectivity(store).await?;
    let drive = store.get_active_drive().ok_or("No active drive")?;

    // Known (paired) peers and the pkarr lookup run at the same time, and
    // the known peers are dialled at once: one after the other, a few gone
    // devices at 22 s each held the "Looking for your devices" screen for
    // minutes.
    let peers_json = get_known_peers();
    let peers: Vec<serde_json::Value> = serde_json::from_str(&peers_json).unwrap_or_default();
    let known_ids: Vec<String> = peers
        .iter()
        .filter_map(|p| p.get("node_id").and_then(|v| v.as_str()))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect();
    let drive_ref = drive.as_str();
    let known = dial_all(&known_ids, PEER_SYNC_ATTEMPT_TIMEOUT, |node_id| async move {
        atomic_lib::sync::peer::sync_drive_with_peer_if_needed(&node_id, drive_ref, store)
            .await
            .map_err(|e| e.to_string())
    });
    let (known, announced) = tokio::join!(known, pkarr_peers(store, drive_ref));

    let mut imported: i32 = 0;
    let mut errors: Vec<String> = Vec::new();
    let mut peers_failed = false;
    let mut lookup_failed = false;
    for (node_id, result) in known {
        match result {
            Ok(count) => {
                imported += count as i32;
                tracing::info!("[sync_now] peer {node_id}: {count} resources");
            }
            Err(e) => {
                tracing::warn!("[sync_now] peer {node_id} failed: {e}");
                peers_failed = true;
                errors.push(format!("{}: {e}", short_id(&node_id)));
            }
        }
    }
    match announced {
        PkarrOutcome::NoneAnnounced => {}
        PkarrOutcome::Synced(count) => imported += count as i32,
        PkarrOutcome::NoneAnswered(lines) => {
            peers_failed = true;
            errors.extend(lines);
        }
        PkarrOutcome::LookupFailed(line) => {
            lookup_failed = true;
            errors.push(line);
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
        // Said only when the lookup worked and named nobody else; the search
        // loop keeps looking (`peer_search_status`).
        NO_OTHER_DEVICE_YET.to_string()
    } else {
        // A short summary, then the raw lines (also in `details`).
        let summary = failure_summary(peers_failed, lookup_failed);
        format!("{summary}\n{}", errors.join("\n"))
    };
    let failed = live == 0 && imported == 0 && !errors.is_empty();
    let kind = failed.then(|| {
        if peers_failed { "no_peers_answered" } else { "lookup_failed" }.to_string()
    });

    Ok(SyncConnectivityReport {
        imported,
        live_peers: live,
        message,
        server: None,
        details: if failed { errors } else { Vec::new() },
        kind,
    })
}

/// Dials every node at once, each bounded by `per_attempt`, and returns each
/// one's result (a timeout as `Err("timed out after Ns")`), in input order.
async fn dial_all<F, Fut, T>(
    node_ids: &[String],
    per_attempt: std::time::Duration,
    dial: F,
) -> Vec<(String, Result<T, String>)>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let attempts = node_ids.iter().map(|id| {
        let attempt = dial(id.clone());
        async move {
            let result = tokio::time::timeout(per_attempt, attempt)
                .await
                .unwrap_or_else(|_| {
                    Err(format!("timed out after {}s", per_attempt.as_secs()))
                });
            (id.clone(), result)
        }
    });
    futures::future::join_all(attempts).await
}

/// What the drive's pkarr record led to.
enum PkarrOutcome {
    /// The lookup worked and named no other device: nothing to report.
    NoneAnnounced,
    Synced(u64),
    /// Devices were named and none answered: the lines for "Details".
    NoneAnswered(Vec<String>),
    LookupFailed(String),
}

/// Looks the drive up in pkarr and dials up to [`PKARR_PEERS_TO_TRY`] of the
/// devices it names at once; the first that answers wins. The record also
/// names replicas that are gone (an uninstalled app, an old laptop), and live
/// ones are skipped (`sync_drive_with_peer_if_needed`). The search loop keeps
/// looking after this; it is woken, too.
async fn pkarr_peers(store: &atomic_lib::Db, drive: &str) -> PkarrOutcome {
    peer_search::PEER_SEARCH.search_again();
    let lookup = tokio::time::timeout(PKARR_RESOLVE_TIMEOUT, async {
        let my_node_id = atomic_lib::sync::peer::get_node_id()
            .ok_or("Peer not started")?
            .to_string();
        // Only other devices: a drive on this device alone names none,
        // which is nothing to report.
        let mut others = Vec::new();
        for search in peer_search::search_drives(store) {
            for id in
                atomic_lib::discovery::resolve_other_node_ids(&search, Some(&my_node_id)).await?
            {
                if !others.contains(&id) {
                    others.push(id);
                }
            }
        }
        Ok::<_, atomic_lib::AtomicError>(others)
    })
    .await;
    let node_ids = match lookup {
        Ok(Ok(ids)) if ids.is_empty() => return PkarrOutcome::NoneAnnounced,
        Ok(Ok(ids)) => ids,
        Ok(Err(e)) => return PkarrOutcome::LookupFailed(format!("Could not look for devices: {e}")),
        Err(_) => {
            return PkarrOutcome::LookupFailed(
                "Could not look for devices: the directory (pkarr) timed out".into(),
            )
        }
    };
    let tried = node_ids.len().min(PKARR_PEERS_TO_TRY);
    let attempts = node_ids.iter().take(PKARR_PEERS_TO_TRY).map(|node_id| {
        Box::pin(async move {
            tokio::time::timeout(
                PEER_SYNC_ATTEMPT_TIMEOUT,
                atomic_lib::sync::peer::sync_drive_with_peer_if_needed(node_id, drive, store),
            )
            .await
            .map_err(|_| format!("{}: timed out", short_id(node_id)))?
            .map_err(|e| format!("{}: {e}", short_id(node_id)))
        })
    });
    // The first that answers wins; the failures before it are only kept when
    // none does.
    let mut pending: futures::stream::FuturesUnordered<_> = attempts.collect();
    let mut failures: Vec<String> = Vec::new();
    while let Some(result) = futures::StreamExt::next(&mut pending).await {
        match result {
            Ok(count) => return PkarrOutcome::Synced(count as u64),
            Err(e) => failures.push(e),
        }
    }
    let mut lines = vec![format!(
        "{tried} device{} announced your drive; none answered",
        if tried == 1 { "" } else { "s" }
    )];
    lines.extend(failures);
    PkarrOutcome::NoneAnswered(lines)
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
    tokio::time::timeout(HOME_SERVER_CONNECT_TIMEOUT, ws_sync::open_ws_sync(&origin))
        .await
        .map_err(|_| {
            format!(
                "{origin} did not answer in {}s",
                HOME_SERVER_CONNECT_TIMEOUT.as_secs()
            )
        })??;
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
    let _busy = busy(Kind::Drives);
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
    catch_up_listed_drives(&home).await;
    OTHER_DRIVES_RUNNING.store(false, Ordering::SeqCst);
}

/// Every drive the person lists, the one in use included: subscribed to, and
/// asked (`SYNC`) for what this device lacks of it. A subscription only
/// brings what happens from then on, and fetching a drive brings its root
/// only, so without this the Activity feed (and everything else under such a
/// drive) had nothing from before the subscription. One drive at a time; the
/// server answers each with just the resources newer than the device's
/// version vectors, so a drive already up to date costs one small frame.
/// Without an open session nothing happens (the next `open_ws_sync` runs it).
async fn catch_up_listed_drives(home: &str) {
    let Ok(store) = db() else { return };
    let Ok(drives) = store.list_drives().await else {
        return;
    };
    let mut subjects: Vec<String> = vec![home.to_string()];
    for d in drives {
        if !subjects.iter().any(|s| same_drive(s, &d.subject)) {
            subjects.push(d.subject);
        }
    }
    let mut caught_up = 0;
    for subject in &subjects {
        if !store.has_resource_locally(subject) {
            continue;
        }
        if ws_sync::follow_drive(subject).await.is_ok()
            && ws_sync::catch_up_drive(subject).await.is_ok()
        {
            caught_up += 1;
        }
    }
    tracing::info!("[home] caught up on {caught_up} of {} drives", subjects.len());
}

fn same_drive(a: &str, b: &str) -> bool {
    let key = |s: &str| {
        s.trim_start_matches("did:ad:")
            .trim_start_matches("atomic:")
            .split('?')
            .next()
            .unwrap_or("")
            .to_string()
    };
    key(a) == key(b)
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
    serde_json::to_string(&peer_search::PEER_SEARCH.status()).unwrap_or_else(|_| "{}".into())
}

/// Look for the other devices now (a "Search again" button, a network
/// change, the app coming back), dialling the ones that did not answer
/// recently too.
#[frb(sync)]
pub fn peer_search_again() {
    peer_search::PEER_SEARCH.search_again();
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

/// What this build is, for the "This device" card: `{"version": …, "os": …,
/// "arch": …}` (the library's version and the platform it was built for).
#[frb(sync)]
pub fn device_info() -> String {
    serde_json::json!({
        "version": atomic_lib::VERSION,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
    .to_string()
}

/// How much of the person's data this device holds: `{disk_bytes?, resources,
/// loro_bytes, blob_bytes, drives: [{subject, name, resources, bytes, …}]}`,
/// biggest drive first. Walks the drives' resources, so it runs on the async
/// pool, never the UI thread; the caller caches it.
pub async fn store_stats() -> Result<String, String> {
    let dir = state::store_dir();
    let stats = atomic_lib::host::store_stats::store_stats(db()?, dir.as_deref())
        .await
        .map_err(err)?;
    Ok(stats.to_string())
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
