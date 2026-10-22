//! Server sync: websocket, resume, connectivity, followed drives, events.

use super::*;

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

pub(crate) async fn drive_resource_exists(store: &atomic_lib::Db) -> bool {
    let Some(drive) = store.get_active_drive() else {
        return false;
    };
    let subject = atomic_lib::Subject::from_raw(&drive, store.get_base_domain().as_deref());
    store.get_resource(&subject).await.is_ok()
}

/// How long a cold start or sign-in waits for the session's server.
pub(crate) const RESUME_WS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Connecting to a verified home server: the WS handshake, auth and the drive.
pub(crate) const HOME_SERVER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

pub(crate) const PEER_SYNC_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(22);

pub(crate) const PKARR_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

/// How many of the NodeIDs a drive's pkarr record names are dialled at once.
pub(crate) const PKARR_PEERS_TO_TRY: usize = 4;

pub(crate) fn short_id(node_id: &str) -> &str {
    &node_id[..node_id.len().min(12)]
}

/// The one-line, non-technical summary of a failed sync attempt.
pub(crate) fn failure_summary(peers_failed: bool, lookup_failed: bool) -> &'static str {
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
pub(crate) const NO_OTHER_DEVICE_YET: &str =
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

pub(crate) async fn sync_connectivity_inner(store: &atomic_lib::Db) -> Result<SyncConnectivityReport, String> {
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
pub(crate) async fn dial_all<F, Fut, T>(
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
pub(crate) enum PkarrOutcome {
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
pub(crate) async fn pkarr_peers(store: &atomic_lib::Db, drive: &str) -> PkarrOutcome {
    // The user is waiting on this (the needs-sync screen, pairing): no kept
    // answer.
    peer_search::search_again_now();
    let lookup = tokio::time::timeout(PKARR_RESOLVE_TIMEOUT, async {
        let my_node_id = atomic_lib::sync::peer::get_node_id()
            .ok_or("Peer not started")?
            .to_string();
        // Only other devices: a drive on this device alone names none,
        // which is nothing to report.
        let mut others = Vec::new();
        for search in peer_search::search_drives(store) {
            let record = directory::resolve_record(&search, directory::DEFAULT_TTL, true).await?;
            for id in directory::others(&record, Some(&my_node_id)) {
                if !others.contains(&id) {
                    others.push(id);
                }
            }
        }
        Ok::<_, String>(others)
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
        directory::resolve_record(&drive, directory::DEFAULT_TTL, false),
    )
    .await
    .map_err(|_| "Server lookup timed out (pkarr)".to_string())??;
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
pub(crate) fn peer_ids_to_try(skip: &std::collections::HashSet<String>) -> Vec<String> {
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

pub(crate) static OTHER_DRIVES_RUNNING: std::sync::atomic::AtomicBool =
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
        for (i, drive) in chunk.iter().enumerate() {
            if i > 0 {
                // Not a burst of relay requests: one every so often.
                tokio::time::sleep(OTHER_DRIVES_STAGGER).await;
            }
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
pub(crate) async fn catch_up_listed_drives(home: &str) {
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

pub(crate) fn same_drive(a: &str, b: &str) -> bool {
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

pub(crate) const OTHER_DRIVES_PARALLEL: usize = 4;

/// Between the starts of the drives of one batch.
pub(crate) const OTHER_DRIVES_STAGGER: std::time::Duration = std::time::Duration::from_millis(150);

/// One drive of the person that this device lacks, tried where it is most
/// likely to be: the server the session is connected to, then the paired
/// devices, then whatever pkarr says hosts this drive (its announced Iroh
/// nodes). Whether it arrived is whether it is stored here afterwards.
pub(crate) async fn fetch_other_drive(
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
    // In the background nothing asks the directory (the connected server and
    // the paired devices above still work).
    let lookup = if peer_search::PEER_SEARCH.is_paused() {
        Ok(Err("the app is in the background".to_string()))
    } else {
        tokio::time::timeout(
            PKARR_RESOLVE_TIMEOUT,
            directory::resolve_record(&drive, directory::DEFAULT_TTL, false),
        )
        .await
    };
    match lookup {
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
pub(crate) async fn try_auto_peer_sync(store: &atomic_lib::Db) -> Result<bool, String> {
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

pub(crate) fn db_event_to_json(event: atomic_lib::DbEvent) -> String {
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
