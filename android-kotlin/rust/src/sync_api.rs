//! What Kotlin calls for sync, servers, devices and the own profile. The
//! behaviour is `crate::sync`; this only binds it to typed records.

use crate::{
    api::Subscription,
    error::CoreResult,
    pairing,
    session,
    state::{self, db, node},
    sync::{discovery, peers, ws},
    types::*,
};
use atomic_lib::Storelike;
use std::sync::Arc;

// ── Start-up ───────────────────────────────────────────────────────────────

/// Start-up with a saved session (Flutter's `resume_app_session`): load the
/// agent, pick the drive, open the WebSocket to `server_url` (empty for none;
/// a failure is logged, not fatal: offline is a normal state) and bring Iroh
/// up in the background. It does not search for a drive that is missing: that
/// takes tens of seconds and belongs on the screen with a loading state
/// ([`sync_connectivity_now`], [`discover_home_server`]).
#[uniffi::export(async_runtime = "tokio")]
pub async fn resume_session(server_url: String, secret: String, drive: Option<String>) -> CoreResult<ResumeStatus> {
    let store = db()?.clone();
    session::resume(&store, &secret, drive.as_deref()).await?;
    let origin = server_url.trim();
    if !origin.is_empty() && !peers::is_unreachable_hub_url(origin) {
        if let Err(e) = ws::open_ws_sync(origin).await {
            tracing::warn!("[resume] WS sync failed: {e}");
        }
    } else if !origin.is_empty() {
        tracing::info!("[resume] skipping {origin} (localhost is not reachable from devices)");
    }
    if !session::drive_exists(&store).await {
        return Ok(ResumeStatus::NeedsSync);
    }
    // Iroh binding waits for the relay (up to 10 s offline): not on the way to the home.
    let background = store.clone();
    tokio::spawn(async move {
        let _ = peers::ensure_sync_connectivity(&background).await;
    });
    if let Some(home) = store.get_active_drive() {
        tokio::spawn(peers::follow_listed_drives(home));
    }
    Ok(ResumeStatus::Ready)
}

/// Make `subject` the active drive (a tap on a drive); when a server session
/// is open it also follows that drive's commits, in the background.
#[uniffi::export(async_runtime = "tokio")]
pub async fn activate_drive(subject: String) -> CoreResult<()> {
    db()?.set_active_drive(&subject)?;
    if ws::is_connected() {
        tokio::spawn(async move {
            let _ = ws::follow_drive(&subject).await;
        });
    }
    Ok(())
}

// ── Servers ────────────────────────────────────────────────────────────────

/// Open the WebSocket session to a server and keep it open (it reconnects by
/// itself until [`close_ws_sync`]).
#[uniffi::export(async_runtime = "tokio")]
pub async fn open_ws_sync(origin: String) -> CoreResult<()> {
    Ok(ws::open_ws_sync(&origin).await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn close_ws_sync() {
    ws::close_ws_sync().await;
}

/// Whether a WebSocket session is open right now.
#[uniffi::export]
pub fn server_connected() -> bool {
    ws::is_connected()
}

/// Look for the server the active drive lives on (pkarr, then each origin's
/// genesis certificate) and connect to it.
#[uniffi::export(async_runtime = "tokio")]
pub async fn discover_home_server(drive: String) -> CoreResult<DiscoveryResult> {
    discovery::discover_home_server(&drive).await
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn server_info(origin: String) -> ServerInfo {
    discovery::server_info(&origin).await
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn drive_usage(origin: String, drive: String) -> Option<DriveUsage> {
    discovery::drive_usage(&origin, &drive).await
}

/// Push the active drive to a server so it is hosted there as well as here
/// (the only way a workspace made on this device reaches a browser). Returns
/// how many resources were pushed.
#[uniffi::export(async_runtime = "tokio")]
pub async fn sync_drive_to_server(origin: String) -> CoreResult<u32> {
    use atomic_lib::sync::replicate::{replicate_drive_to_remote, ReplicateAuth};
    let store = db()?;
    let drive = store.get_active_drive().ok_or("No active drive")?;
    let agent = store.get_default_agent()?;
    let ws_url = ws::server_origin_to_ws_url(&origin)?;
    let outcome = replicate_drive_to_remote(
        store.as_ref(),
        &drive,
        &ws_url,
        &atomic_lib::agents::ForAgent::AgentSubject(agent.subject.clone()),
        ReplicateAuth::Agent(Box::new(agent)),
    )
    .await?;
    // Without `in_sync` the push was acked but dropped, for lack of write rights.
    if !outcome.in_sync {
        return Err("The server accepted the workspace but does not have it. It may not allow this account to write there.".into());
    }
    Ok(outcome.pushed as u32)
}

// ── Devices ────────────────────────────────────────────────────────────────

/// Start the Iroh endpoint; returns this device's node id.
#[uniffi::export(async_runtime = "tokio")]
pub async fn start_peer() -> CoreResult<String> {
    Ok(peers::start_peer().await?)
}

/// This device's node id, `None` while Iroh is not running.
#[uniffi::export]
pub fn peer_id() -> Option<String> {
    peers::get_peer_id()
}

/// Sync the active drive with a device by node id (after a scan or paste), and
/// remember it as paired.
#[uniffi::export(async_runtime = "tokio")]
pub async fn pair_with(node_id: String, name: String) -> CoreResult<PeerSyncOutcome> {
    let report = peers::peer_sync(&node_id).await?;
    peers::add_known_peer(node_id, name);
    Ok(PeerSyncOutcome {
        imported: report.imported,
        pushed: report.pushed,
        in_sync: report.in_sync,
        peer_name: report.peer_name,
    })
}

/// Start Iroh, sync the paired devices, then ask pkarr for others. The slow
/// search for a drive this device lacks.
#[uniffi::export(async_runtime = "tokio")]
pub async fn sync_connectivity_now() -> CoreResult<ConnectivityReport> {
    let report = peers::sync_connectivity_now().await?;
    Ok(ConnectivityReport { imported: report.imported, live_peers: report.live_peers, message: report.message })
}

/// The paired devices, with whether each is connected right now.
#[uniffi::export]
pub fn known_peers() -> CoreResult<Vec<PeerRow>> {
    let live: std::collections::HashSet<String> = atomic_lib::sync::peer::live_peer_ids()
        .iter()
        .map(|id| atomic_lib::sync::peer::normalize_node_id(id))
        .collect();
    Ok(atomic_lib::sync::peer::get_known_peers(db()?)
        .into_iter()
        .map(|p| PeerRow {
            live: live.contains(&atomic_lib::sync::peer::normalize_node_id(&p.node_id)),
            last_synced: p.last_synced.and_then(|t| u64::try_from(t).ok()),
            node_id: p.node_id,
            name: p.name,
        })
        .collect())
}

#[uniffi::export]
pub fn remove_known_peer(node_id: String) {
    peers::remove_known_peer(node_id);
}

#[uniffi::export]
pub fn device_name() -> CoreResult<String> {
    Ok(atomic_lib::sync::peer::get_device_name(db()?))
}

#[uniffi::export]
pub fn set_device_name(name: String) -> CoreResult<()> {
    atomic_lib::sync::peer::set_device_name(db()?, name.trim());
    Ok(())
}

/// Call `listener` for every sync event (a device connected, left, or a sync
/// moved resources) until the subscription is cancelled.
#[uniffi::export(async_runtime = "tokio")]
pub async fn subscribe_sync_events(listener: Arc<dyn SyncListener>) -> Arc<Subscription> {
    let task = tokio::spawn(async move {
        loop {
            let event = atomic_lib::sync::peer::wait_for_sync_event().await;
            listener.on_event(SyncEvent {
                kind: event.kind,
                remote_node_id: event.remote_node_id,
                resources_imported: event.resources_imported as u32,
            });
        }
    });
    Arc::new(Subscription::new(task.abort_handle()))
}

// ── Pairing codes ──────────────────────────────────────────────────────────

/// The node a scanned or pasted code names, `None` when it is not a pairing code.
#[uniffi::export]
pub fn parse_pairing_code(input: String) -> Option<PairingCode> {
    pairing::parse(&input)
}

/// What this device's QR shows.
#[uniffi::export]
pub fn format_pairing_code(node_id: String, device_name: String) -> String {
    pairing::format(&node_id, &device_name)
}

// ── Own profile ────────────────────────────────────────────────────────────

/// The profile of this device's agent: what the store holds, else what the
/// connected server has.
#[uniffi::export(async_runtime = "tokio")]
pub async fn own_profile() -> CoreResult<OwnProfile> {
    let json = atomic_lib::host::own_profile::own_profile(db()?, &state::profiles()).await?;
    let text = |key: &str| json[key].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    Ok(OwnProfile {
        subject: text("subject").unwrap_or_default(),
        name: text("name").unwrap_or_default(),
        description: text("description").unwrap_or_default(),
        emoji: text("emoji"),
        image_url: text("imageUrl"),
    })
}

/// Save the profile: a commit by the agent on its own resource, synced like
/// any edit. An empty description removes it.
#[uniffi::export(async_runtime = "tokio")]
pub async fn set_own_profile(name: String, description: String) -> CoreResult<()> {
    Ok(atomic_lib::host::own_profile::set_own_profile(&node()?, state::pusher().as_ref(), &name, &description, None).await?)
}

/// Whether the active drive is stored on this device (the sign-in is done).
#[uniffi::export(async_runtime = "tokio")]
pub async fn drive_ready() -> bool {
    match db() {
        Ok(store) => session::drive_exists(store).await,
        Err(_) => false,
    }
}
