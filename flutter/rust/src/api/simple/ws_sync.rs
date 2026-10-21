//! WebSocket sync session for Flutter — mirrors browser `WSClient` + drive SUB.

use std::sync::{Arc, Mutex, OnceLock};

use atomic_lib::{
    client::ws::{WsClient, WsMessage},
    sync::{outbox::Outbox, protocol, ws_apply},
    Storelike,
};

use super::state::{db, err, set_server_origin};

static WS_TASK: OnceLock<Mutex<Option<tokio::task::JoinHandle<()>>>> = OnceLock::new();
static WS_CLIENT: OnceLock<Mutex<Option<Arc<WsClient>>>> = OnceLock::new();
static COMMIT_REQUEST_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

fn ws_task_slot() -> &'static Mutex<Option<tokio::task::JoinHandle<()>>> {
    WS_TASK.get_or_init(|| Mutex::new(None))
}

fn ws_client_slot() -> &'static Mutex<Option<Arc<WsClient>>> {
    WS_CLIENT.get_or_init(|| Mutex::new(None))
}

/// `http://host:9883` → `ws://host:9883/ws`
pub fn server_origin_to_ws_url(origin: &str) -> Result<String, String> {
    let origin = origin.trim().trim_end_matches('/');
    let ws_base = if origin.starts_with("wss://") || origin.starts_with("ws://") {
        origin.to_string()
    } else if let Some(rest) = origin.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = origin.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{origin}")
    };
    if ws_base.ends_with("/ws") {
        Ok(ws_base)
    } else {
        Ok(format!("{ws_base}/ws"))
    }
}

pub async fn close_ws_sync() {
    if let Ok(mut guard) = ws_task_slot().lock() {
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
    if let Ok(mut guard) = ws_client_slot().lock() {
        *guard = None;
    }
}

pub async fn open_ws_sync(server_origin: &str) -> Result<(), String> {
    close_ws_sync().await;

    let ws_url = server_origin_to_ws_url(server_origin)?;
    tracing::info!("[ws_sync] connecting to {ws_url}");

    let store = db()?.clone();
    store.set_base_url(server_origin.trim_end_matches('/'));
    set_server_origin(server_origin);

    let client = Arc::new(WsClient::connect(&ws_url).await.map_err(err)?);
    let agent = store.get_default_agent().map_err(err)?;
    client.authenticate(&agent).await.map_err(err)?;

    if let Some(drive) = store.get_active_drive() {
        // Drive-wide SUB now covers everything that used to require a
        // separate `subscribe_query(parent, drive, drive)` — every commit
        // under the drive fans out as `UPDATE` / `DESTROY` on this
        // subscription. See `planning/sync.md` ("QUERY_UPDATE removed").
        client.subscribe_drive(&drive).await.map_err(err)?;
        tracing::info!(
            "[ws_sync] subscribed to drive {}",
            &drive[..drive.len().min(24)]
        );
    }

    let client_loop = client.clone();
    let store_loop = store.clone();
    let handle = tokio::spawn(async move {
        let mut rx = client_loop.subscribe();
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if let Err(e) = handle_ws_message(store_loop.as_ref(), msg).await {
                        tracing::warn!("[ws_sync] message error: {e}");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tracing::info!("[ws_sync] broadcast closed, exiting loop");
                    break;
                }
            }
        }
    });

    if let Ok(mut guard) = ws_client_slot().lock() {
        *guard = Some(client);
    }
    if let Ok(mut guard) = ws_task_slot().lock() {
        *guard = Some(handle);
    }

    if let Some(drive) = store.get_active_drive() {
        if let Err(e) = ensure_drive_materialized(store.as_ref(), &drive).await {
            tracing::warn!("[ws_sync] drive fetch skipped: {e}");
        } else {
            // The session now knows a server: the person's other drives may
            // be on it.
            tokio::spawn(super::follow_listed_drives(drive));
            // Conversations are drives of their own that nothing above
            // lists: subscribe to them and catch up on what was said.
            crate::api::assistant::follow_conversations_in_background();
        }
    }

    // Whatever was written while there was no session goes out now, in
    // dependency order, before any bulk reconcile can race it.
    let store_drain = store.clone();
    tokio::spawn(async move {
        drain_outbox(store_drain.as_ref()).await;
    });

    Ok(())
}

/// Fetch the active drive from the server when the agent secret references a drive
/// that is not yet in the local DB (second device, same account).
pub(crate) async fn ensure_drive_materialized(
    store: &atomic_lib::Db,
    drive: &str,
) -> Result<(), String> {
    let subject = atomic_lib::Subject::from_raw(drive, store.get_base_domain().as_deref());
    if store.get_resource(&subject).await.is_ok() {
        return Ok(());
    }
    tracing::info!(
        "[ws_sync] drive missing locally, fetching {}",
        &drive[..drive.len().min(32)]
    );
    let bytes = fetch_resource_state(store, drive).await?;
    if bytes.is_empty() {
        return Err("Drive not found on server".into());
    }
    ws_apply::apply_state_update(store, drive, &bytes)
        .await
        .map_err(err)
}

async fn handle_ws_message(store: &atomic_lib::Db, msg: WsMessage) -> Result<(), String> {
    match msg {
        WsMessage::Update {
            subject,
            loro_bytes,
            ..
        } => {
            ws_apply::apply_state_update(store, &subject, &loro_bytes)
                .await
                .map_err(err)?;
        }
        // The answer to `catch_up_drive`: the state of what this device
        // lacks or has an older version of.
        WsMessage::SyncPush { entries, .. } => {
            ws_apply::apply_state_updates(store, &entries, false)
                .await
                .map_err(err)?;
        }
        WsMessage::Destroy { subject } => {
            ws_apply::apply_destroy(store, &subject)
                .await
                .map_err(err)?;
        }
        WsMessage::Error { code, message, .. } => {
            tracing::warn!("[ws_sync] server error (code {code}): {message}")
        }
        _ => {}
    }
    Ok(())
}

async fn fetch_resource_state(_store: &atomic_lib::Db, subject: &str) -> Result<Vec<u8>, String> {
    let client = ws_client_slot()
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "WS session not open".to_string())?;

    let request_id = COMMIT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let frame = protocol::encode_get(request_id, subject);
    let mut rx = client.subscribe();
    client.send_binary(frame).await.map_err(err)?;

    match tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Ok(msg) = rx.recv().await {
            match msg {
                WsMessage::Update {
                    subject: s,
                    loro_bytes,
                    ..
                } if s == subject => {
                    return Ok(loro_bytes);
                }
                WsMessage::Error {
                    request_id: rid,
                    message,
                    ..
                } if rid == request_id => return Err(message),
                _ => {}
            }
        }
        Err("WebSocket closed".into())
    })
    .await
    {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("GET timed out".to_string()),
    }
}

/// Best-effort: push a locally signed commit over WS when a session is open.
/// Returns `true` if the commit was accepted by the hub.
///
/// Drain the outbox over the open WebSocket session. `true` when nothing is
/// left waiting. Without a session nothing is attempted; the entries stay
/// on disk for the next `open_ws_sync`.
#[flutter_rust_bridge::frb(ignore)]
pub async fn drain_outbox(store: &atomic_lib::Db) -> bool {
    let Some(client) = ws_client_slot().lock().ok().and_then(|guard| guard.clone()) else {
        return false;
    };
    let mut transport = client;
    match Outbox::new(store.clone()).drain(&mut transport).await {
        Ok(report) => {
            if report.remaining > 0 {
                tracing::info!(
                    "[ws_sync] outbox: {} sent, {} deferred, {} blocked, {} dropped, {} remaining",
                    report.sent,
                    report.deferred,
                    report.blocked,
                    report.dropped,
                    report.remaining
                );
            }
            report.remaining == 0
        }
        Err(e) => {
            tracing::warn!("[ws_sync] outbox drain failed: {e}");
            false
        }
    }
}

/// Follow another drive of the person over the open WS session: fetch it when
/// missing and subscribe to its commits. Fails when the server does not host it.
pub(crate) async fn follow_drive(drive: &str) -> Result<(), String> {
    let client = ws_client_slot()
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "WS session not open".to_string())?;
    let store = db()?;
    client.subscribe_drive(drive).await.map_err(err)?;
    ensure_drive_materialized(store.as_ref(), drive).await
}

/// Ask the server for what this device lacks of `drive`: a `SYNC` with this
/// device's version vectors, which the server answers with the state of every
/// resource it has newer (`SYNC_PUSH`, applied by the session's message loop).
/// A `SUB` only delivers what happens from then on, so a drive this device
/// already holds needs this to get what was said while it was closed or
/// offline. Does not wait for the answer.
pub(crate) async fn catch_up_drive(drive: &str) -> Result<(), String> {
    use std::collections::HashMap;
    let client = ws_client_slot()
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "WS session not open".to_string())?;
    let store = db()?;
    let subject = atomic_lib::Subject::from(drive);
    let subjects = atomic_lib::sync::engine::collect_drive_subjects(store.as_ref(), &subject).await;
    let vvs = atomic_lib::sync::engine::build_drive_vvs(store.as_ref(), &subjects);
    let mut peers: Vec<String> = Vec::new();
    for vv in vvs.values() {
        for peer in vv.keys() {
            if !peers.contains(peer) {
                peers.push(peer.clone());
            }
        }
    }
    let resources: HashMap<String, Vec<i32>> = vvs
        .iter()
        .map(|(subject, vv)| {
            let counters = peers
                .iter()
                .map(|p| vv.get(p).copied().unwrap_or(0))
                .collect();
            (subject.clone(), counters)
        })
        .collect();
    // An empty hash never matches the server's, so it always compares.
    client
        .send_binary(protocol::encode_sync(
            &subject.pure_id(),
            "",
            &peers,
            &resources,
        ))
        .await
        .map_err(err)
}

/// Post a commit JSON-AD over the open WS session (falls back to error if closed).
pub async fn post_commit_over_ws(commit_json: &str) -> Result<String, String> {
    let client = ws_client_slot()
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "WS session not open — call open_ws_sync first".to_string())?;

    let request_id = COMMIT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    client
        .post_commit(request_id, commit_json)
        .await
        .map_err(err)
}
