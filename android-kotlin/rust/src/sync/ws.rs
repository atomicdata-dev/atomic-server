//! WebSocket sync session, copied from `flutter/rust/src/api/simple/ws_sync.rs`
//! (that crate cannot be a dependency): mirrors the browser's `WSClient` + drive SUB.

use std::sync::{Arc, Mutex, OnceLock};

use atomic_lib::{
    client::ws::{WsClient, WsMessage},
    sync::{outbox::Outbox, protocol, ws_apply},
    Storelike,
};

use crate::state::{db, set_server_origin};

fn err(e: atomic_lib::AtomicError) -> String {
    e.to_string()
}

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

/// Bumped by every open and close, so a reconnect loop that belongs to an
/// older session knows to stop.
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn generation() -> u64 {
    GENERATION.load(std::sync::atomic::Ordering::SeqCst)
}

pub async fn close_ws_sync() {
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut guard) = ws_task_slot().lock() {
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
    if let Ok(mut guard) = ws_client_slot().lock() {
        *guard = None;
    }
}

/// Whether a WebSocket session is open right now.
pub fn is_connected() -> bool {
    ws_client_slot()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .is_some_and(|client| !client.is_closed())
}

/// One connection: connect, authenticate, subscribe to the active drive and
/// start applying what arrives. Returns the client and the apply loop.
async fn connect(
    store: &Arc<atomic_lib::Db>,
    ws_url: &str,
) -> Result<(Arc<WsClient>, tokio::task::JoinHandle<()>), String> {
    let client = Arc::new(WsClient::connect(ws_url).await.map_err(err)?);
    let agent = store.get_default_agent().map_err(err)?;
    client.authenticate(&agent).await.map_err(err)?;

    if let Some(drive) = store.get_active_drive() {
        // Drive-wide SUB covers everything under the drive: every commit fans
        // out as `UPDATE` / `DESTROY` on this subscription.
        client.subscribe_drive(&drive).await.map_err(err)?;
        tracing::info!("[ws_sync] subscribed to drive {}", &drive[..drive.len().min(24)]);
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
    Ok((client, handle))
}

fn install(client: Arc<WsClient>, handle: tokio::task::JoinHandle<()>) {
    if let Ok(mut guard) = ws_client_slot().lock() {
        *guard = Some(client);
    }
    if let Ok(mut guard) = ws_task_slot().lock() {
        if let Some(old) = guard.replace(handle) {
            old.abort();
        }
    }
}

/// How long to wait before the next reconnect attempt: 2 s, doubling to 60 s.
pub(crate) fn backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs((2u64 << attempt.min(5)).min(60))
}

/// Keeps the session alive: when it drops (a network change, a sleeping
/// phone, a restarting server), connect again until it works or the session
/// was closed or replaced on purpose.
fn supervise(store: Arc<atomic_lib::Db>, ws_url: String, mine: u64, first: Arc<WsClient>) {
    tokio::spawn(async move {
        let mut client = first;
        loop {
            client.wait_closed().await;
            let mut attempt = 0;
            loop {
                if generation() != mine {
                    return;
                }
                tokio::time::sleep(backoff(attempt)).await;
                if generation() != mine {
                    return;
                }
                match connect(&store, &ws_url).await {
                    Ok((fresh, handle)) => {
                        if generation() != mine {
                            handle.abort();
                            return;
                        }
                        tracing::info!("[ws_sync] reconnected to {ws_url}");
                        install(fresh.clone(), handle);
                        client = fresh;
                        let store_drain = store.clone();
                        tokio::spawn(async move {
                            drain_outbox(store_drain.as_ref()).await;
                        });
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("[ws_sync] reconnect failed: {e}");
                        attempt += 1;
                    }
                }
            }
        }
    });
}

pub async fn open_ws_sync(server_origin: &str) -> Result<(), String> {
    close_ws_sync().await;
    let mine = generation();

    let ws_url = server_origin_to_ws_url(server_origin)?;
    tracing::info!("[ws_sync] connecting to {ws_url}");

    let store = db()?.clone();
    store.set_base_url(server_origin.trim_end_matches('/'));
    set_server_origin(server_origin);

    let (client, handle) = connect(&store, &ws_url).await?;
    install(client.clone(), handle);
    supervise(store.clone(), ws_url, mine, client);

    if let Some(drive) = store.get_active_drive() {
        if let Err(e) = ensure_drive_materialized(store.as_ref(), &drive).await {
            tracing::warn!("[ws_sync] drive fetch skipped: {e}");
        } else {
            // The session now knows a server: the person's other drives may
            // be on it.
            tokio::spawn(super::peers::follow_listed_drives(drive));
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
