//! WebSocket sync session for Flutter — mirrors browser `WSClient` + drive SUB.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atomic_lib::{
    client::ws::{WsClient, WsMessage},
    sync::{
        outbox::{CommitRefused, CommitTransport, Outbox},
        protocol, ws_apply,
    },
    Storelike,
};

use super::state::{default_store, err};

static COMMIT_REQUEST_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

/// Where a drain delivers a commit: the session's WebSocket, or in tests a
/// recorder. One `COMMIT` per call, answered with the id the hub stored it as.
#[flutter_rust_bridge::frb(ignore)]
#[async_trait::async_trait]
pub(crate) trait CommitSink: Send + Sync {
    async fn post(&self, request_id: u16, commit_json: &str) -> Result<String, CommitRefused>;
}

#[async_trait::async_trait]
impl CommitSink for Arc<WsClient> {
    async fn post(&self, request_id: u16, commit_json: &str) -> Result<String, CommitRefused> {
        let mut transport = self.clone();
        transport.post_commit(request_id, commit_json).await
    }
}

/// An outbox transport over a [`CommitSink`].
struct SinkTransport(Arc<dyn CommitSink>);

impl CommitTransport for SinkTransport {
    async fn post_commit(
        &mut self,
        request_id: u16,
        commit_json: &str,
    ) -> Result<String, CommitRefused> {
        self.0.post(request_id, commit_json).await
    }
}

/// One WebSocket sync session to a server: the connection, the task applying
/// what it sends, and the server it is on. Every [`AtomicStore`] has its own
/// (so two handles can be signed in to two servers, or as two agents on one);
/// the free functions of this module are the default store's.
///
/// [`AtomicStore`]: crate::api::resources::AtomicStore
#[derive(Default)]
#[flutter_rust_bridge::frb(ignore)]
pub(crate) struct SyncSession {
    client: Mutex<Option<Arc<WsClient>>>,
    sink: Mutex<Option<Arc<dyn CommitSink>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    origin: Mutex<Option<String>>,
    /// Drives a server refused (401/403) for an agent: not asked again.
    denied: Mutex<DeniedDrives>,
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

impl SyncSession {
    pub(crate) fn origin(&self) -> Option<String> {
        self.origin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn set_origin(&self, origin: &str) {
        *self.origin.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(origin.trim_end_matches('/').to_string());
    }

    /// Whether a connection is open (and not known to be closed).
    pub(crate) fn is_open(&self) -> bool {
        self.sink.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    fn client(&self) -> Result<Arc<WsClient>, String> {
        self.client
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "WS session not open".to_string())
    }

    pub(crate) async fn close(&self) {
        if let Ok(mut guard) = self.task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.client.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.sink.lock() {
            *guard = None;
        }
    }

    /// Replace the session's commit delivery (tests: a recorder that stands
    /// in for the server).
    #[cfg(test)]
    pub(crate) fn set_test_sink(&self, sink: Arc<dyn CommitSink>) {
        *self.sink.lock().unwrap() = Some(sink);
    }

    /// Connect to `server_origin` as `store`'s agent, subscribe to `drive`
    /// and fetch it when missing, apply what the server sends to `store`, and
    /// send what waits in the outbox. Replaces a session that is open.
    /// Returns whether the drive is here now (so the caller may follow the
    /// person's other drives).
    pub(crate) async fn open(
        self: &Arc<Self>,
        store: &Arc<atomic_lib::Db>,
        drive: Option<String>,
        server_origin: &str,
    ) -> Result<bool, String> {
        self.close().await;

        let ws_url = server_origin_to_ws_url(server_origin)?;
        tracing::info!("[ws_sync] connecting to {ws_url}");

        store.set_base_url(server_origin.trim_end_matches('/'));
        self.set_origin(server_origin);

        let client = Arc::new(WsClient::connect(&ws_url).await.map_err(err)?);
        let agent = store.get_default_agent().map_err(err)?;
        client.authenticate(&agent).await.map_err(err)?;

        if let Some(drive) = &drive {
            // Drive-wide SUB now covers everything that used to require a
            // separate `subscribe_query(parent, drive, drive)` — every commit
            // under the drive fans out as `UPDATE` / `DESTROY` on this
            // subscription. See `planning/sync.md` ("QUERY_UPDATE removed").
            client.subscribe_drive(drive).await.map_err(err)?;
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

        if let Ok(mut guard) = self.client.lock() {
            *guard = Some(client.clone());
        }
        if let Ok(mut guard) = self.sink.lock() {
            *guard = Some(Arc::new(client));
        }
        if let Ok(mut guard) = self.task.lock() {
            *guard = Some(handle);
        }

        let mut have_drive = false;
        if let Some(drive) = &drive {
            match self.ensure_drive_materialized(store.as_ref(), drive).await {
                Ok(()) => have_drive = true,
                Err(e) => tracing::warn!("[ws_sync] drive fetch skipped: {e}"),
            }
        }

        // Whatever was written while there was no session goes out now, in
        // dependency order, before any bulk reconcile can race it.
        let (session, store_drain) = (self.clone(), store.clone());
        tokio::spawn(async move {
            session.drain_outbox(store_drain.as_ref()).await;
        });

        Ok(have_drive)
    }

    /// Fetch the drive from the server when the agent secret references a
    /// drive that is not yet in the local DB (second device, same account).
    pub(crate) async fn ensure_drive_materialized(
        &self,
        store: &atomic_lib::Db,
        drive: &str,
    ) -> Result<(), String> {
        let subject = atomic_lib::Subject::from_raw(drive, store.get_base_domain().as_deref());
        if store.get_resource(&subject).await.is_ok() {
            return Ok(());
        }
        let (agent, origin) = self.access_key(store);
        if let Some(why) = self.denied_lock().check(&agent, drive, &origin, Instant::now()) {
            return Err(why);
        }
        tracing::info!(
            "[ws_sync] drive missing locally, fetching {}",
            &drive[..drive.len().min(32)]
        );
        let bytes = match self.fetch_resource_state(drive).await {
            Ok(b) => b,
            Err(e) => {
                if is_access_denied(&e) {
                    self.denied_lock().deny(&agent, drive, &origin, Instant::now());
                }
                return Err(e);
            }
        };
        if bytes.is_empty() {
            return Err("Drive not found on server".into());
        }
        ws_apply::apply_state_update(store, drive, &bytes)
            .await
            .map_err(err)
    }

    fn denied_lock(&self) -> std::sync::MutexGuard<'_, DeniedDrives> {
        self.denied.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn access_key(&self, store: &atomic_lib::Db) -> (String, String) {
        let agent = store
            .get_default_agent()
            .map(|a| a.subject.to_string())
            .unwrap_or_default();
        (agent, self.origin().unwrap_or_default())
    }

    /// Forget which drives were refused (the user signed in, the agent changed).
    pub(crate) fn clear_denied(&self) {
        self.denied_lock().clear();
    }

    /// Whether any server refused this agent the drive: for the drive list.
    pub(crate) fn is_drive_denied(&self, store: &atomic_lib::Db, drive: &str) -> bool {
        let (agent, _) = self.access_key(store);
        self.denied_lock().is_denied_anywhere(&agent, drive, Instant::now())
    }

    async fn fetch_resource_state(&self, subject: &str) -> Result<Vec<u8>, String> {
        let client = self.client()?;

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

    /// Drain the outbox of `store` over this session. `true` when nothing is
    /// left waiting. Without a session nothing is attempted; the entries
    /// stay on disk for the next `open`.
    pub(crate) async fn drain_outbox(&self, store: &atomic_lib::Db) -> bool {
        let Some(sink) = self.sink.lock().ok().and_then(|guard| guard.clone()) else {
            return false;
        };
        let mut transport = SinkTransport(sink);
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

    /// Follow another drive of the person over this session: fetch it when
    /// missing and subscribe to its commits. Fails when the server does not
    /// host it.
    pub(crate) async fn follow_drive(
        &self,
        store: &atomic_lib::Db,
        drive: &str,
    ) -> Result<(), String> {
        let client = self.client()?;
        // A drive lives on the host in its URL; this session is one server.
        if let Some(origin) = self.origin() {
            if !drive_belongs_to_origin(drive, &origin) {
                return Err(format!("{drive} is hosted elsewhere, not on {origin}"));
            }
        }
        // Fetch before subscribing: a refusal then costs one request, not a
        // SUB and a GET that both fail.
        self.ensure_drive_materialized(store, drive).await?;
        client.subscribe_drive(drive).await.map_err(err)
    }

    /// Ask the server for what `store` lacks of `drive`: a `SYNC` with its
    /// version vectors, which the server answers with the state of every
    /// resource it has newer (`SYNC_PUSH`, applied by the session's message
    /// loop). A `SUB` only delivers what happens from then on, so a drive
    /// already held needs this to get what was said while closed or offline.
    /// Does not wait for the answer.
    pub(crate) async fn catch_up_drive(
        &self,
        store: &atomic_lib::Db,
        drive: &str,
    ) -> Result<(), String> {
        use std::collections::HashMap;
        let client = self.client()?;
        let subject = atomic_lib::Subject::from(drive);
        let subjects = atomic_lib::sync::engine::collect_drive_subjects(store, &subject).await;
        let vvs = atomic_lib::sync::engine::build_drive_vvs(store, &subjects);
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

    /// Post a commit JSON-AD over the open session.
    pub(crate) async fn post_commit(&self, commit_json: &str) -> Result<String, String> {
        let client = self
            .client()
            .map_err(|_| "WS session not open — call open_ws_sync first".to_string())?;
        let request_id = COMMIT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        WsClient::post_commit(&client, request_id, commit_json)
            .await
            .map_err(err)
    }
}

// ── The default store's session ────────────────────────────────────────────
//
// The same calls on the session of the store `open_db` opened.

pub async fn close_ws_sync() {
    if let Ok(store) = default_store() {
        store.sync.close().await;
    }
}

pub async fn open_ws_sync(server_origin: &str) -> Result<(), String> {
    default_store()?
        .open_ws_sync(server_origin.to_string())
        .await
        .map_err(|e| e.message)
}

/// Drain the default store's outbox over its session. `true` when nothing is
/// left waiting.
#[flutter_rust_bridge::frb(ignore)]
pub async fn drain_outbox(store: &atomic_lib::Db) -> bool {
    match default_store() {
        Ok(default) => default.sync.drain_outbox(store).await,
        Err(_) => false,
    }
}

/// [`SyncSession::follow_drive`] on the default store.
pub(crate) async fn follow_drive(drive: &str) -> Result<(), String> {
    let store = default_store()?;
    store.sync.follow_drive(&store.db, drive).await
}

/// [`SyncSession::catch_up_drive`] on the default store.
pub(crate) async fn catch_up_drive(drive: &str) -> Result<(), String> {
    let store = default_store()?;
    store.sync.catch_up_drive(&store.db, drive).await
}

/// Post a commit JSON-AD over the default store's session (an error if closed).
pub async fn post_commit_over_ws(commit_json: &str) -> Result<String, String> {
    default_store()?.sync.post_commit(commit_json).await
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

// ── Drives a server refused ────────────────────────────────────────────────

/// How long a 401/403 for a (drive, server) is remembered.
const DENIED_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// Whether a server's error text is a refusal of access (not a missing drive
/// or a dropped connection).
pub(crate) fn is_access_denied(message: &str) -> bool {
    let m = message.to_lowercase();
    m.contains("401") || m.contains("403") || m.contains("unauthorized")
        || m.contains("forbidden") || m.contains("not publicly readable")
}

fn host_of(subject: &str) -> Option<String> {
    let rest = subject.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// A drive named by an http(s) URL is hosted at that URL's host; any other
/// subject (a DID) can be anywhere.
pub(crate) fn drive_belongs_to_origin(drive: &str, origin: &str) -> bool {
    if !(drive.starts_with("http://") || drive.starts_with("https://")) {
        return true;
    }
    match (host_of(drive), host_of(origin)) {
        (Some(d), Some(o)) => d == o,
        _ => true,
    }
}

/// (agent, drive, origin) refusals with the time they were seen.
#[derive(Default)]
pub(crate) struct DeniedDrives {
    seen: HashMap<(String, String, String), Instant>,
}

impl DeniedDrives {
    fn key(agent: &str, drive: &str, origin: &str) -> (String, String, String) {
        (agent.to_string(), drive.to_string(), origin.trim_end_matches('/').to_string())
    }

    pub(crate) fn deny(&mut self, agent: &str, drive: &str, origin: &str, now: Instant) {
        self.seen.insert(Self::key(agent, drive, origin), now);
    }

    /// `Some(reason)` while the refusal is remembered.
    pub(crate) fn check(&mut self, agent: &str, drive: &str, origin: &str, now: Instant) -> Option<String> {
        let key = Self::key(agent, drive, origin);
        match self.seen.get(&key) {
            Some(at) if now.saturating_duration_since(*at) < DENIED_TTL => {
                tracing::debug!("[ws_sync] {drive} on {origin}: refused before, not asked again");
                Some(format!("{drive} is not readable on {origin} (401/403, remembered)"))
            }
            Some(_) => {
                self.seen.remove(&key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn is_denied_anywhere(&self, agent: &str, drive: &str, now: Instant) -> bool {
        self.seen.iter().any(|((a, d, _), at)| {
            a == agent && d == drive && now.saturating_duration_since(*at) < DENIED_TTL
        })
    }

    pub(crate) fn clear(&mut self) {
        self.seen.clear();
    }
}

#[cfg(test)]
mod denied_tests {
    use super::*;

    #[test]
    fn detects_refusals() {
        assert!(is_access_denied("Status: 401 Unauthorized, not publicly readable"));
        assert!(!is_access_denied("GET timed out"));
    }

    #[test]
    fn drive_is_tried_on_its_own_host_only() {
        let d = "https://atomicdata.dev/drive/0PXBdxdX";
        assert!(drive_belongs_to_origin(d, "https://atomicdata.dev"));
        assert!(!drive_belongs_to_origin(d, "https://staging.atomicdata.dev/"));
        assert!(drive_belongs_to_origin("did:ad:abc", "https://staging.atomicdata.dev"));
    }

    #[test]
    fn refusal_is_remembered_per_agent_drive_origin_until_ttl_or_clear() {
        let mut m = DeniedDrives::default();
        let t0 = Instant::now();
        let (d, o) = ("https://atomicdata.dev/drive/x", "https://atomicdata.dev");
        assert!(m.check("me", d, o, t0).is_none());
        m.deny("me", d, o, t0);
        assert!(m.check("me", d, o, t0 + Duration::from_secs(60)).is_some());
        assert!(m.check("other", d, o, t0).is_none(), "another agent asks again");
        assert!(m.check("me", d, "https://elsewhere", t0).is_none());
        assert!(m.is_denied_anywhere("me", d, t0));
        assert!(m.check("me", d, o, t0 + DENIED_TTL + Duration::from_secs(1)).is_none());
        m.deny("me", d, o, t0);
        m.clear();
        assert!(m.check("me", d, o, t0).is_none());
    }
}
