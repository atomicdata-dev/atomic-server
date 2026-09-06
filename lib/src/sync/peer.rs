//! Iroh peer-to-peer transport for the v2 binary protocol.
//!
//! Any device running atomic-lib with the `iroh` feature becomes a peer node.
//! Peers connect via NodeID — no port forwarding, DNS, or TLS needed.
//!
//! Addressing (relay URL, direct addresses) is handled by Iroh's `discovery_n0()`.
//! Peer discovery (agent → NodeID) is handled by pkarr in `discovery.rs`.
//!
//! Wire format is the same v2 protocol used over WebSocket; see
//! `docs/src/websockets.md` (canonical spec) and [`super::protocol`] for
//! tags / encoders. The one extension peer streams add on top of the
//! browser-WS subset is the `HELLO (0x37)` device-name handshake sent
//! immediately after `AUTH_OK` — see `encode_hello` / `decode_hello` in
//! [`super::protocol`].

use crate::{agents::ForAgent, Db, Storelike};
use iroh::{protocol::Router, Endpoint, NodeId};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Map Iroh I/O errors to AtomicError.
fn io_err(e: impl std::fmt::Display) -> crate::errors::AtomicError {
    format!("Iroh I/O error: {e}").into()
}

/// ALPN protocol identifier for Atomic Data over Iroh.
pub(crate) const ATOMIC_ALPN: &[u8] = b"atomic/1";

/// Canonical 64-char lowercase hex NodeID for map keys and UI matching.
pub fn normalize_node_id(id: &str) -> String {
    let mut s = id.trim().to_string();
    if let Some(rest) = s.strip_prefix("did:ad:node:") {
        s = rest.split(':').next().unwrap_or(rest).to_string();
    } else if let Some(rest) = s.strip_prefix("iroh:") {
        s = rest.to_string();
    }
    s.to_lowercase()
}

/// Global NodeID, set once on startup.
static NODE_ID: OnceLock<String> = OnceLock::new();

/// Resolve the device name this node announces in `HELLO` frames.
///
/// Order of precedence:
///  1. Whatever is persisted via [`set_device_name`] (flutter app UI, server
///     `--device-name` / `ATOMIC_DEVICE_NAME` written at startup).
///  2. The OS hostname (`gethostname()`).
///  3. The literal `"Unknown"`.
///
/// Truncates to [`crate::sync::protocol::HELLO_MAX_CHARS`] scalar values
/// so a misconfigured peer can't drive the on-wire length cap into reject.
pub fn effective_device_name(store: &Db) -> String {
    let from_db = get_device_name(store);
    let raw = if !from_db.trim().is_empty() {
        from_db
    } else {
        hostname::get()
            .ok()
            .and_then(|os| os.into_string().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unknown".to_string())
    };
    let max = super::protocol::HELLO_MAX_CHARS;
    if raw.chars().count() > max {
        raw.chars().take(max).collect()
    } else {
        raw
    }
}

/// Returns the Iroh NodeID if the peer node is running.
pub fn get_node_id() -> Option<&'static str> {
    NODE_ID.get().map(|s| s.as_str())
}

/// Key used to persist the Iroh secret key in the DB.
const IROH_SECRET_KEY: &[u8] = b"_iroh_secret_key";
const DEVICE_NAME_KEY: &[u8] = b"_device_name";

/// Get the persisted device name.
pub fn get_device_name(store: &Db) -> String {
    store
        .kv
        .get(crate::db::trees::Tree::PluginMeta, DEVICE_NAME_KEY)
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

/// Set the device name (persisted in DB).
pub fn set_device_name(store: &Db, name: &str) {
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        DEVICE_NAME_KEY,
        name.as_bytes(),
    );
}

/// Load or generate a persistent Iroh secret key.
/// Stored in the DB so the NodeID survives app restarts.
fn load_or_create_secret_key(store: &Db) -> iroh::SecretKey {
    if let Ok(Some(bytes)) = store
        .kv
        .get(crate::db::trees::Tree::PluginMeta, IROH_SECRET_KEY)
    {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return iroh::SecretKey::from_bytes(&arr);
        }
    }
    // Generate and persist. Flush immediately: kv writes use Durability::None
    // (no fsync per commit), which redb rolls back on an unclean kill unless a
    // later durable commit lands. This node's identity is written exactly once
    // and must survive the very next app kill — otherwise every restart mints a
    // new NodeID, the paired server is effectively a stranger again, and the
    // user has to re-scan the QR. A one-time fsync here is well worth that.
    let key = iroh::SecretKey::generate(rand::rngs::OsRng);
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        IROH_SECRET_KEY,
        &key.to_bytes(),
    );
    let _ = store.flush();
    key
}

/// Start the Iroh peer node. Returns the NodeID and a Router that must be kept alive.
///
/// The NodeID is persistent — derived from a secret key stored in the DB.
/// Waits for the relay connection to be established before returning,
/// so that other peers can discover and connect to us immediately.
pub async fn start(store: Db) -> anyhow::Result<(NodeId, Router)> {
    let secret_key = load_or_create_secret_key(&store);
    let endpoint: Endpoint = Endpoint::builder()
        .secret_key(secret_key)
        // n0 discovery (relay + pkarr) reaches devices across networks, but two
        // devices on the same Wi-Fi should not have to round-trip through a
        // relay and hope hole-punching succeeds — which is exactly what fails on
        // restrictive/mobile networks (a tablet dialing a phone by the QR's node
        // id timed out). Local mDNS discovery lets same-LAN peers find and dial
        // each other directly.
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await?;

    let node_id = endpoint.node_id();
    NODE_ID.set(node_id.to_string()).ok();
    ENDPOINT.set(endpoint.clone()).ok();

    // Wait for relay connection so discovery_n0 can find us
    let relay = endpoint.home_relay();
    tracing::info!("Iroh NodeID: {node_id}, waiting for relay...");
    let relay_url =
        tokio::time::timeout(std::time::Duration::from_secs(10), wait_for_relay(relay)).await;
    match relay_url {
        Ok(Some(url)) => tracing::info!("Iroh relay connected: {url}"),
        Ok(None) => tracing::warn!("Iroh relay: none (direct connections only)"),
        Err(_) => tracing::warn!("Iroh relay: timed out after 10s (connections may fail)"),
    }

    let bg_store = store.clone();
    let router = Router::builder(endpoint)
        .accept(ATOMIC_ALPN, AtomicHandler { store })
        .spawn();

    // Keep router alive globally — dropping it stops incoming connections
    ROUTER.set(router.clone()).ok();

    // Start live sync — watches for local changes, pushes to connected peers
    start_live_sync(bg_store.clone());

    // Auto-connect to known peers in background, retry until connected
    let auto_store = bg_store;
    tokio::spawn(async move {
        let my_id = normalize_node_id(get_node_id().unwrap_or_default());

        // Brief delay so relay can register our NodeID
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        loop {
            let drive = match auto_store.get_active_drive() {
                Some(d) => d,
                None => {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
            };
            let peers = get_known_peers(&auto_store);
            if peers.is_empty() {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            let mut all_connected = true;
            for peer in &peers {
                if normalize_node_id(&peer.node_id) == my_id {
                    continue;
                }
                let peer_key = normalize_node_id(&peer.node_id);
                if live_peer_ids().contains(&peer_key) {
                    continue;
                }

                // Prefer the device with the smaller NodeID to dial first (avoids
                // duplicate handshakes). The larger NodeID waits briefly, then
                // also dials if still offline — otherwise one side never connects
                // when relay discovery is flaky.
                if normalize_node_id(&my_id) > peer_key {
                    if live_peer_ids().contains(&peer_key) {
                        continue;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    if live_peer_ids().contains(&peer_key) {
                        continue;
                    }
                }

                all_connected = false;
                tracing::info!(
                    "[auto_connect] connecting to {}",
                    &peer.node_id[..peer.node_id.len().min(12)]
                );
                match sync_drive_with_peer_if_needed(&peer.node_id, &drive, &auto_store).await {
                    Ok(count) => {
                        tracing::info!(
                            "[auto_connect] synced {count} resources, live connection established"
                        );
                    }
                    Err(e) => {
                        tracing::debug!("[auto_connect] failed: {e}");
                    }
                }
            }

            if all_connected {
                // All peers connected — wait and check periodically for disconnects or new peers
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            } else {
                // Some peers failed — retry sooner
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    Ok((node_id, router))
}

/// Wait until the relay watcher emits a Some(url).
async fn wait_for_relay(
    mut watcher: iroh::watchable::Watcher<Option<iroh::RelayUrl>>,
) -> Option<iroh::RelayUrl> {
    // Check current value first
    if let Ok(Some(url)) = watcher.get() {
        return Some(url);
    }
    // Wait for next update
    loop {
        if watcher.updated().await.is_err() {
            return None;
        }
        if let Ok(Some(url)) = watcher.get() {
            return Some(url);
        }
    }
}

#[derive(Debug, Clone)]
struct AtomicHandler {
    store: Db,
}

impl iroh::protocol::ProtocolHandler for AtomicHandler {
    fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> futures::future::BoxFuture<'static, anyhow::Result<()>> {
        let store = self.store.clone();
        Box::pin(async move {
            let remote = connection.remote_node_id()?;
            let remote_str = normalize_node_id(&remote.to_string());
            tracing::info!("[accept] incoming connection from {remote_str}");

            // Accept the first (and only) bi stream for sync + live
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::info!("[accept] connection closed from {remote}: {e}");
                    return Ok(());
                }
            };

            // Handle initial sync, then transition to live mode on the same stream
            let store_clone = store.clone();
            let remote_id = remote_str.clone();
            match handle_stream(send, recv, store_clone, remote_id).await {
                Ok(imported) => {
                    push_event(&remote_str, imported, "sync");
                }
                Err(e) => {
                    tracing::warn!("[accept] stream error: {e}");
                }
            }

            Ok(())
        })
    }
}

/// Global endpoint, set once on startup. Needed for outgoing connections.
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

/// Global router, must be kept alive or incoming connections stop working.
static ROUTER: OnceLock<Router> = OnceLock::new();

// ── Live sync (persistent connections) ──────────────────────────────────

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Active outgoing send streams keyed by peer NodeID.
/// Used to push UPDATE frames to connected peers.
/// Value is `(connection generation, sender)`. The generation exists because a
/// reconnect installs a new entry under the SAME node id, and the old
/// connection's loops then tear down moments later. Keyed only by node id, that
/// teardown removed the entry the *new* connection had just installed — live
/// sync went silent while both ends still displayed "Connected", and nothing
/// recovered it until the next reconnect. Removal now only applies if the entry
/// still belongs to the connection asking to remove it.
static LIVE_PEERS: LazyLock<Mutex<HashMap<String, LivePeer>>> = LazyLock::new(Default::default);

/// One live peer: the write loop's channel, the generation that installed
/// it, and (dial side only) the QUIC connection kept alive for it. Dropping
/// the entry drops the connection, so a re-dial replaces the link it
/// supersedes and a removed peer releases it; before 2026-09 connections
/// were pinned in a separate append-only list for the life of the process.
struct LivePeer {
    generation: u64,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Never read; held so the QUIC connection stays open exactly as long
    /// as the registration does.
    _connection: Option<iroh::endpoint::Connection>,
}

/// Monotonic id per live connection; see [`LIVE_PEERS`].
static LIVE_PEER_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What live peers call themselves, learnt over HELLO.
///
/// In memory, not in the known-peers table: writing a name there marks a peer
/// as one to dial again forever, which an unsolicited inbound connection has
/// not earned (F9, planning/unified-sync.md). Saying who is connected right
/// now grants nothing — it ends when the connection does.
static LIVE_PEER_NAMES: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Default::default);

/// Remember what a connected peer calls itself, for as long as it is connected.
pub fn set_live_peer_name(peer_id: &str, name: &str) {
    if name.is_empty() {
        return;
    }

    if let Ok(mut guard) = LIVE_PEER_NAMES.lock() {
        guard.insert(normalize_node_id(peer_id), name.to_string());
    }
}

/// What a live peer calls itself, if it said.
pub fn live_peer_name(peer_id: &str) -> Option<String> {
    LIVE_PEER_NAMES
        .lock()
        .ok()
        .and_then(|guard| guard.get(&normalize_node_id(peer_id)).cloned())
}

/// Returns the number of currently connected live peers.
pub fn live_peer_count() -> usize {
    LIVE_PEERS.lock().map(|m| m.len()).unwrap_or(0)
}

/// Returns the node IDs of currently connected live peers.
pub fn live_peer_ids() -> Vec<String> {
    LIVE_PEERS
        .lock()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Drop a live peer entry (dead write loop, closed channel, or reconnect).
///
/// `generation` is the connection doing the removing: a stale connection must
/// not evict the entry a newer one installed under the same node id.
pub fn remove_live_peer(peer_id: &str, generation: u64) {
    remove_live_peer_inner(peer_id, Some(generation), true);
}

/// Evict whatever connection is current, whoever installed it. For a deliberate
/// reconnect, where the caller means "drop the existing link" rather than "my
/// own connection ended".
fn remove_live_peer_any_quiet(peer_id: &str) {
    remove_live_peer_inner(peer_id, None, false);
}

/// Evict the current connection and tell the UI. For an explicit user action —
/// "Disconnect" / forget this peer — where the intent is to drop the link
/// whichever connection happens to hold it.
pub fn remove_live_peer_any(peer_id: &str) {
    remove_live_peer_inner(peer_id, None, true);
}

fn remove_live_peer_inner(peer_id: &str, generation: Option<u64>, notify: bool) {
    let key = normalize_node_id(peer_id);
    // Take the entry out under the lock and drop it (connection included)
    // after; the superseding-connection case is excluded, so this never
    // closes a link a newer registration is using.
    let removed = LIVE_PEERS.lock().ok().and_then(|mut map| {
        let is_current = match generation {
            Some(generation) => map.get(&key).is_some_and(|p| p.generation == generation),
            None => true,
        };
        if is_current {
            map.remove(&key)
        } else {
            if map.contains_key(&key) {
                tracing::debug!(
                    "[live] stale connection for {} tried to deregister a newer one — ignored",
                    &key[..key.len().min(12)]
                );
            }
            None
        }
    });
    if let Some(peer) = removed {
        drop(peer);
        tracing::info!("[live] removed peer {}", &key[..key.len().min(12)]);
        if notify {
            push_event(&key, 0, "disconnected");
        }
    }
}

static LAST_EVENT_MS: OnceLock<std::sync::Mutex<std::collections::HashMap<(String, String), u64>>> =
    OnceLock::new();

const EVENT_DEBOUNCE_MS: u64 = 15_000;

fn last_event_ms() -> &'static std::sync::Mutex<std::collections::HashMap<(String, String), u64>> {
    LAST_EVENT_MS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Returns true if we're currently importing data from a remote peer.
pub fn is_importing() -> bool {
    super::ws_apply::is_importing()
}

fn encode_live_update_wire_msg(subject_key: &str, loro_bytes: &[u8]) -> Vec<u8> {
    let frame = super::protocol::encode_update(0, 0, subject_key, None, loro_bytes);
    let len = frame.len() as u32;
    let mut msg = Vec::with_capacity(4 + frame.len());
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&frame);
    msg
}

/// This device's own agent resource as a live UPDATE wire message, or `None`
/// when there's no default agent or it has no stored snapshot yet.
///
/// The agent resource (`did:ad:agent:…`) is owned by itself and sits outside
/// every drive's subtree, so drive sync — which walks the `parent` index down
/// from a drive root — never carries it. That left a freshly signed-in device
/// with a nameless stub agent and an empty `drives` list (you couldn't switch
/// back to a drive you'd just synced, because the switcher reads
/// `agent.drives`). Two same-agent devices are mutually authenticated and each
/// may write the shared agent resource (`hierarchy::check_write`: "Agents can
/// always edit themselves"), so handing it over as an ordinary UPDATE lets both
/// merge its Loro state — `name` converges last-writer-wins, `drives` unions.
fn own_agent_update_frame(store: &Db) -> Option<Vec<u8>> {
    let agent = store.get_default_agent().ok()?;
    let key = crate::Subject::from_raw(
        &agent.subject.to_string(),
        store.get_base_domain().as_deref(),
    )
    .pure_id();
    let snapshot = store
        .kv
        .get(crate::db::trees::Tree::LoroSnapshots, key.as_bytes())
        .ok()
        .flatten()
        .filter(|b| !b.is_empty())?;
    Some(encode_live_update_wire_msg(&key, &snapshot))
}

/// Fan an UPDATE out to live peers, except `skip_peer` — the peer an imported
/// update came from. Sending it back is what made two idle nodes trade the same
/// snapshot indefinitely.
fn send_live_update_wire_msg_except(msg: Vec<u8>, skip_peer: Option<&str>) {
    let mut dead_peers = Vec::new();
    let peers = LIVE_PEERS.lock().unwrap();
    {
        for (peer_id, LivePeer { generation, tx, .. }) in peers.iter() {
            if skip_peer.is_some_and(|skip| normalize_node_id(skip) == *peer_id) {
                continue;
            }

            match tx.try_send(msg.clone()) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(m)) => {
                    let peer = peer_id.clone();
                    let tx_retry = tx.clone();
                    tokio::spawn(async move {
                        if tx_retry.send(m).await.is_err() {
                            tracing::warn!(
                                "[live_sync] retry send failed for {}",
                                &peer[..peer.len().min(12)]
                            );
                        }
                    });
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    dead_peers.push((peer_id.clone(), *generation));
                }
            }
        }
    }
    drop(peers);
    for (peer_id, generation) in dead_peers {
        remove_live_peer(&peer_id, generation);
    }
}

/// Push live-collaboration state — presence, cursors, or the ops of an edit in
/// progress — to connected live peers. `kind` says which; see
/// `protocol::ephemeral_kind`.
///
/// `skip_peer` is the peer it arrived from, if this is a relay rather than a
/// local update — the same echo suppression `UPDATE` frames use, which matters
/// more here: these arrive at keystroke frequency, so a loop would saturate the
/// link far faster than resource changes ever could.
///
/// Nothing is stored and nothing is retried. If the channel is full the frame
/// is dropped, on the grounds that a stale cursor is better than a delayed
/// document — and that a dropped op costs a moment of divergence, which the
/// sender's next save repairs with a full snapshot.
pub fn broadcast_ephemeral(
    kind: u8,
    drive: &str,
    agent: &str,
    payload: &[u8],
    skip_peer: Option<&str>,
) {
    if payload.is_empty() || payload.len() > super::protocol::max_payload_for_kind(kind) {
        return;
    }

    let frame = super::protocol::encode_ephemeral(kind, drive, agent, payload);
    let len = frame.len() as u32;
    let mut msg = Vec::with_capacity(4 + frame.len());
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&frame);
    send_live_update_wire_msg_except(msg, skip_peer);
}

/// Push an UPDATE frame to all connected live peers immediately (e.g. after a stroke save).
pub fn broadcast_live_update(subject_key: &str, loro_bytes: &[u8]) {
    if loro_bytes.is_empty() || super::ws_apply::is_importing() {
        return;
    }
    let msg = encode_live_update_wire_msg(subject_key, loro_bytes);
    send_live_update_wire_msg_except(msg, None);
}

/// Start the live sync system. Watches for local changes and pushes to all connected peers.
fn start_live_sync(store: Db) {
    // Spawn the push loop: watches db_events, pushes deltas/destroys to live peers
    tokio::spawn(async move {
        let mut rx = store.subscribe_events();
        tracing::info!("[live_sync] push loop started");

        loop {
            let event = match rx.recv().await {
                Ok(e) => e,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    rx = store.subscribe_events();
                    continue;
                }
            };

            if super::ws_apply::is_importing() {
                continue;
            }

            let subject_key = match &event {
                crate::DbEvent::Changed { subject, .. }
                | crate::DbEvent::Destroyed { subject, .. } => subject.pure_id(),
                _ => continue,
            };

            // Never send an update back to the peer it arrived from.
            let from_peer: Option<String> = match &event {
                crate::DbEvent::Changed { source_id, .. }
                | crate::DbEvent::Destroyed { source_id, .. } => source_id.clone(),
                _ => None,
            };

            let loro_bytes: Option<Vec<u8>> = match &event {
                crate::DbEvent::Changed {
                    delta: Some(delta), ..
                } if !delta.is_empty() => Some(delta.clone()),
                crate::DbEvent::Changed { .. } => store
                    .kv
                    .get(
                        crate::db::trees::Tree::LoroSnapshots,
                        subject_key.as_bytes(),
                    )
                    .ok()
                    .flatten()
                    .filter(|b| !b.is_empty()),
                // A destroy crosses the link as the signed commit that caused
                // it (planning/serverless-p2p.md, principle 3): the peer
                // validates signature and rights exactly as for any other
                // `COMMIT`, so a naked `DESTROY` frame is neither sent nor
                // accepted (see the read loop). A removal no commit authorises
                // — a cascade-deleted child, a local eviction — is not
                // propagated live; the peer's own apply of the parent commit
                // cascades there too.
                crate::DbEvent::Destroyed {
                    commit_json: Some(commit_json),
                    ..
                } => {
                    let frame = super::protocol::encode_commit(0, commit_json);
                    let len = frame.len() as u32;
                    let mut msg = Vec::with_capacity(4 + frame.len());
                    msg.extend_from_slice(&len.to_be_bytes());
                    msg.extend_from_slice(&frame);
                    send_live_update_wire_msg_except(msg, from_peer.as_deref());
                    continue;
                }
                crate::DbEvent::Destroyed {
                    commit_json: None, ..
                } => {
                    tracing::debug!(
                        "[live] not propagating unsigned removal of {}",
                        &subject_key[..subject_key.len().min(20)]
                    );
                    continue;
                }
                _ => None,
            };

            if let Some(bytes) = loro_bytes {
                let msg = encode_live_update_wire_msg(&subject_key, &bytes);
                send_live_update_wire_msg_except(msg, from_peer.as_deref());
            }
        }
    });
}

/// Register a live peer connection. Spawns read/write loops.
/// Per-connection cache of drive-level write verdicts for live UPDATE/DESTROY
/// frames, so a burst of writes to the same drive (e.g. live typing in one
/// document) doesn't re-walk the rights hierarchy on every single frame.
/// Scoped to one connection's lifetime — a fresh connection re-evaluates from
/// scratch, which is exactly when a changed enrollment/rights grant should
/// take effect anyway.
/// Test window onto [admitted_for_drive] — the admission boundary the
/// agent-resource guard lives in — without standing up two Iroh endpoints and
/// forging a frame to reach it.
#[cfg(test)]
pub(crate) async fn admitted_for_drive_for_test(
    store: &Db,
    agent: &ForAgent,
    drive_subject: &str,
    trust_owned: bool,
    cache: &mut std::collections::HashMap<String, bool>,
) -> bool {
    admitted_for_drive(store, agent, drive_subject, trust_owned, cache).await
}

async fn admitted_for_drive(
    store: &Db,
    agent: &ForAgent,
    drive_subject: &str,
    trust_owned: bool,
    cache: &mut std::collections::HashMap<String, bool>,
) -> bool {
    if let Some(&verdict) = cache.get(drive_subject) {
        return verdict;
    }

    // Same split as `import_sync_push`: an existing drive is gated by
    // allowlist/quota then ACL; a drive we have never stored goes through
    // `admit_unknown_drive` (OQ5 — Public never creates, Owner enrolls only
    // the owner, Open still admits an authenticated first-sync).
    let drive_subj = crate::Subject::from_raw(drive_subject, store.get_base_domain().as_deref());
    let verdict = match store.get_resource(&drive_subj).await {
        Ok(drive_resource) => {
            if !store.sync_policy().admit_drive_write(drive_subject) {
                false
            } else {
                super::engine::may_accept_drive_write(store, &drive_resource, agent, trust_owned)
                    .await
            }
        }
        Err(_) => super::engine::admit_unknown_drive(store, drive_subject, agent),
    };

    cache.insert(drive_subject.to_string(), verdict);
    verdict
}

/// Apply one peer-supplied `SYNC_DIFF.remove[]` entry. A signed destroy
/// envelope (`removeCommits[subject]`) is applied as a peer `COMMIT` — the
/// signature and the signer's rights are the authority, same as the live
/// link. An unsigned entry (legacy tombstone, cascade child, sender without
/// the envelope) still goes through the drive-level admission + ACL check.
async fn apply_peer_remove(
    store: &Db,
    agent: &ForAgent,
    subject: &str,
    trust_owned: bool,
    drive_cache: &mut std::collections::HashMap<String, bool>,
    destroy_commit: Option<&str>,
) {
    if let Some(commit_json) = destroy_commit {
        match super::engine::ingest_commit_json(
            store,
            commit_json,
            &super::engine::CommitIngestOpts::peer(),
        )
        .await
        {
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(
                    "[sync] rejected signed SYNC_DIFF remove for {}: {e}",
                    crate::utils::truncate_string(subject, 30)
                );
                return;
            }
        }
    }

    match super::ws_apply::resolve_destroy_drive(store, subject).await {
        Some(drive_subject) => {
            if admitted_for_drive(store, agent, &drive_subject, trust_owned, drive_cache).await {
                let _ = super::ws_apply::apply_destroy(store, subject).await;
            } else {
                tracing::warn!(
                    "[sync] rejected SYNC_DIFF remove for {} from peer: not admitted for drive {}",
                    crate::utils::truncate_string(subject, 30),
                    crate::utils::truncate_string(&drive_subject, 30)
                );
            }
        }
        None => {
            let _ = super::ws_apply::apply_destroy(store, subject).await;
        }
    }
}

/// Clear `drive_cache` when `agent` no longer matches `previous` — a late
/// AUTH frame mid-connection (see the `handle_frame` fallback dispatch in
/// `register_live_peer`'s read loop) can change the session's identity, and
/// verdicts cached under the old identity are stale. Most consequential
/// case: a `Public` verdict cached before AUTH would otherwise keep
/// rejecting a drive for the rest of the connection even after the peer
/// proves a stronger identity via a subsequent AUTH.
fn invalidate_drive_cache_on_identity_change(
    agent: &ForAgent,
    previous: &ForAgent,
    drive_cache: &mut std::collections::HashMap<String, bool>,
) {
    if agent != previous {
        drive_cache.clear();
    }
}

fn register_live_peer(
    peer_id: String,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    store: Db,
    agent: ForAgent,
    // True when WE dialed this peer. Lets updates to a drive we own through
    // even when the relaying peer is a different agent (a server holding our
    // drive) — see `may_accept_drive_write`. Never relaxed for peers that
    // dialed into us.
    initiated_by_us: bool,
    // Dial side: the QUIC connection this stream lives on, kept alive with
    // the registration so the live stream is not dropped under it. The
    // accept side's connection is owned by the protocol handler.
    connection: Option<iroh::endpoint::Connection>,
) {
    let key = normalize_node_id(&peer_id);
    // F9 minimal (planning/unified-sync.md): this function upgrades BOTH
    // the initiator's own explicitly-dialed connection AND an accept-side
    // connection into live mode — it must not unconditionally register
    // `key` as a known peer, since the auto-connect loop (`start`'s
    // background task) treats "known" as "retry-forever." An unsolicited
    // inbound connection getting auto-registered here meant any Iroh node
    // that discovered and connected to us earned a permanent reconnect
    // slot with zero pairing/consent. The initiator side already records
    // the peer via its own HELLO handler in
    // `sync_drive_with_peer_using_outcome` (an explicit, user-initiated
    // action); nothing here needs to duplicate that.

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    // Cloned for the read loop so it can send responses (e.g. BLOB_RESPONSE
    // back to the requester) through the same write loop.
    let tx_for_read = tx.clone();

    // Add to peer map — replace if already connected (incoming may supersede outgoing)
    let generation = LIVE_PEER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let is_new_peer = {
        let mut map = LIVE_PEERS.lock().unwrap();
        let replacing = map.contains_key(&key);
        if replacing {
            tracing::info!(
                "[live] replacing existing connection to {}",
                &key[..key.len().min(12)]
            );
        }
        // Dropping the replaced entry closes the connection it pinned.
        let _replaced = map.insert(
            key.clone(),
            LivePeer {
                generation,
                tx,
                _connection: connection,
            },
        );
        !replacing
    };

    let peer_short = key[..key.len().min(12)].to_string();
    tracing::info!("[live] registered peer {peer_short} (new={is_new_peer})");
    // Always notify so both sides refresh UI (replacing a dead channel still counts).
    push_event(&key, 0, "connected");

    // Hand the peer our own agent resource on connect. It lives outside every
    // drive's subtree, so drive sync never carries it (see
    // `own_agent_update_frame`) — and yet it is the resource that says who owns
    // which drive. A device signing in with a secret has the key and no name,
    // no drive list, until this arrives; a server holding a drive for you can't
    // tell a browser whose it is without it. So it always goes.
    //
    // It is our OWN identity only (`get_default_agent`), self-authored, so
    // handing it over grants nothing — and the receiver admits an agent
    // resource only from that agent (see `admitted_for_drive`), so nobody can
    // forge someone else's from it. What it does reveal is our name and drive
    // DIDs, to a peer we authenticated with; that is the point, not a leak.
    if let Some(frame) = own_agent_update_frame(&store) {
        let _ = tx_for_read.try_send(frame);
    }

    // Write loop: sends queued UPDATE frames to the peer
    let write_peer_id = key.clone();
    tokio::spawn(async move {
        tracing::info!(
            "[live] write loop started for {}",
            &write_peer_id[..write_peer_id.len().min(12)]
        );
        loop {
            // Send a KEEPALIVE whenever there is nothing else to say, so the
            // peer can tell an idle link from a dead one. Without traffic the
            // far side has no way to distinguish "quiet" from "gone", and a
            // half-open connection survives until some lower layer eventually
            // notices — 15 minutes, in the case this was written for.
            let msg =
                match tokio::time::timeout(super::protocol::KEEPALIVE_INTERVAL, rx.recv()).await {
                    Ok(Some(msg)) => msg,
                    // Channel closed: the peer was deregistered.
                    Ok(None) => break,
                    Err(_) => super::protocol::encode_keepalive_wire_msg(),
                };

            match send.write_all(&msg).await {
                Ok(_) => {
                    tracing::trace!(
                        "[live] wrote {} bytes to {}",
                        msg.len(),
                        &write_peer_id[..write_peer_id.len().min(12)]
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "[live] write failed to {}: {e}",
                        &write_peer_id[..write_peer_id.len().min(12)]
                    );
                    break;
                }
            }
        }
        tracing::info!(
            "[live] write loop ended for {}",
            &write_peer_id[..write_peer_id.len().min(12)]
        );
        remove_live_peer(&write_peer_id, generation);
    });

    // Read loop: receives UPDATE frames from the peer, imports them
    let read_peer_id = key.clone();
    tokio::spawn(async move {
        tracing::info!(
            "[live] read loop started for {} as {agent:?}",
            &read_peer_id[..read_peer_id.len().min(12)]
        );
        // Mutable so a late AUTH frame (a well-behaved peer already sends one
        // during the handshake, but the protocol allows it at any point) can
        // strengthen the session's identity for the rest of the connection —
        // used consistently by both the UPDATE/DESTROY gate below and the
        // generic fallback dispatch, instead of each re-deciding independently.
        let mut agent = agent;
        let mut drive_cache: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        // Whether this peer has ever sent a KEEPALIVE. Older builds do not, and
        // silence from them means nothing — tearing the link down on a timeout
        // would turn every working idle connection to an older peer into a
        // 35-second reconnect loop. Observed for real against a peer that had
        // not been upgraded yet: 10 teardowns in as many minutes, each followed
        // by a full reconnect. So the timeout only becomes a liveness signal
        // once the peer has shown it speaks it.
        let mut peer_sends_keepalives = false;
        loop {
            // Silence is treated as death, not idleness. A half-open link is
            // otherwise invisible: this side keeps believing it is connected,
            // so `auto_connect` will not redial it (it skips peers already in
            // `live_peer_ids`) and every local change is broadcast into a
            // socket nobody reads — with no error anywhere. The peer sends a
            // KEEPALIVE every `KEEPALIVE_INTERVAL`, so hearing nothing for
            // `LIVENESS_TIMEOUT` means the connection is gone.
            let read =
                tokio::time::timeout(super::protocol::LIVENESS_TIMEOUT, recv.read_u32()).await;

            let len = match read {
                Ok(Ok(n)) => {
                    tracing::trace!(
                        "[live] received frame {} bytes from {}",
                        n,
                        &read_peer_id[..read_peer_id.len().min(12)]
                    );
                    n as usize
                }
                Ok(Err(e)) => {
                    tracing::info!(
                        "[live] read error from {}: {e}",
                        &read_peer_id[..read_peer_id.len().min(12)]
                    );
                    break;
                }
                Err(_) if peer_sends_keepalives => {
                    tracing::info!(
                        "[live] no traffic from {} for {:?} — treating the link as dead",
                        &read_peer_id[..read_peer_id.len().min(12)],
                        super::protocol::LIVENESS_TIMEOUT
                    );
                    break;
                }
                Err(_) => {
                    // Never heard a keepalive from this peer, so its silence
                    // carries no information. Keep waiting rather than
                    // manufacture a disconnect.
                    tracing::debug!(
                        "[live] {} is quiet and sends no keepalives — not assuming it is dead",
                        &read_peer_id[..read_peer_id.len().min(12)]
                    );
                    continue;
                }
            };
            // Same "no proven identity → tight budget" rule as the accept-side
            // dispatch loop (`handle_stream`): a connection can reach live
            // mode while still `ForAgent::Public` — an unauthenticated peer
            // that completes the sync handshake transitions into live mode
            // with whatever agent it has, which may be none. Gate on the
            // loop's own (mutable, AUTH-updatable) `agent`, not a flat cap.
            let frame_cap = if matches!(agent, ForAgent::Public) {
                super::protocol::IROH_PREAUTH_FRAME_MAX_BYTES
            } else {
                super::protocol::IROH_FRAME_MAX_BYTES
            };
            if len == 0 || len > frame_cap {
                break;
            }

            let mut buf = vec![0u8; len];
            if recv.read_exact(&mut buf).await.is_err() {
                break;
            }

            if buf.is_empty() {
                continue;
            }

            // Keepalive: nothing to do. Receiving it already did the job —
            // it reset the liveness timeout above.
            if buf[0] == super::protocol::tag::KEEPALIVE {
                peer_sends_keepalives = true;
                continue;
            }

            // Fail closed on identity (planning/serverless-p2p.md, principle 5):
            // a peer that dialed us and never proved who it is gets no live
            // frame processed — not even as `Public`. `handle_stream` already
            // refuses to reach live mode without an AUTH, so this is the same
            // rule restated where the frames actually land, in case the two
            // ever drift. Only for connections dialed *into* us: on the dial
            // side `agent` is the remote's best-effort auth-back, and every
            // write there is gated on our own ownership (`initiated_by_us`).
            if !initiated_by_us
                && matches!(agent, ForAgent::Public)
                && buf[0] != super::protocol::tag::AUTH
            {
                tracing::warn!(
                    "[live] closing: 0x{:02x} from {} before AUTH",
                    buf[0],
                    &read_peer_id[..read_peer_id.len().min(12)]
                );
                let _ = tx_for_read
                    .send(frame_with_len(&auth_required_error(buf[0])))
                    .await;
                break;
            }

            // The peer answered something we sent (a SYNC_PUSH it refused, a
            // BLOB_REQUEST it couldn't serve) with an ERROR. Nothing to apply;
            // say so and keep the link — an ERROR is a verdict, not a fault.
            if buf[0] == super::protocol::tag::ERROR {
                let msg = std::str::from_utf8(buf.get(5..).unwrap_or(&[])).unwrap_or("(non-utf8)");
                tracing::warn!(
                    "[live] {} answered with an error: {msg}",
                    &read_peer_id[..read_peer_id.len().min(12)]
                );
                continue;
            }

            // Live collaboration: presence, cursors, and the ops of an edit in
            // progress. Handled before every other frame type and returned from
            // immediately, because the one thing none of it may do is reach the
            // store: the paths below all end in a write, and cursor positions
            // merged into the CRDT would persist and sync forever. Uncommitted
            // ops become durable only if a local user saves the document they
            // land in, which produces a signed commit under that user's own
            // identity.
            //
            // Two different gates, because the kinds ask for different things.
            // Presence and cursors disclose who is looking at what, so a peer
            // that cannot read must not receive them — but they author nothing,
            // so read is enough. Uncommitted ops are somebody else's characters
            // appearing in a document, so those need write: a peer with read
            // access has no business putting text in front of an editor as
            // though it belonged there.
            if buf[0] == super::protocol::tag::EPHEMERAL {
                if let Some(decoded) = super::protocol::decode_ephemeral(&buf[1..]) {
                    let scope_subj = crate::Subject::from_raw(
                        &decoded.drive,
                        store.get_base_domain().as_deref(),
                    );

                    let admitted = if decoded.kind == super::protocol::ephemeral_kind::DOC {
                        // `None` means the resource isn't stored here: nothing
                        // to check rights against, and no local editor that
                        // could have it open either.
                        match super::ws_apply::resolve_destroy_drive(&store, &decoded.drive).await {
                            Some(drive_subject) => {
                                admitted_for_drive(
                                    &store,
                                    &agent,
                                    &drive_subject,
                                    initiated_by_us,
                                    &mut drive_cache,
                                )
                                .await
                            }
                            None => false,
                        }
                    } else {
                        match store.get_resource(&scope_subj).await {
                            Ok(scope_resource) => {
                                crate::hierarchy::check_read(&store, &scope_resource, &agent)
                                    .await
                                    .is_ok()
                            }
                            // A drive we do not hold has nothing to disclose.
                            Err(_) => false,
                        }
                    };

                    if admitted {
                        store.publish_ephemeral(crate::db::EphemeralEvent {
                            kind: decoded.kind,
                            drive: decoded.drive,
                            agent: decoded.agent,
                            payload: decoded.payload,
                            from_peer: read_peer_id.clone(),
                        });
                    } else {
                        tracing::debug!(
                            "[live] dropped a kind-{} frame {} is not admitted for",
                            decoded.kind,
                            &read_peer_id[..read_peer_id.len().min(12)]
                        );
                    }
                }

                continue;
            }

            // A naked DESTROY frame carries no signature and no signer: the
            // only thing it could be checked against is the connection's
            // drive-level write verdict, which is not what authorises a
            // delete (planning/serverless-p2p.md, principle 3; unified-sync
            // OQ4). Peers send destroys as signed `COMMIT` frames, which the
            // fallback dispatch below validates like any other commit. So
            // this frame is ignored — logged, never applied, whoever sent it.
            if buf[0] == super::protocol::tag::DESTROY {
                let subject = buf
                    .get(3..)
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .unwrap_or_default();
                tracing::warn!(
                    "[live] ignoring naked DESTROY for {} from {}: destroys must arrive as signed COMMIT frames",
                    &subject[..subject.len().min(20)],
                    &read_peer_id[..read_peer_id.len().min(12)]
                );
                continue;
            }

            // Handle UPDATE frames. Gated the same way as DESTROY above.
            // Authoritative source of truth for the wire format: [docs/src/websockets.md](file:///Users/joep/dev/atomic-server/docs/src/websockets.md)
            if buf[0] == super::protocol::tag::UPDATE {
                if let Some(decoded) = super::protocol::decode_update(&buf[1..]) {
                    if !decoded.loro_bytes.is_empty() {
                        if let Some(resolved) = super::ws_apply::resolve_update(
                            &store,
                            &decoded.subject,
                            &decoded.loro_bytes,
                        )
                        .await
                        {
                            if admitted_for_drive(
                                &store,
                                &agent,
                                &resolved.drive_subject,
                                initiated_by_us,
                                &mut drive_cache,
                            )
                            .await
                            {
                                // Hold the importing flag across EVERY live
                                // import so the push loop doesn't re-broadcast
                                // what we just received — an unconditional
                                // re-send of an identical snapshot ping-pongs
                                // between the two nodes.
                                //
                                // This used to apply only when the subject was
                                // this node's own agent, which suppressed the
                                // echo on exactly one side: the device whose
                                // agent it is stays quiet, the peer for whom it
                                // is a stranger's agent re-sends it, and a drive
                                // — nobody's own agent — echoes on both. Two
                                // idle nodes then traded ~8.6KB frames
                                // indefinitely (measured: 355 frames in 58s,
                                // ~50KB/s, for one agent resource and one
                                // drive).
                                //
                                // The WS announcer ignores this flag, so the
                                // local browser still sees the merged state.
                                //
                                // A global mute is the blunt version of this:
                                // `DbEvent` already carries `source_id`, so the
                                // push loop could instead skip only the peer the
                                // update came from, and never mute a concurrent
                                // local edit. That needs `persist_update` to
                                // take a source and the push loop to read it.
                                // Attribute this write to the peer it came
                                // from. `add_resource_opts` reads it while the
                                // write is still on the stack and stamps it on
                                // the `DbEvent`, so the push loop can skip that
                                // one peer rather than muting every broadcast
                                // for the duration of an import.
                                super::ws_apply::set_import_source(Some(read_peer_id.clone()));
                                super::ws_apply::set_importing(true);
                                let _ = super::ws_apply::persist_update(
                                    &store,
                                    &decoded.subject,
                                    resolved,
                                )
                                .await;
                                super::ws_apply::set_importing(false);
                                super::ws_apply::set_import_source(None);
                                tracing::trace!(
                                    "[live] imported update for {} from {}",
                                    &decoded.subject[..decoded.subject.len().min(20)],
                                    &read_peer_id[..read_peer_id.len().min(12)]
                                );
                            } else {
                                tracing::warn!(
                                    "[live] rejected UPDATE for {} from {}: not admitted for drive {}",
                                    &decoded.subject[..decoded.subject.len().min(20)],
                                    &read_peer_id[..read_peer_id.len().min(12)],
                                    &resolved.drive_subject[..resolved.drive_subject.len().min(20)]
                                );
                            }
                        }
                    }
                }
                continue;
            }

            // Fallback: any unhandled tag (BLOB_REQUEST, BLOB_RESPONSE, future
            // additions) is dispatched through the sync engine, mirroring the
            // WS handler at server/src/handlers/web_sockets.rs. Live mode and
            // handshake mode share the same protocol surface; the read loop
            // shouldn't be selective about which tags it understands.
            //
            // Uses the session's own (mutable) agent, not a fresh Public one:
            // a SYNC_PUSH arriving in live mode must be checked as whoever
            // this connection actually authenticated as — dispatching as
            // Public here would silently downgrade every fallback-routed
            // frame regardless of the AUTH this connection already completed
            // (or a later AUTH mid-session, which this call can apply).
            let agent_before_frame = agent.clone();
            let responses = super::engine::handle_frame(&buf, &store, &mut agent).await;
            invalidate_drive_cache_on_identity_change(
                &agent,
                &agent_before_frame,
                &mut drive_cache,
            );
            for response in responses {
                let mut framed = Vec::with_capacity(4 + response.len());
                framed.extend_from_slice(&(response.len() as u32).to_be_bytes());
                framed.extend_from_slice(&response);
                if tx_for_read.send(framed).await.is_err() {
                    tracing::warn!(
                        "[live] response channel closed for {}, dropping responses",
                        &read_peer_id[..read_peer_id.len().min(12)]
                    );
                    break;
                }
            }
        }

        remove_live_peer(&read_peer_id, generation);
    });
}

// ── Sync events (notifies UI of incoming connections) ────────────────────

/// A sync event that the UI can poll for.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncEvent {
    pub remote_node_id: String,
    pub resources_imported: usize,
    pub timestamp: u64,
    /// "sync", "connected", "disconnected"
    #[serde(default = "default_event_kind")]
    pub kind: String,
}

#[allow(dead_code)] // Used via #[serde(default = "...")] attribute above
fn default_event_kind() -> String {
    "sync".into()
}

static SYNC_EVENT_TX: OnceLock<tokio::sync::broadcast::Sender<SyncEvent>> = OnceLock::new();

fn get_event_tx() -> &'static tokio::sync::broadcast::Sender<SyncEvent> {
    SYNC_EVENT_TX.get_or_init(|| tokio::sync::broadcast::channel(32).0)
}

fn push_event(remote_node_id: &str, resources_imported: usize, kind: &str) {
    let now = crate::utils::now() as u64;
    let key = (remote_node_id.to_string(), kind.to_string());
    // Never debounce `connected` — both devices must refresh live-peer UI.
    if kind != "connected" {
        if let Ok(mut last) = last_event_ms().lock() {
            if let Some(&prev) = last.get(&key) {
                if now.saturating_sub(prev) < EVENT_DEBOUNCE_MS {
                    tracing::debug!(
                        "[live] debounced {kind} for {}",
                        &remote_node_id[..remote_node_id.len().min(12)]
                    );
                    return;
                }
            }
            last.insert(key, now);
            // Entries only matter inside the debounce window; without this
            // the map grew by one row per (peer, kind) for the life of the
            // process.
            last.retain(|_, at| now.saturating_sub(*at) < EVENT_DEBOUNCE_MS);
        }
    }

    let event = SyncEvent {
        remote_node_id: remote_node_id.to_string(),
        resources_imported,
        timestamp: now,
        kind: kind.to_string(),
    };
    let _ = get_event_tx().send(event);
}

/// Drain and return all pending sync events (legacy polling API).
pub fn poll_sync_events() -> Vec<SyncEvent> {
    let mut rx = get_event_tx().subscribe();
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    events
}

/// Block until the next sync event arrives. Reactive — no polling.
pub async fn wait_for_sync_event() -> SyncEvent {
    let mut rx = get_event_tx().subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => return event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                rx = get_event_tx().subscribe();
            }
        }
    }
}

/// Block until the live peer count changes from `current`. Reactive.
pub async fn wait_for_peer_count_change(current: usize) -> usize {
    let mut rx = get_event_tx().subscribe();
    loop {
        // Check immediately
        let count = live_peer_count();
        if count != current {
            return count;
        }
        // Wait for any event (connect/disconnect changes count)
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
            Ok(Ok(_)) => {
                let count = live_peer_count();
                if count != current {
                    return count;
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(_)) => {
                rx = get_event_tx().subscribe();
            }
            Err(_) => {} // timeout, loop and check again
        }
    }
}

/// Sync a drive with a remote peer over the global endpoint (set by
/// `start()`), replacing an existing live connection (QR pair / manual
/// sync). Returns the rich [`PeerSyncOutcome`].
///
/// This and [`sync_drive_with_peer_if_needed`] are the two production entry
/// points; [`sync_drive_with_peer_using`] takes an explicit endpoint for
/// tests that run several in one process. All of them are
/// [`sync_drive_with_peer_using_outcome`].
pub async fn sync_drive_with_peer_outcome(
    remote_node_id: &str,
    drive: &str,
    store: &Db,
) -> crate::errors::AtomicResult<PeerSyncOutcome> {
    let endpoint = ENDPOINT
        .get()
        .ok_or("Iroh peer not started. Call start() first.")?;
    sync_drive_with_peer_using_outcome(endpoint, remote_node_id, drive, store, true).await
}

/// Bulk sync only when there is no healthy live stream to this peer
/// (auto-connect / nudge). Returns the number of resources imported.
pub async fn sync_drive_with_peer_if_needed(
    remote_node_id: &str,
    drive: &str,
    store: &Db,
) -> crate::errors::AtomicResult<usize> {
    let endpoint = ENDPOINT
        .get()
        .ok_or("Iroh peer not started. Call start() first.")?;
    sync_drive_with_peer_using(endpoint, remote_node_id, drive, store, false).await
}

/// Rich result for a peer sync round-trip. `peer_name` is whatever the
/// remote announced in its `HELLO` frame (or `None` for old peers that
/// don't speak HELLO yet). Display-only — see [`crate::sync::protocol::HELLO_MAX_CHARS`].
#[derive(Debug, Clone)]
pub struct PeerSyncOutcome {
    /// Resources taken from the peer.
    pub count: usize,
    /// Resources handed to the peer. A device sending its workspace somewhere
    /// that has none takes nothing back — reporting only `count` tells the
    /// person who just did that they did nothing.
    pub pushed: usize,
    /// The peer said both sides already hold the same thing. Nothing moved,
    /// and nothing needed to: the difference between "up to date" and "failed"
    /// is invisible in a count alone.
    pub in_sync: bool,
    pub peer_name: Option<String>,
}

/// Sync a drive using a specific Iroh endpoint. Useful for tests where
/// multiple endpoints exist in the same process.
///
/// Returns the number of resources imported. For callers that also want
/// the remote's self-reported display name, use
/// [`sync_drive_with_peer_using_outcome`].
pub async fn sync_drive_with_peer_using(
    endpoint: &Endpoint,
    remote_node_id: &str,
    drive: &str,
    store: &Db,
    force: bool,
) -> crate::errors::AtomicResult<usize> {
    sync_drive_with_peer_using_outcome(endpoint, remote_node_id, drive, store, force)
        .await
        .map(|o| o.count)
}

/// Same as [`sync_drive_with_peer_using`] but returns [`PeerSyncOutcome`]
/// so callers can render the remote's friendly device name.
pub async fn sync_drive_with_peer_using_outcome(
    endpoint: &Endpoint,
    remote_node_id: &str,
    drive: &str,
    store: &Db,
    force: bool,
) -> crate::errors::AtomicResult<PeerSyncOutcome> {
    let remote_key = normalize_node_id(remote_node_id);
    let node_id: NodeId = remote_key
        .parse()
        .map_err(|e| format!("Invalid NodeID '{remote_node_id}': {e}"))?;

    if !force && live_peer_ids().contains(&remote_key) {
        tracing::debug!(
            "[sync] already live with {}, skipping bulk reconnect",
            &remote_key[..remote_key.len().min(12)]
        );
        return Ok(PeerSyncOutcome {
            count: 0,
            pushed: 0,
            in_sync: true,
            peer_name: None,
        });
    }

    if force && live_peer_ids().contains(&remote_key) {
        remove_live_peer_any_quiet(&remote_key);
    }

    let my_node_id = endpoint.node_id();
    let my_relay = endpoint.home_relay();
    tracing::info!(
        "[sync] my NodeID: {}, relay: {:?}, connecting to: {}, drive: {}",
        &my_node_id.to_string()[..16],
        my_relay.get(),
        &node_id.to_string()[..node_id.to_string().len().min(16)],
        &drive[..drive.len().min(20)],
    );

    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
    let remote_short = &node_id.to_string()[..node_id.to_string().len().min(16)];
    // Prefer a stored relay/address hint over a bare node id, so a re-dial does
    // not hinge on a pkarr lookup that fails behind restrictive NAT.
    let dial = dial_target(store, node_id);
    let conn =
        match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(dial, ATOMIC_ALPN)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::error!("[sync] connect failed to {remote_short}: {e}");
                return Err(format!("Iroh connect to {remote_short} failed: {e}").into());
            }
            Err(_) => {
                tracing::error!("[sync] connect timed out to {remote_short}");
                return Err(format!(
                    "Iroh connect to {remote_short} timed out after {}s. \
                 Is the other device online, on the network, and running the app?",
                    CONNECT_TIMEOUT.as_secs()
                )
                .into());
            }
        };

    tracing::info!("[sync] connected! Opening bi stream...");

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
        tracing::error!("[sync] open_bi failed: {e}");
        format!("Iroh open_bi failed: {e}")
    })?;

    tracing::info!("[sync] bi stream open, sending AUTH...");

    // Authenticate: send AUTH frame so the server knows who we are
    let agent = store.get_default_agent()?;
    let auth_frame = super::protocol::encode_auth(&agent, drive)?;
    send.write_u32(auth_frame.len() as u32)
        .await
        .map_err(io_err)?;
    send.write_all(&auth_frame).await.map_err(io_err)?;

    // Read AUTH_OK or ERROR
    let auth_len = match recv.read_u32().await {
        Ok(n) => n as usize,
        Err(e) => return Err(format!("Failed to read auth response: {e}").into()),
    };
    // Cheap inconsistency sweep (planning/unified-sync.md Phase 0b): this
    // length prefix is attacker-controlled and, unlike every other
    // length-prefixed Iroh read in this file, was never bounded before
    // allocating — an unbounded `vec![0u8; auth_len]` from a hostile peer.
    // Pre-auth cap: we haven't yet learned whether this AUTH succeeded.
    if auth_len > super::protocol::IROH_PREAUTH_FRAME_MAX_BYTES {
        return Err(format!(
            "Auth response frame too large: {auth_len} bytes (max {})",
            super::protocol::IROH_PREAUTH_FRAME_MAX_BYTES
        )
        .into());
    }
    let mut auth_buf = vec![0u8; auth_len];
    recv.read_exact(&mut auth_buf).await.map_err(io_err)?;
    if auth_buf.is_empty() || auth_buf[0] != super::protocol::tag::AUTH_OK {
        let msg = auth_buf
            .get(1..)
            .and_then(super::protocol::decode_error)
            .map(|e| e.message)
            .unwrap_or_else(|| "auth rejected".to_string());
        return Err(format!("Authentication failed: {msg}").into());
    }
    let peer_caps = super::protocol::decode_auth_ok(&auth_buf[1..]);
    tracing::info!("Authenticated with peer (capabilities: {:?})", peer_caps);

    // Self-introduce. We send unprompted right after AUTH_OK; the accept
    // side does the same in `handle_stream`. Either side's HELLO can arrive
    // at any time (TCP is ordered but we don't block on it here) — the
    // read loop below captures it whenever it lands.
    let hello_frame = super::protocol::encode_hello(&effective_device_name(store));
    send.write_u32(hello_frame.len() as u32)
        .await
        .map_err(io_err)?;
    send.write_all(&hello_frame).await.map_err(io_err)?;

    let mut peer_display_name: Option<String> = None;
    // Best-effort mutual auth: the identity the remote proved to us, if any.
    // Stays Public (no special rights beyond whatever Public already has,
    // same as an unauthenticated HTTP request) if the remote has no local
    // agent to authenticate with — e.g. a truly anonymous guest. Every write
    // the remote's SYNC_DIFF/SYNC_PUSH frames cause below, and every subject
    // we serve back for its `pull` list, is gated on THIS identity: the accept
    // side writes its auth-back AUTH immediately after AUTH_OK — before any
    // SYNC_* response — and the QUIC bi-stream is ordered, so a peer that
    // authenticates is identified before its sync frames are processed; a peer
    // that never does stays Public and gets Public semantics. Dialing a peer
    // must not, by itself, grant that peer Sudo over our store.
    let mut remote_agent = ForAgent::Public;
    // Same per-connection drive-verdict cache the live loop uses; cleared on
    // a late identity change, since verdicts cached under the old identity
    // are stale (see `invalidate_drive_cache_on_identity_change`).
    let mut drive_cache: std::collections::HashMap<String, bool> = std::collections::HashMap::new();

    // Build our local sync state
    let drive_subject = crate::Subject::from_raw(drive, store.get_base_domain().as_deref());
    let drive_subjects = super::engine::collect_drive_subjects(store, &drive_subject).await;
    let vvs = super::engine::build_drive_vvs(store, &drive_subjects);
    let drive_hash = super::engine::compute_drive_hash(&vvs);

    // Build compact peer/resource representation
    let mut peer_set = std::collections::BTreeSet::new();
    for vv in vvs.values() {
        for peer_id in vv.keys() {
            peer_set.insert(peer_id.clone());
        }
    }
    let peers: Vec<String> = peer_set.into_iter().collect();
    let peer_index: std::collections::HashMap<&str, usize> = peers
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_str(), i))
        .collect();

    let mut resources: std::collections::HashMap<String, Vec<i32>> =
        std::collections::HashMap::new();
    for (subject, vv) in &vvs {
        let mut counters = vec![0i32; peers.len()];
        for (pid, &counter) in vv {
            if let Some(&idx) = peer_index.get(pid.as_str()) {
                counters[idx] = counter;
            }
        }
        resources.insert(subject.clone(), counters);
    }

    // Send SYNC frame
    let sync_frame = super::protocol::encode_sync(drive, &drive_hash, &peers, &resources);
    send.write_u32(sync_frame.len() as u32)
        .await
        .map_err(io_err)?;
    send.write_all(&sync_frame).await.map_err(io_err)?;

    // Read response frames
    let mut total_imported = 0;
    // What we sent, and whether the remote said we were already level. A sync
    // that pushes a workspace up imports nothing — counting only imports calls
    // that a failure — and one that finds both sides equal moves nothing at
    // all, which is the definition of success.
    let mut total_pushed = 0usize;
    let mut acked_in_sync = false;
    let mut pull_subjects: Vec<String> = Vec::new();

    // Read frames until the peer is done
    while let Ok(n) = recv.read_u32().await {
        let len = n as usize;
        if len == 0 || len > super::protocol::IROH_FRAME_MAX_BYTES {
            break;
        }

        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await.map_err(io_err)?;

        if buf.is_empty() {
            break;
        }

        let tag = buf[0];
        let payload = &buf[1..];

        match tag {
            super::protocol::tag::HELLO => {
                // First HELLO from the accept side wins; later ones are
                // ignored. Decoder enforces 64-char cap + UTF-8 + strips
                // control chars, so we don't need to sanitize again here.
                if peer_display_name.is_none() {
                    peer_display_name = super::protocol::decode_hello(payload);
                    if let Some(name) = &peer_display_name {
                        tracing::info!(
                            "[sync] peer {} introduced itself as \"{}\" (capabilities: {:?})",
                            &remote_key[..remote_key.len().min(12)],
                            name,
                            super::protocol::decode_hello_caps(payload)
                        );
                        // Persist into the known-peers table so any UI that
                        // re-reads `get_known_peers` (flutter dialog, server
                        // sidebar) shows the friendly name without needing
                        // a separate codepath. `add_known_peer` is upsert
                        // and only overwrites `name` when non-empty.
                        if !name.is_empty() {
                            add_known_peer(store, &remote_key, name);
                        }
                    }
                }
                continue;
            }
            super::protocol::tag::SYNC_OK => {
                tracing::info!("Peer says drive {drive} is in sync");
                acked_in_sync = true;
                break;
            }
            super::protocol::tag::SYNC_DIFF => {
                if let Some(diff) = super::protocol::decode_sync_diff(payload) {
                    tracing::info!(
                        "SYNC_DIFF: server pushes {}, server pulls {}, remove {}",
                        diff.push.len(),
                        diff.pull.len(),
                        diff.remove.len()
                    );
                    for subject in &diff.remove {
                        // Dial side: we chose this peer, so a remove targeting a
                        // drive we own is honored even when the peer relaying it
                        // is a different agent (trust_owned=true). A signed
                        // envelope, when present, is applied as a COMMIT instead.
                        let envelope = diff.remove_commits.get(subject).map(String::as_str);
                        apply_peer_remove(
                            store,
                            &remote_agent,
                            subject,
                            true,
                            &mut drive_cache,
                            envelope,
                        )
                        .await;
                    }
                    pull_subjects = diff.pull.clone();

                    // If server has nothing to push, it won't send SYNC_PUSH.
                    // Send our data now and break.
                    if diff.push.is_empty() {
                        if !diff.pull.is_empty() {
                            let entries = super::engine::collect_readable_snapshots(
                                store,
                                &remote_agent,
                                &diff.pull,
                                Some(&remote_key),
                            )
                            .await;
                            if !entries.is_empty() {
                                let refs: Vec<(&str, &[u8])> = entries
                                    .iter()
                                    .map(|(s, b)| (s.as_str(), b.as_slice()))
                                    .collect();
                                for chunk in super::protocol::encode_sync_push_chunks(drive, &refs)
                                {
                                    send.write_u32(chunk.len() as u32).await.map_err(io_err)?;
                                    send.write_all(&chunk).await.map_err(io_err)?;
                                }
                                total_pushed += entries.len();
                                tracing::info!("Pushed {} resources to peer", entries.len());
                            }
                        }
                        break;
                    }
                    // Otherwise, continue reading — SYNC_PUSH should follow
                }
            }
            super::protocol::tag::SYNC_PUSH => {
                let mut last_chunk = false;
                if let Some(push) = super::protocol::decode_sync_push(payload) {
                    last_chunk = push.last;
                    // Import with the identity the peer proved via auth-back,
                    // NOT Sudo — dialing a peer never established the peer's
                    // write rights. `trust_owned=true`: WE dialed this peer, so
                    // a push to a drive we own is accepted even when the peer
                    // relaying it is a different agent (a server holding our
                    // drive authenticates as its own node agent, not ours).
                    // `import_sync_push` still runs the drive-level check + the
                    // admission gate. A drive that does not exist locally is
                    // enrolled only when the policy allows it (OQ5); Public
                    // never creates one.
                    match super::engine::import_sync_push(&push, store, &remote_agent, true).await {
                        Ok((count, blob_requests)) => {
                            total_imported += count;

                            // Send blob requests if any
                            for req_frame in blob_requests {
                                send.write_u32(req_frame.len() as u32)
                                    .await
                                    .map_err(io_err)?;
                                send.write_all(&req_frame).await.map_err(io_err)?;
                            }
                        }
                        // We dialed this peer and asked for its state; the
                        // refusal is our own admission gate saying no to what
                        // came back. Nothing landed, and there is nothing to
                        // tell the peer — it did not ask us for anything.
                        Err(rejected) => {
                            tracing::warn!("[sync] dropped incoming push: {rejected}");
                        }
                    }
                }
                // SYNC_PUSH is chunked: keep reading until the LAST flag fires.
                // Only after that do we send our pushback and exit the loop.
                if !last_chunk {
                    continue;
                }
                if !pull_subjects.is_empty() {
                    let entries = super::engine::collect_readable_snapshots(
                        store,
                        &remote_agent,
                        &pull_subjects,
                        Some(&remote_key),
                    )
                    .await;
                    if !entries.is_empty() {
                        let refs: Vec<(&str, &[u8])> = entries
                            .iter()
                            .map(|(s, b)| (s.as_str(), b.as_slice()))
                            .collect();
                        for chunk in super::protocol::encode_sync_push_chunks(drive, &refs) {
                            send.write_u32(chunk.len() as u32).await.map_err(io_err)?;
                            send.write_all(&chunk).await.map_err(io_err)?;
                        }
                        total_pushed += entries.len();
                        tracing::info!("Pushed {} resources back to peer", entries.len());
                    }
                }
                break;
            }
            super::protocol::tag::ERROR => {
                // [request_id: u16] [code: u16] [message: utf8] (F5,
                // planning/unified-sync.md).
                let code = payload
                    .get(2..4)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .unwrap_or(super::protocol::error_code::UNKNOWN);
                let msg =
                    std::str::from_utf8(payload.get(4..).unwrap_or(&[])).unwrap_or("unknown error");
                // A refused push or a refused identity is the peer saying
                // "nothing of yours landed". Going live and reporting
                // `pushed` as if it had would tell the user the opposite of
                // what happened, so this is the outcome of the sync.
                if code == super::protocol::error_code::SYNC_REJECTED
                    || code == super::protocol::error_code::AUTH_REQUIRED
                {
                    tracing::warn!("[sync] peer refused: {msg}");
                    return Err(format!("Peer refused to sync: {msg}").into());
                }
                tracing::warn!("Peer returned error: {msg}");
                break;
            }
            super::protocol::tag::AUTH => {
                // The remote's best-effort auth-back (see handle_stream). Same
                // verification as any other AUTH — pure signature/timestamp
                // proof of identity, no rights check here. The proof must be
                // signed for *our* node id (that is what `handle_stream` signs
                // it for): a proof the remote captured elsewhere, signed for
                // some other node or origin, does not identify it to us.
                if let Ok(json) = std::str::from_utf8(payload) {
                    match serde_json::from_str::<crate::authentication::AuthValues>(json) {
                        Ok(auth)
                            if normalize_node_id(&auth.requested_subject)
                                != normalize_node_id(&my_node_id.to_string()) =>
                        {
                            tracing::warn!(
                                "[sync] peer's auth-back ignored: signed for {}, not for this node",
                                auth.requested_subject
                            );
                        }
                        Ok(auth) => {
                            match crate::authentication::get_agent_from_auth_values_and_check(
                                Some(auth),
                                store,
                            )
                            .await
                            {
                                Ok(a) => {
                                    tracing::info!(
                                        "[sync] peer {} authenticated back as {a:?}",
                                        &remote_key[..remote_key.len().min(12)]
                                    );
                                    // Whether this agent may have anything of
                                    // ours is `check_read`'s answer, per
                                    // subject — not a question of whether they
                                    // are us. A peer holding a drive shared
                                    // with us is a different agent and has
                                    // every right to sync it.
                                    invalidate_drive_cache_on_identity_change(
                                        &a,
                                        &remote_agent,
                                        &mut drive_cache,
                                    );
                                    remote_agent = a;
                                }
                                Err(e) => {
                                    tracing::debug!("[sync] peer's auth-back rejected: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("[sync] invalid auth-back JSON from peer: {e}");
                        }
                    }
                }
            }
            _ => {
                tracing::debug!("Unexpected frame tag from peer: 0x{tag:02x}");
            }
        }
    }

    tracing::info!(
        "sync_drive_with_peer: imported {total_imported} resources from {remote_node_id}"
    );

    // Nothing moved in either direction, and the remote never said we were
    // level: the far side had nothing for us, wanted nothing from us, and never
    // acked us in sync. Report it rather than leave two devices sitting
    // "synced" and blank — but say what actually happened, not whose account it
    // is: a server holding your drive under a different agent is a device you
    // are meant to sync with, so identity is not the story here.
    //
    // The conditions are what matter, not who the peer is. Pushing a workspace
    // up to a device that had none imports nothing and is exactly what someone
    // came here to do; being already in sync (acked) moves nothing and is the
    // happy ending. Only the all-quiet, no-ack case is a real anomaly.
    if total_imported == 0 && total_pushed == 0 && !acked_in_sync {
        return Err(format!(
            "Connected to that device, but nothing synced: it shared nothing \
             readable with you and took nothing of yours ({remote_agent})."
        )
        .into());
    }

    // The exchange completed and this is a real peer we hold a drive with —
    // stamp it so the UI can show when we last synced, and remember where it
    // lives now (relay + direct addrs) so the next dial skips discovery.
    mark_peer_synced(
        store,
        &remote_key,
        Some(total_pushed as u32),
        Some(total_imported as u32),
    );
    if let Some(info) = endpoint.remote_info(node_id) {
        let addr: iroh::NodeAddr = info.into();
        remember_peer_addr(
            store,
            &remote_key,
            addr.relay_url.map(|u| u.to_string()),
            addr.direct_addresses
                .iter()
                .map(|a| a.to_string())
                .collect(),
        );
    }

    // Transition to live mode: reuse the same bi stream for real-time updates.
    // Don't close it — the server's handle_stream will also transition after
    // the sync exchange completes.
    tracing::info!(
        "[live] transitioning to live mode with {}",
        &remote_node_id[..remote_node_id.len().min(12)]
    );
    // Dial side: we initiated, so trust this peer to relay drives we own.
    // The connection goes into the registry with the stream, so a re-dial
    // replaces (and closes) the link it supersedes instead of leaking it.
    register_live_peer(
        remote_key.clone(),
        send,
        recv,
        store.clone(),
        remote_agent,
        true,
        Some(conn),
    );

    // Remember which drive this node syncs, so it can rebuild this link on its
    // own after a restart. The auto-connect loop above reads `get_active_drive`
    // and sleeps while it is `None` — and `None` is exactly what a device that
    // *received* its drive by pairing has: only `create_drive` and a secret
    // carrying an `initial_drive` ever set it, and the browser's secret carries
    // just a key. Such a pair reconnects only when a human presses "Sync now".
    //
    // Recorded here, after a completed exchange, rather than on the way in: by
    // this point the peer has proved it holds our agent key and the drive has
    // survived the reconcile, so the value is one we're willing to dial again
    // unattended. Last drive synced wins, matching `create_drive` and
    // `load_agent_from_secret`.
    if store.get_active_drive().as_deref() != Some(drive) {
        if let Err(e) = store.set_active_drive(drive) {
            tracing::warn!("[sync] could not remember the drive to reconnect to: {e}");
        }
    }

    Ok(PeerSyncOutcome {
        count: total_imported,
        pushed: total_pushed,
        in_sync: acked_in_sync,
        peer_name: peer_display_name,
    })
}

// ── Known peers (persisted in DB) ────────────────────────────────────────

const KNOWN_PEERS_KEY: &[u8] = b"_iroh_known_peers_v2";

/// A known peer with optional device name.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnownPeer {
    pub node_id: String,
    pub name: String,
    /// What the LAST completed sync with this peer moved, in resources. A
    /// per-sync figure rather than a lifetime total on purpose: a running
    /// counter has to survive re-pairs, store resets and partial syncs, and
    /// quietly becomes fiction the first time one of those is missed. These
    /// two are checkable against the number the sync itself reported.
    #[serde(default)]
    pub last_sent: Option<u32>,
    #[serde(default)]
    pub last_received: Option<u32>,
    /// Unix millis of the last successful sync with this peer, if ever. Absent
    /// for peers stored before this was tracked (serde default), so the UI shows
    /// "not yet" rather than a bogus epoch time.
    #[serde(default)]
    pub last_synced: Option<i64>,
    /// The peer's relay URL, captured from a live connection. Re-dialing with
    /// this avoids a pkarr lookup — which is the difference between reconnecting
    /// reliably and timing out on networks where hole-punching is blocked.
    #[serde(default)]
    pub relay_url: Option<String>,
    /// The peer's last-known direct socket addresses ("ip:port"), captured from
    /// a live connection. A hint alongside the relay, not a requirement.
    #[serde(default)]
    pub direct_addrs: Vec<String>,
}

/// Get all known peers from the DB.
/// Whether this node's user deliberately paired with `node_id`.
///
/// Only the initiator side records a peer (`add_known_peer` is called after we
/// dial and the remote says HELLO); the accept side deliberately does not, on
/// the grounds that the local user never chose an unsolicited inbound
/// connection. So this answers "did the owner of this node choose to sync with
/// that one", which is the authority a replica needs — rather than an ACL entry
/// the owner has to write by hand for every device and every drive.
pub fn is_paired_peer(store: &Db, node_id: &str) -> bool {
    let key = normalize_node_id(node_id);

    get_known_peers(store)
        .iter()
        .any(|p| normalize_node_id(&p.node_id) == key)
}

pub fn get_known_peers(store: &Db) -> Vec<KnownPeer> {
    if let Ok(Some(bytes)) = store
        .kv
        .get(crate::db::trees::Tree::PluginMeta, KNOWN_PEERS_KEY)
    {
        serde_json::from_slice(&bytes).unwrap_or_default()
    } else {
        vec![]
    }
}

/// Add a peer to the known peers list. Updates name if already known.
pub fn add_known_peer(store: &Db, node_id: &str, name: &str) {
    let key = normalize_node_id(node_id);
    let mut peers = get_known_peers(store);
    if let Some(existing) = peers
        .iter_mut()
        .find(|p| normalize_node_id(&p.node_id) == key)
    {
        if !name.is_empty() {
            existing.name = name.to_string();
        }
    } else {
        peers.push(KnownPeer {
            node_id: key,
            last_sent: None,
            last_received: None,
            name: name.to_string(),
            last_synced: None,
            relay_url: None,
            direct_addrs: Vec::new(),
        });
    }
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        KNOWN_PEERS_KEY,
        &serde_json::to_vec(&peers).unwrap_or_default(),
    );
    // Durable now: a paired peer that vanishes on the next app kill means a
    // re-scan. These writes are rare (pairing / first sync), so the fsync cost
    // is negligible.
    let _ = store.flush();
}

/// Remember where a peer can be reached, captured from a live connection. Stored
/// so the next dial can skip discovery and go straight to the relay. Empty
/// values are ignored so a momentary lack of info never erases a good address.
pub fn remember_peer_addr(
    store: &Db,
    node_id: &str,
    relay_url: Option<String>,
    direct_addrs: Vec<String>,
) {
    if relay_url.is_none() && direct_addrs.is_empty() {
        return;
    }
    let key = normalize_node_id(node_id);
    let mut peers = get_known_peers(store);
    let entry = if let Some(existing) = peers
        .iter_mut()
        .find(|p| normalize_node_id(&p.node_id) == key)
    {
        existing
    } else {
        peers.push(KnownPeer {
            node_id: key.clone(),
            last_sent: None,
            last_received: None,
            name: String::new(),
            last_synced: None,
            relay_url: None,
            direct_addrs: Vec::new(),
        });
        peers.last_mut().unwrap()
    };
    if relay_url.is_some() {
        entry.relay_url = relay_url;
    }
    if !direct_addrs.is_empty() {
        entry.direct_addrs = direct_addrs;
    }
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        KNOWN_PEERS_KEY,
        &serde_json::to_vec(&peers).unwrap_or_default(),
    );
    // Durable now: a paired peer that vanishes on the next app kill means a
    // re-scan. These writes are rare (pairing / first sync), so the fsync cost
    // is negligible.
    let _ = store.flush();
}

/// Build a dial target for a peer, preferring a stored relay/address hint over a
/// bare node id. The bare id forces Iroh to discover the address via pkarr,
/// which is exactly what fails on restrictive networks; a stored relay url lets
/// the connection go straight through the relay.
fn dial_target(store: &Db, node_id: NodeId) -> iroh::NodeAddr {
    let key = node_id.to_string();
    for peer in get_known_peers(store) {
        if normalize_node_id(&peer.node_id) != normalize_node_id(&key) {
            continue;
        }
        let mut addr = iroh::NodeAddr::new(node_id);
        if let Some(relay) = peer.relay_url.as_deref().and_then(|s| s.parse().ok()) {
            addr = addr.with_relay_url(relay);
        }
        let socks: Vec<std::net::SocketAddr> = peer
            .direct_addrs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        if !socks.is_empty() {
            addr = addr.with_direct_addresses(socks);
        }
        return addr;
    }
    iroh::NodeAddr::new(node_id)
}

/// Stamp a peer's `last_synced` to now, upserting it if unknown. Called when a
/// sync exchange with the peer completes, so the UI can say "synced 2m ago"
/// without a separate bookkeeping path.
/// Record a completed sync with `node_id`.
///
/// `sent` / `received` are optional because the two sides know different
/// things: the dialling side tallies both directions itself, while the
/// accepting side answers frames through the engine and only counts what came
/// in. Reporting an unknown figure as 0 would be the same class of lie this
/// status work exists to remove, so absent stays absent.
/// Record a sync against a peer we ALREADY know, and do nothing otherwise.
///
/// For the accepting side. `mark_peer_synced` inserts a `KnownPeer` when it
/// finds none, which is right when we did the dialling — choosing to dial is
/// the consent. On the accept side the peer chose us, so inserting would hand
/// any stranger who completes a handshake a permanent entry in known-peers, and
/// with it an auto-reconnect slot that no pairing ever granted.
pub fn mark_known_peer_synced(store: &Db, node_id: &str, sent: Option<u32>, received: Option<u32>) {
    if !is_paired_peer(store, node_id) {
        return;
    }

    mark_peer_synced(store, node_id, sent, received);
}

pub fn mark_peer_synced(store: &Db, node_id: &str, sent: Option<u32>, received: Option<u32>) {
    let key = normalize_node_id(node_id);
    let mut peers = get_known_peers(store);
    let now = crate::utils::now();
    if let Some(existing) = peers
        .iter_mut()
        .find(|p| normalize_node_id(&p.node_id) == key)
    {
        existing.last_synced = Some(now);
        existing.last_sent = sent;
        existing.last_received = received;
    } else {
        peers.push(KnownPeer {
            node_id: key,
            name: String::new(),
            last_sent: sent,
            last_received: received,
            last_synced: Some(now),
            relay_url: None,
            direct_addrs: Vec::new(),
        });
    }
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        KNOWN_PEERS_KEY,
        &serde_json::to_vec(&peers).unwrap_or_default(),
    );
    // Durable now: a paired peer that vanishes on the next app kill means a
    // re-scan. These writes are rare (pairing / first sync), so the fsync cost
    // is negligible.
    let _ = store.flush();
}

/// Remove a peer from the known peers list.
pub fn remove_known_peer(store: &Db, node_id: &str) {
    let key = normalize_node_id(node_id);
    let mut peers = get_known_peers(store);
    peers.retain(|p| normalize_node_id(&p.node_id) != key);
    let _ = store.kv.insert(
        crate::db::trees::Tree::PluginMeta,
        KNOWN_PEERS_KEY,
        &serde_json::to_vec(&peers).unwrap_or_default(),
    );
    // Durable now: a paired peer that vanishes on the next app kill means a
    // re-scan. These writes are rare (pairing / first sync), so the fsync cost
    // is negligible.
    let _ = store.flush();
}

/// Handle a single bidirectional QUIC stream.
/// Reads length-prefixed v2 binary frames and dispatches them via the sync engine.
/// Returns the number of resources imported from the remote peer.
/// After SYNC_OK or SYNC_PUSH response, transitions to live mode by
/// registering the stream for real-time updates.
/// The `ERROR` frame a peer gets for sending `tag` before it authenticated.
fn auth_required_error(tag: u8) -> Vec<u8> {
    super::protocol::encode_error(
        0,
        super::protocol::error_code::AUTH_REQUIRED,
        &format!("AUTH required before frame 0x{tag:02x}"),
    )
}

/// Prefix a frame with the u32 length the Iroh stream framing expects.
fn frame_with_len(frame: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + frame.len());
    framed.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    framed.extend_from_slice(frame);
    framed
}

/// Write `frames`, close our half of the stream, and wait (briefly) for the
/// peer to acknowledge them. Best effort: the peer is being refused, so a
/// failed write changes nothing. The wait matters, though: the caller
/// returns straight after, `accept` then drops the connection, and QUIC
/// would discard anything not yet delivered — the peer would see a closed
/// stream with no ERROR in it, which is the silence this exists to replace.
async fn refuse_stream(send: &mut iroh::endpoint::SendStream, frames: &[Vec<u8>]) {
    for frame in frames {
        let _ = send.write_all(&frame_with_len(frame)).await;
    }
    let _ = send.finish();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), send.stopped()).await;
}

/// The drive an `AUTH` frame was signed for (`requestedSubject`). `None`
/// when the payload does not parse — a frame that did not parse did not
/// authenticate either, so nothing is bound.
fn auth_requested_subject(payload: &[u8]) -> Option<String> {
    let json = std::str::from_utf8(payload).ok()?;
    let auth: crate::authentication::AuthValues = serde_json::from_str(json).ok()?;
    Some(auth.requested_subject)
}

/// The drive a handshake `SYNC` / `SYNC_PUSH` names, or `None` for any other
/// frame (and for a frame that does not decode — the engine will answer
/// that one with its own ERROR).
fn handshake_frame_drive(buf: &[u8]) -> Option<String> {
    match *buf.first()? {
        super::protocol::tag::SYNC => super::protocol::decode_sync(&buf[1..]).map(|s| s.drive),
        super::protocol::tag::SYNC_PUSH => {
            super::protocol::decode_sync_push(&buf[1..]).map(|p| p.drive)
        }
        _ => None,
    }
}

async fn handle_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    store: Db,
    remote_id: String,
) -> anyhow::Result<usize> {
    let remote_key = normalize_node_id(&remote_id);
    let mut agent = ForAgent::Public;
    // The drive the peer's AUTH was signed for. The AUTH proof is bound to
    // this (`requestedSubject` is what the signature covers), so a proof
    // minted for one drive must not open a SYNC on another. Set once, when
    // the AUTH succeeds; checked against every handshake SYNC / SYNC_PUSH.
    let mut bound_drive: Option<crate::Subject> = None;
    let mut total_imported = 0;
    let mut sent_sync_ok = false;
    let mut hello_sent = false;
    let mut auth_sent = false;
    let mut peer_display_name: Option<String> = None;

    while let Ok(n) = recv.read_u32().await {
        let len = n as usize;

        // `agent` is still `Public` until AUTH succeeds — and stays `Public`
        // for a peer that never authenticates at all. Either way, "no proven
        // identity yet" is exactly when this frame budget should be tight:
        // an unauthenticated dialer (anyone who learned our NodeID via pkarr
        // discovery, same threat model as F9) shouldn't be able to force a
        // 50MB allocation before proving who they are. Once `agent` carries
        // a real identity, subsequent frames (bulk SYNC_PUSH payloads etc.)
        // get the larger, authenticated-connection budget.
        let frame_cap = if matches!(agent, ForAgent::Public) {
            super::protocol::IROH_PREAUTH_FRAME_MAX_BYTES
        } else {
            super::protocol::IROH_FRAME_MAX_BYTES
        };
        if len == 0 || len > frame_cap {
            break;
        }

        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await.map_err(io_err)?;
        let Some(&tag) = buf.first() else {
            continue;
        };

        // Fail closed on identity (planning/serverless-p2p.md, principle 5;
        // planning/authorization-sync.md phase 1). Until an AUTH has
        // succeeded, the only frame this loop processes is AUTH. Anything
        // else — SYNC, SYNC_PUSH, even HELLO — gets an ERROR and the stream
        // closed, rather than being handled as `Public`. "Public semantics"
        // was never nothing: an unauthenticated SYNC still walked the drive
        // and served every publicly readable subject, and an unauthenticated
        // SYNC_PUSH could bootstrap a brand-new drive onto an open node. A
        // dialer that wants either can say who it is first; every initiator
        // in this codebase already does.
        if matches!(agent, ForAgent::Public) && tag != super::protocol::tag::AUTH {
            tracing::warn!(
                "[accept] closing: 0x{tag:02x} from {} before AUTH",
                &remote_key[..remote_key.len().min(12)]
            );
            refuse_stream(&mut send, &[auth_required_error(tag)]).await;
            return Ok(total_imported);
        }

        // AUTH.requestedSubject ↔ SYNC.drive binding: the proof the peer gave
        // covers one drive, so a handshake frame for a different drive is a
        // replay of that proof against something it was never signed for.
        if let (Some(bound), Some(named)) = (&bound_drive, handshake_frame_drive(&buf)) {
            let named = crate::Subject::from_raw(&named, store.get_base_domain().as_deref());
            if &named != bound {
                tracing::warn!(
                    "[accept] closing: {} authenticated for {bound} but sent 0x{tag:02x} for {named}",
                    &remote_key[..remote_key.len().min(12)]
                );
                refuse_stream(
                    &mut send,
                    &[super::protocol::encode_error(
                        0,
                        super::protocol::error_code::AUTH_REQUIRED,
                        &format!("AUTH was for {bound}, not {named}"),
                    )],
                )
                .await;
                return Ok(total_imported);
            }
        }

        // HELLO is a peer-stream concern, not an engine concern. Browser WS
        // sessions never see it (they don't speak peer-sync). Intercept here
        // so the engine doesn't have to know about it.
        if tag == super::protocol::tag::HELLO {
            if peer_display_name.is_none() {
                peer_display_name = super::protocol::decode_hello(&buf[1..]);
                if let Some(name) = &peer_display_name {
                    tracing::info!(
                        "[accept] peer {} introduced itself as \"{}\" (capabilities: {:?})",
                        &remote_key[..remote_key.len().min(12)],
                        name,
                        super::protocol::decode_hello_caps(&buf[1..])
                    );
                    // Display-only, and only while connected: a client of this
                    // node is not a node itself and cannot see who we are
                    // paired with unless we say. Not `add_known_peer` — see
                    // below.
                    set_live_peer_name(&remote_key, name);
                    // F9 minimal (planning/unified-sync.md): deliberately
                    // NOT calling `add_known_peer` here. This is the accept
                    // side of an unsolicited inbound connection — the local
                    // user never chose to sync with this peer. Registering
                    // it as "known" here used to hand it a permanent
                    // reconnect slot via the auto-connect background loop
                    // (`start`) with zero pairing/consent. `peer_display_name`
                    // is still tracked in-memory for this connection's own
                    // logs/UI; it just isn't persisted into the known-peers
                    // list from the accept path.
                }
            }
            continue;
        }

        let responses = super::engine::handle_frame(&buf, &store, &mut agent).await;

        // Track imports from SYNC_PUSH frames. A push the engine refused
        // (answered with ERROR instead of SYNC_OK) landed nothing.
        if tag == super::protocol::tag::SYNC_PUSH
            && responses
                .iter()
                .any(|r| r.first() == Some(&super::protocol::tag::SYNC_OK))
        {
            if let Some(push) = super::protocol::decode_sync_push(&buf[1..]) {
                total_imported += push.entries.len();
            }
        }

        // Send our HELLO once, immediately after AUTH succeeded. We tack it
        // on to the AUTH_OK response so old peers that don't read past
        // AUTH_OK still get something coherent (an unknown tag they'll just
        // skip). Skipping HELLO before AUTH_OK would leak our hostname to
        // unauthenticated peers — small thing, but no reason to.
        let just_authed = tag == super::protocol::tag::AUTH
            && responses
                .iter()
                .any(|r| !r.is_empty() && r[0] == super::protocol::tag::AUTH_OK);

        if tag == super::protocol::tag::AUTH {
            if just_authed {
                if bound_drive.is_none() {
                    bound_drive = auth_requested_subject(&buf[1..])
                        .map(|s| crate::Subject::from_raw(&s, store.get_base_domain().as_deref()));
                }
            } else {
                // A failed AUTH leaves `agent` as Public; the next frame would
                // be refused anyway. Say why and close now, rather than let a
                // peer keep guessing on an open stream.
                tracing::warn!(
                    "[accept] closing: AUTH from {} failed",
                    &remote_key[..remote_key.len().min(12)]
                );
                refuse_stream(&mut send, &responses).await;
                return Ok(total_imported);
            }
        }

        // Who this agent is decides nothing here; what they may read decides
        // everything, per subject, in `check_read` — the same answer they would
        // get over WS, which never asked this question. This connection used to
        // be refused unless the agent was ours, on the grounds that a stranger
        // would be denied every subject anyway and an empty "successful" sync
        // is a poor way to say no. But that reasoning only holds for a device
        // holding one person's drives. A server holds many people's, and would
        // have served each of them exactly what they own; a drive shared with
        // someone else's device is theirs to sync, and this refused that too.
        //
        // Refusing here also meant a workspace could only reach a server over
        // HTTP, which is the thing Iroh is here to avoid — a node id needs no
        // address, no port, no certificate.
        if just_authed {
            tracing::info!(
                "[accept] {} authenticated as {agent} — serving what they may read",
                &remote_key[..remote_key.len().min(12)]
            );
        }

        // Check if the client sent us a SYNC_PUSH (bidirectional data exchange complete)
        let client_pushed = tag == super::protocol::tag::SYNC_PUSH;
        // Check if we responded with SYNC_OK (fast path — already in sync)
        let sync_ok = responses
            .iter()
            .any(|r| !r.is_empty() && r[0] == super::protocol::tag::SYNC_OK);
        if sync_ok {
            sent_sync_ok = true;
        }
        // If our SYNC_DIFF does not ask the initiator to push anything back, the
        // bulk exchange is complete once our responses are written. Without this
        // transition, the accept side stays in handshake mode and later live
        // UPDATE frames are dispatched to the sync engine, which ignores them.
        let sync_diff_needs_no_pushback = responses.iter().any(|r| {
            !r.is_empty()
                && r[0] == super::protocol::tag::SYNC_DIFF
                && super::protocol::decode_sync_diff(&r[1..])
                    .is_some_and(|diff| diff.pull.is_empty())
        });

        for response in responses {
            if let Err(e) = send.write_u32(response.len() as u32).await {
                tracing::warn!(
                    "[accept] failed to write response header to {}: {e}",
                    &remote_key[..remote_key.len().min(12)]
                );
                break;
            }
            if let Err(e) = send.write_all(&response).await {
                tracing::warn!(
                    "[accept] failed to write response body to {}: {e}",
                    &remote_key[..remote_key.len().min(12)]
                );
                break;
            }
        }

        if just_authed && !hello_sent {
            hello_sent = true;
            let hello = super::protocol::encode_hello(&effective_device_name(&store));
            // Two-step write so the ? in either step doesn't have to convert
            // between io::Error (write_u32) and WriteError (write_all).
            let header_ok = send.write_u32(hello.len() as u32).await;
            if let Err(e) = header_ok {
                tracing::warn!(
                    "[accept] failed to write HELLO header to {}: {e}",
                    &remote_key[..remote_key.len().min(12)]
                );
            } else if let Err(e) = send.write_all(&hello).await {
                tracing::warn!(
                    "[accept] failed to write HELLO body to {}: {e}",
                    &remote_key[..remote_key.len().min(12)]
                );
            }
        }

        // Best-effort mutual auth: prove our own identity back to the peer, so
        // it can resolve real write rights for whatever we send once live,
        // instead of falling back to Public. Optional — a peer with no local
        // agent (a truly anonymous guest) simply doesn't send this, and stays
        // unidentified on the remote's side, same as an unauthenticated HTTP
        // request. Sent once, the same trigger as HELLO.
        if just_authed && !auth_sent {
            auth_sent = true;
            if let Ok(our_agent) = store.get_default_agent() {
                if let Ok(auth_frame) = super::protocol::encode_auth(&our_agent, &remote_key) {
                    if let Err(e) = send.write_u32(auth_frame.len() as u32).await {
                        tracing::warn!(
                            "[accept] failed to write auth-back header to {}: {e}",
                            &remote_key[..remote_key.len().min(12)]
                        );
                    } else if let Err(e) = send.write_all(&auth_frame).await {
                        tracing::warn!(
                            "[accept] failed to write auth-back body to {}: {e}",
                            &remote_key[..remote_key.len().min(12)]
                        );
                    }
                }
            }
        }

        // Transition to live mode after the sync exchange is fully complete:
        // - SYNC_OK: no data to exchange, we're done
        // - Client's SYNC_PUSH: bidirectional exchange complete
        // Register even if the last write failed — the initiator may already have
        // read SYNC_OK and registered, and we must not show "connected" only on one side.
        if sync_ok || client_pushed || sync_diff_needs_no_pushback {
            tracing::info!(
                "[accept] sync complete, transitioning to live mode with {}",
                &remote_key[..remote_key.len().min(12)]
            );
            // Record it here too. This used to run only on the dialling side,
            // so an always-on node — which is always the one being dialled —
            // reported "not synced yet" about a peer it had been exchanging
            // data with for hours. The counts are from this node's point of
            // view: what it served, and what it took in.
            //
            // `mark_known_peer_synced`, not `mark_peer_synced`: this side did
            // not choose the connection, so recording a sync must never be what
            // introduces the peer. Updating a peer we already paired with is
            // reporting; inserting one we have not is granting access.
            mark_known_peer_synced(&store, &remote_key, None, Some(total_imported as u32));
            // Accept side: the peer dialed us. No owned-drive relaxation — it
            // must hold real write rights to touch anything here.
            register_live_peer(remote_key, send, recv, store, agent, false, None);
            return Ok(total_imported);
        }
    }

    // Initiator may stop sending after reading our SYNC_OK; we already sent it.
    if sent_sync_ok {
        tracing::info!(
            "[accept] SYNC_OK sent, entering live mode with {}",
            &remote_key[..remote_key.len().min(12)]
        );
        register_live_peer(remote_key, send, recv, store, agent, false, None);
    }

    Ok(total_imported)
}

#[cfg(test)]
mod live_write_admission_tests {
    use super::*;
    use crate::Db;
    use std::collections::HashMap;

    /// Regression coverage for the live-sync write bypass: `apply_state_update`
    /// / `apply_destroy` used to run with no ACL check and no admission-gate
    /// check at all once a connection reached live mode. `admitted_for_drive`
    /// is what closes it — these tests exercise it directly (rather than via a
    /// full two-peer Iroh handshake) so the ACL and admission-gate layers are
    /// each provable in isolation.
    /// The relay case: a server holding our drive authenticates as its OWN
    /// agent, which can't write our drive — so gating on the transport peer's
    /// identity dropped every update it relayed back (a phone stopped receiving
    /// a browser's edits once its drive already existed on the server). When WE
    /// dialed the peer (`trust_owned`), an update to a drive our own agent owns
    /// is accepted; a peer dialing into us gets no such relaxation.
    #[tokio::test]
    async fn relayed_write_to_our_own_drive_accepted_only_when_we_dialed() {
        let db = Db::init_temp("relay_owned_drive").await.unwrap();
        // Alice is this device's agent and owns the drive.
        let (_alice, drive) = db.setup("Alice").await.unwrap();
        // The server: a different agent with no rights to Alice's drive.
        let server = db.create_agent(Some("Server")).await.unwrap();
        let server_agent = ForAgent::AgentSubject(server.subject.clone());

        // Peer dialed into us (trust_owned=false): the server's own identity
        // can't write our drive, so its relayed write is refused.
        let mut cache = HashMap::new();
        assert!(
            !admitted_for_drive(&db, &server_agent, &drive, false, &mut cache).await,
            "a peer that dialed us may not write our drive on its own identity"
        );

        // We dialed the server (trust_owned=true): it is relaying updates to a
        // drive we own, which is the whole point of pairing with it.
        let mut cache = HashMap::new();
        assert!(
            admitted_for_drive(&db, &server_agent, &drive, true, &mut cache).await,
            "a server we dialed must be able to relay updates to our own drive"
        );
    }

    #[tokio::test]
    async fn owner_admitted_stranger_rejected() {
        let db = Db::init_temp("live_admission_owner_vs_stranger")
            .await
            .unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();

        let mut cache = HashMap::new();
        assert!(
            admitted_for_drive(
                &db,
                &ForAgent::AgentSubject(alice.subject.clone()),
                &drive,
                false,
                &mut cache
            )
            .await,
            "the drive's own owner must be admitted"
        );

        let mut cache = HashMap::new();
        assert!(
            !admitted_for_drive(
                &db,
                &ForAgent::AgentSubject(mallory.subject.clone()),
                &drive,
                false,
                &mut cache
            )
            .await,
            "an unrelated agent with no rights to the drive must be rejected"
        );
    }

    #[tokio::test]
    async fn missing_drive_is_not_a_free_pass_for_public() {
        let db = Db::init_temp("live_admission_missing_public")
            .await
            .unwrap();
        let mut cache = HashMap::new();
        assert!(
            !admitted_for_drive(&db, &ForAgent::Public, "did:ad:brandnew", false, &mut cache).await,
            "Public must not live-write a drive this node has never stored"
        );
    }

    #[tokio::test]
    async fn missing_drive_on_owner_mode_admits_only_the_owner() {
        let db = Db::init_temp("live_admission_missing_owner").await.unwrap();
        let (owner, _) = db.setup("Owner").await.unwrap();
        let stranger = db.create_agent(Some("Stranger")).await.unwrap();
        db.set_sync_policy(std::sync::Arc::new(crate::sync::policy::OwnerPolicy::new(
            owner.subject.to_string(),
        )));

        let missing = "did:ad:notonthisnode";
        let mut cache = HashMap::new();
        assert!(
            !admitted_for_drive(
                &db,
                &ForAgent::AgentSubject(stranger.subject.clone()),
                missing,
                false,
                &mut cache
            )
            .await,
            "a stranger must not live-write a drive this node has never stored"
        );

        let mut cache = HashMap::new();
        assert!(
            admitted_for_drive(
                &db,
                &ForAgent::AgentSubject(owner.subject.clone()),
                missing,
                false,
                &mut cache
            )
            .await,
            "the owner may live-write a drive arriving for the first time"
        );
        assert!(
            db.sync_policy().admit_drive_write(missing),
            "admitting the owner must enroll the drive"
        );
    }

    /// The admission gate (allowlist/quota) is checked too, not just the ACL —
    /// even the rightful owner is rejected once their drive isn't admitted
    /// (e.g. a managed node whose allowlist doesn't include this drive).
    #[tokio::test]
    async fn owner_rejected_when_drive_not_admitted() {
        let db = Db::init_temp("live_admission_policy_gate").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();

        let policy = std::sync::Arc::new(crate::sync::policy::AllowlistPolicy::new());
        policy.set_grace(std::time::Duration::ZERO);
        db.set_sync_policy(policy);

        let mut cache = HashMap::new();
        assert!(
            !admitted_for_drive(
                &db,
                &ForAgent::AgentSubject(alice.subject.clone()),
                &drive,
                false,
                &mut cache
            )
            .await,
            "the owner's ACL rights don't matter if the drive isn't admitted by policy"
        );
    }

    /// The cache actually gets populated after the first check, so a burst of
    /// frames to the same drive on one connection doesn't re-walk the rights
    /// hierarchy every time.
    #[tokio::test]
    async fn verdict_is_cached_after_first_check() {
        let db = Db::init_temp("live_admission_cache").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();

        let mut cache = HashMap::new();
        assert!(cache.get(&drive).is_none());
        admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &drive,
            false,
            &mut cache,
        )
        .await;
        assert_eq!(cache.get(&drive), Some(&true));
    }

    /// F3 follow-up: a `drive_cache` verdict computed under a weaker
    /// identity (e.g. `Public`, before a late AUTH frame) must not survive
    /// the identity change — otherwise a peer that proves a stronger
    /// identity mid-connection keeps being rejected for a drive it now
    /// legitimately has rights to, until reconnect.
    #[tokio::test]
    async fn stale_public_verdict_cleared_after_late_auth_upgrades_identity() {
        let db = Db::init_temp("live_admission_cache_identity_change")
            .await
            .unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();

        // Simulate the connection starting as Public and getting rejected
        // for Alice's drive — the verdict lands in the cache.
        let mut cache = HashMap::new();
        assert!(
            !admitted_for_drive(&db, &ForAgent::Public, &drive, false, &mut cache).await,
            "Public should not be admitted for Alice's drive"
        );
        assert_eq!(cache.get(&drive), Some(&false));

        // A late AUTH frame strengthens the session to Alice herself.
        let previous = ForAgent::Public;
        let upgraded = ForAgent::AgentSubject(alice.subject.clone());
        invalidate_drive_cache_on_identity_change(&upgraded, &previous, &mut cache);
        assert!(
            cache.get(&drive).is_none(),
            "the stale Public verdict must be gone after the identity change"
        );

        // Re-checking now correctly admits Alice — proving the clear
        // wasn't just cosmetic; a *stale* cache would have kept returning
        // the cached `false` regardless of the new identity.
        assert!(
            admitted_for_drive(&db, &upgraded, &drive, false, &mut cache).await,
            "Alice must be admitted for her own drive once the stale cache is cleared"
        );
    }

    /// Sanity check for the inverse: no identity change means no
    /// invalidation — the whole point of the cache (skip re-walking rights
    /// on every frame) would be defeated by clearing it unconditionally.
    #[tokio::test]
    async fn cache_survives_when_identity_is_unchanged() {
        let db = Db::init_temp("live_admission_cache_identity_stable")
            .await
            .unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();

        let mut cache = HashMap::new();
        admitted_for_drive(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &drive,
            false,
            &mut cache,
        )
        .await;
        assert_eq!(cache.get(&drive), Some(&true));

        let same = ForAgent::AgentSubject(alice.subject.clone());
        invalidate_drive_cache_on_identity_change(&same, &same, &mut cache);
        assert_eq!(
            cache.get(&drive),
            Some(&true),
            "an unchanged identity must not clear the cache"
        );
    }
}

#[cfg(test)]
mod initiator_trust_tests {
    //! When THIS node dials a peer (the initiator side,
    //! `sync_drive_with_peer_using_outcome`), it used to trust that peer
    //! unconditionally — serve any subject it named in `pull` straight from the
    //! snapshot tree with no `check_read`, import its `SYNC_PUSH` as
    //! `ForAgent::Sudo`, and apply its `remove[]` deletes with no rights check.
    //! Dialing a peer never established the peer's rights. These tests exercise
    //! the three gate helpers directly, mirroring how
    //! `live_write_admission_tests` exercises `admitted_for_drive`.
    use super::*;
    use crate::Db;
    use std::collections::HashMap;

    /// Build a drive whose read/write is restricted to `owner` (no public
    /// grant) plus one child resource under it. Returns `(drive_did, child)`.
    pub(super) async fn private_drive_with_child(
        db: &Db,
        owner: &crate::agents::Agent,
    ) -> (String, String) {
        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::IS_A.into(),
            crate::Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
        );
        builder.set(
            crate::urls::NAME.into(),
            crate::Value::String("Private Drive".into()),
        );
        builder.set(
            crate::urls::WRITE.into(),
            crate::Value::ResourceArray(vec![owner.subject.to_string().into()]),
        );
        builder.set(
            crate::urls::READ.into(),
            crate::Value::ResourceArray(vec![owner.subject.to_string().into()]),
        );
        let commit = crate::commit::Commit::create_did(builder, owner, db)
            .await
            .unwrap();
        let drive_did = commit.subject.to_string();
        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        db.apply_commit(commit, &opts).await.unwrap();
        db.set_active_drive(&drive_did).unwrap();

        let child = db
            .create_resource(
                crate::urls::CLASS,
                &drive_did,
                "Secret Doc",
                // A schema-valid Class instance (shortname + description), so
                // a later commit against it, a destroy included, is judged on
                // signature and rights rather than tripping validation.
                Some(vec![
                    (
                        crate::urls::DESCRIPTION,
                        crate::Value::String("top secret".into()),
                    ),
                    (
                        crate::urls::SHORTNAME,
                        crate::Value::Slug("secret-doc".into()),
                    ),
                ]),
            )
            .await
            .unwrap();
        (drive_did, child)
    }

    /// A peer we dialed that only proved `Public` (or nothing) must NOT be
    /// served snapshots for subjects it can't read — even though it named them
    /// in its `pull` list. The old code read `Tree::LoroSnapshots` directly and
    /// handed the bytes over regardless.
    #[tokio::test]
    async fn pull_serving_refuses_unreadable_subjects_for_public_peer() {
        let db = Db::init_temp("initiator_pull_public").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;

        // Public peer asks for the secret child — must get nothing.
        let served = crate::sync::engine::collect_readable_snapshots(
            &db,
            &ForAgent::Public,
            &[child.clone()],
            None,
        )
        .await;
        assert!(
            served.is_empty(),
            "a Public peer must not be served a snapshot for a subject it can't read"
        );

        // The rightful owner asking for the same subject IS served — proving
        // the gate rejects on rights, not on some unrelated failure.
        let served_owner = crate::sync::engine::collect_readable_snapshots(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &[child.clone()],
            None,
        )
        .await;
        assert_eq!(
            served_owner.len(),
            1,
            "the owner must still be served the snapshot it can read"
        );
        assert_eq!(served_owner[0].0, child);
    }

    /// A stranger agent (proved identity, but no rights on this drive) is
    /// treated the same as Public for the pull-serving gate.
    #[tokio::test]
    async fn pull_serving_refuses_unreadable_subjects_for_stranger() {
        let db = Db::init_temp("initiator_pull_stranger").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();

        let served = crate::sync::engine::collect_readable_snapshots(
            &db,
            &ForAgent::AgentSubject(mallory.subject.clone()),
            &[child],
            None,
        )
        .await;
        assert!(
            served.is_empty(),
            "a peer that authenticated as an unrelated agent must not receive unreadable snapshots"
        );
    }

    /// A node the owner deliberately paired with may replicate what the owner
    /// can read, even though its own agent holds no rights on the drive.
    ///
    /// Without this, two of the same person's machines sync nothing: the
    /// serving node refuses every subject because the peer's node agent is a
    /// stranger to the drive, and the only remedy is hand-writing an ACL entry
    /// naming that agent — per device, per drive, with no prompt and no error.
    /// Pairing is already an authenticated choice by the owner; this treats it
    /// as one.
    #[tokio::test]
    async fn a_paired_replica_receives_what_the_owner_can_read() {
        let db = Db::init_temp("paired_replica_serves").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;

        // The replica's own identity: a node agent, granted nothing.
        let replica_node = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999";
        let replica_agent = db.create_agent(Some("Replica")).await.unwrap();
        let as_replica = ForAgent::AgentSubject(replica_agent.subject.clone());

        // Not paired yet — rights only, so nothing is served.
        let unpaired = crate::sync::engine::collect_readable_snapshots(
            &db,
            &as_replica,
            &[child.clone()],
            Some(replica_node),
        )
        .await;
        assert!(
            unpaired.is_empty(),
            "a node the owner never dialled must not be served"
        );

        // The owner pairs with it.
        add_known_peer(&db, replica_node, "Replica");

        let paired = crate::sync::engine::collect_readable_snapshots(
            &db,
            &as_replica,
            &[child],
            Some(replica_node),
        )
        .await;
        assert_eq!(
            paired.len(),
            1,
            "a paired replica must receive what the owner can read"
        );
    }

    /// A peer we dialed that isn't admitted for the drive must NOT be able to
    /// delete + tombstone a subject we legitimately hold via `remove[]`. The
    /// old code called `apply_destroy` (unchecked) for every remove entry.
    #[tokio::test]
    async fn remove_rejected_for_unadmitted_peer_known_subject() {
        let db = Db::init_temp("initiator_remove_stranger").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();

        let mut cache = HashMap::new();
        apply_peer_remove(
            &db,
            &ForAgent::AgentSubject(mallory.subject.clone()),
            &child,
            false,
            &mut cache,
            None,
        )
        .await;

        assert!(
            db.get_resource(&child.as_str().into()).await.is_ok(),
            "an unadmitted peer's remove[] entry must NOT delete a subject we hold"
        );
        assert!(
            !crate::sync::tombstones::is_tombstoned(&db, &child),
            "an unadmitted peer's remove[] entry must NOT tombstone a subject we hold"
        );
    }

    /// The rightful owner's remove IS applied — proving the gate is about
    /// rights, not a blanket refusal that would break legitimate reconcile.
    #[tokio::test]
    async fn remove_applied_for_admitted_owner() {
        let db = Db::init_temp("initiator_remove_owner").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;

        let mut cache = HashMap::new();
        apply_peer_remove(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &child,
            false,
            &mut cache,
            None,
        )
        .await;

        assert!(
            db.get_resource(&child.as_str().into()).await.is_err(),
            "the owner's remove[] entry must delete the subject"
        );
        assert!(
            crate::sync::tombstones::is_tombstoned(&db, &child),
            "the owner's remove[] entry must record a tombstone"
        );
    }

    /// A signed destroy envelope is applied as a COMMIT: the connection's
    /// AUTH identity does not authorise the delete, the commit's signer does.
    /// Mallory's session can relay Alice's destroy and it still lands.
    #[tokio::test]
    async fn signed_remove_envelope_applies_even_when_connection_agent_is_a_stranger() {
        let db = Db::init_temp("initiator_remove_signed").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();

        let subject = crate::Subject::from_raw(&child, None);
        let resource = db.get_resource(&subject).await.unwrap();
        let mut builder = crate::commit::CommitBuilder::new(subject.clone());
        builder.destroy(true);
        let commit = builder.sign(&alice, &db, &resource).await.unwrap();
        let commit_json = commit
            .into_resource(&db)
            .await
            .unwrap()
            .to_json_ad(None)
            .unwrap();

        let mut cache = HashMap::new();
        apply_peer_remove(
            &db,
            &ForAgent::AgentSubject(mallory.subject.clone()),
            &child,
            false,
            &mut cache,
            Some(&commit_json),
        )
        .await;

        assert!(
            db.get_resource(&subject).await.is_err(),
            "a valid destroy envelope must apply regardless of the connection agent"
        );
        assert!(crate::sync::tombstones::is_tombstoned(&db, &child));
        assert!(
            crate::sync::tombstones::destroy_envelope(&db, &child).is_some(),
            "the applied destroy must leave its envelope on the tombstone"
        );
    }

    /// A tampered envelope must not fall back to the unsigned tombstone path.
    #[tokio::test]
    async fn tampered_remove_envelope_does_not_delete() {
        let db = Db::init_temp("initiator_remove_tampered").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (_drive, child) = private_drive_with_child(&db, &alice).await;

        let subject = crate::Subject::from_raw(&child, None);
        let resource = db.get_resource(&subject).await.unwrap();
        let mut builder = crate::commit::CommitBuilder::new(subject.clone());
        builder.destroy(true);
        let commit = builder.sign(&alice, &db, &resource).await.unwrap();
        let commit_json = commit
            .into_resource(&db)
            .await
            .unwrap()
            .to_json_ad(None)
            .unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&commit_json).unwrap();
        json[crate::urls::SIGNATURE] = serde_json::Value::String("AAAA".into());
        let tampered = json.to_string();

        let mut cache = HashMap::new();
        apply_peer_remove(
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            &child,
            false,
            &mut cache,
            Some(&tampered),
        )
        .await;

        assert!(
            db.get_resource(&subject).await.is_ok(),
            "a tampered destroy envelope must not delete, even from the owner"
        );
        assert!(!crate::sync::tombstones::is_tombstoned(&db, &child));
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod accept_gate_tests {
    //! The accept side of the Iroh transport (`handle_stream`) and the sync
    //! engine's `SYNC_PUSH` answer, exercised the way a hostile or merely
    //! confused peer would hit them: frames before AUTH, AUTH for one drive
    //! followed by a handshake for another, and a push from an agent with
    //! no write right. Each refusal must be *visible* — an `ERROR` frame with
    //! a registered code — never a silent drop or a `SYNC_OK` for nothing.
    use super::initiator_trust_tests::private_drive_with_child;
    use super::*;
    use crate::sync::protocol::{self, error_code, tag};
    use crate::Db;

    /// `(request_id, code, message)` of an ERROR frame, or `None` for any
    /// other frame.
    fn parse_error(frame: &[u8]) -> Option<(u16, u16, String)> {
        if frame.first() != Some(&tag::ERROR) || frame.len() < 5 {
            return None;
        }
        let request_id = u16::from_be_bytes([frame[1], frame[2]]);
        let code = u16::from_be_bytes([frame[3], frame[4]]);
        let message = String::from_utf8_lossy(&frame[5..]).into_owned();
        Some((request_id, code, message))
    }

    /// A SYNC_PUSH frame carrying the owner's current snapshot of `child`,
    /// as a peer that replays it would send it.
    async fn push_frame_for(
        db: &Db,
        owner: &crate::agents::Agent,
        drive: &str,
        child: &str,
    ) -> Vec<u8> {
        let snapshots = crate::sync::engine::collect_readable_snapshots(
            db,
            &ForAgent::AgentSubject(owner.subject.clone()),
            &[child.to_string()],
            None,
        )
        .await;
        assert_eq!(snapshots.len(), 1, "owner can read its own child");
        let entries: Vec<(&str, &[u8])> = snapshots
            .iter()
            .map(|(s, b)| (s.as_str(), b.as_slice()))
            .collect();
        protocol::encode_sync_push(drive, &entries, true)
    }

    #[tokio::test]
    async fn import_sync_push_refuses_agent_without_write_right() {
        let db = Db::init_temp("gate_import_stranger").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (drive, child) = private_drive_with_child(&db, &alice).await;
        let mallory = crate::agents::Agent::new(Some("Mallory")).unwrap();

        let frame = push_frame_for(&db, &alice, &drive, &child).await;
        let push = protocol::decode_sync_push(&frame[1..]).unwrap();

        for (who, agent) in [
            ("Public", ForAgent::Public),
            (
                "a stranger",
                ForAgent::AgentSubject(mallory.subject.clone()),
            ),
        ] {
            let rejected = crate::sync::engine::import_sync_push(&push, &db, &agent, false)
                .await
                .expect_err(&format!(
                    "{who} must not be able to push into a private drive"
                ));
            assert_eq!(rejected.drive, drive);
            assert!(
                rejected.reason.contains("no write right"),
                "reason names the cause: {}",
                rejected.reason
            );
        }

        // The owner's push is admitted — the refusal is about rights, not a
        // blanket one.
        crate::sync::engine::import_sync_push(
            &push,
            &db,
            &ForAgent::AgentSubject(alice.subject.clone()),
            false,
        )
        .await
        .expect("the owner may push into its own drive");
    }

    /// The wire-level consequence: a refused push is answered with ERROR
    /// `SYNC_REJECTED`, and there is no `SYNC_OK` anywhere in the response.
    /// Before this, the engine answered `SYNC_OK` for a push it had dropped,
    /// so the sender believed its data had landed.
    #[tokio::test]
    async fn rejected_sync_push_is_answered_with_error_not_sync_ok() {
        let db = Db::init_temp("gate_push_error_frame").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (drive, child) = private_drive_with_child(&db, &alice).await;
        let mallory = crate::agents::Agent::new(Some("Mallory")).unwrap();

        let frame = push_frame_for(&db, &alice, &drive, &child).await;
        let mut as_mallory = ForAgent::AgentSubject(mallory.subject.clone());
        let responses = crate::sync::engine::handle_frame(&frame, &db, &mut as_mallory).await;

        assert!(
            !responses.iter().any(|f| f.first() == Some(&tag::SYNC_OK)),
            "a rejected push must never be acknowledged with SYNC_OK"
        );
        let (request_id, code, message) = responses
            .iter()
            .find_map(|f| parse_error(f))
            .expect("a rejected push is answered with an ERROR frame");
        assert_eq!(
            request_id, 0,
            "connection-level error, not tied to a request"
        );
        assert_eq!(code, error_code::SYNC_REJECTED);
        assert!(
            message.contains(&drive),
            "the message names the drive so the sender can act on it: {message}"
        );

        // And the owner's push still gets its SYNC_OK.
        let mut as_alice = ForAgent::AgentSubject(alice.subject.clone());
        let responses = crate::sync::engine::handle_frame(&frame, &db, &mut as_alice).await;
        assert!(
            responses.iter().any(|f| f.first() == Some(&tag::SYNC_OK)),
            "the owner's push is acknowledged"
        );
    }

    /// Dial a running accept side with a raw endpoint and return the stream.
    async fn raw_stream(
        router: &Router,
        node_id: &NodeId,
    ) -> (
        iroh::Endpoint,
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
    ) {
        let ep = iroh::Endpoint::builder().bind().await.unwrap();
        let addr = router.endpoint().node_addr().await.unwrap();
        ep.add_node_addr(addr).unwrap();
        let conn = ep.connect(*node_id, ATOMIC_ALPN).await.unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        (ep, send, recv)
    }

    async fn write_frame(send: &mut iroh::endpoint::SendStream, frame: &[u8]) {
        send.write_all(&frame_with_len(frame)).await.unwrap();
    }

    /// The next frame from the accept side, or `None` once it closed the
    /// stream. The unsolicited HELLO and the auth-back AUTH the accept side
    /// sends after AUTH_OK are skipped; they are not what these tests are
    /// about.
    async fn read_frame(recv: &mut iroh::endpoint::RecvStream) -> Option<Vec<u8>> {
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_u32())
                .await
                .expect("accept side answers within 10s")
                .ok()?;
            let mut buf = vec![0u8; n as usize];
            recv.read_exact(&mut buf).await.ok()?;
            // Not the answer being waited for: the accept side's handshake
            // chatter, the KEEPALIVE its live loop sends after
            // `KEEPALIVE_INTERVAL` of silence, and the live fan-out
            // (`UPDATE`, signed-destroy `COMMIT`) of writes made by the
            // *other* tests in this process, which reaches every stream in
            // the process-global peer registry. None of these tests waits
            // for a fan-out frame.
            if !matches!(
                buf.first(),
                Some(&tag::HELLO)
                    | Some(&tag::AUTH)
                    | Some(&tag::KEEPALIVE)
                    | Some(&tag::UPDATE)
                    | Some(&tag::COMMIT)
            ) {
                return Some(buf);
            }
        }
    }

    /// A handshake frame before AUTH — here a SYNC for a *public* drive,
    /// which the old code would happily have served as `Public` — gets
    /// `AUTH_REQUIRED` and a closed stream. Fail closed on identity.
    #[tokio::test]
    async fn iroh_sync_before_auth_is_refused_and_stream_closed() {
        let db = Db::init_temp("gate_iroh_preauth").await.unwrap();
        let (_alice, drive) = db.setup("Alice").await.unwrap();
        let (node_id, router) = start(db.clone()).await.unwrap();

        let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
        let sync = protocol::encode_sync(&drive, "", &[], &std::collections::HashMap::new());
        write_frame(&mut send, &sync).await;

        let reply = read_frame(&mut recv)
            .await
            .expect("an ERROR frame, not silence");
        let (_, code, message) = parse_error(&reply).expect("ERROR frame");
        assert_eq!(code, error_code::AUTH_REQUIRED, "{message}");
        assert!(
            read_frame(&mut recv).await.is_none(),
            "the accept side closes the stream after refusing"
        );
    }

    /// `AUTH.requestedSubject` is bound to the drive of the handshake that
    /// follows: an AUTH signed for drive X does not open drive Y.
    #[tokio::test]
    async fn iroh_auth_for_one_drive_does_not_open_another() {
        let db = Db::init_temp("gate_iroh_binding").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let (node_id, router) = start(db.clone()).await.unwrap();

        let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
        let auth = protocol::encode_auth(&alice, "did:key:z6MkSomeOtherDrive").unwrap();
        write_frame(&mut send, &auth).await;
        let reply = read_frame(&mut recv).await.expect("AUTH_OK");
        assert_eq!(reply.first(), Some(&tag::AUTH_OK), "AUTH itself is valid");

        let sync = protocol::encode_sync(&drive, "", &[], &std::collections::HashMap::new());
        write_frame(&mut send, &sync).await;
        let reply = read_frame(&mut recv)
            .await
            .expect("an ERROR frame, not a SYNC_DIFF");
        let (_, code, message) = parse_error(&reply).expect("ERROR frame");
        assert_eq!(code, error_code::AUTH_REQUIRED, "{message}");
        assert!(message.contains(&drive), "{message}");
        assert!(read_frame(&mut recv).await.is_none(), "stream closed");
    }

    /// The happy path through the same raw stream, so the two refusals
    /// above are known to be about the gate and not about the fixture:
    /// AUTH for the drive, then SYNC of it, yields a handshake answer.
    #[tokio::test]
    async fn iroh_auth_then_sync_for_same_drive_is_served() {
        let db = Db::init_temp("gate_iroh_happy").await.unwrap();
        let (alice, drive) = db.setup("Alice").await.unwrap();
        let (node_id, router) = start(db.clone()).await.unwrap();

        let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
        write_frame(&mut send, &protocol::encode_auth(&alice, &drive).unwrap()).await;
        assert_eq!(
            read_frame(&mut recv).await.unwrap().first(),
            Some(&tag::AUTH_OK)
        );

        let sync = protocol::encode_sync(&drive, "", &[], &std::collections::HashMap::new());
        write_frame(&mut send, &sync).await;
        let reply = read_frame(&mut recv).await.expect("a handshake answer");
        assert!(
            matches!(
                reply.first(),
                Some(&tag::SYNC_DIFF) | Some(&tag::SYNC_PUSH) | Some(&tag::SYNC_OK)
            ),
            "expected a sync answer, got 0x{:02x}",
            reply[0]
        );
    }

    /// Complete the handshake on a raw stream as `owner` for `drive` and
    /// drain the accept side's answer until it has transitioned to live mode
    /// (the client sent an empty version vector, so the server pushes
    /// everything and expects nothing back).
    async fn handshake_to_live(
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
        owner: &crate::agents::Agent,
        drive: &str,
    ) {
        write_frame(send, &protocol::encode_auth(owner, drive).unwrap()).await;
        let reply = read_frame(recv).await.expect("AUTH_OK");
        assert_eq!(reply.first(), Some(&tag::AUTH_OK));
        assert!(
            protocol::decode_auth_ok(&reply[1..])
                .iter()
                .any(|c| c == "signed-destroy"),
            "AUTH_OK advertises this build's capabilities"
        );

        let sync = protocol::encode_sync(drive, "", &[], &std::collections::HashMap::new());
        write_frame(send, &sync).await;
        loop {
            let reply = read_frame(recv).await.expect("a handshake answer");
            match reply.first() {
                Some(&tag::SYNC_OK) => break,
                Some(&tag::SYNC_PUSH) => {
                    let push = protocol::decode_sync_push(&reply[1..]).unwrap();
                    if push.last {
                        break;
                    }
                }
                Some(&tag::SYNC_DIFF) => continue,
                other => panic!("unexpected handshake frame {other:?}"),
            }
        }
        // Give the accept side a moment to register the live loop.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    /// A naked `DESTROY` frame carries no signature, so it authorises
    /// nothing — not even from the drive's owner, on an authenticated live
    /// link. The resource survives. (planning/serverless-p2p.md, principle 3.)
    #[tokio::test]
    async fn naked_destroy_on_the_live_link_is_ignored() {
        let db = Db::init_temp("gate_iroh_naked_destroy").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (drive, child) = private_drive_with_child(&db, &alice).await;
        let (node_id, router) = start(db.clone()).await.unwrap();

        let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
        handshake_to_live(&mut send, &mut recv, &alice, &drive).await;

        write_frame(&mut send, &protocol::encode_destroy(0, &child)).await;
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;

        let subject = crate::Subject::from_raw(&child, None);
        assert!(
            db.get_resource(&subject).await.is_ok(),
            "a naked DESTROY must never remove a resource"
        );
        assert!(
            !crate::sync::tombstones::is_tombstoned(&db, &child),
            "and must not leave a tombstone that would poison later imports"
        );
    }

    /// The same delete as a signed destroy `COMMIT` is applied: the live
    /// loop routes it through the engine's COMMIT arm, which verifies the
    /// signature and the signer's rights like any other write.
    #[tokio::test]
    async fn signed_destroy_commit_on_the_live_link_is_applied() {
        let db = Db::init_temp("gate_iroh_signed_destroy").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (drive, child) = private_drive_with_child(&db, &alice).await;
        let (node_id, router) = start(db.clone()).await.unwrap();

        let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
        handshake_to_live(&mut send, &mut recv, &alice, &drive).await;

        let subject = crate::Subject::from_raw(&child, None);
        let resource = db.get_resource(&subject).await.unwrap();
        // A bare destroy: no property edits ride along, so the only thing
        // the receiver validates is the signature and the signer's rights.
        let mut builder = crate::commit::CommitBuilder::new(subject.clone());
        builder.destroy(true);
        let commit = builder.sign(&alice, &db, &resource).await.unwrap();
        // The same serialisation the live push loop forwards.
        let commit_json = commit
            .into_resource(&db)
            .await
            .unwrap()
            .to_json_ad(None)
            .unwrap();
        write_frame(&mut send, &protocol::encode_commit(0, &commit_json)).await;

        // The engine answers the COMMIT: COMMIT_OK, or an ERROR that says
        // why it was refused (which is the useful failure message here).
        let reply = read_frame(&mut recv)
            .await
            .expect("an answer to the COMMIT");
        if let Some((_, code, message)) = parse_error(&reply) {
            panic!("signed destroy commit refused (code {code}): {message}");
        }
        assert_eq!(reply.first(), Some(&tag::COMMIT_OK), "expected COMMIT_OK");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while db.get_resource(&subject).await.is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "COMMIT_OK was answered but the resource is still there after 5s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// A destroy commit signed by an agent without write rights is refused by
    /// the same COMMIT arm — the connection's identity does not matter, the
    /// signature does.
    #[tokio::test]
    async fn signed_destroy_from_stranger_on_the_live_link_is_refused() {
        let db = Db::init_temp("gate_iroh_stranger_destroy").await.unwrap();
        let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
        db.set_default_agent(alice.clone());
        let (drive, child) = private_drive_with_child(&db, &alice).await;
        let mallory = db.create_agent(Some("Mallory")).await.unwrap();
        let (node_id, router) = start(db.clone()).await.unwrap();

        let (_ep, mut send, mut recv) = raw_stream(&router, &node_id).await;
        handshake_to_live(&mut send, &mut recv, &alice, &drive).await;

        let subject = crate::Subject::from_raw(&child, None);
        let resource = db.get_resource(&subject).await.unwrap();
        let mut builder = crate::commit::CommitBuilder::new(subject.clone());
        builder.destroy(true);
        let commit = builder.sign(&mallory, &db, &resource).await.unwrap();
        let commit_json = commit
            .into_resource(&db)
            .await
            .unwrap()
            .to_json_ad(None)
            .unwrap();
        write_frame(&mut send, &protocol::encode_commit(0, &commit_json)).await;

        let reply = read_frame(&mut recv).await.expect("an ERROR frame");
        let (_, code, message) = parse_error(&reply).expect("ERROR frame");
        assert_eq!(code, error_code::UNAUTHORIZED_WRITE, "{message}");
        assert!(
            db.get_resource(&subject).await.is_ok(),
            "Mallory's destroy must not be applied"
        );
    }
}

#[cfg(test)]
mod live_peer_registry_tests {
    use super::*;

    fn register(key: &str) -> u64 {
        let generation =
            LIVE_PEER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        LIVE_PEERS.lock().unwrap().insert(
            normalize_node_id(key),
            LivePeer {
                generation,
                tx,
                _connection: None,
            },
        );

        generation
    }

    fn is_registered(key: &str) -> bool {
        LIVE_PEERS
            .lock()
            .unwrap()
            .contains_key(&normalize_node_id(key))
    }

    /// A reconnect installs a new connection under the same node id, and the
    /// old one's loops tear down a moment later. That teardown must not evict
    /// the live connection that replaced it — otherwise sync goes silent while
    /// both ends still show "Connected", and nothing recovers it until the next
    /// reconnect.
    #[test]
    fn a_stale_connection_does_not_deregister_its_replacement() {
        let peer = "test-peer-stale-vs-replacement";
        let old = register(peer);
        let new = register(peer);
        assert_ne!(old, new);

        remove_live_peer(peer, old);
        assert!(
            is_registered(peer),
            "the replacement connection must survive the old one's teardown"
        );

        remove_live_peer(peer, new);
        assert!(
            !is_registered(peer),
            "the current connection must still be able to deregister itself"
        );
    }

    #[test]
    fn a_deliberate_reconnect_evicts_whoever_is_current() {
        let peer = "test-peer-forced-reconnect";
        register(peer);
        remove_live_peer_any_quiet(peer);
        assert!(!is_registered(peer));
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod peer_sync_volume_tests {
    use super::*;

    /// The card needs to say what a sync moved, not just that one happened —
    /// a timestamp cannot distinguish a link carrying data from one being
    /// refused every subject.
    #[tokio::test]
    async fn a_completed_sync_records_what_it_moved() {
        let db = Db::init_temp("peer_sync_volume").await.unwrap();
        let node = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";

        mark_peer_synced(&db, node, Some(49), Some(1));

        let peer = get_known_peers(&db)
            .into_iter()
            .find(|p| normalize_node_id(&p.node_id) == normalize_node_id(node))
            .expect("the sync must record the peer");

        assert_eq!(peer.last_sent, Some(49));
        assert_eq!(peer.last_received, Some(1));
        assert!(peer.last_synced.is_some());

        // A later, quieter sync replaces the figures rather than accumulating:
        // these describe the last pass, so they must be checkable against what
        // that pass reported.
        mark_peer_synced(&db, node, Some(0), Some(2));

        let peer = get_known_peers(&db)
            .into_iter()
            .find(|p| normalize_node_id(&p.node_id) == normalize_node_id(node))
            .unwrap();

        assert_eq!(peer.last_sent, Some(0));
        assert_eq!(peer.last_received, Some(2));
    }
}
