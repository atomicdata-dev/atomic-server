//! The registry of live peer connections and their commit transport.

use super::*;

// ── Live sync (persistent connections) ──────────────────────────────────

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

/// The live peer map, whether or not a previous holder panicked. The map only
/// holds channel senders and connection handles, which a panic cannot leave
/// half-updated in a way that matters, so a poisoned lock is recovered rather
/// than propagated: unwrapping it here made one panic (in whichever task
/// happened to hold the lock) kill live broadcast for the rest of the process.
pub(super) fn live_peers() -> std::sync::MutexGuard<'static, HashMap<String, LivePeer>> {
    LIVE_PEERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One live peer: the write loop's channel, the generation that installed
/// it, and (dial side only) the QUIC connection kept alive for it. Dropping
/// the entry drops the connection, so a re-dial replaces the link it
/// supersedes and a removed peer releases it; before 2026-09 connections
/// were pinned in a separate append-only list for the life of the process.
pub(super) struct LivePeer {
    pub(super) generation: u64,
    pub(super) tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// The peer listed `canonical-scheme`: live frames carry `atomic:`
    /// subjects. A peer that predates the rename gets `did:ad:`.
    pub(super) canonical_scheme: bool,
    /// Never read; held so the QUIC connection stays open exactly as long
    /// as the registration does.
    pub(super) _connection: Option<iroh::endpoint::Connection>,
}

/// Monotonic id per live connection; see [`LIVE_PEERS`].
pub(super) static LIVE_PEER_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

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
    live_peers().len()
}

/// Returns the node IDs of currently connected live peers.
pub fn live_peer_ids() -> Vec<String> {
    live_peers().keys().cloned().collect()
}

type CommitWaiter =
    tokio::sync::oneshot::Sender<Result<String, crate::sync::outbox::CommitRefused>>;

/// `COMMIT`s sent over a live link and not yet answered, keyed by
/// `(peer, request id)`. The peer's read loop resolves one when the
/// matching `COMMIT_OK` or `ERROR` arrives on that link.
static COMMIT_WAITERS: LazyLock<Mutex<HashMap<(String, u16), CommitWaiter>>> =
    LazyLock::new(Default::default);

/// Request ids for live-link commits. Per process, not per drain pass, so
/// two drains over one link cannot collide.
static LIVE_COMMIT_REQUEST_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

pub(super) fn resolve_commit_waiter(
    peer_key: &str,
    request_id: u16,
    result: Result<String, crate::sync::outbox::CommitRefused>,
) -> bool {
    let waiter = COMMIT_WAITERS
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&(normalize_node_id(peer_key), request_id)));
    match waiter {
        Some(tx) => {
            let _ = tx.send(result);
            true
        }
        None => false,
    }
}

/// The outbox transport for a live Iroh link: one signed `COMMIT` per call
/// through the peer's write loop, answered by its engine with `COMMIT_OK`
/// or `ERROR` on the same stream. This is the sending half of
/// `planning/serverless-p2p.md` P4: a device with no hub in reach delivers
/// its writes to a paired peer, which validates them like a hub would.
pub struct LivePeerCommitTransport {
    peer: String,
}

impl LivePeerCommitTransport {
    pub fn new(peer_id: &str) -> Self {
        Self {
            peer: normalize_node_id(peer_id),
        }
    }

    /// Whether the peer currently has a live link.
    pub fn is_live(&self) -> bool {
        live_peers().contains_key(&self.peer)
    }
}

impl crate::sync::outbox::CommitTransport for LivePeerCommitTransport {
    async fn post_commit(
        &mut self,
        _request_id: u16,
        commit_json: &str,
    ) -> Result<String, crate::sync::outbox::CommitRefused> {
        use crate::sync::outbox::CommitRefused;
        use crate::sync::protocol::error_code;

        let transport_error = |message: String| CommitRefused {
            code: error_code::UNKNOWN,
            message,
        };
        let rid = LIVE_COMMIT_REQUEST_ID
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .max(1);
        let (tx_wait, rx_wait) = tokio::sync::oneshot::channel();
        if let Ok(mut map) = COMMIT_WAITERS.lock() {
            map.insert((self.peer.clone(), rid), tx_wait);
        }
        let forget = || {
            if let Ok(mut map) = COMMIT_WAITERS.lock() {
                map.remove(&(self.peer.clone(), rid));
            }
        };

        let Some(tx) = live_peers().get(&self.peer).map(|p| p.tx.clone()) else {
            forget();
            return Err(transport_error(format!(
                "peer {} is not live",
                &self.peer[..self.peer.len().min(12)]
            )));
        };
        let frame = frame_with_len(&super::protocol::encode_commit(rid, commit_json));
        if tx.send(frame).await.is_err() {
            forget();
            return Err(transport_error(
                "live link closed before COMMIT was sent".into(),
            ));
        }

        match tokio::time::timeout(std::time::Duration::from_secs(30), rx_wait).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(transport_error(
                "live link closed while waiting for COMMIT_OK".into(),
            )),
            Err(_) => {
                forget();
                Err(transport_error(
                    "COMMIT over the live link timed out".into(),
                ))
            }
        }
    }
}

/// Drain the store's outbox to one live peer. `Err` only for a store or
/// link failure; refusals become outbox state.
pub async fn drain_outbox_to_live_peer(
    store: &Db,
    peer_id: &str,
) -> crate::errors::AtomicResult<crate::sync::outbox::DrainReport> {
    let mut transport = LivePeerCommitTransport::new(peer_id);
    crate::sync::outbox::Outbox::new(store.clone())
        .drain(&mut transport)
        .await
}

/// Drain the outbox to the first live peer, if any. `None` when there is
/// no live link or nothing to send.
pub async fn drain_outbox_to_any_live_peer(store: &Db) -> Option<crate::sync::outbox::DrainReport> {
    let outbox = crate::sync::outbox::Outbox::new(store.clone());
    if outbox.entries().ok()?.is_empty() {
        return None;
    }
    let peer = live_peer_ids().into_iter().next()?;
    match drain_outbox_to_live_peer(store, &peer).await {
        Ok(report) => Some(report),
        Err(e) => {
            tracing::warn!(
                "[live] outbox drain to {} failed: {e}",
                &peer[..peer.len().min(12)]
            );
            None
        }
    }
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
pub(super) fn remove_live_peer_any_quiet(peer_id: &str) {
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
    let removed = {
        let mut map = live_peers();
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
    };
    if let Some(peer) = removed {
        drop(peer);
        tracing::info!("[live] removed peer {}", &key[..key.len().min(12)]);
        if notify {
            push_event(&key, 0, "disconnected");
        }
    }
}
