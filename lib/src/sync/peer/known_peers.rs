//! Known peers persisted in the DB, and how to dial them.

use super::*;

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
    /// The drives this node has dialed the peer for. This is what a
    /// `forget-peer` request is authorized against: whoever may write one of
    /// these drives chose to sync it with that device, and may undo that.
    /// Empty for peers recorded before this was tracked; those can only be
    /// forgotten by the node's own agent.
    #[serde(default)]
    pub drives: Vec<String>,
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
    add_known_peer_for_drive(store, node_id, name, "");
}

/// [`add_known_peer`], also recording `drive` (when non-empty) as one of the
/// drives this node dialed the peer for. See [`KnownPeer::drives`].
pub fn add_known_peer_for_drive(store: &Db, node_id: &str, name: &str, drive: &str) {
    let key = normalize_node_id(node_id);
    let mut peers = get_known_peers(store);
    if let Some(existing) = peers
        .iter_mut()
        .find(|p| normalize_node_id(&p.node_id) == key)
    {
        if !name.is_empty() {
            existing.name = name.to_string();
        }
        if !drive.is_empty() && !existing.drives.iter().any(|d| d == drive) {
            existing.drives.push(drive.to_string());
        }
    } else {
        peers.push(KnownPeer {
            node_id: key,
            drives: if drive.is_empty() {
                vec![]
            } else {
                vec![drive.to_string()]
            },
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
            drives: Vec::new(),
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
pub(super) fn dial_target(store: &Db, node_id: NodeId) -> iroh::NodeAddr {
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
            drives: Vec::new(),
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
