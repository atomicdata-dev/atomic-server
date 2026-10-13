use super::*;

fn register(key: &str) -> u64 {
    let generation = LIVE_PEER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    live_peers().insert(
        normalize_node_id(key),
        LivePeer {
            generation,
            tx,
            canonical_scheme: true,
            _connection: None,
        },
    );

    generation
}

fn is_registered(key: &str) -> bool {
    live_peers().contains_key(&normalize_node_id(key))
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
