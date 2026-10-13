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
