//! Broadcasting local changes and ephemera to live peers.

use super::*;

/// Whether the current task is applying data from a remote peer (see
/// [`super::ws_apply::import_scope`]).
pub fn is_importing() -> bool {
    super::ws_apply::is_importing()
}

fn encode_live_update_wire_msg(
    subject_key: &str,
    loro_bytes: &[u8],
    wire: super::engine::WireScheme,
) -> Vec<u8> {
    let frame = super::protocol::encode_update(0, 0, &wire.subject(subject_key), None, loro_bytes);
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
pub(super) fn own_agent_update_frame(
    store: &Db,
    wire: super::engine::WireScheme,
) -> Option<Vec<u8>> {
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
    Some(encode_live_update_wire_msg(&key, &snapshot, wire))
}

/// Fan an UPDATE out to live peers, except `skip_peer` — the peer an imported
/// update came from. Sending it back is what made two idle nodes trade the same
/// snapshot indefinitely.
fn send_live_update_wire_msg_except(
    build: &dyn Fn(super::engine::WireScheme) -> Vec<u8>,
    skip_peer: Option<&str>,
) {
    let mut dead_peers = Vec::new();
    let peers = live_peers();
    // One encoding per identifier scheme, built on first use: most links
    // speak the canonical scheme and the `did:ad:` copy is never made.
    let mut by_scheme: [Option<Vec<u8>>; 2] = [None, None];
    {
        for (
            peer_id,
            LivePeer {
                generation,
                tx,
                canonical_scheme,
                ..
            },
        ) in peers.iter()
        {
            if skip_peer.is_some_and(|skip| normalize_node_id(skip) == *peer_id) {
                continue;
            }
            let wire = if *canonical_scheme {
                super::engine::WireScheme::CANONICAL
            } else {
                super::engine::WireScheme::LEGACY
            };
            let msg = by_scheme[usize::from(*canonical_scheme)].get_or_insert_with(|| build(wire));

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

    // The drive and agent identifiers ride in the frame header, so they
    // follow the peer's scheme like every other subject on the link.
    send_live_update_wire_msg_except(
        &|wire| {
            let frame = super::protocol::encode_ephemeral(
                kind,
                &wire.subject(drive),
                &wire.subject(agent),
                payload,
            );
            let len = frame.len() as u32;
            let mut msg = Vec::with_capacity(4 + frame.len());
            msg.extend_from_slice(&len.to_be_bytes());
            msg.extend_from_slice(&frame);
            msg
        },
        skip_peer,
    );
}

/// Push an UPDATE frame to all connected live peers immediately (e.g. after a stroke save).
pub fn broadcast_live_update(subject_key: &str, loro_bytes: &[u8]) {
    if loro_bytes.is_empty() || super::ws_apply::is_importing() {
        return;
    }
    send_live_update_wire_msg_except(
        &|wire| encode_live_update_wire_msg(subject_key, loro_bytes, wire),
        None,
    );
}

/// Start the live sync system. Watches for local changes and pushes to all connected peers.
pub(super) fn start_live_sync(store: Db) {
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
                    // Signed JSON: the same bytes whatever the peer speaks.
                    send_live_update_wire_msg_except(&|_| msg.clone(), from_peer.as_deref());
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
                send_live_update_wire_msg_except(
                    &|wire| encode_live_update_wire_msg(&subject_key, &bytes, wire),
                    from_peer.as_deref(),
                );
            }
        }
    });
}
