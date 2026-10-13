//! Admission checks and the read/write loops of one live peer connection.

use super::*;

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

pub(super) async fn admitted_for_drive(
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
pub(super) async fn apply_peer_remove(
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
pub(super) fn invalidate_drive_cache_on_identity_change(
    agent: &ForAgent,
    previous: &ForAgent,
    drive_cache: &mut std::collections::HashMap<String, bool>,
) {
    if agent != previous {
        drive_cache.clear();
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn register_live_peer(
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
    // What the peer listed in its `AUTH_OK` (dial side) or `HELLO` (accept
    // side). Decides the identifier scheme on every frame this link carries.
    peer_caps: Vec<String>,
) {
    let key = normalize_node_id(&peer_id);
    let wire = super::engine::WireScheme::from_caps(&peer_caps);
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
        let mut map = live_peers();
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
                canonical_scheme: wire.is_canonical(),
                _connection: connection,
            },
        );
        !replacing
    };

    let peer_short = key[..key.len().min(12)].to_string();
    tracing::info!("[live] registered peer {peer_short} (new={is_new_peer})");
    // Always notify so both sides refresh UI (replacing a dead channel still counts).
    push_event(&key, 0, "connected");

    // Whatever this device wrote while no link was up goes to the peer now,
    // as signed commits it validates like a hub would. Best effort: a
    // refusal lands in the outbox, a dead link is retried on the next one.
    {
        let store_drain = store.clone();
        let peer_drain = key.clone();
        tokio::spawn(async move {
            // Let the HELLO and agent frames below go first.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if let Ok(entries) = crate::sync::outbox::Outbox::new(store_drain.clone()).entries() {
                if entries.is_empty() {
                    return;
                }
            }
            match drain_outbox_to_live_peer(&store_drain, &peer_drain).await {
                Ok(report) => tracing::info!(
                    "[live] outbox drain to {}: {} sent, {} deferred, {} blocked, {} dropped, {} remaining",
                    &peer_drain[..peer_drain.len().min(12)],
                    report.sent,
                    report.deferred,
                    report.blocked,
                    report.dropped,
                    report.remaining
                ),
                Err(e) => tracing::warn!(
                    "[live] outbox drain to {} failed: {e}",
                    &peer_drain[..peer_drain.len().min(12)]
                ),
            }
        });
    }

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
    if let Some(frame) = own_agent_update_frame(&store, wire) {
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
                // A refusal of one of our outbox COMMITs: the drain is
                // waiting for exactly this verdict.
                if let Some(err) = super::protocol::decode_error(&buf[1..]) {
                    if resolve_commit_waiter(
                        &read_peer_id,
                        err.request_id,
                        Err(crate::sync::outbox::CommitRefused {
                            code: err.code,
                            message: err.message,
                        }),
                    ) {
                        continue;
                    }
                }
                let msg = std::str::from_utf8(buf.get(5..).unwrap_or(&[])).unwrap_or("(non-utf8)");
                tracing::warn!(
                    "[live] {} answered with an error: {msg}",
                    &read_peer_id[..read_peer_id.len().min(12)]
                );
                continue;
            }

            // The peer applied one of our outbox COMMITs.
            if buf[0] == super::protocol::tag::COMMIT_OK {
                if let Some(ok) = super::protocol::decode_commit_ok(&buf[1..]) {
                    resolve_commit_waiter(&read_peer_id, ok.request_id, Ok(ok.commit_id));
                }
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
                                // Attribute this write to the peer it came
                                // from: `add_resource_opts` reads the import
                                // scope while the write is still on the stack
                                // and stamps it on the `DbEvent`, so the push
                                // loop skips exactly that peer. Without it an
                                // unconditional re-send of an identical
                                // snapshot ping-pongs between the two nodes
                                // (measured: 355 frames in 58s, ~50KB/s, for
                                // one agent resource and one drive). The scope
                                // is per task, so another connection's import
                                // or a concurrent local edit is never muted by
                                // this one (security audit C16). The WS
                                // announcer ignores it, so the local browser
                                // still sees the merged state.
                                let admitted_drive = resolved.drive_subject.clone();
                                let persisted = super::ws_apply::import_scope(
                                    Some(read_peer_id.clone()),
                                    super::ws_apply::persist_update(
                                        &store,
                                        &decoded.subject,
                                        resolved,
                                    ),
                                )
                                .await;
                                // A File introduced during a live link needs
                                // the same blob request as a bulk SYNC_PUSH. Request
                                // only after admission and successful persistence,
                                // and only from the peer that supplied this resource.
                                if persisted.is_ok() {
                                    let subject = crate::Subject::from_raw(
                                        &decoded.subject,
                                        store.get_base_domain().as_deref(),
                                    );
                                    if let Ok(resource) = store.get_resource(&subject).await {
                                        if let Ok(value) = resource.get(crate::urls::BLOB) {
                                            let blob =
                                                crate::Subject::from_raw(&value.to_string(), None);
                                            if let Some(hash_hex) = blob.blob_hash_hex() {
                                                if let Ok(bytes) = hex::decode(hash_hex) {
                                                    if let Ok(hash) = <[u8; 32]>::try_from(bytes) {
                                                        if !store
                                                            .has_blob(&hash)
                                                            .await
                                                            .unwrap_or(false)
                                                        {
                                                            store.note_pending_blob_request(
                                                                hash,
                                                                admitted_drive,
                                                            );
                                                            let frame = super::protocol::encode_blob_request(&hash);
                                                            let _ = tx_for_read
                                                                .send(frame_with_len(&frame))
                                                                .await;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
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
            //
            // Inside this connection's import scope, so a `COMMIT` the engine
            // applies is attributed to this peer and the push loop does not
            // send it straight back (see `ws_apply::import_scope`).
            let agent_before_frame = agent.clone();
            let responses = super::ws_apply::import_scope(
                Some(read_peer_id.clone()),
                super::engine::handle_frame_for_caps(&buf, &store, &mut agent, wire),
            )
            .await;
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
