//! Outgoing sync: dialing a peer and reconciling a drive with it.

use super::*;

/// Inspect access and the device name without importing or pairing.
pub async fn inspect_workspace_peer(
    node_id: &str,
    drive: &str,
    store: &Db,
) -> crate::errors::AtomicResult<super::discover::WorkspacePeer> {
    let endpoint = ENDPOINT.get().ok_or("Iroh peer has not started")?;
    super::discover::inspect_workspace(endpoint, node_id, drive, store).await
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

    // Authenticate: send AUTH frame so the server knows who we are. The proof
    // names the drive AND the node we are talking to (`drive#nodeId`, in the
    // same fragment slot the WS CHALLENGE nonce uses): a proof captured by
    // one responder must not open another node hosting the same drive.
    let agent = store.get_default_agent()?;
    // AUTH goes out before the responder has said what it speaks, so it
    // names the drive in the spelling every responder parses. A responder
    // from before the rename cannot read `atomic:`; one from after binds
    // the drive by identity, so either spelling opens the same SYNC.
    let auth_frame = super::protocol::encode_auth(
        &agent,
        &auth_subject_for(&crate::identifiers::to_legacy_scheme(drive), &remote_key),
    )?;
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
    // Subjects on this stream follow what the peer listed; a responder that
    // predates the rename gets `did:ad:` and answers in kind.
    let wire = super::engine::WireScheme::from_caps(&peer_caps);

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
        resources.insert(wire.subject(subject), counters);
    }

    // Send SYNC frame
    let sync_frame =
        super::protocol::encode_sync(&wire.subject(drive), &drive_hash, &peers, &resources);
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
                        // Always, name or not: the drive is what a later
                        // `forget-peer` is authorized against.
                        add_known_peer_for_drive(store, &remote_key, name, drive);
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
                        // Dial side: we chose this peer, so a remove targeting
                        // THE drive we dialed it for is honored even when the
                        // peer relaying it is a different agent (trust_owned).
                        // That trust stops at that drive: a peer dialed for a
                        // shared drive must not get to delete in every drive
                        // this node owns. Anything else is judged on the peer's
                        // own rights. A signed envelope, when present, is
                        // applied as a COMMIT instead.
                        let in_dialed_drive =
                            super::ws_apply::resolve_destroy_drive(store, subject)
                                .await
                                .map(|d| same_drive(store, &d, drive))
                                .unwrap_or(false);
                        let envelope = diff.remove_commits.get(subject).map(String::as_str);
                        apply_peer_remove(
                            store,
                            &remote_agent,
                            subject,
                            in_dialed_drive,
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
                                for chunk in super::engine::sync_push_chunks_for_wire(
                                    store, drive, &entries, wire,
                                ) {
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
                    if !same_drive(store, &push.drive, drive) {
                        // We asked for one drive; owner trust below is for that
                        // drive only. A push claiming another drive is judged
                        // as if the peer had dialed us: on its own rights.
                        tracing::warn!(
                            "SYNC_PUSH for {} while syncing {}: applying without owner trust",
                            push.drive,
                            drive
                        );
                        if let Ok((count, _)) =
                            super::engine::import_sync_push(&push, store, &remote_agent, false)
                                .await
                        {
                            total_imported += count;
                        }
                        if last_chunk {
                            break;
                        }
                        continue;
                    }
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
                        for chunk in
                            super::engine::sync_push_chunks_for_wire(store, drive, &entries, wire)
                        {
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
        peer_caps.clone(),
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

/// Whether two drive subjects name the same drive, ignoring spelling
/// (routing hints, localized vs. absolute form).
fn same_drive(store: &Db, a: &str, b: &str) -> bool {
    let base = store.get_base_domain();
    crate::Subject::from_raw(a, base.as_deref()).pure_id()
        == crate::Subject::from_raw(b, base.as_deref()).pure_id()
}
