//! Incoming stream handling: the accept-side handshake and sync.

use super::*;

/// Handle a single bidirectional QUIC stream.
/// Reads length-prefixed v2 binary frames and dispatches them via the sync engine.
/// Returns the number of resources imported from the remote peer.
/// After SYNC_OK or SYNC_PUSH response, transitions to live mode by
/// registering the stream for real-time updates.
/// The `ERROR` frame a peer gets for sending `tag` before it authenticated.
pub(super) fn auth_required_error(tag: u8) -> Vec<u8> {
    super::protocol::encode_error(
        0,
        super::protocol::error_code::AUTH_REQUIRED,
        &format!("AUTH required before frame 0x{tag:02x}"),
    )
}

/// Prefix a frame with the u32 length the Iroh stream framing expects.
pub(super) fn frame_with_len(frame: &[u8]) -> Vec<u8> {
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

/// What a dialer signs in its AUTH: the drive it wants, bound to the node it
/// is dialing. The node id rides in the fragment slot the WS CHALLENGE nonce
/// uses (`split_challenge_fragment`), so the signed string keeps its
/// `"{requestedSubject} {timestamp}"` shape.
pub fn auth_subject_for(drive: &str, responder_node_id: &str) -> String {
    format!("{drive}#{}", normalize_node_id(responder_node_id))
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

pub(super) async fn handle_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    store: Db,
    remote_id: String,
    my_node_id: String,
) -> anyhow::Result<usize> {
    let remote_key = normalize_node_id(&remote_id);
    let my_node_key = normalize_node_id(&my_node_id);
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
    // What the dialer listed in its HELLO, which precedes its SYNC. A dialer
    // that sends none predates the rename and is answered in `did:ad:`.
    let mut peer_caps: Vec<String> = Vec::new();

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
            peer_caps = super::protocol::decode_hello_caps(&buf[1..]);
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

        let responses = if tag == super::protocol::tag::AUTH {
            // The proof must be minted for THIS node: the dialer signs
            // `drive#nodeId` (see `auth_subject_for`). Without that binding a
            // peer we dial could forward our AUTH to any other node hosting
            // the drive and be served as us for the proof's lifetime. A proof
            // without the node id is a pre-binding dialer; it is honoured only
            // from a peer this node's owner paired with, and only until that
            // peer upgrades.
            let carries_node_id = auth_requested_subject(&buf[1..])
                .map(|s| super::protocol::split_challenge_fragment(&s).1.is_some())
                .unwrap_or(false);
            if !carries_node_id && !is_paired_peer(&store, &remote_key) {
                vec![super::protocol::encode_error(
                    0,
                    super::protocol::error_code::AUTH_FAILED,
                    "Auth failed: the AUTH proof must name this node (requestedSubject `drive#nodeId`); upgrade the dialing peer",
                )]
            } else {
                super::engine::handle_auth_frame(
                    &buf[1..],
                    &store,
                    &mut agent,
                    super::engine::AuthBinding::Unbound,
                    super::engine::AuthChallenge::Issued(&my_node_key),
                )
                .await
            }
        } else {
            super::engine::handle_frame_for_caps(
                &buf,
                &store,
                &mut agent,
                super::engine::WireScheme::from_caps(&peer_caps),
            )
            .await
        };

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
                    bound_drive = auth_requested_subject(&buf[1..]).map(|s| {
                        // `drive#nodeId`: the drive is the part before the
                        // fragment the binding check above consumed.
                        let (drive, _) = super::protocol::split_challenge_fragment(&s);
                        crate::Subject::from_raw(drive, store.get_base_domain().as_deref())
                    });
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
            register_live_peer(
                remote_key,
                send,
                recv,
                store,
                agent,
                false,
                None,
                peer_caps.clone(),
            );
            return Ok(total_imported);
        }
    }

    // Initiator may stop sending after reading our SYNC_OK; we already sent it.
    if sent_sync_ok {
        tracing::info!(
            "[accept] SYNC_OK sent, entering live mode with {}",
            &remote_key[..remote_key.len().min(12)]
        );
        register_live_peer(
            remote_key,
            send,
            recv,
            store,
            agent,
            false,
            None,
            peer_caps.clone(),
        );
    }

    Ok(total_imported)
}
