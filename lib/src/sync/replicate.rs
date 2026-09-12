//! Push a drive to a *remote* Atomic Server, as a sync client.
//!
//! This is the server-side analogue of the browser's `resyncDrive`
//! (`browser/lib/src/websockets.ts`): it speaks the same WebSocket sync
//! handshake, but it runs inside a server that already holds the *complete*
//! drive. A browser can only ever push what its partial cache happens to hold,
//! which is why "back up my self-hosted drive somewhere else" cannot be done
//! from the browser alone.
//!
//! The mechanism is deliberately generic — any drive, any remote — and is only
//! ever invoked because a user asked for it. It carries no knowledge of who the
//! remote is; the caller supplies the target.
//!
//! Two identities are in play, and conflating them is the trap:
//!
//! - **`export_as`** — whose *read* rights bound what leaves this server. Only
//!   subjects this identity can read are exported. This is the user who asked.
//! - **`auth`** — whose *write* rights the remote will check when it imports
//!   ([`super::engine::import_sync_push`] runs `check_write` against the
//!   connection's agent). This must be an agent authorized on the drive at the
//!   remote — i.e. the drive owner.
//!
//! For the "back up my drive to a hosted node" flow both are the same person,
//! but this server does not have that person's private key. Hence
//! [`ReplicateAuth::PreSigned`]: the owner's browser mints the AUTH frame and
//! hands it over, so the key never leaves the browser.

use crate::{
    agents::{Agent, ForAgent},
    client::ws::{WsClient, WsMessage},
    db::Db,
    errors::{AtomicError, AtomicResult},
    sync::{engine, protocol},
    Storelike,
};
use tokio::sync::broadcast::Receiver;

/// How to authenticate to the remote server.
pub enum ReplicateAuth {
    /// Sign the AUTH frame with an agent whose key we hold (this server's own
    /// identity). Only lands data if *that* agent has write rights on the drive
    /// at the remote.
    Agent(Box<Agent>),
    /// Relay an AUTH frame signed elsewhere — by the drive owner's browser —
    /// so this server can push as the owner without ever holding their key.
    /// The frame is timestamp-bound (`AUTH_MAX_AGE_MS`), so it must be minted
    /// for this attempt, and its `requestedSubject` must be the *remote's*
    /// origin (`https://host[:port]`): the remote binds the proof to itself
    /// and refuses one signed for anything else with `AUTH_FAILED`.
    PreSigned(Vec<u8>),
    /// Connect anonymously. Only useful for *reading*: a WebSocket remote
    /// refuses `SYNC_PUSH` before `AUTH` (`ERROR` code `AUTH_REQUIRED`), so an
    /// anonymous replication can verify that a public drive is already in
    /// sync, but can never land data.
    Anonymous,
}

/// What a replication attempt actually accomplished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicateOutcome {
    /// Resources whose state we sent.
    pub pushed: usize,
    /// Blobs the remote asked for and we served.
    pub blobs_served: usize,
    /// The remote's drive hash matched ours on a second probe — i.e. the data
    /// really landed. A refused import comes back as an `ERROR` frame
    /// (`SYNC_REJECTED`) and fails the attempt outright; the second probe
    /// guards against the subtler case where the remote accepted the push but
    /// kept less than we sent (per-subject drops, quota), so we re-ask rather
    /// than trust the per-chunk `SYNC_OK` ack.
    pub in_sync: bool,
}

/// How long to wait for the remote to say anything before deciding it's done
/// talking. Blob transfers of large files are the slow case here.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Ceiling on the whole exchange, so a chatty or malicious remote can't pin
/// this task open forever.
const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Push `drive` to the Atomic Server at `target_ws_url` (a `ws://` or `wss://`
/// URL, e.g. `wss://example.com/ws`).
///
/// Exports only what `export_as` may read, and authenticates to the remote per
/// `auth`. This is a **push**: state the remote sends back is not imported, so
/// a remote we dial can never write into us.
pub async fn replicate_drive_to_remote(
    store: &Db,
    drive: &str,
    target_ws_url: &str,
    export_as: &ForAgent,
    auth: ReplicateAuth,
) -> AtomicResult<ReplicateOutcome> {
    let started = std::time::Instant::now();
    let client = WsClient::connect(target_ws_url).await?;

    match auth {
        ReplicateAuth::Agent(agent) => client.authenticate(&agent).await?,
        ReplicateAuth::PreSigned(frame) => client.authenticate_with_frame(frame).await?,
        ReplicateAuth::Anonymous => {}
    }

    let mut rx = client.subscribe();
    let mut outcome = ReplicateOutcome {
        pushed: 0,
        blobs_served: 0,
        in_sync: false,
    };

    // Round 1 — offer our version vector; the remote replies with what it wants.
    client
        .send_binary(build_sync_frame(store, drive).await)
        .await?;
    let sent = drive_exchange(
        &client,
        &mut rx,
        store,
        drive,
        export_as,
        &mut outcome,
        started,
    )
    .await?;

    if sent == 0 && outcome.in_sync {
        // The remote already had everything; no second probe needed.
        return Ok(outcome);
    }

    // Round 2 — the honest verification. Re-offer our (unchanged) version
    // vector: if the push really landed, the remote's hash now matches ours and
    // it answers SYNC_OK. A SYNC_DIFF here means it kept less than we sent
    // (an outright refusal would already have surfaced as an ERROR frame).
    outcome.in_sync = false;
    client
        .send_binary(build_sync_frame(store, drive).await)
        .await?;
    drive_exchange(
        &client,
        &mut rx,
        store,
        drive,
        export_as,
        &mut outcome,
        started,
    )
    .await?;

    Ok(outcome)
}

/// Read replies until the acknowledged resource-only exchange is drained, or
/// the remote goes quiet. Returns how many resources we pushed in this round.
async fn drive_exchange(
    client: &WsClient,
    rx: &mut Receiver<WsMessage>,
    store: &Db,
    drive: &str,
    export_as: &ForAgent,
    outcome: &mut ReplicateOutcome,
    started: std::time::Instant,
) -> AtomicResult<usize> {
    let mut sent_this_round = 0;
    let mut pending_chunks = 0;
    let mut draining = false;
    let mut requested_blob = false;
    let echoes_keepalive = client
        .server_capabilities()
        .iter()
        .any(|c| c == "keepalive");

    loop {
        if started.elapsed() > TOTAL_TIMEOUT {
            return Err(AtomicError::from(format!(
                "Replicating {drive} exceeded the time limit"
            )));
        }

        let msg = match tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await {
            // Quiet, or the socket closed: the remote has said all it will say.
            Err(_) | Ok(Err(_)) => break,
            Ok(Ok(msg)) => msg,
        };

        match msg {
            WsMessage::SyncOk { drive: d } if d == drive => {
                if sent_this_round == 0 {
                    outcome.in_sync = true;
                    break;
                }
                // Each accepted chunk has its own ack. None proves matching
                // state: only the separate SYNC probe may set in_sync.
                if pending_chunks > 0 {
                    pending_chunks -= 1;
                    if pending_chunks == 0 && echoes_keepalive {
                        // The server queues blob requests AFTER the chunk ack.
                        // Its WS keepalive echo drains those trailing frames;
                        // it is not a barrier for asynchronous blob writes.
                        client.send_keepalive().await?;
                        draining = true;
                    }
                }
            }
            WsMessage::Keepalive if draining => {
                draining = false;
                if !requested_blob {
                    break;
                }
                // Blob writes have no completion ack. Preserve the existing
                // idle grace period (also used for older peers without the
                // keepalive capability) rather than racing their storage.
            }
            WsMessage::SyncDiff { drive: d, pull, .. } if d == drive => {
                if pull.is_empty() {
                    break;
                }

                // No paired-replica relaxation here: this is the relayed
                // WebSocket path, where there is no dialled node identity to
                // stand in for the owner's pairing choice. Rights only.
                let entries =
                    engine::collect_readable_snapshots(store, export_as, &pull, None).await;

                if entries.is_empty() {
                    tracing::warn!(
                        "[replicate] remote asked for {} subjects of {drive} but none are readable by {export_as:?}",
                        pull.len()
                    );

                    break;
                }

                let refs: Vec<(&str, &[u8])> = entries
                    .iter()
                    .map(|(s, b)| (s.as_str(), b.as_slice()))
                    .collect();

                let chunks = protocol::encode_sync_push_chunks(drive, &refs);
                pending_chunks += chunks.len();
                for chunk in chunks {
                    client.send_binary(chunk).await?;
                }

                sent_this_round += entries.len();
                outcome.pushed += entries.len();
                tracing::info!("[replicate] pushed {} resources of {drive}", entries.len());
            }
            WsMessage::BlobRequest { hash } => {
                requested_blob = true;
                // The remote imported a resource referencing a blob it lacks.
                // Blobs are only ever served on request — it will not accept an
                // unsolicited one.
                match store.get_blob(&hash).await {
                    Ok(Some(bytes)) => {
                        client
                            .send_binary(protocol::encode_blob_response(&hash, &bytes))
                            .await?;
                        outcome.blobs_served += 1;
                    }
                    _ => tracing::warn!("[replicate] remote asked for a blob we don't have"),
                }
            }
            // We are a pusher: whatever the remote offers us, we don't import.
            // Dialing a remote never gave it the right to write into us.
            WsMessage::SyncPush { .. } => {}
            WsMessage::Error { message, .. } => {
                return Err(AtomicError::from(format!(
                    "Remote refused to sync {drive}: {message}"
                )));
            }
            _ => {}
        }
    }

    Ok(sent_this_round)
}

/// Our version vector for the whole drive, in the shape `SYNC` expects: a
/// deduplicated peer list plus per-subject counters indexed into it.
async fn build_sync_frame(store: &Db, drive: &str) -> Vec<u8> {
    let drive_subject = crate::Subject::from_raw(drive, store.get_base_domain().as_deref());
    let subjects = engine::collect_drive_subjects(store, &drive_subject).await;
    let vvs = engine::build_drive_vvs(store, &subjects);
    let drive_hash = engine::compute_drive_hash(&vvs);

    let peers: Vec<String> = vvs
        .values()
        .flat_map(|vv| vv.keys().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let peer_index: std::collections::HashMap<&str, usize> = peers
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_str(), i))
        .collect();

    let mut resources: std::collections::HashMap<String, Vec<i32>> =
        std::collections::HashMap::new();

    for (subject, vv) in &vvs {
        let mut counters = vec![0i32; peers.len()];

        for (peer_id, &counter) in vv {
            if let Some(&idx) = peer_index.get(peer_id.as_str()) {
                counters[idx] = counter;
            }
        }

        resources.insert(subject.clone(), counters);
    }

    protocol::encode_sync(drive, &drive_hash, &peers, &resources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};

    type Peer = WebSocketStream<TcpStream>;

    async fn receive(peer: &mut Peer, tag: u8) -> Vec<u8> {
        let frame = peer.next().await.unwrap().unwrap().into_data().to_vec();
        assert_eq!(frame.first(), Some(&tag), "unexpected frame: {frame:?}");
        frame
    }

    async fn send(peer: &mut Peer, frame: Vec<u8>) {
        peer.send(Message::Binary(frame.into())).await.unwrap();
    }

    async fn source() -> (Db, String) {
        let db = Db::init_memory(Some("https://localhost".into()))
            .await
            .unwrap();
        let (_, drive) = db.setup("Replication test").await.unwrap();
        (db, drive)
    }

    async fn accept_peer(listener: TcpListener, caps: &[&str]) -> Peer {
        let mut peer = accept_async(listener.accept().await.unwrap().0)
            .await
            .unwrap();
        // This scripted peer tests exchange ordering, not AUTH verification.
        receive(&mut peer, protocol::tag::HELLO).await;
        receive(&mut peer, protocol::tag::AUTH).await;
        send(&mut peer, protocol::encode_auth_ok_with_caps(caps)).await;
        receive(&mut peer, protocol::tag::SYNC).await;
        peer
    }

    fn request(drive: &str, count: usize) -> Vec<u8> {
        protocol::encode_sync_diff(
            drive,
            &vec![drive.to_owned(); count],
            &[],
            &[],
            &Default::default(),
            &Default::default(),
        )
    }

    async fn with_peer<F, Fut>(
        caps: &'static [&'static str],
        script: F,
    ) -> AtomicResult<ReplicateOutcome>
    where
        F: FnOnce(Peer, String) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let (db, drive) = source().await;
        db.put_blob(blake3::hash(b"attachment").as_bytes(), b"attachment")
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let remote_drive = drive.clone();
        let peer = tokio::spawn(async move {
            let peer = accept_peer(listener, caps).await;
            script(peer, remote_drive).await;
        });
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            replicate_drive_to_remote(
                &db,
                &drive,
                &url,
                &ForAgent::Sudo,
                ReplicateAuth::PreSigned(vec![protocol::tag::AUTH]),
            ),
        )
        .await
        .expect("replication waited for the 30-second idle timeout");
        peer.await.unwrap();
        outcome
    }

    async fn drain(peer: &mut Peer) {
        receive(peer, protocol::tag::KEEPALIVE).await;
        send(peer, protocol::encode_keepalive()).await;
    }

    async fn assert_waiting(peer: &mut Peer) {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), peer.next())
                .await
                .is_err(),
            "client advanced before the exchange was complete"
        );
    }

    #[tokio::test]
    async fn acknowledged_push_is_verified_without_waiting_for_idle() {
        let outcome = with_peer(&["keepalive"], |mut peer, drive| async move {
            send(&mut peer, request(&drive, 1)).await;
            receive(&mut peer, protocol::tag::SYNC_PUSH).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
            drain(&mut peer).await;
            receive(&mut peer, protocol::tag::SYNC).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
        })
        .await
        .unwrap();
        assert_eq!(outcome.pushed, 1);
        assert!(outcome.in_sync);
    }

    #[tokio::test]
    async fn waits_for_every_chunk_ack_and_ignores_other_drives() {
        let outcome = with_peer(&["keepalive"], |mut peer, drive| async move {
            // Repeating one readable snapshot exercises the real chunk encoder
            // without creating 101 unrelated resources in the test fixture.
            send(
                &mut peer,
                request(&drive, protocol::SYNC_PUSH_MAX_ENTRIES + 1),
            )
            .await;
            let first = receive(&mut peer, protocol::tag::SYNC_PUSH).await;
            assert!(!protocol::decode_sync_push(&first[1..]).unwrap().last);
            let last = receive(&mut peer, protocol::tag::SYNC_PUSH).await;
            assert!(protocol::decode_sync_push(&last[1..]).unwrap().last);
            send(&mut peer, protocol::encode_sync_ok("did:ad:another-drive")).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
            assert_waiting(&mut peer).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
            drain(&mut peer).await;
            receive(&mut peer, protocol::tag::SYNC).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
        })
        .await
        .unwrap();
        assert_eq!(outcome.pushed, protocol::SYNC_PUSH_MAX_ENTRIES + 1);
        assert!(outcome.in_sync);
    }

    #[tokio::test]
    async fn chunk_ack_does_not_prove_the_final_hash_matches() {
        let outcome = with_peer(&["keepalive"], |mut peer, drive| async move {
            send(&mut peer, request(&drive, 1)).await;
            receive(&mut peer, protocol::tag::SYNC_PUSH).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
            drain(&mut peer).await;
            receive(&mut peer, protocol::tag::SYNC).await;
            // The remote still differs, even though it acknowledged the push.
            send(
                &mut peer,
                protocol::encode_sync_diff(
                    &drive,
                    &[],
                    &[drive.clone()],
                    &[],
                    &Default::default(),
                    &Default::default(),
                ),
            )
            .await;
        })
        .await
        .unwrap();
        assert_eq!(outcome.pushed, 1);
        assert!(!outcome.in_sync);
    }

    #[tokio::test]
    async fn trailing_blob_request_keeps_the_storage_grace_period() {
        let error = with_peer(&["keepalive"], |mut peer, drive| async move {
            send(&mut peer, request(&drive, 1)).await;
            receive(&mut peer, protocol::tag::SYNC_PUSH).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
            receive(&mut peer, protocol::tag::KEEPALIVE).await;
            let hash = *blake3::hash(b"attachment").as_bytes();
            // The engine sends blob requests after the corresponding ack.
            send(&mut peer, protocol::encode_blob_request(&hash)).await;
            send(&mut peer, protocol::encode_keepalive()).await;
            let frame = receive(&mut peer, protocol::tag::BLOB_RESPONSE).await;
            let response = protocol::decode_blob_response(&frame[1..]).unwrap();
            assert_eq!(response.hash, hash);
            assert_eq!(response.bytes, b"attachment");
            assert_waiting(&mut peer).await;
            // Asynchronous remote storage failure must still reach the caller.
            send(
                &mut peer,
                protocol::encode_error(0, protocol::error_code::UNKNOWN, "Blob storage failed"),
            )
            .await;
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Blob storage failed"));
    }

    #[tokio::test]
    async fn older_peer_without_keepalive_keeps_the_idle_fallback() {
        let error = with_peer(&[], |mut peer, drive| async move {
            send(&mut peer, request(&drive, 1)).await;
            receive(&mut peer, protocol::tag::SYNC_PUSH).await;
            send(&mut peer, protocol::encode_sync_ok(&drive)).await;
            assert_waiting(&mut peer).await;
            send(
                &mut peer,
                protocol::encode_error(0, protocol::error_code::SYNC_REJECTED, "Import refused"),
            )
            .await;
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Import refused"));
    }
}
