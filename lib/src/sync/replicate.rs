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

/// Read frames until the remote goes quiet, answering as we go. Returns how
/// many resources we pushed in this round.
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
            // A SYNC_OK arriving before we pushed anything means our hashes
            // already match. One arriving *after* is just a per-chunk ack —
            // it says the chunk was admitted, not that every subject in it
            // was kept — so those fall through and we keep listening.
            WsMessage::SyncOk { drive: d } if d == drive && sent_this_round == 0 => {
                outcome.in_sync = true;

                break;
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

                for chunk in protocol::encode_sync_push_chunks(drive, &refs) {
                    client.send_binary(chunk).await?;
                }

                sent_this_round += entries.len();
                outcome.pushed += entries.len();
                tracing::info!("[replicate] pushed {} resources of {drive}", entries.len());
            }
            WsMessage::BlobRequest { hash } => {
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
