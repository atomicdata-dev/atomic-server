//! Verify the frozen snapshots sent by an Iroh reconciliation before publishing
//! completion. GET already returns a stored snapshot; no new wire receipt is needed.
use super::protocol;
use crate::{errors::AtomicResult, loro::AtomicLoroDoc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn write<W: AsyncWrite + Unpin>(send: &mut W, frame: &[u8]) -> AtomicResult<()> {
    send.write_u32(frame.len() as u32).await?;
    send.write_all(frame).await?;
    Ok(())
}

pub(super) async fn read<R: AsyncRead + Unpin>(recv: &mut R) -> AtomicResult<Vec<u8>> {
    let len = recv.read_u32().await? as usize;
    if len == 0 || len > protocol::IROH_FRAME_MAX_BYTES {
        return Err("Invalid peer verification frame length".into());
    }
    let mut frame = vec![0; len];
    recv.read_exact(&mut frame).await?;
    Ok(frame)
}

/// Returns interleaved live frames, in order, for the normal authenticated
/// live dispatcher. They must not be discarded or applied under weaker rules.
pub(super) async fn verify<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    send: &mut W,
    recv: &mut R,
    drive: &str,
    entries: &[(String, Vec<u8>)],
    mut pending_acks: usize,
    envelopes: &std::collections::HashMap<String, Vec<String>>,
) -> AtomicResult<Vec<Vec<u8>>> {
    let expected = entries
        .iter()
        .map(|(_, bytes)| AtomicLoroDoc::vv_map_from_snapshot(bytes))
        .collect::<AtomicResult<Vec<_>>>()?;
    let mut deferred = Vec::new();
    let mut deferred_bytes = 0usize;
    // Each round is bounded even if a peer floods unrelated frames or stops
    // halfway through a header/body. Two retries after the original push.
    for attempt in 0..=2 {
        let missing = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut missing = Vec::new();
            let mut index = 0;
            let mut awaiting_get = false;
            loop {
                if pending_acks == 0 && !awaiting_get {
                    if index == entries.len() {
                        return Ok::<_, crate::errors::AtomicError>(missing);
                    }
                    write(send, &protocol::encode_get(1, &entries[index].0)).await?;
                    awaiting_get = true;
                }
                let frame = read(recv).await?;
                match frame[0] {
                    protocol::tag::SYNC_OK if pending_acks > 0 => {
                        if frame != protocol::encode_sync_ok(drive) {
                            return Err("Peer acknowledged a different drive".into());
                        }
                        pending_acks -= 1;
                    }
                    protocol::tag::ERROR => {
                        let error = protocol::decode_error(&frame[1..])
                            .ok_or("Invalid peer verification error")?;
                        // GET currently maps both absent and unreadable resources
                        // to UNKNOWN. Neither proves delivery; retry boundedly.
                        if awaiting_get
                            && error.request_id == 1
                            && error.code == protocol::error_code::UNKNOWN
                        {
                            missing.push(index);
                            index += 1;
                            awaiting_get = false;
                            continue;
                        }
                        return Err(
                            format!("Peer sync verification failed: {}", error.message).into()
                        );
                    }
                    protocol::tag::UPDATE if awaiting_get => {
                        let update = protocol::decode_update(&frame[1..])
                            .ok_or("Invalid peer verification update")?;
                        if update.request_id == 1 {
                            if update.subject != entries[index].0
                                || update.flag_bits & protocol::flags::SNAPSHOT == 0
                            {
                                return Err("Peer returned the wrong verification snapshot".into());
                            }
                            let remote = AtomicLoroDoc::vv_map_from_snapshot(&update.loro_bytes)?;
                            if expected[index].iter().any(|(peer, count)| {
                                remote.get(peer).copied().unwrap_or(0) < *count
                            }) {
                                missing.push(index);
                            }
                            index += 1;
                            awaiting_get = false;
                            continue;
                        }
                        deferred_bytes += frame.len();
                        deferred.push(frame);
                    }
                    _ => {
                        deferred_bytes += frame.len();
                        deferred.push(frame);
                    }
                }
                if deferred_bytes > protocol::IROH_FRAME_MAX_BYTES {
                    return Err("Too much pending live data during peer verification".into());
                }
            }
        })
        .await
        .map_err(|_| "Peer sync verification timed out; local data retained")??;
        if missing.is_empty() {
            return Ok(deferred);
        }
        if attempt == 2 {
            return Err(format!("Peer has not confirmed {} resource(s) after sync retries; local data retained. Reconnect to retry.", missing.len()).into());
        }
        let refs = missing
            .iter()
            .map(|&i| (entries[i].0.as_str(), entries[i].1.as_slice()))
            .collect::<Vec<_>>();
        let frames = protocol::encode_sync_push_chunks_with_envelopes(drive, &refs, envelopes);
        pending_acks = frames.len();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            for frame in frames {
                write(send, &frame).await?;
            }
            Ok::<_, crate::errors::AtomicError>(())
        })
        .await
        .map_err(|_| "Peer sync retry timed out; local data retained")??;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retries_only_missing_versions_and_preserves_live_frames() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(crate::urls::NAME, &crate::Value::String("sent".into()))
            .unwrap();
        let snapshot = doc.export_snapshot();
        let old = AtomicLoroDoc::new().export_snapshot();
        let entries = vec![
            ("did:ad:a".into(), snapshot.clone()),
            ("did:ad:b".into(), snapshot.clone()),
        ];
        let (local, remote) = tokio::io::duplex(65536);
        let (mut recv, mut send) = tokio::io::split(local);
        let task = tokio::spawn(async move {
            let (mut recv, mut send) = tokio::io::split(remote);
            // Two chunks: verification must not send GET after just one ACK.
            write(&mut send, &protocol::encode_sync_ok("did:ad:drive"))
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(20), recv.read_u8())
                    .await
                    .is_err()
            );
            write(&mut send, &protocol::encode_sync_ok("did:ad:drive"))
                .await
                .unwrap();
            let live = protocol::encode_update(
                protocol::flags::SNAPSHOT,
                0,
                "did:ad:live",
                None,
                &snapshot,
            );
            write(&mut send, &live).await.unwrap();
            for subject in ["did:ad:a", "did:ad:b"] {
                let get = read(&mut recv).await.unwrap();
                assert_eq!(get, protocol::encode_get(1, subject));
                let bytes = if subject == "did:ad:a" {
                    &snapshot
                } else {
                    &old
                };
                write(
                    &mut send,
                    &protocol::encode_update(protocol::flags::SNAPSHOT, 1, subject, None, bytes),
                )
                .await
                .unwrap();
            }
            let retry = read(&mut recv).await.unwrap();
            let retry = protocol::decode_sync_push(&retry[1..]).unwrap();
            assert_eq!(retry.entries.len(), 1);
            assert_eq!(retry.entries[0].subject, "did:ad:b");
            assert_eq!(retry.entries[0].loro_bytes, snapshot);
            assert_eq!(retry.envelopes.len(), 1);
            assert_eq!(retry.envelopes[0].subject, "did:ad:b");
            assert_eq!(retry.envelopes[0].json, "signed-envelope");
            write(&mut send, &protocol::encode_sync_ok("did:ad:drive"))
                .await
                .unwrap();
            // Additional remote operations must not prevent completion.
            doc.set_property(crate::urls::NAME, &crate::Value::String("newer".into()))
                .unwrap();
            for subject in ["did:ad:a", "did:ad:b"] {
                assert_eq!(
                    read(&mut recv).await.unwrap(),
                    protocol::encode_get(1, subject)
                );
                write(
                    &mut send,
                    &protocol::encode_update(
                        protocol::flags::SNAPSHOT,
                        1,
                        subject,
                        None,
                        &doc.export_snapshot(),
                    ),
                )
                .await
                .unwrap();
            }
            live
        });
        let deferred = verify(
            &mut send,
            &mut recv,
            "did:ad:drive",
            &entries,
            2,
            &std::collections::HashMap::from([("did:ad:b".into(), vec!["signed-envelope".into()])]),
        )
        .await
        .unwrap();
        assert_eq!(deferred, vec![task.await.unwrap()]);
    }

    #[tokio::test]
    async fn missing_resource_exhausts_retries_without_success() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(crate::urls::NAME, &crate::Value::String("local".into()))
            .unwrap();
        let entries = vec![("did:ad:missing".into(), doc.export_snapshot())];
        let (local, remote) = tokio::io::duplex(65536);
        let (mut recv, mut send) = tokio::io::split(local);
        let task = tokio::spawn(async move {
            let (mut recv, mut send) = tokio::io::split(remote);
            for attempt in 0..3 {
                write(&mut send, &protocol::encode_sync_ok("did:ad:drive"))
                    .await
                    .unwrap();
                assert_eq!(
                    read(&mut recv).await.unwrap(),
                    protocol::encode_get(1, "did:ad:missing")
                );
                write(
                    &mut send,
                    &protocol::encode_error(1, protocol::error_code::UNKNOWN, "not found"),
                )
                .await
                .unwrap();
                if attempt < 2 {
                    assert_eq!(read(&mut recv).await.unwrap()[0], protocol::tag::SYNC_PUSH);
                }
            }
        });
        let result = verify(
            &mut send,
            &mut recv,
            "did:ad:drive",
            &entries,
            1,
            &Default::default(),
        )
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("after sync retries"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_before_ack_is_failure() {
        let (local, remote) = tokio::io::duplex(64);
        drop(remote);
        let (mut recv, mut send) = tokio::io::split(local);
        assert!(verify(
            &mut send,
            &mut recv,
            "did:ad:drive",
            &[],
            1,
            &Default::default()
        )
        .await
        .is_err());
    }
}
