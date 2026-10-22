//! Local writes: save a resource, record it in the outbox and push it.

use super::*;

/// Save resource locally, record it in the durable outbox, and drain the
/// outbox over WS when a session is open. Offline edits wait on disk.
pub(crate) async fn save_and_push(
    resource: &mut atomic_lib::Resource,
    store: &atomic_lib::Db,
) -> Result<(), String> {
    let response = node()?.save_locally(resource).await.map_err(err)?;
    push_local_write(&response, store).await;
    Ok(())
}

/// Hand a commit this device just signed to whoever can take it: live peers
/// get the state at once, the server gets the queued commit, and a paired
/// device takes it when there is no server in reach.
/// Apply a commit this device signed itself and queue it for the server, like
/// `save_locally` does for an edit.
pub(crate) async fn node_apply_local(
    commit: atomic_lib::Commit,
    opts: &atomic_lib::commit::CommitOpts,
) -> Result<atomic_lib::commit::CommitResponse, String> {
    node()?.apply_local_commit(commit, opts).await.map_err(err)
}

pub(crate) async fn push_local_write(
    response: &atomic_lib::commit::CommitResponse,
    store: &atomic_lib::Db,
) {
    if let Some(bytes) = &response.commit.loro_update {
        if !bytes.is_empty() {
            let subject_key = response.commit.subject.pure_id();
            atomic_lib::sync::peer::broadcast_live_update(store, &subject_key, bytes);
        }
    }
    let ws_ok = ws_sync::drain_outbox(store).await;
    // No hub in reach: a paired peer takes the signed commit instead
    // (planning/serverless-p2p.md P4). The raw broadcast above already gave
    // every live peer the state; this is what makes it attributable.
    if !ws_ok {
        atomic_lib::sync::peer::drain_outbox_to_any_live_peer(store).await;
    }
    // Hub unreachable or no WS session: bulk Iroh reconcile. When live peers exist
    // we already broadcast above; still bulk-nudge if P2P-only (no hub).
    if !ws_ok || atomic_lib::sync::peer::live_peer_count() == 0 {
        nudge_peers_after_local_change(store).await;
    }
}

pub(crate) fn is_unreachable_hub_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("localhost") || lower.contains("127.0.0.1")
}

/// Start Iroh (live sync + auto-connect loop) and announce on pkarr.
pub(crate) async fn ensure_sync_connectivity(store: &atomic_lib::Db) -> Result<(), String> {
    let Some(drive) = store.get_active_drive() else {
        return Ok(());
    };
    let _ = drive;
    // `start_peer` also starts the search loop, which announces this device
    // for the active and the private drive and keeps looking for the others.
    let _ = start_peer().await?;
    Ok(())
}

pub(crate) static LAST_PEER_NUDGE_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// When WS push failed, run a debounced bulk sync with known peers / pkarr discover.
pub(crate) async fn nudge_peers_after_local_change(store: &atomic_lib::Db) {
    // The bridge unit tests assert local cache/store invariants. Standing up a
    // real Iroh endpoint for them would make every save network-dependent and
    // slow for no added coverage — the transport itself is covered by
    // `atomic_lib`'s two-node `sync::iroh_e2e` suite.
    #[cfg(test)]
    {
        let _ = store;
        return;
    }
    #[cfg(not(test))]
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = LAST_PEER_NUDGE_MS.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < 2_000 {
            return;
        }
        LAST_PEER_NUDGE_MS.store(now, std::sync::atomic::Ordering::Relaxed);

        if ensure_sync_connectivity(store).await.is_err() {
            return;
        }
        if let Err(e) = try_auto_peer_sync(store).await {
            tracing::debug!("[save_and_push] peer nudge failed: {e}");
        }
    }
}
