//! The bridge's binding of `atomic_lib::host::peer_search`: pkarr is the
//! directory, Iroh the dialer, the global store the drives.

use atomic_lib::host::peer_search::{PeerDialer, PeerDirectory, PeerSearch, PeerSearchSchedule};
use async_trait::async_trait;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// One search per process, like the one Iroh endpoint.
pub(crate) static PEER_SEARCH: LazyLock<Arc<PeerSearch>> =
    LazyLock::new(|| PeerSearch::new(PeerSearchSchedule::default()));

/// A record entry has a 300 s TTL and every device rewrites the record: ten
/// minutes keeps this device in it without writing on every round.
const ANNOUNCE_EVERY: Duration = Duration::from_secs(600);

struct PkarrDirectory;

#[async_trait]
impl PeerDirectory for PkarrDirectory {
    async fn announced(&self, drive: &str) -> Result<Vec<String>, String> {
        tokio::time::timeout(
            super::PKARR_RESOLVE_TIMEOUT,
            atomic_lib::discovery::resolve_other_node_ids(drive, None),
        )
        .await
        .map_err(|_| "device directory (pkarr) timed out".to_string())?
        .map_err(|e| e.to_string())
    }

    async fn announce(&self, drive: &str, me: &str) -> Result<(), String> {
        atomic_lib::discovery::publish_node_id(drive, me)
            .await
            .map_err(|e| e.to_string())
    }
}

struct IrohDialer {
    store: atomic_lib::Db,
}

#[async_trait]
impl PeerDialer for IrohDialer {
    async fn dial(&self, node_id: &str, drive: &str) -> Result<(), String> {
        tokio::time::timeout(
            super::PEER_SYNC_ATTEMPT_TIMEOUT,
            atomic_lib::sync::peer::sync_drive_with_peer_if_needed(node_id, drive, &self.store),
        )
        .await
        .map_err(|_| {
            format!(
                "timed out after {}s",
                super::PEER_SYNC_ATTEMPT_TIMEOUT.as_secs()
            )
        })?
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    fn live(&self) -> Vec<String> {
        atomic_lib::sync::peer::live_peer_ids()
    }
}

/// The drives to look for devices in: the active one, and the private drive,
/// which every device of the same agent holds (a device signed in with the
/// secret starts there, while the others may have another workspace open).
pub(crate) fn search_drives(store: &atomic_lib::Db) -> Vec<String> {
    let mut drives = Vec::new();
    if let Some(active) = store.get_active_drive() {
        drives.push(active);
    }
    if let Ok(private) = store.private_drive_subject() {
        if !drives.contains(&private) {
            drives.push(private);
        }
    }
    drives
}

/// Start the search loop (once) for the endpoint that just started, and wake
/// it whenever the last live peer goes away.
pub(crate) fn spawn(store: atomic_lib::Db, me: String) {
    // The bridge unit tests stand up real endpoints but must not talk to the
    // public pkarr relay in the background.
    if cfg!(test) {
        return;
    }
    let drives_store = store.clone();
    tokio::spawn(PEER_SEARCH.clone().run(
        me,
        move || search_drives(&drives_store),
        Arc::new(PkarrDirectory),
        Arc::new(IrohDialer { store }),
        ANNOUNCE_EVERY,
    ));
    tokio::spawn(async {
        let mut count = atomic_lib::sync::peer::live_peer_count();
        loop {
            let now = atomic_lib::sync::peer::wait_for_peer_count_change(count).await;
            if now < count {
                tracing::info!("[peer_search] live peers {count} → {now}, searching again");
                PEER_SEARCH.search_again();
            }
            count = now;
        }
    });
}
