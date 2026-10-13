//! Sync events that notify the UI of incoming connections.

use super::*;

static LAST_EVENT_MS: OnceLock<std::sync::Mutex<std::collections::HashMap<(String, String), u64>>> =
    OnceLock::new();

const EVENT_DEBOUNCE_MS: u64 = 15_000;

fn last_event_ms() -> &'static std::sync::Mutex<std::collections::HashMap<(String, String), u64>> {
    LAST_EVENT_MS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

// ── Sync events (notifies UI of incoming connections) ────────────────────

/// A sync event that the UI can poll for.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncEvent {
    pub remote_node_id: String,
    pub resources_imported: usize,
    pub timestamp: u64,
    /// "sync", "connected", "disconnected"
    #[serde(default = "default_event_kind")]
    pub kind: String,
}

#[allow(dead_code)] // Used via #[serde(default = "...")] attribute above
fn default_event_kind() -> String {
    "sync".into()
}

static SYNC_EVENT_TX: OnceLock<tokio::sync::broadcast::Sender<SyncEvent>> = OnceLock::new();

fn get_event_tx() -> &'static tokio::sync::broadcast::Sender<SyncEvent> {
    SYNC_EVENT_TX.get_or_init(|| tokio::sync::broadcast::channel(32).0)
}

pub(super) fn push_event(remote_node_id: &str, resources_imported: usize, kind: &str) {
    let now = crate::utils::now() as u64;
    let key = (remote_node_id.to_string(), kind.to_string());
    // Never debounce `connected` — both devices must refresh live-peer UI.
    if kind != "connected" {
        if let Ok(mut last) = last_event_ms().lock() {
            if let Some(&prev) = last.get(&key) {
                if now.saturating_sub(prev) < EVENT_DEBOUNCE_MS {
                    tracing::debug!(
                        "[live] debounced {kind} for {}",
                        &remote_node_id[..remote_node_id.len().min(12)]
                    );
                    return;
                }
            }
            last.insert(key, now);
            // Entries only matter inside the debounce window; without this
            // the map grew by one row per (peer, kind) for the life of the
            // process.
            last.retain(|_, at| now.saturating_sub(*at) < EVENT_DEBOUNCE_MS);
        }
    }

    let event = SyncEvent {
        remote_node_id: remote_node_id.to_string(),
        resources_imported,
        timestamp: now,
        kind: kind.to_string(),
    };
    let _ = get_event_tx().send(event);
}

/// Drain and return all pending sync events (legacy polling API).
pub fn poll_sync_events() -> Vec<SyncEvent> {
    let mut rx = get_event_tx().subscribe();
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    events
}

/// Block until the next sync event arrives. Reactive — no polling.
pub async fn wait_for_sync_event() -> SyncEvent {
    let mut rx = get_event_tx().subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => return event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                rx = get_event_tx().subscribe();
            }
        }
    }
}

/// Block until the live peer count changes from `current`. Reactive.
pub async fn wait_for_peer_count_change(current: usize) -> usize {
    let mut rx = get_event_tx().subscribe();
    loop {
        // Check immediately
        let count = live_peer_count();
        if count != current {
            return count;
        }
        // Wait for any event (connect/disconnect changes count)
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
            Ok(Ok(_)) => {
                let count = live_peer_count();
                if count != current {
                    return count;
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(_)) => {
                rx = get_event_tx().subscribe();
            }
            Err(_) => {} // timeout, loop and check again
        }
    }
}
