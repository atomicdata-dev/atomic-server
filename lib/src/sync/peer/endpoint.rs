//! Endpoint and router lifecycle: `start`, the accept handler and the global handles.

use super::*;

/// Start the Iroh peer node. Returns the NodeID and a Router that must be kept alive.
///
/// The NodeID is persistent — derived from a secret key stored in the DB.
/// Waits for the relay connection to be established before returning,
/// so that other peers can discover and connect to us immediately.
pub async fn start(store: Db) -> anyhow::Result<(NodeId, Router)> {
    let secret_key = load_or_create_secret_key(&store);
    let endpoint: Endpoint = Endpoint::builder()
        .secret_key(secret_key)
        // n0 discovery (relay + pkarr) reaches devices across networks, but two
        // devices on the same Wi-Fi should not have to round-trip through a
        // relay and hope hole-punching succeeds — which is exactly what fails on
        // restrictive/mobile networks (a tablet dialing a phone by the QR's node
        // id timed out). Local mDNS discovery lets same-LAN peers find and dial
        // each other directly.
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await?;

    let node_id = endpoint.node_id();
    NODE_ID.set(node_id.to_string()).ok();
    ENDPOINT.set(endpoint.clone()).ok();

    // Wait for relay connection so discovery_n0 can find us
    let relay = endpoint.home_relay();
    tracing::info!("Iroh NodeID: {node_id}, waiting for relay...");
    let relay_url =
        tokio::time::timeout(std::time::Duration::from_secs(10), wait_for_relay(relay)).await;
    match relay_url {
        Ok(Some(url)) => tracing::info!("Iroh relay connected: {url}"),
        Ok(None) => tracing::warn!("Iroh relay: none (direct connections only)"),
        Err(_) => tracing::warn!("Iroh relay: timed out after 10s (connections may fail)"),
    }

    let bg_store = store.clone();
    let router = Router::builder(endpoint)
        .accept(
            ATOMIC_ALPN,
            AtomicHandler {
                store,
                my_node_id: node_id.to_string(),
            },
        )
        .spawn();

    // Keep router alive globally — dropping it stops incoming connections
    ROUTER.set(router.clone()).ok();

    // Start live sync — watches for local changes, pushes to connected peers
    start_live_sync(bg_store.clone());

    // Auto-connect to known peers in background, retry until connected
    let auto_store = bg_store;
    tokio::spawn(async move {
        let my_id = normalize_node_id(get_node_id().unwrap_or_default());

        // Brief delay so relay can register our NodeID
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        loop {
            let drive = match auto_store.get_active_drive() {
                Some(d) => d,
                None => {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
            };
            let peers = get_known_peers(&auto_store);
            if peers.is_empty() {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            let mut all_connected = true;
            for peer in &peers {
                if normalize_node_id(&peer.node_id) == my_id {
                    continue;
                }
                let peer_key = normalize_node_id(&peer.node_id);
                if live_peer_ids().contains(&peer_key) {
                    continue;
                }

                // Prefer the device with the smaller NodeID to dial first (avoids
                // duplicate handshakes). The larger NodeID waits briefly, then
                // also dials if still offline — otherwise one side never connects
                // when relay discovery is flaky.
                if normalize_node_id(&my_id) > peer_key {
                    if live_peer_ids().contains(&peer_key) {
                        continue;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    if live_peer_ids().contains(&peer_key) {
                        continue;
                    }
                }

                all_connected = false;
                tracing::info!(
                    "[auto_connect] connecting to {}",
                    &peer.node_id[..peer.node_id.len().min(12)]
                );
                match sync_drive_with_peer_if_needed(&peer.node_id, &drive, &auto_store).await {
                    Ok(count) => {
                        tracing::info!(
                            "[auto_connect] synced {count} resources, live connection established"
                        );
                    }
                    Err(e) => {
                        tracing::debug!("[auto_connect] failed: {e}");
                    }
                }
            }

            if all_connected {
                // All peers connected — wait and check periodically for disconnects or new peers
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            } else {
                // Some peers failed — retry sooner
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    Ok((node_id, router))
}

/// Wait until the relay watcher emits a Some(url).
async fn wait_for_relay(
    mut watcher: iroh::watchable::Watcher<Option<iroh::RelayUrl>>,
) -> Option<iroh::RelayUrl> {
    // Check current value first
    if let Ok(Some(url)) = watcher.get() {
        return Some(url);
    }
    // Wait for next update
    loop {
        if watcher.updated().await.is_err() {
            return None;
        }
        if let Ok(Some(url)) = watcher.get() {
            return Some(url);
        }
    }
}

#[derive(Debug, Clone)]
struct AtomicHandler {
    store: Db,
    /// This endpoint's node id: what a dialer's AUTH proof must name.
    my_node_id: String,
}

impl iroh::protocol::ProtocolHandler for AtomicHandler {
    fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> futures::future::BoxFuture<'static, anyhow::Result<()>> {
        let store = self.store.clone();
        let my_node_id = self.my_node_id.clone();
        Box::pin(async move {
            let remote = connection.remote_node_id()?;
            let remote_str = normalize_node_id(&remote.to_string());
            tracing::info!("[accept] incoming connection from {remote_str}");

            // Accept the first (and only) bi stream for sync + live
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::info!("[accept] connection closed from {remote}: {e}");
                    return Ok(());
                }
            };

            // Handle initial sync, then transition to live mode on the same stream
            let store_clone = store.clone();
            let remote_id = remote_str.clone();
            match handle_stream(send, recv, store_clone, remote_id, my_node_id).await {
                Ok(imported) => {
                    push_event(&remote_str, imported, "sync");
                }
                Err(e) => {
                    tracing::warn!("[accept] stream error: {e}");
                }
            }

            Ok(())
        })
    }
}

/// Global endpoint, set once on startup. Needed for outgoing connections.
pub(super) static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

/// Global router, must be kept alive or incoming connections stop working.
static ROUTER: OnceLock<Router> = OnceLock::new();
