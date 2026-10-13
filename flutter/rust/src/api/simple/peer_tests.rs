//! The bridge's peer surface — the code the Android Canvas app calls to sync.
//!
//! `tests.rs` covers the canvas editing session; this covers getting a drawing
//! off the device. Everything here goes through the same `pub` functions
//! Flutter calls, against a **real remote peer in another OS process** rather
//! than a mock: the closest thing in CI to "Canvas syncs with my desktop".
//!
//! Why a separate process: `atomic_lib::sync::peer` keeps its router, endpoint
//! and live-peer table in process globals, and this crate's `DB` is a
//! `OnceLock`. Two peers in one process would share all of it and the sync
//! would be a node talking to itself.
//!
//! Discovery is short-circuited — the remote's address is handed over through a
//! file and seeded with `remember_peer_addr`, the same routing data a real
//! pairing stores. That keeps the test off relay/mDNS reachability (its own
//! concern, covered by `pkarr_discovery_and_iroh_sync`) while still exercising
//! the real dial path, since `peer_sync` builds its dial target from exactly
//! that stored data.

use super::tests::shared_drive;
use super::*;

const CHILD_DIR_ENV: &str = "ATOMIC_BRIDGE_PEER_CHILD_DIR";
const REMOTE_NAME: &str = "Desktop";

/// What the parent hands the remote, and what the remote hands back.
#[derive(serde::Serialize, serde::Deserialize)]
struct Handshake {
    /// The account both sides run as. A peer serves only what the asking agent
    /// may read, so a different identity here would prove nothing.
    secret: String,
    /// The exact canvas to watch for. Every test in this binary shares one
    /// drive, so "any canvas with strokes" would happily match a neighbour's
    /// drawing and prove nothing about ours.
    canvas: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RemoteAddr {
    node_id: String,
    relay_url: Option<String>,
    direct_addrs: Vec<String>,
}

fn handshake_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("handshake.json")
}

fn addr_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("remote-addr.json")
}

/// Written by the remote once it can actually see the pushed drawing.
fn receipt_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("receipt.txt")
}

/// A second device on the same account: its own store, its own node, its own
/// process globals. Accepts an inbound sync and reports what landed.
#[test]
#[ignore = "child process entry point, driven by the parent test"]
fn child_is_a_second_device() {
    let Some(dir) = std::env::var(CHILD_DIR_ENV)
        .ok()
        .map(std::path::PathBuf::from)
    else {
        return;
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let handshake: Handshake =
            serde_json::from_slice(&std::fs::read(handshake_path(&dir)).unwrap()).unwrap();

        let store = atomic_lib::Db::init_redb_file(&dir, None, &dir.join("uploads"))
            .await
            .unwrap();
        store
            .load_agent_from_secret(&handshake.secret)
            .await
            .unwrap();
        atomic_lib::sync::peer::set_device_name(&store, REMOTE_NAME);

        let (node_id, router) = atomic_lib::sync::peer::start(store.clone()).await.unwrap();
        let addr = router.endpoint().node_addr().await.unwrap();

        std::fs::write(
            addr_path(&dir),
            serde_json::to_vec(&RemoteAddr {
                node_id: node_id.to_string(),
                relay_url: addr.relay_url.map(|u| u.to_string()),
                direct_addrs: addr
                    .direct_addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
            })
            .unwrap(),
        )
        .unwrap();

        // Watch for the drawing to arrive. Reporting from the receiving side is
        // what makes this independent proof rather than the sender's own count.
        for _ in 0..1200 {
            if let Ok(resource) = store.get_resource(&handshake.canvas.as_str().into()).await {
                if let Ok(atomic_lib::Value::Json(strokes)) = resource.get(CANVAS_STROKE_DATA) {
                    if strokes.as_array().is_some_and(|a| !a.is_empty()) {
                        std::fs::write(receipt_path(&dir), strokes.to_string()).unwrap();
                    }
                }
            }
            if receipt_path(&dir).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    });
}

/// Owns the remote process so a failing assertion cannot leak a live peer that
/// keeps answering for its full lifetime.
struct RemoteDevice {
    dir: std::path::PathBuf,
    process: std::process::Child,
}

impl Drop for RemoteDevice {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Boot the remote device and wait until it publishes a dialable address.
async fn start_remote_device(secret: String, canvas: String) -> (RemoteDevice, RemoteAddr) {
    let dir = std::env::temp_dir().join(format!("atomic-bridge-peer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        handshake_path(&dir),
        serde_json::to_vec(&Handshake { secret, canvas }).unwrap(),
    )
    .unwrap();

    let exe = std::env::current_exe().expect("test binary path");
    let process = std::process::Command::new(exe)
        // Fully qualified: libtest knows this test by its module path, and a
        // bare name matches nothing under `--exact`.
        .args([
            "api::simple::peer_tests::child_is_a_second_device",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(CHILD_DIR_ENV, &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn remote device");

    let mut remote = RemoteDevice { dir, process };

    for _ in 0..600 {
        if let Ok(bytes) = std::fs::read(addr_path(&remote.dir)) {
            if let Ok(addr) = serde_json::from_slice::<RemoteAddr>(&bytes) {
                return (remote, addr);
            }
        }
        if let Ok(Some(status)) = remote.process.try_wait() {
            panic!("remote device exited before it was ready: {status}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    panic!("remote device never published an address");
}

/// A drawing made on this device reaches a second device, driven entirely
/// through the bridge API Flutter calls.
///
/// This is the one test that exercises `start_peer` → `add_known_peer` →
/// `peer_sync` as a sequence, against something that can actually refuse.
#[tokio::test]
async fn a_canvas_syncs_to_a_second_device_through_the_bridge() {
    let _ = shared_drive().await;

    let canvas = create_canvas("Synced drawing".to_string()).await.unwrap();
    push_stroke(canvas.clone(), r#"{"color":42,"path":[[3.0,4.0]]}"#.into())
        .await
        .unwrap();

    let secret = get_active_agent()
        .await
        .unwrap()
        .expect("the shared setup signs us in")
        .secret;

    // Our own node has to exist before we can dial anyone.
    let my_node = start_peer().await.expect("start_peer");
    assert_eq!(
        get_peer_id().as_deref(),
        Some(my_node.as_str()),
        "get_peer_id must report the node start_peer just created"
    );

    let (remote, addr) = start_remote_device(secret, canvas.clone()).await;

    // What pairing records: the peer, plus how to reach it. `peer_sync` builds
    // its dial target from this, so an unroutable record fails the sync.
    add_known_peer(addr.node_id.clone(), REMOTE_NAME.to_string());
    atomic_lib::sync::peer::remember_peer_addr(
        db().unwrap().as_ref(),
        &addr.node_id,
        addr.relay_url.clone(),
        addr.direct_addrs.clone(),
    );

    let report: serde_json::Value =
        serde_json::from_str(&peer_sync(addr.node_id.clone()).await.expect("peer_sync")).unwrap();

    // `start_peer` runs an auto-connect loop that dials every known peer on a
    // ~10s tick. When a tick lands between `add_known_peer` and the explicit
    // sync above, the loop delivers the drawing first and this sync finds
    // nothing left to push (`pushed: 0`). Whether the drawing arrived is
    // therefore judged on the receiving side below, not on who pushed it.
    assert_eq!(
        report["peer_name"].as_str(),
        Some(REMOTE_NAME),
        "the peer's HELLO name is what the UI labels a device with: {report}"
    );

    // Independent proof: the receiving side reports what it can actually read,
    // rather than us trusting our own push count.
    let receipt = {
        let mut found = None;
        for _ in 0..300 {
            if let Ok(body) = std::fs::read_to_string(receipt_path(&remote.dir)) {
                found = Some(body);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        found.expect("the second device never saw the drawing")
    };

    assert!(
        receipt.contains("42"),
        "the second device saw a drawing, but not the stroke we drew: {receipt}"
    );
}

/// Known peers as `(normalised node id, name)`, decoded from the JSON the
/// bridge hands Flutter.
fn listed_peers() -> Vec<(String, String)> {
    serde_json::from_str::<Vec<serde_json::Value>>(&get_known_peers())
        .unwrap()
        .into_iter()
        .map(|p| {
            (
                p["node_id"].as_str().unwrap_or_default().to_string(),
                p["name"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Pairing bookkeeping, as the Flutter UI drives it. No network: this is the
/// list a device shows and auto-dials from, so losing or duplicating an entry
/// is a re-pair for the user.
#[tokio::test]
async fn known_peers_round_trip_through_the_bridge() {
    let _ = shared_drive().await;

    let node = format!("did:ad:node:{}", "c".repeat(64));
    add_known_peer(node.clone(), "Tablet".to_string());

    // The store keeps peers under a normalised id, not the `did:ad:node:` form
    // the UI passes in — so look them up the same way the app does.
    let key = atomic_lib::sync::peer::normalize_node_id(&node);
    let listed = listed_peers();
    let entry = listed
        .iter()
        .find(|p| p.0 == key)
        .expect("the peer we just added must be listed");
    assert_eq!(entry.1, "Tablet");

    // Re-pairing the same device must update it, not add a second card.
    add_known_peer(node.clone(), "Tablet renamed".to_string());
    let listed = listed_peers();
    let matching: Vec<_> = listed.iter().filter(|p| p.0 == key).collect();
    assert_eq!(matching.len(), 1, "re-pairing must not duplicate the peer");
    assert_eq!(matching[0].1, "Tablet renamed");

    remove_known_peer(node.clone());
    assert!(
        !listed_peers().iter().any(|p| p.0 == key),
        "a forgotten peer must not come back"
    );
}

/// Syncing before the node exists must say so, not panic or hang. The Flutter
/// app can reach this ordering on a cold start.
#[tokio::test]
async fn peer_sync_without_a_drive_reports_rather_than_panics() {
    let _ = shared_drive().await;

    let unreachable = format!("did:ad:node:{}", "d".repeat(64));
    let result = peer_sync(unreachable).await;

    assert!(
        result.is_err(),
        "dialling a node that does not exist must be an error, got {result:?}"
    );
}
