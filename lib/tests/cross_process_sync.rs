//! Two devices that are genuinely two processes.
//!
//! `sync::iroh_e2e` already runs two Iroh nodes over real QUIC, but both live
//! inside one test process and therefore share `LIVE_PEERS`, `ROUTER` and every
//! other global the sync layer keeps. That shared state is invisible in-process
//! and very visible in production, where the two sides are separate apps on
//! separate devices. This test puts a real OS process boundary between them:
//! nothing is shared except the bytes on the wire.
//!
//! Discovery is deliberately short-circuited — the child hands over its full
//! `NodeAddr` through a file rather than making the parent find it on the
//! network. Discovery has its own coverage (`pkarr_discovery_and_iroh_sync`),
//! and depending on relay/mDNS reachability here would buy nothing but flakes.
//! What is under test is the reconcile itself, across the process boundary.
//!
//! Run: cargo test -p atomic_lib --features db-redb,iroh --test cross_process_sync
#![cfg(all(feature = "db-redb", feature = "iroh"))]

use std::path::{Path, PathBuf};

const CHILD_DIR_ENV: &str = "ATOMIC_XPROC_CHILD_DIR";
const CANVAS_CLASS: &str = "https://atomicdata.dev/ontology/canvas/Canvas";
const STROKE_DATA: &str = "https://atomicdata.dev/ontology/canvas/strokeData";

/// Everything the parent needs to become the same account and dial the child.
#[derive(serde::Serialize, serde::Deserialize)]
struct Handshake {
    node_id: String,
    relay_url: Option<String>,
    direct_addrs: Vec<String>,
    drive: String,
    secret: String,
    canvas: String,
}

fn handshake_path(dir: &Path) -> PathBuf {
    dir.join("handshake.json")
}

async fn open_store(dir: &Path) -> atomic_lib::Db {
    atomic_lib::test_utils::init_redb_file_without_periodic_flush(dir)
        .await
        .expect("open store")
}

/// The remote device. Publishes a canvas, then stays up long enough to be
/// dialed — the parent kills it when the exchange is done.
#[test]
#[ignore = "child process entry point, driven by the parent test"]
fn child_hosts_a_drive_over_iroh() {
    let Some(dir) = std::env::var(CHILD_DIR_ENV).ok().map(PathBuf::from) else {
        return;
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = open_store(&dir).await;
        let (agent, drive) = store.setup("Remote device").await.unwrap();
        let secret = agent.build_secret().unwrap();

        let canvas = store
            .create_resource(
                CANVAS_CLASS,
                &drive,
                "Shared canvas",
                Some(vec![(
                    STROKE_DATA,
                    atomic_lib::Value::Json(serde_json::json!([
                        { "color": 7, "path": [[1.0, 2.0]] }
                    ])),
                )]),
            )
            .await
            .unwrap();

        let (node_id, router) = atomic_lib::sync::peer::start(store.clone()).await.unwrap();
        let addr = router.endpoint().node_addr().await.unwrap();

        let handshake = Handshake {
            node_id: node_id.to_string(),
            relay_url: addr.relay_url.map(|u| u.to_string()),
            direct_addrs: addr
                .direct_addresses
                .iter()
                .map(|a| a.to_string())
                .collect(),
            drive,
            secret,
            canvas,
        };
        std::fs::write(
            handshake_path(&dir),
            serde_json::to_vec(&handshake).unwrap(),
        )
        .unwrap();

        // Stay reachable. The parent kills this process once it has synced; the
        // ceiling only stops a stray child outliving a crashed parent.
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    });
}

/// Poll for the child's handshake. It has a real node to bind and a drive to
/// build first, so the parent cannot assume it is instant — but waiting on the
/// file it actually writes beats sleeping a guessed interval.
fn await_handshake(dir: &Path, child: &mut std::process::Child) -> Handshake {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);

    while std::time::Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(handshake_path(dir)) {
            if let Ok(handshake) = serde_json::from_slice::<Handshake>(&bytes) {
                return handshake;
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("child exited before publishing its address: {status}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = child.kill();
    panic!("child never published its address");
}

#[tokio::test]
async fn verified_sync_survives_receiver_kill() {
    use atomic_lib::Storelike;

    let dir = std::env::temp_dir().join(format!("atomic-xproc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let child_dir = dir.join("remote");
    let local_dir = dir.join("local");
    std::fs::create_dir_all(&child_dir).unwrap();
    std::fs::create_dir_all(&local_dir).unwrap();

    let exe = std::env::current_exe().expect("test binary path");
    let mut child = std::process::Command::new(exe)
        .args([
            "child_hosts_a_drive_over_iroh",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(CHILD_DIR_ENV, &child_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn child");

    let remote = await_handshake(&child_dir, &mut child);

    // Same account on this side — a peer only hands over what the agent may
    // read, so signing in as someone else would prove nothing.
    let store = open_store(&local_dir).await;
    store.load_agent_from_secret(&remote.secret).await.unwrap();

    let endpoint = iroh::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();

    let mut addr = iroh::NodeAddr::new(remote.node_id.parse().unwrap());
    if let Some(relay) = remote.relay_url.as_deref().and_then(|u| u.parse().ok()) {
        addr = addr.with_relay_url(relay);
    }
    let socks: Vec<std::net::SocketAddr> = remote
        .direct_addrs
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();
    if !socks.is_empty() {
        addr = addr.with_direct_addresses(socks);
    }
    endpoint.add_node_addr(addr).unwrap();

    let synced = atomic_lib::sync::peer::sync_drive_with_peer_using(
        &endpoint,
        &remote.node_id,
        &remote.drive,
        &store,
        true,
    )
    .await;

    let pushed = if synced.is_ok() {
        atomic_lib::sync::peer::remove_live_peer_any(&remote.node_id);
        let mut canvas = store
            .get_resource(&remote.canvas.as_str().into())
            .await
            .unwrap();
        canvas.ensure_materialized().unwrap();
        canvas
            .set_unsafe(
                atomic_lib::urls::NAME.into(),
                atomic_lib::Value::String("Offline edit from parent".into()),
            )
            .unwrap();
        canvas.save_locally(&store).await.unwrap();
        let result = atomic_lib::sync::peer::sync_drive_with_peer_using_outcome(
            &endpoint,
            &remote.node_id,
            &remote.drive,
            &store,
            true,
        )
        .await;
        Some(result)
    } else {
        None
    };
    let _ = child.kill();
    let _ = child.wait();
    endpoint.close().await;

    let count = synced.expect("sync with the remote process should succeed");
    assert!(
        count > 0,
        "expected resources to cross the process boundary"
    );

    let outcome = pushed
        .unwrap()
        .expect("outbound offline edit must be verified");
    assert!(outcome.pushed > 0);
    // Reopen only after SIGKILL and wait: neither a graceful shutdown nor a
    // periodic server flush can rescue an acknowledged-but-volatile write.
    let recovered = open_store(&child_dir).await;
    let resource = recovered
        .get_resource(&remote.canvas.as_str().into())
        .await
        .unwrap();
    assert_eq!(
        resource.get(atomic_lib::urls::NAME).unwrap().to_string(),
        "Offline edit from parent"
    );
    let key = atomic_lib::Subject::from_raw(&remote.canvas, None).pure_id();
    let bytes = recovered
        .kv
        .get(atomic_lib::db::trees::Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    let recovered_vv = atomic_lib::loro::AtomicLoroDoc::vv_map_from_snapshot(&bytes).unwrap();
    let local_bytes = store
        .kv
        .get(atomic_lib::db::trees::Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    let expected_vv = atomic_lib::loro::AtomicLoroDoc::vv_map_from_snapshot(&local_bytes).unwrap();
    assert!(expected_vv
        .iter()
        .all(|(peer, count)| recovered_vv.get(peer).copied().unwrap_or(0) >= *count));

    // The drive arriving is not enough — the canvas the remote actually drew
    // has to be here, with its stroke intact.
    let canvas = store
        .get_resource(&remote.canvas.as_str().into())
        .await
        .expect("the remote's canvas must exist locally after sync");

    let strokes = match canvas.get(STROKE_DATA) {
        Ok(atomic_lib::Value::Json(v)) => v.clone(),
        other => panic!("expected stroke data, got {other:?}"),
    };
    assert_eq!(
        strokes,
        serde_json::json!([{ "color": 7, "path": [[1.0, 2.0]] }]),
        "the stroke drawn in the other process must survive the reconcile"
    );
}
