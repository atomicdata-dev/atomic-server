//! End-to-end tests: two Iroh endpoints, real QUIC sync (bulk + live).
//!
//! Run (single-threaded — tests share global `LIVE_PEERS` / `ROUTER` state):
//! `cargo test -p atomic_lib --features "iroh,db-redb" --lib -- sync::iroh_e2e -- --test-threads=1`

use crate::{agents::ForAgent, Db, Storelike};
use iroh::protocol::Router;

const STROKE_DATA: &str = "https://atomicdata.dev/ontology/canvas/strokeData";
const FOLDER_PROP: &str = "https://atomicdata.dev/ontology/canvas/folderId";
const CANVAS_CLASS: &str = "https://atomicdata.dev/ontology/canvas/Canvas";
const FOLDER_CLASS: &str = "https://atomicdata.dev/classes/Folder";

/// Two logical devices: A runs `peer::start` (router + live push), B uses a separate endpoint.
struct IrohPair {
    db_a: Db,
    db_b: Db,
    drive: String,
    node_id_a: String,
    _router_a: Router,
    ep_b: iroh::Endpoint,
}

async fn setup_pair(prefix: &str) -> IrohPair {
    use crate::sync::peer;

    let db_a = Db::init_temp(&format!("{prefix}_a")).await.unwrap();
    let (agent_a, drive) = db_a.setup("Alice").await.unwrap();
    let secret = agent_a.build_secret().unwrap();

    let db_b = Db::init_temp(&format!("{prefix}_b")).await.unwrap();
    db_b.load_agent_from_secret(&secret).await.unwrap();

    let (node_id_a, router_a) = peer::start(db_a.clone()).await.unwrap();
    let ep_b = iroh::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();
    let node_addr_a = router_a.endpoint().node_addr().await.unwrap();
    ep_b.add_node_addr(node_addr_a).unwrap();

    IrohPair {
        db_a,
        db_b,
        drive,
        node_id_a: node_id_a.to_string(),
        _router_a: router_a,
        ep_b,
    }
}

async fn sync_b_from_a(pair: &IrohPair) -> usize {
    use crate::sync::peer;

    peer::sync_drive_with_peer_using(&pair.ep_b, &pair.node_id_a, &pair.drive, &pair.db_b, true)
        .await
        .expect("B→A sync should succeed")
}

async fn wait_until<F, Fut>(timeout: std::time::Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

async fn wait_for_live_peers(min: usize, timeout: std::time::Duration) {
    let ok = wait_until(timeout, || async {
        crate::sync::peer::live_peer_count() >= min
    })
    .await;
    assert!(
        ok,
        "expected ≥{min} live peer(s), got {}",
        crate::sync::peer::live_peer_count()
    );
}

async fn stroke_count(db: &Db, canvas: &str) -> usize {
    let r = db.get_resource(&canvas.into()).await.unwrap();
    match r.get(STROKE_DATA) {
        Ok(crate::Value::Json(serde_json::Value::Array(arr))) => arr.len(),
        _ => 0,
    }
}

async fn folder_id_on(db: &Db, canvas: &str) -> Option<String> {
    let r = db.get_resource(&canvas.into()).await.ok()?;
    r.get(FOLDER_PROP)
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty())
}

async fn assign_folder(db: &Db, canvas: &str, folder: &str) {
    let mut r = db.get_resource(&canvas.into()).await.unwrap();
    r.ensure_materialized().unwrap();
    r.set_unsafe(FOLDER_PROP.into(), crate::Value::String(folder.into()))
        .unwrap();
    r.save_locally(db).await.unwrap();
}

/// The HELLO exchange itself is symmetric (both sides learn the other's
/// device name), but persisting it into `known-peers` — which the
/// background auto-connect loop treats as "retry-forever" — is NOT: only
/// the initiator (the side that explicitly dialed, i.e. an affirmative
/// pairing/sync action by the local user) persists it. The accept side
/// (an unsolicited inbound connection the local user never chose to sync
/// with) deliberately does not (F9 minimal, planning/unified-sync.md) —
/// without this asymmetry, any Iroh node that discovers and connects to
/// us earns a permanent reconnect slot with zero consent.
#[tokio::test]
async fn e2e_hello_exchanges_device_names() {
    use crate::sync::peer;

    let pair = setup_pair("e2e_hello").await;

    // Pin a recognisable name on A so the assertion isn't at the mercy of
    // whatever the test host's `hostname` happens to be.
    peer::set_device_name(&pair.db_a, "Alice's Laptop");
    // B too — its name flows back over the HELLO that A replies with, but
    // (per the asymmetry above) A must not persist it — see the negative
    // assertion below.
    peer::set_device_name(&pair.db_b, "Bob's Phone");

    let outcome = peer::sync_drive_with_peer_using_outcome(
        &pair.ep_b,
        &pair.node_id_a,
        &pair.drive,
        &pair.db_b,
        true,
    )
    .await
    .expect("B→A sync should succeed");

    assert_eq!(
        outcome.peer_name.as_deref(),
        Some("Alice's Laptop"),
        "initiator should see A's self-reported HELLO name"
    );

    // B is the initiator (explicit, user-chosen sync target) — it persists
    // A's name into known-peers so the UI picks it up on its next refresh.
    let b_known = peer::get_known_peers(&pair.db_b);
    let alice_on_b = b_known
        .iter()
        .find(|p| peer::normalize_node_id(&p.node_id) == peer::normalize_node_id(&pair.node_id_a));
    assert_eq!(
        alice_on_b.map(|p| p.name.as_str()),
        Some("Alice's Laptop"),
        "B (initiator) should have persisted A's HELLO name into known-peers"
    );

    // A is the accept side — B's connection was unsolicited from A's point
    // of view (A never called sync_drive_with_peer against B). Give the
    // accept side a few hundred ms to process the HELLO and NOT write it
    // down, same window the old (vulnerable) assertion waited on.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let a_known = peer::get_known_peers(&pair.db_a);
    let ep_b_node_id = pair.ep_b.node_id().to_string();
    assert!(
        !a_known
            .iter()
            .any(|p| peer::normalize_node_id(&p.node_id) == peer::normalize_node_id(&ep_b_node_id)),
        "A (accept side) must NOT persist an unsolicited peer into \
         known-peers — that hands them a permanent auto-reconnect slot \
         with no pairing/consent (got {a_known:?})"
    );
}

/// Initial bulk sync: canvases, strokes, and bidirectional merge (same agent / drive).
#[tokio::test]
async fn e2e_bidirectional_bulk_sync() {
    let pair = setup_pair("e2e_bulk").await;

    let canvas_a = pair
        .db_a
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "Canvas A",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![
                    serde_json::json!({"color": 1}),
                ])),
            )]),
        )
        .await
        .unwrap();

    let canvas_b = pair
        .db_b
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "Canvas B",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![
                    serde_json::json!({"color": 2}),
                ])),
            )]),
        )
        .await
        .unwrap();

    let imported = sync_b_from_a(&pair).await;
    assert!(imported > 0, "B should import A's resources");

    pair.db_b
        .get_resource(&canvas_a.as_str().into())
        .await
        .expect("B should have A's canvas after bulk sync");

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    pair.db_a
        .get_resource(&canvas_b.as_str().into())
        .await
        .expect("A should have B's canvas after bidirectional SYNC_PUSH");
}

/// After bulk sync, an edit on A reaches B via the live stream.
/// An idle link stays up.
///
/// The read loop now treats silence as a dead connection, which is what makes a
/// half-open link recoverable — one side's stream can die while the other keeps
/// broadcasting into it, and until this it took ~15 minutes for the second side
/// to notice, during which every local change was silently dropped and
/// `auto_connect` would not redial (it skips peers it believes are connected).
///
/// The hazard in that fix is tearing down healthy connections that simply have
/// nothing to say, so this waits past the keepalive interval with no traffic at
/// all and asserts the peer is still there and still syncing.
#[tokio::test]
async fn e2e_an_idle_link_survives_on_keepalives() {
    let pair = setup_pair("e2e_idle_link").await;

    sync_b_from_a(&pair).await;
    wait_for_live_peers(1, std::time::Duration::from_secs(3)).await;

    // Quiet for longer than a keepalive interval — but inside the liveness
    // timeout, so only the keepalives are holding it open.
    tokio::time::sleep(crate::sync::protocol::KEEPALIVE_INTERVAL * 2).await;

    assert!(
        crate::sync::peer::live_peer_count() >= 1,
        "an idle connection must be held open by keepalives, not torn down"
    );

    // And it still works, rather than merely appearing registered.
    let canvas = pair
        .db_a
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "After idling",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![
                    serde_json::json!({"color": 2, "path": [[1.0, 1.0]]}),
                ])),
            )]),
        )
        .await
        .unwrap();

    sync_b_from_a(&pair).await;
    assert_eq!(stroke_count(&pair.db_b, &canvas).await, 1);
}

/// Presence crosses a peer link — and never reaches the store.
///
/// Both halves matter. Before this, `EPHEMERAL` (0x40) was a reserved tag with
/// no sender and no handler, so two machines syncing the same drive could not
/// see each other's cursors at all. And presence must stay out of the store:
/// every other frame on this link ends in a write, and cursor positions merged
/// into the CRDT would be persisted and synced forever.
#[tokio::test]
async fn e2e_presence_crosses_the_link_without_being_stored() {
    let pair = setup_pair("e2e_presence").await;

    sync_b_from_a(&pair).await;
    wait_for_live_peers(1, std::time::Duration::from_secs(3)).await;

    let before = pair.db_b.all_resources(true).count();
    let mut presence = pair.db_b.subscribe_ephemeral();

    let payload = b"cursor-position-blob".to_vec();
    crate::sync::peer::broadcast_ephemeral(
        crate::sync::protocol::ephemeral_kind::PRESENCE,
        &pair.drive,
        "did:ad:agent:someone",
        &payload,
        None,
    );

    let received = tokio::time::timeout(std::time::Duration::from_secs(5), presence.recv())
        .await
        .expect("presence must arrive before the timeout")
        .expect("the presence channel must stay open");

    assert_eq!(received.drive, pair.drive);
    assert_eq!(received.agent, "did:ad:agent:someone");
    assert_eq!(received.payload, payload);

    let after = pair.db_b.all_resources(true).count();
    assert_eq!(
        before, after,
        "presence must not create resources — it is not data"
    );
}

#[tokio::test]
async fn e2e_stroke_append_after_sync() {
    let pair = setup_pair("e2e_stroke").await;

    let canvas = pair
        .db_a
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "Stroke canvas",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![
                    serde_json::json!({"color": 1, "path": [[0.0, 0.0]]}),
                ])),
            )]),
        )
        .await
        .unwrap();

    sync_b_from_a(&pair).await;
    wait_for_live_peers(1, std::time::Duration::from_secs(3)).await;
    assert_eq!(stroke_count(&pair.db_b, &canvas).await, 1);

    let mut resource_a = pair
        .db_a
        .get_resource(&canvas.as_str().into())
        .await
        .unwrap();
    resource_a.ensure_materialized().unwrap();
    resource_a.init_undo();
    resource_a
        .push_list_item(
            STROKE_DATA,
            serde_json::json!({"color": 2, "width": 2.0, "path": [[1.0, 1.0]]}),
        )
        .unwrap();
    resource_a.save_locally(&pair.db_a).await.unwrap();

    let live_ok = wait_until(std::time::Duration::from_secs(3), || async {
        stroke_count(&pair.db_b, &canvas).await == 2
    })
    .await;

    assert!(live_ok, "B must see second stroke via live push");
}

/// Gallery folder moves: `folderId` on a canvas propagates over Iroh.
#[tokio::test]
async fn e2e_canvas_folder_assignment_syncs() {
    let pair = setup_pair("e2e_folder").await;

    let folder = pair
        .db_a
        .create_resource(FOLDER_CLASS, &pair.drive, "Sketches", None)
        .await
        .unwrap();

    let canvas = pair
        .db_a
        .create_resource(CANVAS_CLASS, &pair.drive, "Inbox", None)
        .await
        .unwrap();

    sync_b_from_a(&pair).await;
    wait_for_live_peers(1, std::time::Duration::from_secs(3)).await;

    assign_folder(&pair.db_a, &canvas, &folder).await;

    let live_ok = wait_until(std::time::Duration::from_secs(3), || async {
        folder_id_on(&pair.db_b, &canvas).await.as_deref() == Some(folder.as_str())
    })
    .await;

    if !live_ok {
        let _ = sync_b_from_a(&pair).await;
    }

    assert_eq!(
        folder_id_on(&pair.db_b, &canvas).await.as_deref(),
        Some(folder.as_str()),
        "B must see folderId after A assigns canvas to folder (live or bulk resync)"
    );
}

/// New `did:ad:` resources (genesis commits) reach B live while the link is
/// up, and via a follow-up bulk sync otherwise.
///
/// The live delta used to be the commit's own bytes, which a peer could not
/// always apply for a genesis, so this test once asserted that B did NOT have
/// the canvas until a resync. `CommitResponse::fanout_delta` now carries
/// everything the apply added and B usually has it before anyone asks for a
/// resync; the bulk path is the fallback, not the rule.
#[tokio::test]
async fn e2e_new_resource_after_bulk_resync() {
    let pair = setup_pair("e2e_new_res").await;

    pair.db_a
        .create_resource(CANVAS_CLASS, &pair.drive, "Seed", None)
        .await
        .unwrap();

    sync_b_from_a(&pair).await;

    let new_canvas = pair
        .db_a
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "After sync",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![
                    serde_json::json!({"color": 99}),
                ])),
            )]),
        )
        .await
        .unwrap();

    let live_ok = wait_until(std::time::Duration::from_secs(3), || async {
        pair.db_b
            .get_resource(&new_canvas.as_str().into())
            .await
            .is_ok()
    })
    .await;

    if !live_ok {
        let imported = sync_b_from_a(&pair).await;
        assert!(
            imported > 0,
            "bulk resync must import the canvas when live delivery did not"
        );
    }

    let on_b = pair
        .db_b
        .get_resource(&new_canvas.as_str().into())
        .await
        .expect("B should have new canvas after bulk resync");
    assert_eq!(
        on_b.get(crate::urls::NAME).unwrap().to_string(),
        "After sync"
    );
}

/// Engine pull still works when live is unavailable (documents mobile fallback path).
#[tokio::test]
async fn e2e_engine_pull_after_iroh_bulk_sync() {
    let pair = setup_pair("e2e_engine_pull").await;

    let canvas = pair
        .db_a
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "Pull test",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![serde_json::json!({"n": 1})])),
            )]),
        )
        .await
        .unwrap();

    sync_b_from_a(&pair).await;

    let mut resource_a = pair
        .db_a
        .get_resource(&canvas.as_str().into())
        .await
        .unwrap();
    resource_a.ensure_materialized().unwrap();
    resource_a.init_undo();
    resource_a
        .push_list_item(STROKE_DATA, serde_json::json!({"n": 2}))
        .unwrap();
    resource_a.save_locally(&pair.db_a).await.unwrap();

    // Simulate second bulk sync (nudge_peers / manual sync) via engine frames.
    let drive_subject =
        crate::Subject::from_raw(&pair.drive, pair.db_b.get_base_domain().as_deref());
    let subjects = crate::sync::engine::collect_drive_subjects(&pair.db_b, &drive_subject).await;
    let vvs = crate::sync::engine::build_drive_vvs(&pair.db_b, &subjects);
    let hash = crate::sync::engine::compute_drive_hash(&vvs);
    // Pull as the drive's own agent, not `Public`. Since the personal drive is
    // derived and provisioned private, nothing on it is world-readable, and the
    // push side of `handle_sync_vv` filters by `check_read` — so a `Public`
    // pull now returns SYNC_DIFF with no SYNC_PUSH behind it and imports
    // nothing. `Public` passed here only while test drives happened to be
    // readable by anyone, which is not the shape this fallback runs in: the
    // device doing the pull is the owner's other device, holding the owner's
    // agent.
    let owner = crate::agents::ForAgent::from(pair.db_a.get_default_agent().unwrap());
    let frames = crate::sync::engine::handle_sync_vv(
        &pair.drive,
        &hash,
        &[],
        &std::collections::HashMap::new(),
        &pair.db_a,
        &owner,
    )
    .await;

    let mut imported = 0;
    for frame in frames {
        if frame.first() == Some(&crate::sync::protocol::tag::SYNC_PUSH) {
            if let Some(push) = crate::sync::protocol::decode_sync_push(&frame[1..]) {
                let (count, _) = crate::sync::engine::import_sync_push(
                    &push,
                    &pair.db_b,
                    &ForAgent::Sudo,
                    false,
                )
                .await
                .expect("Sudo import is never rejected");
                imported += count;
            }
        }
    }
    assert!(imported > 0, "engine pull should import A's edit");

    assert_eq!(stroke_count(&pair.db_b, &canvas).await, 2);
}

/// The managed-node replication path, end to end on localhost: a drive that
/// lives on A but not on B is pulled to B — exactly what
/// `node.rs::pull_allowed_drives` does, minus the pkarr lookup (which we replace
/// with a direct address; pkarr only maps drive DID → NodeID). Afterwards B
/// hosts the drive (`has_resource_locally`, the managed-node skip check) and can
/// account for its usage (`per_drive_usage`).
#[tokio::test]
async fn e2e_managed_node_replicates_missing_drive() {
    let pair = setup_pair("e2e_replicate").await;

    // A has content under the drive; B starts without the drive at all.
    let doc = pair
        .db_a
        .create_resource(
            CANVAS_CLASS,
            &pair.drive,
            "Doc on A",
            Some(vec![(
                STROKE_DATA,
                crate::Value::Json(serde_json::Value::Array(vec![serde_json::json!({"n": 1})])),
            )]),
        )
        .await
        .unwrap();

    assert!(
        !pair.db_b.has_resource_locally(&pair.drive),
        "B should not host the drive before replicating"
    );

    // Replicate: the same Iroh pull the managed node performs.
    let imported = sync_b_from_a(&pair).await;
    assert!(imported > 0, "B should import the drive's resources");

    // B now has the drive's content...
    pair.db_b
        .get_resource(&doc.as_str().into())
        .await
        .expect("B should have A's resource after replicating");

    // ...reports usage for it...
    let usage = pair
        .db_b
        .per_drive_usage(&[pair.drive.clone()])
        .await
        .unwrap();
    let row = usage
        .iter()
        .find(|u| u.drive_subject == pair.drive)
        .expect("usage row for the replicated drive");
    assert!(
        row.resource_count > 0,
        "replicated drive should report resources, got {row:?}"
    );

    // ...and now counts as hosted, so the managed-node pull skips it next cycle.
    assert!(
        pair.db_b.has_resource_locally(&pair.drive),
        "B should host the drive after replicating"
    );
}

/// Pushing a workspace to a device that has none imports nothing — and that is
/// the whole point of doing it. This is a phone sending its workspace to an
/// always-on device, which is how it reaches a browser.
///
/// A check that counted only imports called this a failure, and told the owner
/// their own workspace belonged to "a different account".
#[tokio::test]
async fn pushing_a_workspace_to_an_empty_device_is_not_a_failure() {
    use crate::sync::peer;

    // The always-on device: its own account, and nothing of Alice's on it.
    let db_server = Db::init_temp("push_server").await.unwrap();
    db_server.setup("Server").await.unwrap();

    // Alice's phone, holding the only copy of her workspace.
    let db_phone = Db::init_temp("push_phone").await.unwrap();
    let (_agent, drive) = db_phone.setup("Alice").await.unwrap();
    db_phone
        .create_resource(crate::urls::FOLDER, &drive, "notes", None)
        .await
        .unwrap();

    let (node_id, router) = peer::start(db_server.clone()).await.unwrap();
    let ep_phone = iroh::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();
    ep_phone
        .add_node_addr(router.endpoint().node_addr().await.unwrap())
        .unwrap();

    peer::sync_drive_with_peer_using(&ep_phone, &node_id.to_string(), &drive, &db_phone, true)
        .await
        .expect("pushing a workspace up must not be reported as a failure");

    // The dialer writes its push and returns; the far side imports after that,
    // so wait for the write to land rather than for the call to come back.
    let landed = wait_until(std::time::Duration::from_secs(10), || async {
        db_server.has_resource_locally(&drive)
    })
    .await;

    assert!(landed, "the workspace should land on the always-on device");
}

/// Two devices, two different accounts, and nothing shared between them. The
/// dialer proves a valid agent key, so AUTH succeeds — and then `check_read`
/// denies it every subject, because none of them are its to read.
///
/// The sync must say that, not report an empty success: two real devices sat
/// there "synced" and blank, which is the worst way to answer a question.
///
/// It used to be said by refusing any agent that was not the acceptor's own.
/// That answered before asking: a peer holding a drive shared with them, or a
/// server holding one for them, was refused the same way — and a workspace
/// could then only reach a server over HTTP, which is what Iroh is here to
/// avoid. Rights decide, per subject (serverless-p2p Principle 2: one engine,
/// one set of checks, every node). The explanation is for what actually failed.
#[tokio::test]
async fn peer_sync_says_why_when_a_different_agent_may_read_nothing() {
    use crate::sync::peer;

    let db_a = Db::init_temp("xagent_a").await.unwrap();
    let (agent_a, drive) = db_a.setup("Alice").await.unwrap();

    // `create_drive` makes a drive public-read. Alice's is private here, so
    // "nothing is shared with Bob" is the drive's own doing, not the
    // transport's.
    let mut drive_resource = db_a.get_resource(&drive.clone().into()).await.unwrap();
    drive_resource
        .set(
            crate::urls::READ.into(),
            vec![agent_a.subject.to_string()].into(),
            &db_a,
        )
        .await
        .unwrap();
    drive_resource.save(&db_a).await.unwrap();

    // Bob holds his own key: a perfectly valid agent, just not Alice.
    let db_b = Db::init_temp("xagent_b").await.unwrap();
    db_b.setup("Bob").await.unwrap();

    let (node_id_a, router_a) = peer::start(db_a.clone()).await.unwrap();
    let ep_b = iroh::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();
    ep_b.add_node_addr(router_a.endpoint().node_addr().await.unwrap())
        .unwrap();

    let result =
        peer::sync_drive_with_peer_using(&ep_b, &node_id_a.to_string(), &drive, &db_b, true).await;

    let error = result.expect_err("an empty sync must not report success");
    let message = error.to_string();
    assert!(
        message.contains("nothing synced"),
        "the failure must say why, got: {message}"
    );

    assert!(
        !db_b.has_resource_locally(&drive),
        "a private drive may not cross to somebody else's device"
    );
}

/// The agent resource (`did:ad:agent:…`) is owned by itself and lives outside
/// every drive's subtree, so drive sync never carries it: a device restored
/// from a secret has the key but a nameless stub agent, and can't see the drives
/// its other devices know about. Same-agent peers now hand each other the agent
/// resource on connect and merge its Loro state.
#[tokio::test]
async fn same_agent_peers_reconcile_the_agent_resource() {
    let pair = setup_pair("agent_reconcile").await;

    // B restored from the secret: it holds the key and the drive DID, but the
    // name only ever existed on A's copy of the agent resource.
    let agent_subject = pair.db_b.get_default_agent().unwrap().subject.to_string();
    let before = pair
        .db_b
        .get_resource(&agent_subject.as_str().into())
        .await
        .unwrap();
    assert!(
        before.get(crate::urls::NAME).is_err(),
        "B starts with a nameless stub agent"
    );

    // Establish the live link (B dials A). Both push their agent on connect.
    sync_b_from_a(&pair).await;

    let db_b = pair.db_b.clone();
    let subject = agent_subject.clone();
    let got_name = wait_until(std::time::Duration::from_secs(10), || {
        let db_b = db_b.clone();
        let subject = subject.clone();
        async move {
            db_b.get_resource(&subject.as_str().into())
                .await
                .ok()
                .and_then(|r| r.get(crate::urls::NAME).ok().map(|v| v.to_string()))
                == Some("Alice".to_string())
        }
    })
    .await;
    assert!(
        got_name,
        "B's agent resource should gain the name A holds, over the live link"
    );
}

/// A device hands a server its own agent resource on connect, even though they
/// are different accounts. That is what lets a browser reading from the server
/// later learn whose drives are whose: the agent resource carries `name` and
/// `personalDrive`, lives outside every drive (so drive sync never moves it),
/// and only travels on this handshake. Without it, signing in with a secret
/// leaves the server holding your drive with no way to say it is yours.
#[tokio::test]
async fn a_device_hands_its_agent_resource_to_a_different_account_server() {
    use crate::sync::peer;

    // The server: its own account.
    let db_server = Db::init_temp("agentx_server").await.unwrap();
    db_server.setup("Server").await.unwrap();

    // The phone: a named account with a drive, whose agent resource carries the
    // name and drive pointer a fresh reader needs.
    let db_phone = Db::init_temp("agentx_phone").await.unwrap();
    let (phone_agent, _drive) = db_phone.setup("Alice").await.unwrap();
    let phone_agent_subject = phone_agent.subject.to_string();

    let (node_id, router) = peer::start(db_server.clone()).await.unwrap();
    let ep_phone = iroh::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();
    ep_phone
        .add_node_addr(router.endpoint().node_addr().await.unwrap())
        .unwrap();

    peer::sync_drive_with_peer_using(&ep_phone, &node_id.to_string(), &_drive, &db_phone, true)
        .await
        .expect("sync should not fail");

    // The server should now hold the phone's agent resource, with its name —
    // even though the phone is not the server's account.
    let db_server_c = db_server.clone();
    let subject = phone_agent_subject.clone();
    let landed = wait_until(std::time::Duration::from_secs(10), || {
        let db = db_server_c.clone();
        let subject = subject.clone();
        async move {
            db.get_resource(&subject.as_str().into())
                .await
                .ok()
                .and_then(|r| r.get(crate::urls::NAME).ok().map(|v| v.to_string()))
                == Some("Alice".to_string())
        }
    })
    .await;

    assert!(
        landed,
        "the server should hold the phone's agent resource so a browser can find its drive"
    );
}

/// A peer may hand over its *own* agent resource, and only its own. Now that
/// every connect offers it (not just same-account ones), the boundary that
/// keeps a peer from planting a *stranger's* identity — a forged public key, a
/// `personalDrive` pointing at the attacker's drive — has to hold under that
/// wider traffic. It does, and without a special case: `get_resource`
/// synthesizes an agent resource from its own DID's public key, so the write
/// is always checked against the real agent, and "agents can always edit
/// themselves" admits only the holder of the key. This pins that.
#[tokio::test]
async fn a_peer_cannot_forge_a_third_agents_resource() {
    use crate::agents::{Agent, ForAgent};
    use crate::sync::peer;

    let db_server = Db::init_temp("spoof_server").await.unwrap();
    db_server.setup("Server").await.unwrap();

    // Eve connects as herself; Victim is an account whose key she does not hold.
    let eve = Agent::new(Some("Eve")).unwrap();
    let victim = Agent::new(Some("Victim")).unwrap();

    let mut cache = std::collections::HashMap::new();

    // Eve tries to have Victim's agent resource admitted. She holds no key for
    // it, and check_write against the synthesized victim agent denies her.
    let forged = peer::admitted_for_drive_for_test(
        &db_server,
        &ForAgent::AgentSubject(eve.subject.clone()),
        &victim.subject.to_string(),
        false,
        &mut cache,
    )
    .await;
    assert!(
        !forged,
        "a peer must not write an agent resource it holds no key for"
    );

    // Her own, by contrast, is admitted — the boundary is identity, not a
    // blanket refusal of agent resources.
    let own = peer::admitted_for_drive_for_test(
        &db_server,
        &ForAgent::AgentSubject(eve.subject.clone()),
        &eve.subject.to_string(),
        false,
        &mut cache,
    )
    .await;
    assert!(own, "a peer's own agent resource must be admitted");
}

/// A device that gets its drive by pairing has no active drive of its own: the
/// browser's secret carries a key and nothing else, so neither `create_drive`
/// nor `load_agent_from_secret` ever names one. The auto-connect loop reads the
/// active drive and sleeps while it is `None`, which left two paired phones
/// talking only when a human pressed "Sync now" — never on their own, and never
/// again after a restart.
#[tokio::test]
async fn a_completed_peer_sync_names_the_drive_to_reconnect_to() {
    use crate::sync::peer;

    let db_a = Db::init_temp("active_drive_a").await.unwrap();
    let (agent_a, drive) = db_a.setup("Alice").await.unwrap();

    // Alice's other device: her key, and no idea which drive it belongs to.
    let db_b = Db::init_temp("active_drive_b").await.unwrap();
    let mut agent_b = agent_a.clone();
    agent_b.initial_drive = None;
    db_b.set_default_agent(agent_b);
    assert_eq!(
        db_b.get_active_drive(),
        None,
        "the second device starts out not knowing which drive is hers"
    );

    let (node_id_a, router_a) = peer::start(db_a.clone()).await.unwrap();
    let ep_b = iroh::Endpoint::builder()
        .discovery_n0()
        .discovery_local_network()
        .bind()
        .await
        .unwrap();
    ep_b.add_node_addr(router_a.endpoint().node_addr().await.unwrap())
        .unwrap();

    peer::sync_drive_with_peer_using(&ep_b, &node_id_a.to_string(), &drive, &db_b, true)
        .await
        .expect("Alice's two devices should sync");

    assert_eq!(
        db_b.get_active_drive().as_deref(),
        Some(drive.as_str()),
        "after syncing a drive, the device must know to dial back for it"
    );
}
