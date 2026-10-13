//! Exercise the shared HTTP/WS acknowledgement boundary without the periodic
//! flush thread: a successful commit must be durable even between flush ticks.
use atomic_lib::{Db, Storelike};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const CHILD_DIR: &str = "ATOMIC_COMMIT_DURABILITY_DIR";
const UPDATED_NAME: &str = "Acknowledged edit survives a crash";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn open(dir: &Path) -> Db {
    atomic_lib::test_utils::init_redb_file_without_periodic_flush(dir)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "subprocess entry point"]
async fn child_acknowledges_then_exits_uncleanly() {
    let dir = std::path::PathBuf::from(std::env::var(CHILD_DIR).unwrap());
    let store = open(&dir).await;
    store.set_base_url("http://localhost");
    let (agent, drive) = store.setup("Durability test").await.unwrap();
    // The drive is an existing editable resource with a persisted causal history.
    store.flush().unwrap();
    let mut resource = store.get_resource(&drive.clone().into()).await.unwrap();
    resource.set_name(UPDATED_NAME).unwrap();
    let snapshot = resource.build_state_doc().unwrap().export_snapshot();
    let mut builder = resource.get_commit_builder().clone();
    builder.set_loro_update(snapshot);
    let commit = builder.sign(&agent, &store, &resource).await.unwrap();
    let json = atomic_lib::client::commit_to_wire_json(&commit, &store)
        .await
        .unwrap();
    let response = super::apply_commit_json(&store, "http://localhost", &json, None)
        .await
        .unwrap();
    assert!(!response.is_empty());
    // An independent ledger is written only after the acknowledgement boundary.
    std::fs::write(dir.join("acknowledged-subject"), &drive).unwrap();
    // No Db::drop, runtime cleanup or periodic flush may rescue this write.
    std::mem::forget(store);
    std::process::exit(73);
}

#[tokio::test]
async fn acknowledged_commit_survives_unclean_exit() {
    check_acknowledged_survives(
        "handlers::commit::durability_tests::child_acknowledges_then_exits_uncleanly",
    )
    .await;
}

#[tokio::test]
async fn acknowledged_sync_survives_unclean_exit() {
    check_acknowledged_survives(
        "handlers::commit::durability_tests::child_acknowledges_sync_then_exits_uncleanly",
    )
    .await;
}

async fn check_acknowledged_survives(child_test: &str) {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("child.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([child_test, "--exact", "--ignored", "--nocapture"])
            .env(CHILD_DIR, dir.path())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "child timed out: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(
        status.code(),
        Some(73),
        "child failed before acknowledgement: {}",
        std::fs::read_to_string(&log_path).unwrap()
    );
    let subject = std::fs::read_to_string(dir.path().join("acknowledged-subject")).unwrap();
    let store = open(dir.path()).await;
    let resource = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        resource.get(atomic_lib::urls::NAME).unwrap().to_string(),
        UPDATED_NAME
    );
}

/// Inject an fsync failure without changing the real redb write path.
struct FlushGate {
    inner: std::sync::Arc<dyn atomic_lib::db::kv_store::KvStore>,
    fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl atomic_lib::db::kv_store::KvStore for FlushGate {
    fn get(
        &self,
        tree: atomic_lib::db::trees::Tree,
        key: &[u8],
    ) -> atomic_lib::errors::AtomicResult<Option<Vec<u8>>> {
        self.inner.get(tree, key)
    }
    fn insert(
        &self,
        tree: atomic_lib::db::trees::Tree,
        key: &[u8],
        val: &[u8],
    ) -> atomic_lib::errors::AtomicResult<()> {
        self.inner.insert(tree, key, val)
    }
    fn remove(
        &self,
        tree: atomic_lib::db::trees::Tree,
        key: &[u8],
    ) -> atomic_lib::errors::AtomicResult<()> {
        self.inner.remove(tree, key)
    }
    fn contains_key(
        &self,
        tree: atomic_lib::db::trees::Tree,
        key: &[u8],
    ) -> atomic_lib::errors::AtomicResult<bool> {
        self.inner.contains_key(tree, key)
    }
    fn scan_prefix(
        &self,
        tree: atomic_lib::db::trees::Tree,
        prefix: &[u8],
    ) -> atomic_lib::db::kv_store::KvIter {
        self.inner.scan_prefix(tree, prefix)
    }
    fn range(
        &self,
        tree: atomic_lib::db::trees::Tree,
        start: Vec<u8>,
        end: Vec<u8>,
        reverse: bool,
    ) -> atomic_lib::db::kv_store::KvIter {
        self.inner.range(tree, start, end, reverse)
    }
    fn iter_tree(&self, tree: atomic_lib::db::trees::Tree) -> atomic_lib::db::kv_store::KvIter {
        self.inner.iter_tree(tree)
    }
    fn clear_tree(
        &self,
        tree: atomic_lib::db::trees::Tree,
    ) -> atomic_lib::errors::AtomicResult<()> {
        self.inner.clear_tree(tree)
    }
    fn apply_batch(
        &self,
        operations: &[atomic_lib::db::trees::Operation],
    ) -> atomic_lib::errors::AtomicResult<()> {
        self.inner.apply_batch(operations)
    }
    fn flush(&self) -> atomic_lib::errors::AtomicResult<()> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("injected disk flush failure".into());
        }
        self.inner.flush()
    }
    fn begin_batch(&self) {
        self.inner.begin_batch();
    }
    fn commit_batch(&self) -> atomic_lib::errors::AtomicResult<()> {
        self.inner.commit_batch()
    }
    fn len(&self, tree: atomic_lib::db::trees::Tree) -> atomic_lib::errors::AtomicResult<usize> {
        self.inner.len(tree)
    }
}

#[tokio::test]
async fn failed_flush_is_not_acknowledged_and_exact_retry_recovers() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(dir.path()).await;
    store.set_base_url("http://localhost");
    let (agent, drive) = store.setup("Flush failure test").await.unwrap();
    store.flush().unwrap();
    let mut resource = store.get_resource(&drive.clone().into()).await.unwrap();
    resource.set_name(UPDATED_NAME).unwrap();
    let mut builder = resource.get_commit_builder().clone();
    builder.set_loro_update(resource.build_state_doc().unwrap().export_snapshot());
    let commit = builder.sign(&agent, &store, &resource).await.unwrap();
    let json = atomic_lib::client::commit_to_wire_json(&commit, &store)
        .await
        .unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    store.kv = Arc::new(FlushGate {
        inner: store.kv.clone(),
        fail: fail.clone(),
    });
    let error = super::apply_commit_json(&store, "http://localhost", &json, None)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("injected disk flush failure"),
        "{error}"
    );
    fail.store(false, Ordering::SeqCst);
    super::apply_commit_json(&store, "http://localhost", &json, None)
        .await
        .unwrap();
    let saved = store.get_resource(&drive.clone().into()).await.unwrap();
    let versions = atomic_lib::history::versions(&saved).unwrap().len();
    // Simulate losing the successful acknowledgement, then delivering the
    // same signed commit again. Retry must be idempotent and still durable.
    super::apply_commit_json(&store, "http://localhost", &json, None)
        .await
        .unwrap();
    let saved = store.get_resource(&drive.into()).await.unwrap();
    assert_eq!(
        saved.get(atomic_lib::urls::NAME).unwrap().to_string(),
        UPDATED_NAME
    );
    assert_eq!(
        atomic_lib::history::versions(&saved).unwrap().len(),
        versions
    );
}

/// Same shared engine entry point used by the WebSocket handler, with no
/// periodic flush task that could hide an early acknowledgement.
#[tokio::test]
#[ignore = "subprocess entry point"]
async fn child_acknowledges_sync_then_exits_uncleanly() {
    use atomic_lib::{
        db::trees::Tree,
        loro::AtomicLoroDoc,
        sync::{engine, protocol},
    };
    let dir = std::path::PathBuf::from(std::env::var(CHILD_DIR).unwrap());
    let store = open(&dir).await;
    let (agent, drive) = store.setup("Sync crash test").await.unwrap();
    store.flush().unwrap();
    let key = atomic_lib::Subject::from_raw(&drive, None).pure_id();
    let bytes = store
        .kv
        .get(Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    let doc = AtomicLoroDoc::from_snapshot(&bytes).unwrap();
    doc.set_property(
        atomic_lib::urls::NAME,
        &atomic_lib::Value::String(UPDATED_NAME.into()),
    )
    .unwrap();
    let snapshot = doc.export_snapshot();
    let frame = protocol::encode_sync_push(&drive, &[(&drive, &snapshot)], true);
    let mut as_agent = atomic_lib::agents::ForAgent::from(agent);
    let result = engine::handle_frame_full(&frame, &store, &mut as_agent).await;
    assert!(result.frames.contains(&protocol::encode_sync_ok(&drive)));
    // The verification response must also cover what was sent.
    let result =
        engine::handle_frame_full(&protocol::encode_get(1, &drive), &store, &mut as_agent).await;
    let update = protocol::decode_update(&result.frames[0][1..]).unwrap();
    let remote = AtomicLoroDoc::vv_map_from_snapshot(&update.loro_bytes).unwrap();
    let sent = AtomicLoroDoc::vv_map_from_snapshot(&snapshot).unwrap();
    assert!(sent
        .iter()
        .all(|(peer, count)| remote.get(peer).copied().unwrap_or(0) >= *count));
    std::fs::write(dir.join("acknowledged-subject"), drive).unwrap();
    std::mem::forget(store);
    std::process::exit(73);
}

#[tokio::test]
async fn failed_sync_flush_blocks_push_and_matching_probe_acknowledgements() {
    use atomic_lib::{
        db::trees::Tree,
        loro::AtomicLoroDoc,
        sync::{engine, protocol},
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut store = open(dir.path()).await;
    let (agent, drive) = store.setup("Sync flush failure").await.unwrap();
    store.flush().unwrap();
    let key = atomic_lib::Subject::from_raw(&drive, None).pure_id();
    let bytes = store
        .kv
        .get(Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    let doc = AtomicLoroDoc::from_snapshot(&bytes).unwrap();
    doc.set_property(
        atomic_lib::urls::NAME,
        &atomic_lib::Value::String(UPDATED_NAME.into()),
    )
    .unwrap();
    let snapshot = doc.export_snapshot();
    let push = protocol::encode_sync_push(&drive, &[(&drive, &snapshot)], true);
    let fail = Arc::new(AtomicBool::new(true));
    store.kv = Arc::new(FlushGate {
        inner: store.kv.clone(),
        fail: fail.clone(),
    });
    let mut as_agent = atomic_lib::agents::ForAgent::from(agent);
    let replies = engine::handle_frame_full(&push, &store, &mut as_agent)
        .await
        .frames;
    assert!(!replies.contains(&protocol::encode_sync_ok(&drive)));
    assert_eq!(replies[0][0], protocol::tag::ERROR);
    // An import can be readable despite flush failure. A subsequent matching
    // hash must not turn that volatile state into an apparent durable success.
    let hash = engine::drive_sync_hash_for(&store, &drive, &as_agent)
        .await
        .unwrap();
    for probe in [
        protocol::encode_sync_probe(&drive, &hash),
        protocol::encode_sync(&drive, &hash, &[], &Default::default()),
    ] {
        let replies = engine::handle_frame_full(&probe, &store, &mut as_agent)
            .await
            .frames;
        assert_eq!(replies[0][0], protocol::tag::ERROR);
    }
    fail.store(false, Ordering::SeqCst);
    for _ in 0..2 {
        let replies = engine::handle_frame_full(&push, &store, &mut as_agent)
            .await
            .frames;
        assert!(replies.contains(&protocol::encode_sync_ok(&drive)));
    }
    let bytes = store
        .kv
        .get(Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        AtomicLoroDoc::vv_map_from_snapshot(&bytes).unwrap(),
        AtomicLoroDoc::vv_map_from_snapshot(&snapshot).unwrap()
    );
}

#[path = "seeded_sync_tests.rs"]
mod seeded_sync_tests;
