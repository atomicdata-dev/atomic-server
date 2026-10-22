//! Sync per store handle: a handle has its own server session, and a write
//! through it goes out over that session, not another handle's. The server is
//! a recorder standing in for the hub (`SyncSession::set_test_sink`); the
//! transport itself is tested in `atomic_lib`.

use super::ws_sync::CommitSink;
use crate::api::resources::{AtomicStore, AtomicValue, Datatype, PropValue};
use crate::api::simple::tests::shared_drive;
use atomic_lib::{sync::outbox::CommitRefused, urls};
use std::sync::{Arc, Mutex};

/// A hub that takes every commit and remembers the JSON it was sent.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl CommitSink for Recorder {
    async fn post(&self, _request_id: u16, commit_json: &str) -> Result<String, CommitRefused> {
        let mut seen = self.0.lock().unwrap();
        seen.push(commit_json.to_string());
        Ok(format!("did:ad:commit:recorded-{}", seen.len()))
    }
}

impl Recorder {
    fn commits(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    fn signed_by(&self, agent: &str) -> bool {
        let seen = self.commits();
        !seen.is_empty() && seen.iter().all(|json| json.contains(agent))
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "atomic-bridge-session-{name}-{}-{}",
        std::process::id(),
        super::state::now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn open(dir: &std::path::Path) -> AtomicStore {
    AtomicStore::open(dir.to_string_lossy().into_owned(), None, None)
        .await
        .unwrap()
}

fn folder(name: &str, parent: &str) -> Vec<PropValue> {
    let text = |datatype, text: &str| AtomicValue {
        datatype,
        text: text.into(),
        items: vec![],
        props: vec![],
        unsupported_datatype: None,
    };
    vec![
        PropValue {
            property: urls::IS_A.into(),
            value: AtomicValue {
                items: vec![text(Datatype::Link, urls::FOLDER)],
                ..text(Datatype::Array, "")
            },
        },
        PropValue {
            property: urls::NAME.into(),
            value: text(Datatype::String, name),
        },
        PropValue {
            property: urls::PARENT.into(),
            value: text(Datatype::Link, parent),
        },
    ]
}

#[tokio::test]
async fn a_write_goes_out_over_its_own_handles_session() {
    let dir = temp_dir("own");
    let (a, b) = (open(&dir).await, open(&dir).await);
    assert!(a.shares_store_with(&b), "one file, two handles");
    let (sa, sb) = (a.setup("Alice".into()).await.unwrap(), b.setup("Bob".into()).await.unwrap());
    // Nothing connected yet: the write waits in the outbox.
    assert!(!a.is_syncing() && !b.is_syncing());
    let queued = a
        .create_resource_with_values(folder("Offline", &sa.drive))
        .await
        .unwrap();
    assert!(a.node().outbox().has_pending(&queued));
    assert!(!a.push_pending().await, "no session, nothing sent");

    let (hub_a, hub_b) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    a.sync.set_test_sink(hub_a.clone());
    b.sync.set_test_sink(hub_b.clone());
    assert!(a.is_syncing() && b.is_syncing());

    // Opening a session sends what waited (here: the explicit push).
    assert!(a.push_pending().await);
    assert!(!a.node().outbox().has_pending(&queued));
    assert!(hub_a.signed_by(&sa.agent_subject));
    assert!(hub_b.commits().is_empty(), "b's session saw nothing of a's write");

    let before = hub_a.commits().len();
    let by_b = b
        .create_resource_with_values(folder("From Bob", &sb.drive))
        .await
        .unwrap();
    assert!(!b.node().outbox().has_pending(&by_b), "sent without being asked");
    assert!(hub_b.signed_by(&sb.agent_subject));
    assert_eq!(hub_a.commits().len(), before, "a's session saw nothing of b's write");

    // Closing a handle's session stops its writes going out; the other's
    // keeps working.
    b.close_ws_sync().await;
    assert!(!b.is_syncing() && a.is_syncing());
    let held = b
        .create_resource_with_values(folder("Held back", &sb.drive))
        .await
        .unwrap();
    assert!(b.node().outbox().has_pending(&held));
    let sent_by_b = hub_b.commits().len();
    a.create_resource_with_values(folder("More", &sa.drive))
        .await
        .unwrap();
    assert_eq!(hub_b.commits().len(), sent_by_b);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn handles_on_other_files_sync_independently() {
    let (dir_a, dir_b) = (temp_dir("file-a"), temp_dir("file-b"));
    let (a, b) = (open(&dir_a).await, open(&dir_b).await);
    let (sa, sb) = (a.setup("Alice".into()).await.unwrap(), b.setup("Bob".into()).await.unwrap());
    let (hub_a, hub_b) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    a.sync.set_test_sink(hub_a.clone());
    b.sync.set_test_sink(hub_b.clone());
    a.create_resource_with_values(folder("A's", &sa.drive)).await.unwrap();
    b.create_resource_with_values(folder("B's", &sb.drive)).await.unwrap();
    assert!(hub_a.signed_by(&sa.agent_subject));
    assert!(hub_b.signed_by(&sb.agent_subject));
    std::fs::remove_dir_all(dir_a).ok();
    std::fs::remove_dir_all(dir_b).ok();
}

#[tokio::test]
async fn the_free_functions_are_the_default_handle() {
    let drive = shared_drive().await.to_string();
    let default = AtomicStore::global().unwrap();
    // A write by a free function waits in the outbox of the default store
    // while its session is closed, and `close_ws_sync` is safe without one.
    super::ws_sync::close_ws_sync().await;
    assert!(!default.is_syncing());
    let subject = crate::api::resources::create_resource_with_values(folder("Via free fn", &drive))
        .await
        .unwrap();
    assert!(default.node().outbox().has_pending(&subject));
    assert!(!default.push_pending().await);
    assert!(!super::ws_sync::drain_outbox(&default.db).await);
}
