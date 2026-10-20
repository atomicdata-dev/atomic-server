//! Host-side tests: the home data on a temporary store, and the process-level
//! `open_store` guard. Run with `cargo test` in `android-kotlin/rust`.

use crate::{api, home, store, types::*};
use atomic_lib::{host::{create::create_resource_of_class, recents::RecentsIndex, NoPush}, runtime::AtomicNode, urls};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "atomic-kotlin-{name}-{}-{}",
        std::process::id(),
        crate::state::now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A store with an agent and its private drive, like the end of first run.
struct Device {
    db: atomic_lib::Db,
    node: AtomicNode,
    drive: String,
    index: RecentsIndex,
}

impl Device {
    async fn new(name: &str) -> Self {
        let (db, recovery) = store::open_native_store(&temp_dir(name)).await.unwrap();
        assert_eq!(recovery, None);
        let (_agent, drive) = db.setup("Pelican").await.unwrap();
        Device { node: AtomicNode::from_db(db.clone()), db, drive, index: RecentsIndex::new() }
    }

    async fn make(&self, class: &str, name: &str) -> String {
        create_resource_of_class(&self.node, &NoPush, &self.drive, class, name).await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn first_run_gives_one_named_drive() {
    let d = Device::new("drives").await;
    let drives = home::drives(&d.db).await.unwrap();
    assert!(!drives.is_empty());
    let own = drives.iter().find(|r| r.subject == d.drive).expect("the private drive is listed");
    assert_eq!(own.name, "Pelican's Drive");
}

#[tokio::test(flavor = "multi_thread")]
async fn recents_lists_what_was_opened_newest_first() {
    let d = Device::new("recents").await;
    let a = d.make(urls::DOCUMENT_V2, "First doc").await;
    let b = d.make(urls::FOLDER, "Second folder").await;
    let never = d.make(urls::DOCUMENT_V2, "Never opened").await;
    d.index.note_opened(&d.drive, &a, 1_000);
    d.index.note_opened(&d.drive, &b, 2_000);

    let rows = home::recents(&d.db, &d.index, 10).await.unwrap();
    let subjects: Vec<_> = rows.iter().map(|r| r.subject.as_str()).collect();
    assert_eq!(subjects, [b.as_str(), a.as_str()]);
    assert!(!subjects.contains(&never.as_str()));
    assert_eq!(rows[0].title, "Second folder");
    assert_eq!(rows[0].opened_at, 2_000);
    assert_eq!(rows[0].drive, d.drive);
    assert!(!rows[0].class_name.is_empty());
    assert_eq!(home::recents(&d.db, &d.index, 1).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn ai_chats_are_listed_with_their_name() {
    let d = Device::new("chats").await;
    let chat = atomic_lib::host::chats::create_ai_chat(&d.node, &NoPush, "Plan the trip").await.unwrap();
    let rows = home::ai_chats(&d.db, &d.index, 10).await.unwrap();
    let row = rows.iter().find(|r| r.subject == chat).expect("chat listed");
    assert_eq!(row.title, "Plan the trip");
    assert_eq!(row.class_name, "AiChat");
}

#[tokio::test(flavor = "multi_thread")]
async fn favorites_and_messages_start_empty() {
    let d = Device::new("empty").await;
    assert!(home::favorites(&d.db, 10).await.unwrap().is_empty());
    let conversations = atomic_lib::host::conversations::Conversations::new(
        atomic_lib::host::profiles::AgentProfiles::new(std::sync::Arc::new(atomic_lib::host::NoProfiles)),
    );
    assert!(home::messages(&d.db, &conversations, 10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn search_finds_a_document_by_a_word_prefix() {
    let d = Device::new("search").await;
    let doc = d.make(urls::DOCUMENT_V2, "Pelican migration notes").await;
    // Indexing may be deferred; drain it like the app does after a write.
    while atomic_lib::search::index_pending(&d.db, 500).await.unwrap_or(0) > 0 {}

    let hits = home::search(&d.db, "migra", 10).unwrap();
    let hit = hits.iter().find(|h| h.subject == doc).unwrap_or_else(|| panic!("{doc} not in {hits:?}"));
    assert_eq!(hit.title, "Pelican migration notes");
    assert!(home::search(&d.db, "   ", 10).unwrap().is_empty(), "an empty query finds nothing");
}

#[test]
fn rows_without_a_title_use_their_name() {
    let rows = vec![serde_json::json!({"subject": "s", "name": "A chat", "last_activity": 7})];
    let row = home::__row_for_test(rows);
    assert_eq!(row.title, "A chat");
    assert_eq!(row.opened_at, 7);
}

/// Android recreates the activity in the same process and runs start-up again:
/// the second `open_store` must keep the store that is open.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_open_store_keeps_the_store_that_is_open() {
    let first = temp_dir("global");
    api::open_store(first.to_string_lossy().into_owned()).await.unwrap();
    let before = crate::state::db().unwrap().clone();

    let elsewhere = temp_dir("second");
    api::open_store(elsewhere.to_string_lossy().into_owned()).await.unwrap();
    assert!(std::sync::Arc::ptr_eq(&before, crate::state::db().unwrap()));
    assert!(!elsewhere.join("atomic.redb").exists(), "no second store is opened");

    // The public surface works on it: first run, favorites, events.
    assert!(api::active_agent().unwrap().is_none());
    let setup = api::create_agent_and_drive("Heron".into()).await.unwrap();
    assert_eq!(setup.agent.name.as_deref(), Some("Heron"));
    assert_eq!(api::active_agent().unwrap().unwrap().subject, setup.agent.subject);
    let doc = api::create_document(setup.drive_subject.clone(), "Starred".into()).await.unwrap();
    api::add_favorite(doc.clone()).await.unwrap();
    api::add_favorite(doc.clone()).await.unwrap();
    let favs = api::home_list(HomeList::Favorites, 10).await.unwrap();
    assert_eq!(favs.iter().filter(|r| r.subject == doc).count(), 1);
    assert!(!api::list_drives().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_store_is_kept_and_replaced() {
    let dir = temp_dir("damaged");
    std::fs::write(dir.join("atomic.redb"), b"this is not a redb file at all").unwrap();
    let (_db, recovery) = store::open_native_store(&dir).await.unwrap();
    let recovery = recovery.expect("recovery is reported");
    assert!(std::path::Path::new(&recovery.kept_path).exists(), "the damaged file is kept");
}
