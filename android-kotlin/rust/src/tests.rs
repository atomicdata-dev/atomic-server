//! Host-side tests: the home data on a temporary store, and the process-level
//! `open_store` guard. Run with `cargo test` in `android-kotlin/rust`.

use crate::{api, home, store, sync_api, types::*};
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
pub(crate) struct Device {
    pub(crate) db: atomic_lib::Db,
    pub(crate) node: AtomicNode,
    pub(crate) drive: String,
    pub(crate) index: RecentsIndex,
}

impl Device {
    pub(crate) async fn new(name: &str) -> Self {
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

    let hits = home::search(&d.db, "migra", 10, None, &[]).unwrap();
    let hit = hits.iter().find(|h| h.subject == doc).unwrap_or_else(|| panic!("{doc} not in {hits:?}"));
    assert_eq!(hit.title, "Pelican migration notes");
    assert!(home::search(&d.db, "   ", 10, None, &[]).unwrap().is_empty(), "an empty query finds nothing");
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

    // Start-up with a saved session: the same agent comes back, offline is not
    // an error, and a drive this device does not hold means "needs sync".
    let secret = setup.agent.secret.clone();
    let drive = Some(setup.drive_subject.clone());
    let ready = sync_api::resume_session("http://127.0.0.1:1".into(), secret.clone(), drive.clone()).await.unwrap();
    assert_eq!(ready, ResumeStatus::Ready);
    assert_eq!(api::active_agent().unwrap().unwrap().subject, setup.agent.subject);
    let missing = Some("did:ad:not-on-this-device".to_string());
    assert_eq!(
        sync_api::resume_session(String::new(), secret.clone(), missing).await.unwrap(),
        ResumeStatus::NeedsSync
    );
    // Tapping a drive makes it active.
    sync_api::activate_drive(setup.drive_subject.clone()).await.unwrap();
    assert_eq!(api::active_drive().unwrap(), drive);

    // Devices and the own profile.
    assert!(sync_api::known_peers().unwrap().is_empty());
    sync_api::set_device_name("  Pixel  ".into()).unwrap();
    assert_eq!(sync_api::device_name().unwrap(), "Pixel");
    assert_eq!(sync_api::own_profile().await.unwrap().name, "Heron");
    sync_api::set_own_profile("Heron Two".into(), "Likes reeds".into()).await.unwrap();
    let profile = sync_api::own_profile().await.unwrap();
    assert_eq!((profile.name.as_str(), profile.description.as_str()), ("Heron Two", "Likes reeds"));
    assert!(sync_api::set_own_profile("  ".into(), String::new()).await.is_err());
}

/// A local write waits in the outbox until a server takes it, and the real
/// pusher (unlike `NoPush`) offers it to the session, which here is closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_write_stays_queued_when_no_server_is_reachable() {
    let d = Device::new("outbox").await;
    struct Direct(atomic_lib::Db);
    #[async_trait::async_trait]
    impl atomic_lib::host::LocalWritePusher for Direct {
        async fn push(&self, response: &atomic_lib::commit::CommitResponse) {
            crate::sync::peers::push_local_write(response, &self.0).await;
        }
    }
    let doc = create_resource_of_class(&d.node, &Direct(d.db.clone()), &d.drive, urls::DOCUMENT_V2, "Offline note")
        .await
        .unwrap();
    let queued = atomic_lib::sync::outbox::Outbox::new(d.db.clone()).entries().unwrap();
    assert!(!queued.is_empty(), "the write waits for a server");
    assert!(crate::sync::ws::drain_outbox(&d.db).await == false, "no session: nothing is sent");
    assert!(atomic_lib::Storelike::get_resource(&d.db, &doc.as_str().into()).await.is_ok());
}

#[test]
fn reconnect_waits_longer_each_time_up_to_a_minute() {
    use crate::sync::ws::backoff;
    let secs: Vec<u64> = (0..8).map(|n| backoff(n).as_secs()).collect();
    assert_eq!(secs, [2, 4, 8, 16, 32, 60, 60, 60]);
}

#[test]
fn a_server_origin_becomes_its_websocket_url() {
    use crate::sync::ws::server_origin_to_ws_url as ws;
    assert_eq!(ws("https://a.example/").unwrap(), "wss://a.example/ws");
    assert_eq!(ws("http://10.0.0.2:9883").unwrap(), "ws://10.0.0.2:9883/ws");
    assert_eq!(ws("wss://a.example/ws").unwrap(), "wss://a.example/ws");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_store_is_kept_and_replaced() {
    let dir = temp_dir("damaged");
    std::fs::write(dir.join("atomic.redb"), b"this is not a redb file at all").unwrap();
    let (_db, recovery) = store::open_native_store(&dir).await.unwrap();
    let recovery = recovery.expect("recovery is reported");
    assert!(std::path::Path::new(&recovery.kept_path).exists(), "the damaged file is kept");
}

// ── The embedded renderer's channel ────────────────────────────────────────

mod embed_channel {
    use super::*;
    use crate::embed::{changed_subjects, EchoFilter, Embed};
    use atomic_lib::{
        host::{embed::EmbedHost, profiles::AgentProfiles, NoProfiles},
        DbEvent, Storelike, Subject,
    };
    use serde_json::{json, Value as Json};
    use std::sync::Arc;

    fn embed_of(d: &Device) -> Embed {
        Embed::new(EmbedHost::new(
            d.node.clone(),
            Arc::new(NoPush),
            AgentProfiles::new(Arc::new(NoProfiles)),
        ))
    }

    async fn ask(embed: &Embed, method: &str, args: Json) -> Json {
        serde_json::from_str(&embed.call(method, &args.to_string()).await.unwrap()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_page_reads_a_resource_from_the_store() {
        let d = Device::new("embed-read").await;
        let embed = embed_of(&d);
        let doc = d.make(urls::DOCUMENT_V2, "Read by the page").await;
        let rows = ask(&embed, "getResourcesWithSnapshots", json!([[doc, "did:ad:not-here"]])).await;
        assert!(rows[0]["jsonAd"].as_str().unwrap().contains("Read by the page"));
        assert!(!rows[0]["snapshot"].as_str().unwrap().is_empty());
        assert!(rows[1]["jsonAd"].is_null());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_page_cannot_get_arbitrary_bytes_signed() {
        let d = Device::new("embed-sign").await;
        let embed = embed_of(&d);
        for payload in ["hello", r#"{"not":"a commit"}"#] {
            let err = embed.call("sign", &json!([payload]).to_string()).await.unwrap_err();
            assert!(err.contains("commit"), "{err}");
        }
        let err = embed.call("nonsense", "[]").await.unwrap_err();
        assert!(err.contains("not available"), "{err}");
        let err = embed.call("getResource", "not json").await.unwrap_err();
        assert!(!err.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_commit_the_page_applied_is_not_echoed_back_to_it() {
        use atomic_lib::loro::AtomicLoroDoc;
        let d = Device::new("embed-echo").await;
        let embed = embed_of(&d);
        let doc = d.make(urls::DOCUMENT_V2, "Typed doc").await;
        let subject = Subject::from_raw(&doc, d.db.get_base_domain().as_deref());

        let opened = ask(&embed, "getResourcesWithSnapshots", json!([[doc]])).await;
        let snapshot = atomic_lib::agents::decode_base64(opened[0]["snapshot"].as_str().unwrap()).unwrap();
        let page_doc = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();
        page_doc.set_peer_id(0x5eed).unwrap();
        let before = page_doc.oplog_vv();
        page_doc.doc().get_text("documentContent").insert(0, "Typed on the phone").unwrap();
        page_doc.commit_with_message("e-typing");
        let update = page_doc.export_updates_since(&before);
        let std_b64 = {
            let s = atomic_lib::agents::encode_base64(&update).replace('-', "+").replace('_', "/");
            format!("{s}{}", "=".repeat((4 - s.len() % 4) % 4))
        };
        let previous = d.db.get_resource(&subject).await.unwrap()
            .get(urls::LAST_COMMIT).map(|v| v.to_string())
            .unwrap_or_else(|_| "did:ad:commit:earlier".into());
        let mut commit = json!({
            urls::IS_A: [urls::COMMIT],
            urls::SUBJECT: doc,
            urls::SIGNER: ask(&embed, "agent", json!([])).await,
            urls::CREATED_AT: atomic_lib::utils::now(),
            urls::PREVIOUS_COMMIT: previous,
            urls::LORO_UPDATE: std_b64,
        });
        commit[urls::SIGNATURE] = ask(&embed, "sign", json!([commit.to_string()])).await;

        assert!(!embed.echo.is_echo(&doc));
        assert_eq!(ask(&embed, "applyCommit", json!([commit.to_string()])).await, Json::Null);
        assert!(embed.echo.is_echo(&doc), "the page's own write is remembered");
        // Under the other spelling of the same resource too.
        assert!(embed.echo.is_echo(&doc.replacen("did:ad:", "atomic:", 1)));

        let reopened = ask(&embed, "getResourcesWithSnapshots", json!([[doc]])).await;
        let snap = atomic_lib::agents::decode_base64(reopened[0]["snapshot"].as_str().unwrap()).unwrap();
        let text = AtomicLoroDoc::from_snapshot(&snap).unwrap().extract_document_plain_text();
        assert!(text.contains("Typed on the phone"), "{text:?}");
    }

    fn changed(subject: &str) -> DbEvent {
        DbEvent::Changed {
            subject: Subject::from(subject),
            delta: None,
            source_id: None,
            is_new: false,
            from_commit: true,
        }
    }

    #[test]
    fn a_burst_of_events_is_one_deduplicated_list_without_the_pages_own_writes() {
        let echo = EchoFilter::default();
        echo.wrote("did:ad:mine");
        let events = [
            changed("did:ad:a"),
            changed("did:ad:a"),
            changed("did:ad:mine"),
            changed("did:ad:b"),
            DbEvent::QueryMembershipChanged { query_id: vec![], subject: "q".into(), added: true, source_id: None },
        ];
        assert_eq!(changed_subjects(&events, &echo), ["did:ad:a", "did:ad:b"]);
    }
}

/// The bug found on the phone: after a restart the store had no agent, the app
/// ran first-run again and made a new one. The agent is in memory only; the
/// secret the app keeps brings the same agent and drive back.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_open_of_the_same_store_keeps_the_same_agent_and_drive() {
    let dir = temp_dir("reopen");
    let (secret, subject, drive) = {
        let (db, _) = store::open_native_store(&dir).await.unwrap();
        let (agent, drive) = db.setup("Pelican").await.unwrap();
        db.flush().unwrap();
        (agent.build_secret().unwrap(), agent.subject.to_string(), drive)
    };

    let (db, recovery) = store::open_native_store(&dir).await.unwrap();
    assert_eq!(recovery, None);
    // What the phone showed: nothing in the store says who this device is...
    assert!(atomic_lib::Storelike::get_default_agent(&db).is_err());
    // ...but the drive it was working on is remembered.
    assert_eq!(db.get_active_drive().as_deref(), Some(drive.as_str()));

    // Resuming with the kept secret and drive gives the same agent and drive.
    let here = crate::session::resume(&db, &secret, Some(&drive)).await.unwrap();
    assert!(here, "the drive is in the store");
    let agent = atomic_lib::Storelike::get_default_agent(&db).unwrap();
    assert_eq!(agent.subject.to_string(), subject);
    assert_eq!(db.get_active_drive().as_deref(), Some(drive.as_str()));
    let drives = home::drives(&db).await.unwrap();
    assert!(drives.iter().any(|d| d.subject == drive && d.name == "Pelican's Drive"));
}

#[tokio::test(flavor = "multi_thread")]
async fn resuming_without_a_drive_hint_uses_the_private_drive() {
    let dir = temp_dir("resume-home");
    let (db, _) = store::open_native_store(&dir).await.unwrap();
    let (agent, drive) = db.setup("Pelican").await.unwrap();
    db.set_active_drive("did:ad:something-else").unwrap();
    assert!(crate::session::resume(&db, &agent.build_secret().unwrap(), None).await.unwrap());
    assert_eq!(db.get_active_drive().as_deref(), Some(drive.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn ai_chats_come_in_pages_by_offset() {
    let d = Device::new("chat-pages").await;
    for i in 0..5 {
        atomic_lib::host::chats::create_ai_chat(&d.node, &NoPush, &format!("Chat {i}")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    }
    let first = home::ai_chats_page(&d.db, &d.index, 0, 3).await.unwrap();
    let rest = home::ai_chats_page(&d.db, &d.index, 3, 3).await.unwrap();
    assert_eq!(first.len(), 3);
    assert_eq!(rest.len(), 2, "a short page is the last");
    assert!(first.iter().all(|a| rest.iter().all(|b| a.subject != b.subject)));
}

#[tokio::test(flavor = "multi_thread")]
async fn search_filters_by_class_before_the_limit() {
    let d = Device::new("search-class").await;
    let chat = atomic_lib::host::chats::create_ai_chat(&d.node, &NoPush, "Pelican chat").await.unwrap();
    for i in 0..3 {
        d.make(urls::DOCUMENT_V2, &format!("Pelican doc {i}")).await;
    }
    while atomic_lib::search::index_pending(&d.db, 500).await.unwrap_or(0) > 0 {}
    let chats = home::search(&d.db, "pelican", 1, None, &["aichat".to_string()]).unwrap();
    assert_eq!(chats.iter().map(|h| h.subject.as_str()).collect::<Vec<_>>(), [chat.as_str()]);
    let in_drive = home::search(&d.db, "pelican doc", 10, Some(&d.drive), &[]).unwrap();
    assert!(in_drive.len() >= 3);
    assert!(home::search(&d.db, "pelican", 5, None, &["nonsense".to_string()]).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn drives_are_listed_the_active_one_first_then_by_use() {
    let d = Device::new("drive-order").await;
    let other = d.db.create_drive("Zed").await.unwrap();
    d.db.set_active_drive(&other).unwrap();
    let rows = home::drives(&d.db).await.unwrap();
    assert_eq!(rows[0].subject, other, "the active drive leads");
}
