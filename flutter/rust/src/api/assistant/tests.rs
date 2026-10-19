//! Tests for the assistant reads, against the real store the other bridge
//! tests share (`simple::tests::shared_drive`): chats and pages are created
//! through the library's own commit path, nothing is mocked.

use super::*;
use crate::api::simple::tests::shared_drive;
use crate::recents;
use atomic_lib::{
    chat_log::Entry,
    commit::{CommitBuilder, CommitOpts},
    loro::AtomicLoroDoc,
    Commit, Value,
};

async fn new_chat(name: &str) -> String {
    let drive = shared_drive().await;
    db().unwrap()
        .create_resource(AI_CHAT, drive, name, None)
        .await
        .unwrap()
}

/// A `ChatLog` page under `chat`, signed by the active agent like the web app's.
async fn add_page(chat: &str, entries: &[(&str, Entry)]) {
    let store = db().unwrap();
    let agent = store.get_default_agent().unwrap();
    let doc = AtomicLoroDoc::new();
    for (key, entry) in entries {
        doc.put_entry(key, entry).unwrap();
    }
    let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
    let parent = Value::AtomicUrl(chat.into());
    doc.set_property(urls::IS_A, &is_a).unwrap();
    doc.set_property(urls::PARENT, &parent).unwrap();
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = Commit::create_did(builder, &agent, store.as_ref())
        .await
        .unwrap();
    let opts = CommitOpts {
        validate_signature: true,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    store.apply_commit(commit, &opts).await.unwrap();
}

fn ai_entry(role: &str, text: &str, c: i64) -> Entry {
    let author = db()
        .unwrap()
        .get_default_agent()
        .unwrap()
        .subject
        .to_string();
    let mut entry = Entry::new(author, "", c);
    entry.extra.insert("role".into(), role.into());
    let parts = json!([{ "type": "text", "text": text }]).to_string();
    entry.extra.insert("parts".into(), parts.as_str().into());
    entry
}

#[tokio::test]
async fn assistant_reads_chat_entries_oldest_first_across_pages() {
    let chat = new_chat("Entries").await;
    add_page(
        &chat,
        &[
            ("2-00000002", ai_entry("assistant", "second", 2_000)),
            ("1-00000001", ai_entry("user", "first", 1_000)),
        ],
    )
    .await;
    add_page(&chat, &[("3-00000003", ai_entry("user", "third", 3_000))]).await;

    let entries: Vec<Json> = serde_json::from_str(&read_chat(chat).await.unwrap()).unwrap();
    let texts: Vec<&str> = entries
        .iter()
        .map(|e| e["parts"][0]["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, ["first", "second", "third"]);
    assert_eq!(entries[0]["role"], "user");
    assert_eq!(entries[1]["role"], "assistant");
    assert_eq!(entries[0]["c"], 1_000);
    assert!(entries[0]["id"].as_str().unwrap().ends_with("#1-00000001"));
}

#[tokio::test]
async fn assistant_lists_chats_by_last_activity() {
    shared_drive().await;
    let mut rx = db().unwrap().subscribe_events();
    let old = new_chat("Assistant old chat").await;
    let new = new_chat("Assistant new chat").await;
    let empty = new_chat("Assistant empty chat").await;
    add_page(&old, &[("1-00000001", ai_entry("user", "hi", 1_000))]).await;
    add_page(&new, &[("1-00000001", ai_entry("user", "hi", 9_000))]).await;

    pump(&mut rx).await;
    let list: Vec<Json> = serde_json::from_str(&list_ai_chats(50).await.unwrap()).unwrap();
    let position = |subject: &str| list.iter().position(|c| c["subject"] == subject).unwrap();
    assert!(position(&new) < position(&old));
    assert!(position(&old) < position(&empty));
    assert_eq!(list[position(&new)]["name"], "Assistant new chat");
    assert_eq!(list[position(&new)]["last_activity"], 9_000);
    assert_eq!(list[position(&empty)]["last_activity"], 0);
}

#[tokio::test]
async fn assistant_list_leaves_out_other_classes() {
    let drive = shared_drive().await;
    let folder = db()
        .unwrap()
        .create_resource(urls::FOLDER, drive, "Not a chat", None)
        .await
        .unwrap();
    let list = list_ai_chats(50).await.unwrap();
    assert!(!list.contains(&folder));
}

#[tokio::test]
async fn assistant_search_is_scoped_to_the_given_drive() {
    let chat = new_chat("Quokka scoping chat").await;
    let other = "https://example.test/not-this-drive".to_string();
    let hits = search(Some(other), "quokka".into(), 5).await.unwrap();
    assert!(!hits.contains(&chat));
    let drive = shared_drive().await.to_string();
    let hits = search(Some(drive), "quokka".into(), 5).await.unwrap();
    assert!(hits.contains(&chat));
}

#[tokio::test]
async fn assistant_lists_the_chats_of_every_drive() {
    let drive = shared_drive().await.to_string();
    let mut rx = db().unwrap().subscribe_events();
    let second = crate::api::simple::create_drive("Second drive".into())
        .await
        .unwrap();
    assert_ne!(second, drive);
    // Creating a drive makes it the active one; the other tests expect theirs.
    db().unwrap().set_active_drive(&drive).unwrap();
    let there = db()
        .unwrap()
        .create_resource(AI_CHAT, &second, "Chat in the second drive", None)
        .await
        .unwrap();
    let here = new_chat("Chat in the first drive").await;
    pump(&mut rx).await;
    let list = list_ai_chats(500).await.unwrap();
    assert!(list.contains(&there) && list.contains(&here));
}

#[tokio::test]
async fn assistant_search_finds_a_prefix_with_title_and_class() {
    let chat = new_chat("Zebrafinch migration notes").await;
    let drive = shared_drive().await.to_string();
    let hits: Vec<Json> = serde_json::from_str(
        &search(Some(drive.clone()), "zebraf".into(), 5)
            .await
            .unwrap(),
    )
    .unwrap();
    let hit = hits
        .iter()
        .find(|h| h["subject"] == chat.as_str())
        .unwrap_or_else(|| panic!("chat not found in {hits:?}"));
    assert_eq!(hit["title"], "Zebrafinch migration notes");
    assert!(hit["score"].as_f64().unwrap() > 0.0);
    assert!(hit["class_name"].as_str().is_some_and(|c| !c.is_empty()));

    let none = search(Some(drive), "qqqxxnothing".into(), 5).await.unwrap();
    assert_eq!(none, "[]");
}

#[tokio::test]
async fn assistant_web_url_names_the_connected_server() {
    let _ = shared_drive().await;
    assert!(resource_web_url("did:ad:abc".into()).is_err());
    crate::api::simple::state::set_server_origin("https://example.test/");
    assert_eq!(
        resource_web_url("did:ad:abc?drive=did:ad:x y".into()).unwrap(),
        "https://example.test/app/show?subject=did%3Aad%3Aabc%3Fdrive%3Ddid%3Aad%3Ax%20y"
    );
}

/// Feed the store's pending change events to the recents index, as the
/// listener does in the app.
async fn pump(rx: &mut tokio::sync::broadcast::Receiver<atomic_lib::db::DbEvent>) {
    let store = db().unwrap();
    // The channel holds 64 events and tests run side by side: a receiver that
    // fell behind skips what it missed instead of stopping.
    loop {
        match rx.try_recv() {
            Ok(event) => recents::handle_event(store, event).await,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
}

#[tokio::test]
async fn recents_follow_the_commits_without_rescanning() {
    shared_drive().await;
    // From here on only events can tell the index about new chats.
    recents::ensure_scanned().await.unwrap();
    let mut rx = db().unwrap().subscribe_events();

    let first = new_chat("Recents first").await;
    let second = new_chat("Recents second").await;
    add_page(&first, &[("1-00000001", ai_entry("user", "hi", 5_000_000))]).await;
    add_page(
        &second,
        &[("1-00000001", ai_entry("user", "hi", 4_000_000))],
    )
    .await;
    add_page(
        &second,
        &[("2-00000002", ai_entry("user", "again", 6_000_000))],
    )
    .await;
    pump(&mut rx).await;

    // Other tests add chats at the same time: look at these two among all.
    let chats = recents::recent_chats(500).await.unwrap();
    let at = |chat: &str| chats.iter().position(|(subject, _, _)| subject == chat);
    let (second_at, first_at) = (at(&second).unwrap(), at(&first).unwrap());
    assert!(second_at < first_at);
    assert_eq!(
        chats[second_at],
        (second.clone(), "Recents second".to_string(), 6_000_000)
    );
    assert_eq!(
        chats[first_at],
        (first.clone(), "Recents first".to_string(), 5_000_000)
    );
    let one = recents::recent_chats(1).await.unwrap();
    assert_eq!(one.len(), 1);
}

#[tokio::test]
async fn recents_drop_destroyed_chats() {
    shared_drive().await;
    recents::ensure_scanned().await.unwrap();
    let mut rx = db().unwrap().subscribe_events();
    let chat = new_chat("Recents doomed").await;
    pump(&mut rx).await;
    assert!(list_ai_chats(500).await.unwrap().contains(&chat));

    db().unwrap()
        .remove_resource(&chat.as_str().into())
        .await
        .unwrap();
    pump(&mut rx).await;
    assert!(!list_ai_chats(500).await.unwrap().contains(&chat));
}

#[tokio::test]
async fn opened_resources_are_listed_newest_first_and_stay_local() {
    let drive = shared_drive().await.to_string();
    let store = db().unwrap();
    let a = new_chat("Opened a").await;
    let b = new_chat("Opened b").await;
    let before = store.get_resource(&a.as_str().into()).await.unwrap();
    recents::note_opened(&drive, &a, 1_000);
    recents::note_opened(&drive, &b, 2_000);
    recents::note_opened(&drive, &a, 3_000);
    recents::note_opened(&drive, "https://example.test/gone", 4_000);

    let list: Vec<Json> =
        serde_json::from_str(&list_recent_resources(drive.clone(), 10).await.unwrap()).unwrap();
    let subjects: Vec<&str> = list
        .iter()
        .map(|r| r["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects[..2], [a.as_str(), b.as_str()]);
    assert!(!subjects.contains(&"https://example.test/gone"));
    assert_eq!(list[0]["title"], "Opened a");
    assert_eq!(list[0]["opened_at"], 3_000);

    // Opening is not an edit: the resource itself did not change.
    let after = store.get_resource(&a.as_str().into()).await.unwrap();
    assert_eq!(
        before.get(urls::LAST_COMMIT).map(|v| v.to_string()).ok(),
        after.get(urls::LAST_COMMIT).map(|v| v.to_string()).ok()
    );

    let limited: Vec<Json> =
        serde_json::from_str(&list_recent_resources(drive, 1).await.unwrap()).unwrap();
    assert_eq!(limited.len(), 1);
}

#[tokio::test]
async fn a_chat_started_here_takes_messages_in_order_on_one_page() {
    shared_drive().await;
    let mut rx = db().unwrap().subscribe_events();
    let chat = create_ai_chat("Phone chat".into()).await.unwrap();
    let user = append_chat_entry(
        chat.clone(),
        "user".into(),
        json!([{ "type": "text", "text": "Hallo" }]).to_string(),
    )
    .await
    .unwrap();
    let assistant = append_chat_entry(
        chat.clone(),
        "assistant".into(),
        json!([{ "type": "text", "text": "Hoi!" }]).to_string(),
    )
    .await
    .unwrap();
    // Both entries sit on the same page, the second after the first.
    assert_eq!(user.split('#').next(), assistant.split('#').next());

    let entries: Vec<Json> = serde_json::from_str(&read_chat(chat.clone()).await.unwrap()).unwrap();
    let texts: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| {
            (
                e["role"].as_str().unwrap(),
                e["parts"][0]["text"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(texts, [("user", "Hallo"), ("assistant", "Hoi!")]);

    // It is in the private drive, and shows up in the recents.
    pump(&mut rx).await;
    let list = list_ai_chats(500).await.unwrap();
    assert!(list.contains(&chat));
    assert!(list.contains("Phone chat"));
}

/// Put `subjects` in a list property of the private drive, as the web app does.
async fn set_home_list(property: &str, subjects: &[&str]) {
    let store = db().unwrap();
    let home = store.ensure_private_drive().await.unwrap();
    let mut drive = store
        .get_resource(&Subject::from(home.as_str()))
        .await
        .unwrap();
    let list = Value::ResourceArray(subjects.iter().map(|s| (*s).into()).collect());
    drive.set_unsafe(property.into(), list).unwrap();
    let response = super::super::simple::state::node()
        .unwrap()
        .save_locally(&mut drive)
        .await
        .unwrap();
    super::super::simple::push_local_write(&response, store.as_ref()).await;
}

#[tokio::test]
async fn favorites_come_from_the_private_drive_newest_first() {
    let a = new_chat("Fav a").await;
    let b = new_chat("Fav b").await;
    set_home_list(FAVORITES, &[&a, "https://example.test/gone", &b]).await;

    let list: Vec<Json> = serde_json::from_str(&list_favorites(10).await.unwrap()).unwrap();
    let titles: Vec<&str> = list.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert_eq!(titles, ["Fav b", "Fav a"]);
    assert_eq!(list[0]["subject"], b.as_str());

    let limited: Vec<Json> = serde_json::from_str(&list_favorites(1).await.unwrap()).unwrap();
    assert_eq!(limited.len(), 1);
}

#[tokio::test]
async fn conversations_are_titled_by_the_other_members() {
    shared_drive().await;
    let store = db().unwrap();
    let me = store.get_default_agent().unwrap().subject.to_string();
    let convo = new_chat("Ignored name").await;
    let mut resource = store
        .get_resource(&Subject::from(convo.as_str()))
        .await
        .unwrap();
    let members = Value::ResourceArray(vec![
        me.as_str().into(),
        "https://example.test/agent".into(),
    ]);
    resource.set_unsafe(urls::READ.into(), members).unwrap();
    super::super::simple::state::node()
        .unwrap()
        .save_locally(&mut resource)
        .await
        .unwrap();
    let alone = new_chat("Alone").await;
    set_home_list(urls::CONVERSATIONS, &[&convo, &alone]).await;

    let list: Vec<Json> = serde_json::from_str(&list_conversations(10).await.unwrap()).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["subject"], convo.as_str());
    assert_eq!(list[0]["title"], UNKNOWN_MEMBER);
    assert_eq!(list[1]["title"], "Only you");
}

#[tokio::test]
async fn activity_follows_creates_and_deletes_and_skips_chats() {
    let drive = shared_drive().await.to_string();
    let store = db().unwrap();
    let mut rx = store.subscribe_events();

    let folder = store
        .create_resource(urls::FOLDER, &drive, "Activity folder", None)
        .await
        .unwrap();
    let chat = new_chat("Activity chat").await;
    pump(&mut rx).await;

    let list = list_activity(500).await.unwrap();
    let entry = list.iter().find(|a| a.subject == folder).unwrap();
    assert_eq!(entry.kind, "created");
    assert_eq!(entry.name, "Activity folder");
    assert!(entry.at > 0);
    assert!(list.iter().all(|a| a.subject != chat));
    // The signer comes from the stored commit.
    let raw = recents::activity(500)
        .into_iter()
        .find(|a| a.subject == folder)
        .unwrap();
    assert!(raw.actor.is_some());

    store
        .remove_resource(&folder.as_str().into())
        .await
        .unwrap();
    pump(&mut rx).await;
    let list = list_activity(500).await.unwrap();
    let entry = list.iter().find(|a| a.subject == folder).unwrap();
    assert_eq!(entry.kind, "deleted");
    assert_eq!(entry.name, "Activity folder");
}

#[test]
fn agent_name_is_read_from_json_ad() {
    let body = format!(r#"{{"{}":"Ada","@id":"x"}}"#, urls::NAME);
    assert_eq!(name_from_json_ad(&body).as_deref(), Some("Ada"));
    let arr = format!(r#"[{{"{}":"Bo"}}]"#, urls::SHORTNAME);
    assert_eq!(name_from_json_ad(&arr).as_deref(), Some("Bo"));
    assert_eq!(name_from_json_ad(r#"{"@id":"x"}"#), None);
    assert_eq!(name_from_json_ad("nope"), None);
}

/// Times the home lists over 3 drives x 20 resources (run with
/// `--ignored --nocapture` to see the numbers). The lists read propvals only, so no
/// resource row decodes a Loro snapshot.
#[tokio::test]
#[ignore = "timing; creates extra drives other tests share state with"]
async fn home_lists_do_not_decode_snapshots_per_row() {
    let first = shared_drive().await.to_string();
    let store = db().unwrap();
    let mut rx = store.subscribe_events();
    let mut drives = vec![first.clone()];
    for i in 0..2 {
        drives.push(
            crate::api::simple::create_drive(format!("Timing drive {i}"))
                .await
                .unwrap(),
        );
    }
    store.set_active_drive(&first).unwrap();
    for (d, drive) in drives.iter().enumerate() {
        for i in 0..20 {
            let name = format!("Timing {d}-{i}");
            let subject = store
                .create_resource(urls::FOLDER, drive, &name, None)
                .await
                .unwrap();
            // Some history, as a real resource has.
            for edit in 0..5 {
                let mut r = store.get_resource(&subject.as_str().into()).await.unwrap();
                r.set_string(urls::DESCRIPTION.into(), &format!("edit {edit}"), store.as_ref())
                    .await
                    .unwrap();
                r.save_locally(store.as_ref()).await.unwrap();
            }
            recents::note_opened(drive, &subject, 10_000 + i);
        }
    }
    pump(&mut rx).await;

    store.reset_fetch_counters();
    let t = std::time::Instant::now();
    let mut rows = 0;
    for drive in &drives {
        let list: Vec<Json> =
            serde_json::from_str(&list_recent_resources(drive.clone(), 10).await.unwrap()).unwrap();
        rows += list.len();
    }
    let recents_ms = t.elapsed().as_secs_f64() * 1000.0;
    let (full, shallow) = (
        store.get_resource_call_count(),
        store.get_resource_shallow_call_count(),
    );
    let t = std::time::Instant::now();
    let activity = list_activity(30).await.unwrap().len();
    let activity_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!(
        "[timing] recents {rows} rows over {} drives: {recents_ms:.1} ms (full reads {full}, shallow {shallow}); activity {activity} rows: {activity_ms:.1} ms",
        drives.len()
    );
    assert!(rows >= 30);

/// A resource as the server's sync delivers it: a Loro state with a parent but
/// no `drive` property of its own.
async fn synced_page(parent: &str, name: &str, with_drive: Option<&str>) -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let store = db().unwrap();
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let subject = format!("did:ad:syncpage{:0>60}{n}==", std::process::id());
    let mut authored = atomic_lib::Resource::new(subject.clone());
    authored
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent.into()))
        .unwrap();
    if let Some(drive) = with_drive {
        authored
            .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
    }
    authored
        .set_unsafe(urls::NAME.into(), Value::String(name.into()))
        .unwrap();
    let state = authored.build_state_doc().unwrap().export_snapshot();
    atomic_lib::sync::ws_apply::apply_state_update(store.as_ref(), &subject, &state)
        .await
        .unwrap();
    subject
}

#[tokio::test]
async fn assistant_search_finds_resources_delivered_by_sync() {
    let drive = shared_drive().await.to_string();
    let page = synced_page(&drive, "Okapi delivered by sync", None).await;
    let hits: Vec<Json> =
        serde_json::from_str(&search(Some(drive), "okapi".into(), 5).await.unwrap()).unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["title"], "Okapi delivered by sync");
    assert!(hits[0]["subject"].as_str().unwrap().ends_with(&page[9..]));
}

#[tokio::test]
async fn assistant_search_covers_every_drive_and_names_the_hit_drive() {
    let first = shared_drive().await.to_string();
    let second = crate::api::simple::create_drive("Search second drive".into())
        .await
        .unwrap();
    db().unwrap().set_active_drive(&first).unwrap();
    let here = db()
        .unwrap()
        .create_resource(AI_CHAT, &first, "Pangolin in the first drive", None)
        .await
        .unwrap();
    let there = db()
        .unwrap()
        .create_resource(AI_CHAT, &second, "Pangolin in the second drive", None)
        .await
        .unwrap();

    let hits: Vec<Json> =
        serde_json::from_str(&search(None, "pangolin".into(), 10).await.unwrap()).unwrap();
    let drive_of = |subject: &str| {
        hits.iter()
            .find(|h| h["subject"] == subject)
            .map(|h| h["drive"].as_str().unwrap().to_string())
    };
    assert_eq!(drive_of(&here).as_deref(), Some(first.as_str()));
    assert_eq!(drive_of(&there).as_deref(), Some(second.as_str()));

    // Scoping to one drive still works.
    let only: Vec<Json> = serde_json::from_str(
        &search(Some(second.clone()), "pangolin".into(), 10)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(only.len(), 1);
    assert_eq!(only[0]["subject"], there.as_str());
}
