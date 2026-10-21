//! The assistant and home-screen functions end to end through the bridge,
//! against the real store the other bridge tests share
//! (`simple::tests::shared_drive`): the process-global store, recents index
//! and caches, and the bridge's push after a write. What the lists, chats and
//! conversations contain is tested in `atomic_lib::host`.

use super::*;
use crate::api::simple::tests::shared_drive;
use atomic_lib::{
    agents::Agent,
    commit::CommitBuilder,
    conversation::{encryption_public_key, seal_message, Keyring, Member},
    host::{conversations::vault_proof, notifications, own_commit_opts, rows::FAVORITES},
    urls, Commit, Storelike, Subject, Value,
};
use serde_json::{json, Value as Json};

async fn new_chat(name: &str) -> String {
    let drive = shared_drive().await;
    db().unwrap()
        .create_resource(atomic_lib::host::rows::AI_CHAT, drive, name, None)
        .await
        .unwrap()
}

/// Feed the store's pending change events to the recents index, as the
/// listener does in the app.
async fn pump(rx: &mut tokio::sync::broadcast::Receiver<atomic_lib::db::DbEvent>) {
    let store = db().unwrap();
    // The channel holds 64 events and tests run side by side: a receiver that
    // fell behind skips what it missed instead of stopping.
    loop {
        match rx.try_recv() {
            Ok(event) => recents().handle_event(store, event).await,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
}

/// Put `subjects` in a list property of the private drive, as the web app does.
async fn set_home_list(property: &str, subjects: &[&str]) {
    let _one_at_a_time = crate::api::simple::tests::PRIVATE_DRIVE.lock().await;
    let store = db().unwrap();
    let home = store.ensure_private_drive().await.unwrap();
    let mut drive = store
        .get_resource(&Subject::from(home.as_str()))
        .await
        .unwrap();
    let list = Value::ResourceArray(subjects.iter().map(|s| (*s).into()).collect());
    drive.set_unsafe(property.into(), list).unwrap();
    let response = node().unwrap().save_locally(&mut drive).await.unwrap();
    super::super::simple::push_local_write(&response, store.as_ref()).await;
}

#[tokio::test]
async fn a_chat_started_here_takes_messages_in_order_and_is_listed() {
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

    pump(&mut rx).await;
    let list = list_ai_chats(500, 0).await.unwrap();
    assert!(list.contains(&chat));
    assert!(list.contains("Phone chat"));
}

#[tokio::test]
async fn assistant_search_finds_a_prefix_with_title_and_class() {
    let chat = new_chat("Zebrafinch migration notes").await;
    let drive = shared_drive().await.to_string();
    let hits: Vec<Json> = serde_json::from_str(
        &search(Some(drive.clone()), "zebraf".into(), 5, vec![])
            .await
            .unwrap(),
    )
    .unwrap();
    let hit = hits
        .iter()
        .find(|h| h["subject"] == chat.as_str())
        .unwrap_or_else(|| panic!("chat not found in {hits:?}"));
    assert_eq!(hit["title"], "Zebrafinch migration notes");
    assert!(hit["class_name"].as_str().is_some_and(|c| !c.is_empty()));
    let other = "https://example.test/not-this-drive".to_string();
    assert!(!search(Some(other), "zebraf".into(), 5, vec![])
        .await
        .unwrap()
        .contains(&chat));
}

#[tokio::test]
async fn assistant_search_filters_the_class_and_pages_the_chats() {
    let chat = new_chat("Gerenuk pagination chat").await;
    let drive = shared_drive().await.to_string();
    for i in 0..5 {
        db().unwrap()
            .create_resource(
                atomic_lib::urls::FOLDER,
                &drive,
                &format!("Gerenuk folder {i}"),
                None,
            )
            .await
            .unwrap();
    }
    let only_chats: Vec<Json> = serde_json::from_str(
        &search(None, "gerenuk".into(), 2, vec!["aichat".into()])
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(only_chats.len(), 1, "{only_chats:?}");
    assert_eq!(only_chats[0]["subject"], chat.as_str());

    // Pages of one chat each add up to the whole list. Other tests add chats
    // to the same store in parallel, so the pages only count when the whole
    // list read before and after them is the same.
    let mut rx = db().unwrap().subscribe_events();
    pump(&mut rx).await;
    let read = |limit, offset| async move {
        serde_json::from_str::<Vec<Json>>(&list_ai_chats(limit, offset).await.unwrap()).unwrap()
    };
    let mut stable = false;
    for _ in 0..20 {
        let all = read(1000, 0).await;
        let pages = [read(1, 0).await, read(1000, 1).await].concat();
        if read(1000, 0).await == all {
            assert_eq!(pages, all);
            stable = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(stable, "the chat list kept changing while it was paged");

    warm_search().await.unwrap();
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

#[tokio::test]
async fn opened_resources_are_listed_newest_first() {
    let drive = shared_drive().await.to_string();
    let a = new_chat("Opened a").await;
    let b = new_chat("Opened b").await;
    note_resource_opened(drive.clone(), a.clone());
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    note_resource_opened(drive.clone(), b.clone());
    note_resource_opened(drive.clone(), "https://example.test/gone".into());

    let list: Vec<Json> =
        serde_json::from_str(&list_recent_resources(drive.clone(), 500).await.unwrap()).unwrap();
    let at = |s: &str| list.iter().position(|r| r["subject"] == s).unwrap();
    assert!(at(&b) < at(&a));
    assert!(!list
        .iter()
        .any(|r| r["subject"] == "https://example.test/gone"));
    assert_eq!(list[at(&a)]["title"], "Opened a");
}

#[tokio::test]
async fn favorites_come_from_the_private_drive_newest_first() {
    let a = new_chat("Fav a").await;
    let b = new_chat("Fav b").await;
    set_home_list(FAVORITES, &[&a, "https://example.test/gone", &b]).await;

    let list: Vec<Json> = serde_json::from_str(&list_favorites(10).await.unwrap()).unwrap();
    let titles: Vec<&str> = list.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert_eq!(titles, ["Fav b", "Fav a"]);
}

#[tokio::test]
async fn activity_lists_other_agents_changes_not_the_own() {
    let drive = shared_drive().await.to_string();
    let store = db().unwrap();
    let mut rx = store.subscribe_events();
    let folder = store
        .create_resource(urls::FOLDER, &drive, "Activity folder", None)
        .await
        .unwrap();
    pump(&mut rx).await;
    // Made here, by the person: Recents, not Activity.
    let list = list_activity(500, false).await.unwrap();
    assert!(list.iter().all(|a| a.subject != folder));

    // Another member renames it.
    let bob = Agent::new(Some("Bob")).unwrap();
    let mut r = store.get_resource(&folder.as_str().into()).await.unwrap();
    r.set_string(urls::NAME.into(), "Renamed by Bob", store.as_ref())
        .await
        .unwrap();
    r.save_as(&bob, store.as_ref()).await.unwrap();
    pump(&mut rx).await;
    let list = list_activity(500, false).await.unwrap();
    let entry = list.iter().find(|a| a.subject == folder).unwrap();
    assert_eq!(entry.kind, "changed");
    assert_eq!(entry.name, "Renamed by Bob");
    let actor = entry.actor.as_deref().unwrap();
    assert!(!actor.is_empty() && actor != "Someone", "{actor}");
}

#[tokio::test]
async fn rows_and_icons_carry_the_resources_own_emoji() {
    let drive = shared_drive().await.to_string();
    let with = new_chat("Icon with").await;
    let without = new_chat("Icon without").await;
    let set_emoji = |subject: String, emoji: &'static str| async move {
        let store = db().unwrap();
        let mut r = store.get_resource(&subject.as_str().into()).await.unwrap();
        r.set_string(urls::EMOJI.into(), emoji, store.as_ref())
            .await
            .unwrap();
        r.save_locally(store.as_ref()).await.unwrap();
    };
    set_emoji(with.clone(), "🦊").await;
    note_resource_opened(drive.clone(), with.clone());

    let recent: Vec<Json> =
        serde_json::from_str(&list_recent_resources(drive.clone(), 500).await.unwrap()).unwrap();
    let row = recent
        .iter()
        .find(|r| r["subject"] == with.as_str())
        .unwrap();
    assert_eq!(row["emoji"], "🦊");

    let icons: serde_json::Map<String, Json> = serde_json::from_str(
        &resource_icons(vec![with.clone(), without.clone()])
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(icons.len(), 1);
    assert_eq!(icons[&with], "🦊");

    // A drive's own icon comes with the drive list.
    set_emoji(drive.clone(), "🏔").await;
    let drives: Vec<Json> =
        serde_json::from_str(&crate::api::simple::list_drives_with_names().await.unwrap()).unwrap();
    let row = drives
        .iter()
        .find(|r| r["subject"] == drive.as_str())
        .unwrap();
    assert_eq!(row["emoji"], "🏔");
}

/// A conversation between the device's agent and a new agent called `name`,
/// with a keyring both can open; returns it and a way to speak as the other.
async fn new_talk(name: &str) -> (String, Keyring, Agent, Vec<u8>) {
    shared_drive().await;
    let store = db().unwrap();
    let me = store.get_default_agent().unwrap();
    let other = Agent::new(Some(name)).unwrap();
    store
        .add_resource(&other.to_resource().unwrap())
        .await
        .unwrap();
    let (my_proof, other_proof) = (vault_proof(&me).unwrap(), vault_proof(&other).unwrap());
    let mut keyring = Keyring::default();
    keyring
        .add_epoch(&[
            Member {
                agent: me.subject.to_string(),
                encryption_key: encryption_public_key(&my_proof),
            },
            Member {
                agent: other.subject.to_string(),
                encryption_key: encryption_public_key(&other_proof),
            },
        ])
        .unwrap();
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::CONVERSATION.into(), urls::DRIVE.into()]),
    );
    builder.set(
        urls::READ.into(),
        Value::ResourceArray(vec![
            me.subject.to_string().into(),
            other.subject.to_string().into(),
        ]),
    );
    builder.set(
        urls::CONVERSATION_KEYS.into(),
        Value::String(keyring.to_json().unwrap()),
    );
    let commit = Commit::create_did(builder, &me, store.as_ref())
        .await
        .unwrap();
    let conversation = commit.subject.to_string();
    super::super::simple::node_apply_local(commit, &own_commit_opts())
        .await
        .unwrap();
    (conversation, keyring, other, other_proof)
}

async fn say_as(conversation: &str, keyring: &Keyring, other: &Agent, proof: &[u8], text: &str) {
    let store = db().unwrap();
    let key = keyring
        .open_current(&other.subject.to_string(), proof)
        .unwrap();
    let sealed = seal_message(
        &key,
        conversation,
        json!({ "text": text }).to_string().as_bytes(),
    )
    .unwrap();
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::SEALED_MESSAGE.into()]),
    );
    builder.set(urls::PARENT.into(), Value::AtomicUrl(conversation.into()));
    builder.set(urls::SEALED.into(), Value::String(sealed));
    let commit = Commit::create_did(builder, other, store.as_ref())
        .await
        .unwrap();
    store
        .apply_commit(commit, &own_commit_opts())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_conversation_is_read_listed_and_written_through_the_bridge() {
    let (conversation, keyring, other, proof) = new_talk("Alice").await;
    say_as(&conversation, &keyring, &other, &proof, "Hoi!").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    send_conversation_message(conversation.clone(), "Hallo Alice".into())
        .await
        .unwrap();

    let messages: Vec<Json> =
        serde_json::from_str(&read_conversation(conversation.clone()).await.unwrap()).unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["author_name"], "Alice");
    assert_eq!(messages[0]["text"], "Hoi!");
    assert_eq!(messages[1]["text"], "Hallo Alice");
    assert_eq!(messages[1]["mine"], true);

    set_home_list(urls::CONVERSATIONS, &[&conversation]).await;
    let list: Vec<Json> = serde_json::from_str(&list_conversations(10).await.unwrap()).unwrap();
    assert_eq!(list[0]["subject"], conversation.as_str());
    assert_eq!(list[0]["title"], "Alice");
    assert_eq!(list[0]["last_message"], "Hallo Alice");
}

#[tokio::test]
async fn a_chat_room_is_written_and_read_through_the_bridge() {
    let drive = shared_drive().await;
    let room = db()
        .unwrap()
        .create_resource(atomic_lib::host::rows::AI_CHAT, drive, "Standup", None)
        .await
        .unwrap();
    send_chat_room_message(room.clone(), "Hallo".into(), None)
        .await
        .unwrap();
    let messages: Vec<Json> =
        serde_json::from_str(&read_chat_room(room.clone()).await.unwrap()).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["kind"], "text");
    assert_eq!(messages[0]["text"], "Hallo");
    assert_eq!(messages[0]["mine"], true);
}

#[tokio::test]
async fn a_document_created_here_is_in_the_drive_and_found_by_search() {
    let drive = shared_drive().await;
    let subject = create_resource_of_class(
        drive.to_string(),
        urls::DOCUMENT_V2.into(),
        "Narwhal bridge document".into(),
    )
    .await
    .unwrap();
    let r = db()
        .unwrap()
        .get_resource(&subject.as_str().into())
        .await
        .unwrap();
    assert_eq!(r.get(urls::PARENT).unwrap().to_string(), drive);
    assert_eq!(
        r.get(urls::NAME).unwrap().to_string(),
        "Narwhal bridge document"
    );
    let hits = search(Some(drive.to_string()), "narwhal".into(), 5, vec![])
        .await
        .unwrap();
    assert!(hits.contains(&subject), "{hits}");
}

#[tokio::test]
async fn the_inbox_is_listed_and_a_notification_marked_read_through_the_bridge() {
    let _one_at_a_time = crate::api::simple::tests::PRIVATE_DRIVE.lock().await;
    let drive = shared_drive().await;
    let store = db().unwrap();
    let inbox = store
        .create_resource("https://atomicdata.dev/classes/Inbox", drive, "Inbox", None)
        .await
        .unwrap();
    let mut home = store.get_resource(&Subject::from(drive)).await.unwrap();
    home.set_unsafe(
        notifications::INBOX.into(),
        Value::AtomicUrl(inbox.as_str().into()),
    )
    .unwrap();
    node().unwrap().save_locally(&mut home).await.unwrap();
    let subject = store
        .create_resource(
            notifications::NOTIFICATION,
            &inbox,
            "Polle in Team chat",
            Some(vec![
                (
                    notifications::NOTIFICATION_SOURCE,
                    Value::AtomicUrl("https://example.test/bridge-message".into()),
                ),
                (notifications::OCCURRED_AT, Value::Timestamp(4_000)),
            ]),
        )
        .await
        .unwrap();

    let list: Vec<Json> = serde_json::from_str(&list_notifications(50).await.unwrap()).unwrap();
    let found = list.iter().find(|n| n["subject"] == subject).unwrap();
    assert_eq!(found["title"], "Polle in Team chat");
    assert_eq!(found["read"], false);

    mark_notification_read(subject.clone()).await.unwrap();
    let list: Vec<Json> = serde_json::from_str(&list_notifications(50).await.unwrap()).unwrap();
    let found = list.iter().find(|n| n["subject"] == subject).unwrap();
    assert_eq!(found["read"], true);
}

#[tokio::test]
async fn an_imported_chat_reads_back_in_order() {
    shared_drive().await;
    let entries = json!([
        { "role": "user", "parts": [{ "type": "text", "text": "Vraag" }], "c": 1_000 },
        { "role": "assistant", "parts": "[{\"type\":\"text\",\"text\":\"Antwoord\"}]", "c": 2_000 },
    ]);
    let chat = import_ai_chat("Imported".into(), entries.to_string())
        .await
        .unwrap();
    let read: Json = serde_json::from_str(&read_chat(chat).await.unwrap()).unwrap();
    assert_eq!(read[0]["role"], "user");
    assert_eq!(read[0]["parts"][0]["text"], "Vraag");
    assert_eq!(read[1]["parts"][0]["text"], "Antwoord");
    assert_eq!(read[1]["c"], 2_000);
}

#[test]
fn the_conversations_endpoint_answer_is_read_as_links_or_nested_resources() {
    let prop = atomic_lib::urls::CONVERSATIONS;
    let links = json!({ prop: ["did:ad:one", "did:ad:two"] }).to_string();
    assert_eq!(
        super::conversations_in_json_ad(&links),
        vec!["did:ad:one", "did:ad:two"]
    );
    let nested = json!([{ prop: [{ "@id": "did:ad:three" }] }]).to_string();
    assert_eq!(
        super::conversations_in_json_ad(&nested),
        vec!["did:ad:three"]
    );
    assert!(super::conversations_in_json_ad("not json").is_empty());
    assert!(super::conversations_in_json_ad("{}").is_empty());
}
