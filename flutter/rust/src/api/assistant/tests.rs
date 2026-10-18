//! Tests for the assistant reads, against the real store the other bridge
//! tests share (`simple::tests::shared_drive`): chats and pages are created
//! through the library's own commit path, nothing is mocked.

use super::*;
use crate::api::simple::tests::shared_drive;
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
async fn assistant_lists_chats_of_the_drive_by_last_activity() {
    let old = new_chat("Assistant old chat").await;
    let new = new_chat("Assistant new chat").await;
    let empty = new_chat("Assistant empty chat").await;
    add_page(&old, &[("1-00000001", ai_entry("user", "hi", 1_000))]).await;
    add_page(&new, &[("1-00000001", ai_entry("user", "hi", 9_000))]).await;

    let list: Vec<Json> = serde_json::from_str(&list_ai_chats().await.unwrap()).unwrap();
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
    let list = list_ai_chats().await.unwrap();
    assert!(!list.contains(&folder));
}

#[tokio::test]
async fn assistant_search_finds_a_prefix_with_title_and_class() {
    let chat = new_chat("Zebrafinch migration notes").await;
    let hits: Vec<Json> = serde_json::from_str(&search("zebraf".into(), 5).await.unwrap()).unwrap();
    let hit = hits
        .iter()
        .find(|h| h["subject"] == chat.as_str())
        .unwrap_or_else(|| panic!("chat not found in {hits:?}"));
    assert_eq!(hit["title"], "Zebrafinch migration notes");
    assert!(hit["score"].as_f64().unwrap() > 0.0);
    assert!(hit["class_name"].as_str().is_some_and(|c| !c.is_empty()));

    let none = search("qqqxxnothing".into(), 5).await.unwrap();
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
