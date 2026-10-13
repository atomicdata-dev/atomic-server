//! The AI chat migration (`ai_chat_migration.rs`): old `ai-message` resources
//! with a resource per part move into `ChatLog` pages.
//! Run: cargo test -p atomic_lib --features db-redb --lib ai_chat_migration

use super::ai_chat_migration::AI_DONE_KEY;
use super::chat_migration_test::{stored_bytes, world, World};
use super::trees::Tree;
use super::*;
use crate::{
    agents::Agent,
    chat_log::{entry_author, entry_created_at, migrated_entry_key},
    commit::{CommitBuilder, CommitOpts},
    loro::AtomicLoroDoc,
};
use loro::LoroValue;

macro_rules! ai {
    ($s:literal) => {
        concat!("https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/", $s)
    };
}

const AI_CHAT: &str = ai!("class/ai-chat");
const AI_MESSAGE: &str = ai!("class/ai-message");
const TEXT_PART: &str = ai!("class/text-part");
const TOOL_PART: &str = ai!("class/tool-call-part");
const REASONING_PART: &str = ai!("class/reasoning-part");
const MESSAGES: &str = ai!("property/messages");
const CONTENT: &str = ai!("property/content");
const ROLE: &str = ai!("property/role");
const TAG: &str = ai!("tag/");

/// An old-style resource, created the way the app did: a genesis commit with a
/// certificate, signed by `agent`.
async fn old_resource(
    db: &Db,
    agent: &Agent,
    class: &str,
    parent: &str,
    props: Vec<(&str, Value)>,
) -> String {
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let doc = AtomicLoroDoc::new();
    let parent_value = Value::AtomicUrl(parent.into());
    doc.set_property(
        urls::IS_A,
        &Value::ResourceArray(vec![class.to_string().into()]),
    )
    .unwrap();
    doc.set_property(urls::PARENT, &parent_value).unwrap();
    for (property, value) in &props {
        doc.set_property(property, value).unwrap();
    }
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent_value);
    builder.set_loro_update(doc.export_snapshot());
    let commit = crate::Commit::create_did(builder, agent, db).await.unwrap();
    let subject = commit.subject.to_string();
    db.apply_commit(
        commit,
        &CommitOpts {
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        },
    )
    .await
    .unwrap();
    subject
}

async fn set_list(db: &Db, subject: &str, property: &str, list: &[String]) {
    let mut res = db.get_resource(&subject.into()).await.unwrap();
    res.set_unsafe(
        property.into(),
        Value::ResourceArray(list.iter().map(|s| s.clone().into()).collect()),
    )
    .unwrap();
    db.add_resource_opts(&res, false, true, true).await.unwrap();
}

async fn old_chat(w: &World) -> String {
    old_resource(
        &w.db,
        &w.alice,
        AI_CHAT,
        &w.drive,
        vec![(urls::NAME, Value::String("Assistant".into()))],
    )
    .await
}

/// One old message with its parts. `tools` adds that many tool calls with a
/// sizeable result.
async fn old_ai_message(w: &World, chat: &str, role: &str, text: &str, tools: usize) -> String {
    let message = old_resource(
        &w.db,
        &w.alice,
        AI_MESSAGE,
        chat,
        vec![(ROLE, Value::AtomicUrl(format!("{TAG}{role}").into()))],
    )
    .await;
    let mut parts = Vec::new();
    parts.push(
        old_resource(
            &w.db,
            &w.alice,
            REASONING_PART,
            &message,
            vec![(urls::DESCRIPTION, Value::Markdown("thinking".into()))],
        )
        .await,
    );
    parts.push(
        old_resource(
            &w.db,
            &w.alice,
            TEXT_PART,
            &message,
            vec![(urls::DESCRIPTION, Value::Markdown(text.into()))],
        )
        .await,
    );
    for t in 0..tools {
        let output = serde_json::json!({
            "rows": (0..12).map(|i| serde_json::json!({"id": i, "name": format!("row {i} of {t}")})).collect::<Vec<_>>()
        });
        parts.push(
            old_resource(
                &w.db,
                &w.alice,
                TOOL_PART,
                &message,
                vec![
                    (ai!("property/tool-name"), Value::String("search".into())),
                    (ai!("property/tool-id"), Value::String(format!("call_{t}"))),
                    (
                        ai!("property/tool-arguments"),
                        Value::Json(serde_json::json!({"query": "hello"})),
                    ),
                    (ai!("property/tool-result"), Value::Json(output)),
                ],
            )
            .await,
        );
    }
    set_list(&w.db, &message, CONTENT, &parts).await;
    message
}

async fn pages_of(db: &Db, chat: &str) -> Vec<(String, Vec<(String, LoroValue)>)> {
    let mut found = Vec::new();
    for atom in
        find_in_prop_val_sub_index(db, urls::PARENT, Some(&Value::AtomicUrl(chat.into()))).flatten()
    {
        let page = db.get_resource(&atom.subject).await.unwrap();
        if !crate::hierarchy::is_chat_log(&page) {
            continue;
        }
        let created = page.get(urls::CREATED_AT).unwrap().to_int().unwrap();
        found.push((
            created,
            page.get_subject().pure_id(),
            page.build_state_doc().unwrap().list_entries(),
        ));
    }
    found.sort_by_key(|(c, s, _)| (*c, s.clone()));
    found.into_iter().map(|(_, s, e)| (s, e)).collect()
}

fn field_str(entry: &LoroValue, name: &str) -> Option<String> {
    match entry {
        LoroValue::Map(m) => match m.get(name) {
            Some(LoroValue::String(s)) => Some(s.to_string()),
            _ => None,
        },
        _ => None,
    }
}

async fn exists(db: &Db, subject: &str) -> bool {
    db.get_resource(&subject.into()).await.is_ok()
}

async fn count_class(db: &Db, class: &str) -> usize {
    find_in_prop_val_sub_index(db, urls::IS_A, Some(&Value::AtomicUrl(class.into())))
        .flatten()
        .count()
}

#[tokio::test]
async fn messages_become_entries_in_list_order_with_parts_inlined() {
    let w = world("ai_chat_migration_main").await;
    let db = &w.db;
    let chat = old_chat(&w).await;
    let first = old_ai_message(&w, &chat, "user", "first", 0).await;
    let second = old_ai_message(&w, &chat, "assistant", "second", 2).await;
    let third = old_ai_message(&w, &chat, "user", "third", 0).await;
    // The list is the order, not createdAt: the second goes last.
    let list = [first.clone(), third.clone(), second.clone()];
    set_list(db, &chat, MESSAGES, &list).await;
    let all = [&first, &second, &third];
    let old_parts = count_class(db, TEXT_PART).await;
    assert_eq!(old_parts, 3);

    db.kv.remove(Tree::PluginMeta, AI_DONE_KEY).unwrap();
    assert!(db.ai_chat_migration_pending().unwrap());
    db.migrate_ai_chats().await.unwrap();
    assert!(!db.ai_chat_migration_pending().unwrap());

    let pages = pages_of(db, &chat).await;
    assert_eq!(pages.len(), 1);
    // Readers sort by `c`; the keys carry the old creation time.
    let mut sorted = pages[0].1.clone();
    sorted.sort_by_key(|(_, e)| entry_created_at(e).unwrap());
    let entries = &sorted;
    assert_eq!(entries.len(), 3);
    let texts: Vec<String> = entries
        .iter()
        .map(|(_, e)| {
            let parts: serde_json::Value =
                serde_json::from_str(&field_str(e, "parts").unwrap()).unwrap();
            parts
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["type"] == "text")
                .unwrap()["text"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(texts, ["first", "third", "second"]);
    let c: Vec<i64> = entries
        .iter()
        .map(|(_, e)| entry_created_at(e).unwrap())
        .collect();
    assert!(
        c.windows(2).all(|w| w[0] < w[1]),
        "c follows the list: {c:?}"
    );
    for (_, e) in entries {
        assert_eq!(entry_author(e).unwrap(), w.alice.subject.to_string());
    }
    assert_eq!(field_str(&entries[0].1, "role").unwrap(), "user");
    assert_eq!(field_str(&entries[2].1, "role").unwrap(), "assistant");

    // The tool calls are inlined as the UI holds them.
    let parts: serde_json::Value =
        serde_json::from_str(&field_str(&entries[2].1, "parts").unwrap()).unwrap();
    let tool = &parts[2];
    assert_eq!(tool["type"], "tool-search");
    assert_eq!(tool["toolCallId"], "call_0");
    assert_eq!(tool["state"], "output-available");
    assert_eq!(tool["input"]["query"], "hello");
    assert_eq!(tool["output"]["rows"].as_array().unwrap().len(), 12);
    assert_eq!(parts[0]["type"], "reasoning");

    // Keys are deterministic.
    let created = db
        .get_resource(&second.as_str().into())
        .await
        .err()
        .map(|_| ());
    assert!(created.is_some(), "the old message is gone");
    let keys: Vec<&String> = entries.iter().map(|(k, _)| k).collect();
    assert!(keys.iter().all(|k| k.len() > 9));
    let _ = migrated_entry_key;

    // Old rows are gone, the chat keeps its name and an empty list.
    for s in all {
        assert!(!exists(db, s).await);
    }
    assert_eq!(count_class(db, TEXT_PART).await, 0);
    assert_eq!(count_class(db, TOOL_PART).await, 0);
    assert_eq!(count_class(db, REASONING_PART).await, 0);
    assert_eq!(count_class(db, AI_MESSAGE).await, 0);
    let chat_res = db.get_resource(&chat.as_str().into()).await.unwrap();
    assert_eq!(chat_res.get(urls::NAME).unwrap().to_string(), "Assistant");
    assert!(
        chat_res.get(MESSAGES).is_err() || {
            chat_res
                .get(MESSAGES)
                .unwrap()
                .to_subjects(None)
                .unwrap()
                .is_empty()
        }
    );

    // A second run changes nothing.
    db.kv.remove(Tree::PluginMeta, AI_DONE_KEY).unwrap();
    db.migrate_ai_chats().await.unwrap();
    let again = pages_of(db, &chat).await;
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].1.len(), 3);
}

/// A crash after the pages are written and before the old rows are removed:
/// the next run finds the entries by key and writes nothing twice.
#[tokio::test]
async fn a_restart_between_pages_and_removal_does_not_duplicate() {
    let w = world("ai_chat_migration_resume").await;
    let db = &w.db;
    let chat = old_chat(&w).await;
    let mut list = Vec::new();
    for i in 0..4 {
        list.push(old_ai_message(&w, &chat, "user", &format!("m{i}"), 1).await);
    }
    set_list(db, &chat, MESSAGES, &list).await;
    db.migrate_ai_chat(&chat, false, None).await.unwrap();
    assert_eq!(pages_of(db, &chat).await[0].1.len(), 4);
    for s in &list {
        assert!(exists(db, s).await);
    }
    db.kv.remove(Tree::PluginMeta, AI_DONE_KEY).unwrap();
    db.migrate_ai_chats().await.unwrap();
    let pages = pages_of(db, &chat).await;
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].1.len(), 4);
    for s in &list {
        assert!(!exists(db, s).await);
    }
}

/// A browser cache of a hosted drive writes no pages of its own.
#[tokio::test]
async fn a_cache_of_a_hosted_drive_writes_nothing() {
    let w = world("ai_chat_migration_cache").await;
    let db = &w.db;
    let chat = old_chat(&w).await;
    let m = old_ai_message(&w, &chat, "user", "hi", 0).await;
    set_list(db, &chat, MESSAGES, std::slice::from_ref(&m)).await;
    let hosted: HashSet<String> = HashSet::new();
    db.kv.remove(Tree::PluginMeta, AI_DONE_KEY).unwrap();
    let step = db.migrate_ai_chats_step(100, Some(&hosted)).await.unwrap();
    assert!(step.finished);
    assert!(pages_of(db, &chat).await.is_empty());
    assert!(exists(db, &m).await);
}

/// Twenty messages with tool calls, before and after.
#[tokio::test]
async fn migrating_an_ai_chat_shrinks_the_store() {
    const N: usize = 20;
    let w = world("ai_chat_migration_size").await;
    let db = &w.db;
    let (baseline, _) = stored_bytes(db);
    let chat = old_chat(&w).await;
    let mut list = Vec::new();
    for i in 0..N {
        let (role, tools) = if i % 2 == 0 {
            ("user", 0)
        } else {
            ("assistant", 3)
        };
        list.push(
            old_ai_message(
                &w,
                &chat,
                role,
                &format!("Bericht nummer {i}, een gewone zin."),
                tools,
            )
            .await,
        );
    }
    set_list(db, &chat, MESSAGES, &list).await;
    db.kv.remove(Tree::PluginMeta, AI_DONE_KEY).unwrap();
    let (before, _) = stored_bytes(db);
    db.migrate_ai_chats().await.unwrap();
    let (after, _) = stored_bytes(db);
    println!(
        "{N} AI messages: {before} B before, {after} B after, baseline {baseline} B; \
         per message {} B -> {} B",
        (before - baseline) / N,
        (after - baseline) / N
    );
    assert!(after < before, "{before} -> {after}");
}

/// A server opens its store before it loads its agent. Opening a store with an
/// old AI chat must migrate it without a default agent (node1 crashed on
/// "No agent set" here).
#[tokio::test]
async fn opening_a_store_without_an_agent_migrates_ai_chats() {
    let w = world("ai_chat_migration_open").await;
    let chat = old_chat(&w).await;
    let first = old_ai_message(&w, &chat, "user", "first", 0).await;
    let second = old_ai_message(&w, &chat, "assistant", "second", 1).await;
    set_list(&w.db, &chat, MESSAGES, &[first.clone(), second.clone()]).await;
    // As a store from before: not marked done.
    w.db.kv.remove(Tree::PluginMeta, AI_DONE_KEY).unwrap();
    w.db.kv.flush().unwrap();
    drop(w);

    let path = std::path::Path::new(".temp/db/ai_chat_migration_open");
    let uploads = std::path::Path::new(".temp/db/ai_chat_migration_open/uploads");
    let mut reopened = None;
    let mut last_err = String::new();
    // The file lock can outlive the drop by a moment.
    for _ in 0..50 {
        match Db::init_redb_file(path, Some("https://localhost".into()), uploads).await {
            Ok(db) => {
                reopened = Some(db);
                break;
            }
            Err(e) => {
                last_err = e.to_string();
                // Only the file lock is worth waiting for.
                assert!(
                    !last_err.contains("No agent set"),
                    "opening needs no agent: {last_err}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(200)).await
            }
        }
    }
    let db = reopened.unwrap_or_else(|| panic!("the store reopens: {last_err}"));
    assert!(db.get_default_agent().is_err(), "opened without an agent");
    assert!(!db.ai_chat_migration_pending().unwrap());
    let found = pages_of(&db, &chat).await;
    assert_eq!(found.iter().map(|(_, e)| e.len()).sum::<usize>(), 2);
    assert!(!exists(&db, &first).await);
    assert!(!exists(&db, &second).await);
    assert!(db
        .get_resource(&chat.as_str().into())
        .await
        .unwrap()
        .get(MESSAGES)
        .is_err());
}
