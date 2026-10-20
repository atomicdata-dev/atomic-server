//! AI chats as the web app stores them: an `AiChat` resource with `ChatLog`
//! pages under it, one entry per message (`planning/chat-log.md`, "Step 3: AI
//! chat").

use super::{own_commit_opts, rows::AI_CHAT, LocalWritePusher};
use crate::{
    chat_log::Entry, commit::CommitBuilder, errors::AtomicResult, loro::AtomicLoroDoc,
    runtime::AtomicNode, storelike::Query, urls, Commit, Db, Storelike, Value,
};
use serde_json::{json, Value as Json};

/// Every entry of the `ChatLog` pages under `chat`, oldest first (by `c`, then
/// key), as the entry's own fields plus `id` (`<page>#<key>`). `parts` is
/// stored as a JSON string and comes out parsed. An entry key that sits on two
/// pages is listed once. Each entry comes with its time (`c`, 0 when absent).
pub async fn chat_entries(store: &Db, chat: &str) -> AtomicResult<Vec<(i64, Json)>> {
    let pages = store
        .query(&Query::new_prop_val(urls::PARENT, chat))
        .await?;
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<(i64, String, Json)> = Vec::new();
    for subject in &pages.subjects {
        let Ok(page) = store.get_resource(subject).await else {
            continue;
        };
        if !crate::hierarchy::is_chat_log(&page) {
            continue;
        }
        let Ok(doc) = page.build_state_doc() else {
            continue;
        };
        for (key, entry) in doc.entries() {
            if !seen.insert(key.clone()) {
                continue;
            }
            let Ok(Json::Object(mut fields)) = serde_json::to_value(&entry) else {
                continue;
            };
            if let Some(Json::String(raw)) = fields.get("parts") {
                let parsed = serde_json::from_str(raw).unwrap_or_else(|_| json!([]));
                fields.insert("parts".into(), parsed);
            }
            fields.insert("id".into(), json!(format!("{}#{key}", page.get_subject())));
            let c = crate::chat_log::entry_created_at(&entry).unwrap_or(0);
            out.push((c, key, Json::Object(fields)));
        }
    }
    out.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    Ok(out.into_iter().map(|(c, _, json)| (c, json)).collect())
}

/// The entries of a chat, oldest first: the fields the web app stores, `id`,
/// `a`, `c`, `role`, `parts` (array) and the rest as is.
pub async fn read_chat(store: &Db, chat: &str) -> AtomicResult<Vec<Json>> {
    Ok(chat_entries(store, chat)
        .await?
        .into_iter()
        .map(|(_, json)| json)
        .collect())
}

/// Start an AI chat named `name` in the agent's private drive, as the web
/// app's AI sidebar does. Returns the chat's subject.
pub async fn create_ai_chat(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    name: &str,
) -> AtomicResult<String> {
    let store = node.db();
    let agent = store.get_default_agent()?;
    let home = store.ensure_private_drive().await?;

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![AI_CHAT.into()]),
    );
    builder.set(urls::NAME.into(), Value::String(name.to_string()));
    builder.set(urls::PARENT.into(), Value::AtomicUrl(home.as_str().into()));
    let commit = Commit::create_did(builder, &agent, store).await?;
    let subject = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok(subject)
}

/// Add a message to a chat: `role` is `user` or `assistant`, `parts_json` the
/// message's parts as the web app stores them (`[{"type":"text","text":…}]`).
/// It goes on the newest page with room, or on a new page. Returns the entry's
/// id (`<page>#<key>`).
pub async fn append_chat_entry(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    role: &str,
    parts_json: &str,
) -> AtomicResult<String> {
    let author = node.db().get_default_agent()?.subject.to_string();
    let mut entry = Entry::new(author, "", crate::utils::now());
    entry.extra.insert("role".into(), role.into());
    entry.extra.insert("parts".into(), parts_json.into());
    append_entry(node, pusher, chat, &entry).await
}

/// Add `entry` to the log of `chat`: on the newest `ChatLog` page with room
/// (the same rule as the web app, so both fill one page), or on a new page.
/// Returns the entry's id (`<page>#<key>`).
pub async fn append_entry(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    entry: &Entry,
) -> AtomicResult<String> {
    let store = node.db();

    if let Some(subject) = crate::chat_log::page_with_room(store, chat).await? {
        let mut page = store.get_resource(&subject).await?;
        let key = page.add_chat_entry(entry)?;
        let response = node.save_locally(&mut page).await?;
        pusher.push(&response).await;
        return Ok(format!("{subject}#{key}"));
    }

    // A first page.
    let (page, keys) = new_page(node, pusher, chat, std::slice::from_ref(entry)).await?;
    Ok(format!("{page}#{}", keys[0]))
}

/// A new `ChatLog` page under `chat` holding `entries`, in one commit by the
/// device's agent. Returns the page's subject and the entries' keys.
async fn new_page(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    entries: &[Entry],
) -> AtomicResult<(String, Vec<String>)> {
    let store = node.db();
    let agent = store.get_default_agent()?;
    let doc = AtomicLoroDoc::new();
    let keys = entries
        .iter()
        .map(|entry| doc.add_entry(entry))
        .collect::<AtomicResult<Vec<_>>>()?;
    let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
    let parent = Value::AtomicUrl(chat.into());
    doc.set_property(urls::IS_A, &is_a)?;
    doc.set_property(urls::PARENT, &parent)?;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = Commit::create_did(builder, &agent, store).await?;
    let page = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok((page, keys))
}

/// Import a whole AI chat at once: an `AiChat` named `name` in the agent's
/// private drive with `entries` (oldest first) on as few `ChatLog` pages as
/// the page capacity allows. One commit for the chat and one per page,
/// instead of one per message as [`append_chat_entry`] does; for importing a
/// conversation from elsewhere and for seeding a store in performance tests.
/// Returns the chat's subject.
pub async fn import_ai_chat(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    name: &str,
    entries: &[Entry],
) -> AtomicResult<String> {
    let chat = create_ai_chat(node, pusher, name).await?;
    for page in entries.chunks(crate::chat_log::CHAT_LOG_CAPACITY) {
        new_page(node, pusher, &chat, page).await?;
    }
    Ok(chat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{lists, test_support::Device};

    #[tokio::test]
    async fn chat_entries_are_read_oldest_first_across_pages() {
        let d = Device::new().await;
        let chat = d.new_chat("Entries").await;
        d.add_page(
            &chat,
            &[
                ("2-00000002", d.ai_entry("assistant", "second", 2_000)),
                ("1-00000001", d.ai_entry("user", "first", 1_000)),
            ],
        )
        .await;
        d.add_page(&chat, &[("3-00000003", d.ai_entry("user", "third", 3_000))])
            .await;

        let entries = read_chat(&d.store, &chat).await.unwrap();
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
    async fn an_imported_chat_fills_pages_up_to_their_capacity() {
        let d = Device::new().await;
        let n = crate::chat_log::CHAT_LOG_CAPACITY + 10;
        let entries: Vec<Entry> = (0..n)
            .map(|i| d.ai_entry("user", &format!("message {i}"), 1_000 + i as i64))
            .collect();
        let chat = import_ai_chat(&d.node, &crate::host::NoPush, "Imported", &entries)
            .await
            .unwrap();
        let read = read_chat(&d.store, &chat).await.unwrap();
        assert_eq!(read.len(), n);
        assert_eq!(read[0]["parts"][0]["text"], "message 0");
        assert_eq!(read[n - 1]["parts"][0]["text"], format!("message {}", n - 1));
        let pages: std::collections::HashSet<&str> = read
            .iter()
            .map(|e| e["id"].as_str().unwrap().split('#').next().unwrap())
            .collect();
        assert_eq!(pages.len(), 2);
        // A message added later goes on the page with room.
        append_chat_entry(&d.node, &crate::host::NoPush, &chat, "user", "[]")
            .await
            .unwrap();
        assert_eq!(read_chat(&d.store, &chat).await.unwrap().len(), n + 1);
    }

    #[tokio::test]
    async fn a_chat_started_here_takes_messages_in_order_on_one_page() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let chat = create_ai_chat(&d.node, &crate::host::NoPush, "Phone chat")
            .await
            .unwrap();
        let parts = |text: &str| json!([{ "type": "text", "text": text }]).to_string();
        let user = append_chat_entry(
            &d.node,
            &crate::host::NoPush,
            &chat,
            "user",
            &parts("Hallo"),
        )
        .await
        .unwrap();
        let assistant = append_chat_entry(
            &d.node,
            &crate::host::NoPush,
            &chat,
            "assistant",
            &parts("Hoi!"),
        )
        .await
        .unwrap();
        // Both entries sit on the same page, the second after the first.
        assert_eq!(user.split('#').next(), assistant.split('#').next());

        let entries = read_chat(&d.store, &chat).await.unwrap();
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
        d.pump(&mut rx).await;
        let list = lists::list_ai_chats(&d.store, &d.recents, 500)
            .await
            .unwrap();
        assert!(list
            .iter()
            .any(|c| c["subject"] == chat.as_str() && c["name"] == "Phone chat"));
    }
}
