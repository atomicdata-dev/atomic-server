//! Read-only access for the assistant screens: AI chats, chat entries, search.
//!
//! Generic on purpose: everything works on resources of the drive it is given and
//! returns JSON, with no canvas logic. Chat messages are `ChatLog` entries, as
//! the web app stores them (`planning/chat-log.md`, "Step 3: AI chat").

#[cfg(test)]
mod tests;

use super::simple::state::{connected_server, db, err};
use crate::recents;
use atomic_lib::{
    chat_log::Entry,
    commit::{CommitBuilder, CommitOpts},
    loro::AtomicLoroDoc,
    storelike::Query,
    urls, Commit, Resource, Storelike, Subject, Value,
};
use flutter_rust_bridge::frb;
use serde_json::{json, Value as Json};

/// `ai.classes.aiChat` (`browser/lib/src/ontologies/ai.ts`).
pub(crate) const AI_CHAT: &str = "https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat";

pub(crate) fn name_of(resource: &Resource) -> String {
    resource
        .get(urls::NAME)
        .or_else(|_| resource.get(urls::SHORTNAME))
        .map(|v| v.to_string())
        .unwrap_or_default()
}

/// The name of a resource's first class, its subject when the class has none.
async fn class_name_of(resource: &Resource) -> String {
    let class = match resource.get(urls::IS_A).map(|v| v.to_subjects(None)) {
        Ok(Ok(classes)) => classes.into_iter().next().unwrap_or_default(),
        _ => String::new(),
    };
    let Ok(store) = db() else { return class };
    match store.get_resource(&Subject::from(class.as_str())).await {
        Ok(c) if !name_of(&c).is_empty() => name_of(&c),
        _ => class,
    }
}

/// Every entry of the `ChatLog` pages under `chat`, oldest first (by `c`, then
/// key), as the entry's own fields plus `id` (`<page>#<key>`). `parts` is
/// stored as a JSON string and comes out parsed. An entry key that sits on two
/// pages is listed once.
pub(crate) async fn chat_entries(chat: &str) -> Result<Vec<(i64, Json)>, String> {
    let store = db()?;
    let pages = store
        .query(&Query::new_prop_val(urls::PARENT, chat))
        .await
        .map_err(err)?;
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<(i64, String, Json)> = Vec::new();
    for subject in &pages.subjects {
        let Ok(page) = store.get_resource(subject).await else {
            continue;
        };
        if !atomic_lib::hierarchy::is_chat_log(&page) {
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
            let c = atomic_lib::chat_log::entry_created_at(&entry).unwrap_or(0);
            out.push((c, key, Json::Object(fields)));
        }
    }
    out.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    Ok(out.into_iter().map(|(c, _, json)| (c, json)).collect())
}

/// A `{subject, title, class_name, <extra>}` row of the resource lists.
async fn resource_row(subject: &str, resource: &Resource, extra: (&str, Json)) -> Json {
    json!({
        "subject": subject,
        "title": name_of(resource),
        "class_name": class_name_of(resource).await,
        extra.0: extra.1,
    })
}

/// The newest `limit` AI chats of the person (all drives), newest activity first, as JSON
/// `[{subject, name, last_activity}]` (`last_activity` in ms, 0 when empty).
/// Read from the recents index, not rebuilt from the chats' pages.
pub async fn list_ai_chats(limit: u32) -> Result<String, String> {
    let chats = recents::recent_chats(limit as usize).await?;
    let list: Vec<Json> = chats
        .into_iter()
        .map(|(subject, name, last)| json!({ "subject": subject, "name": name, "last_activity": last }))
        .collect();
    serde_json::to_string(&list).map_err(|e| e.to_string())
}

/// Record that this device opened `subject` in `drive`. Local to the device:
/// nothing is committed or synced.
#[frb(sync)]
pub fn note_resource_opened(drive: String, subject: String) {
    recents::note_opened(&drive, &subject, super::simple::state::now_ms());
}

/// The `limit` resources of `drive` this device opened last, newest first, as
/// JSON `[{subject, title, class_name, opened_at}]`. Resources that are gone
/// are left out.
pub async fn list_recent_resources(drive: String, limit: u32) -> Result<String, String> {
    let store = db()?;
    let mut out = Vec::new();
    let opened = recents::opened(&drive, limit as usize * 2);
    tracing::info!("[recents] {} opened in {drive}", opened.len());
    for (subject, opened_at) in opened {
        if out.len() >= limit as usize {
            break;
        }
        let resource = match store.get_resource(&Subject::from(subject.as_str())).await {
            Ok(resource) => resource,
            Err(e) => {
                tracing::warn!("[recents] {subject} not readable: {e}");
                continue;
            }
        };
        out.push(resource_row(&subject, &resource, ("opened_at", json!(opened_at))).await);
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// The entries of a chat, oldest first, as a JSON array of the fields the web
/// app stores: `id`, `a`, `c`, `role`, `parts` (array) and the rest as is.
pub async fn read_chat(subject: String) -> Result<String, String> {
    let entries: Vec<Json> = chat_entries(&subject)
        .await?
        .into_iter()
        .map(|(_, json)| json)
        .collect();
    serde_json::to_string(&entries).map_err(|e| e.to_string())
}

/// Full-text search in `drive` (type-ahead on the last word). JSON
/// `[{subject, title, class_name, score}]`, best first.
pub async fn search(drive: String, query: String, limit: u32) -> Result<String, String> {
    let store = db()?;
    let opts = atomic_lib::client::search::SearchOpts {
        limit: Some(limit),
        parents: Some(vec![drive]),
        ..Default::default()
    };
    let hits = atomic_lib::search::query(store.as_ref(), query.trim(), &opts).map_err(err)?;

    let mut out = Vec::new();
    for hit in hits {
        let Ok(resource) = store.get_resource(&hit.subject).await else {
            continue;
        };
        out.push(
            resource_row(
                &hit.subject.to_string(),
                &resource,
                ("score", json!(hit.score)),
            )
            .await,
        );
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// The URL that shows `subject` in the data-browser of the connected server,
/// for a webview. Errors when no server is connected (`open_ws_sync`).
#[frb(sync)]
pub fn resource_web_url(subject: String) -> Result<String, String> {
    let origin = connected_server().ok_or("Not connected to a server")?;
    Ok(format!(
        "{origin}/app/show?subject={}",
        urlencoding::encode(&subject)
    ))
}

/// The options of a commit this device signs for its own agent.
fn own_commit_opts() -> CommitOpts {
    CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    }
}

/// Start an AI chat named `name` in the agent's private drive, as the web
/// app's AI sidebar does. Returns the chat's subject.
pub async fn create_ai_chat(name: String) -> Result<String, String> {
    let store = db()?;
    let agent = store.get_default_agent().map_err(err)?;
    let home = store.ensure_private_drive().await.map_err(err)?;

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![AI_CHAT.into()]),
    );
    builder.set(urls::NAME.into(), Value::String(name));
    builder.set(urls::PARENT.into(), Value::AtomicUrl(home.as_str().into()));
    let commit = Commit::create_did(builder, &agent, store.as_ref())
        .await
        .map_err(err)?;
    let subject = commit.subject.to_string();
    let response = super::simple::node_apply_local(commit, &own_commit_opts()).await?;
    super::simple::push_local_write(&response, store.as_ref()).await;
    Ok(subject)
}

/// Add a message to a chat: `role` is `user` or `assistant`, `parts_json` the
/// message's parts as the web app stores them (`[{"type":"text","text":…}]`).
/// It goes on the newest page with room, or on a new page. Returns the entry's
/// id (`<page>#<key>`).
pub async fn append_chat_entry(
    chat: String,
    role: String,
    parts_json: String,
) -> Result<String, String> {
    let store = db()?;
    let agent = store.get_default_agent().map_err(err)?;
    let author = agent.subject.to_string();
    let mut entry = Entry::new(author, "", super::simple::state::now_ms());
    entry.extra.insert("role".into(), role.as_str().into());
    entry
        .extra
        .insert("parts".into(), parts_json.as_str().into());

    if let Some(subject) = atomic_lib::chat_log::page_with_room(store.as_ref(), &chat)
        .await
        .map_err(err)?
    {
        let mut page = store.get_resource(&subject).await.map_err(err)?;
        let key = page.add_chat_entry(&entry).map_err(err)?;
        let response = super::simple::state::node()?
            .save_locally(&mut page)
            .await
            .map_err(err)?;
        super::simple::push_local_write(&response, store.as_ref()).await;
        return Ok(format!("{subject}#{key}"));
    }

    // A first page.
    let doc = AtomicLoroDoc::new();
    let key = doc.add_entry(&entry).map_err(err)?;
    let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
    let parent = Value::AtomicUrl(chat.as_str().into());
    doc.set_property(urls::IS_A, &is_a).map_err(err)?;
    doc.set_property(urls::PARENT, &parent).map_err(err)?;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = Commit::create_did(builder, &agent, store.as_ref())
        .await
        .map_err(err)?;
    let page = commit.subject.to_string();
    let response = super::simple::node_apply_local(commit, &own_commit_opts()).await?;
    super::simple::push_local_write(&response, store.as_ref()).await;
    Ok(format!("{page}#{key}"))
}
