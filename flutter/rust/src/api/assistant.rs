//! Read-only access for the assistant screens: AI chats, chat entries, search.
//!
//! Generic on purpose: everything works on resources of the active drive and
//! returns JSON, with no canvas logic. Chat messages are `ChatLog` entries, as
//! the web app stores them (`planning/chat-log.md`, "Step 3: AI chat").

#[cfg(test)]
mod tests;

use super::simple::state::{connected_server, db, err};
use atomic_lib::{storelike::Query, urls, Resource, Storelike, Subject};
use flutter_rust_bridge::frb;
use serde_json::{json, Value as Json};

/// `ai.classes.aiChat` (`browser/lib/src/ontologies/ai.ts`).
const AI_CHAT: &str = "https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat";

fn name_of(resource: &Resource) -> String {
    resource
        .get(urls::NAME)
        .or_else(|_| resource.get(urls::SHORTNAME))
        .map(|v| v.to_string())
        .unwrap_or_default()
}

/// Every entry of the `ChatLog` pages under `chat`, oldest first (by `c`, then
/// key), as the entry's own fields plus `id` (`<page>#<key>`). `parts` is
/// stored as a JSON string and comes out parsed. An entry key that sits on two
/// pages is listed once.
async fn chat_entries(chat: &str) -> Result<Vec<(i64, Json)>, String> {
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

/// AI chats of the active drive, newest activity first, as JSON
/// `[{subject, name, last_activity}]` (`last_activity` in ms, 0 when empty).
pub async fn list_ai_chats() -> Result<String, String> {
    let store = db()?;
    let drive = store.get_active_drive().ok_or("No active drive")?;
    let drive_id = Subject::from(drive.as_str()).pure_id();
    let found = store.query(&Query::new_class(AI_CHAT)).await.map_err(err)?;

    let mut items: Vec<(i64, String, Json)> = Vec::new();
    for subject in &found.subjects {
        let Ok(chat) = store.get_resource(subject).await else {
            continue;
        };
        let in_drive = chat
            .get(urls::DRIVE_PROP)
            .is_ok_and(|d| Subject::from(d.to_string().as_str()).pure_id() == drive_id);
        if !in_drive {
            continue;
        }
        let subject = chat.get_subject().to_string();
        let last = chat_entries(&subject).await?.last().map_or(0, |(c, _)| *c);
        let name = name_of(&chat);
        items.push((
            last,
            name.clone(),
            json!({ "subject": subject, "name": name, "last_activity": last }),
        ));
    }
    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let list: Vec<Json> = items.into_iter().map(|(_, _, json)| json).collect();
    serde_json::to_string(&list).map_err(|e| e.to_string())
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

/// Full-text search in the active drive (type-ahead on the last word). JSON
/// `[{subject, title, class_name, score}]`, best first.
pub async fn search(query: String, limit: u32) -> Result<String, String> {
    let store = db()?;
    let drive = store.get_active_drive().ok_or("No active drive")?;
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
        let class = match resource.get(urls::IS_A).map(|v| v.to_subjects(None)) {
            Ok(Ok(classes)) => classes.into_iter().next().unwrap_or_default(),
            _ => String::new(),
        };
        let class_name = match store.get_resource(&Subject::from(class.as_str())).await {
            Ok(c) => name_of(&c),
            Err(_) => String::new(),
        };
        out.push(json!({
            "subject": hit.subject.to_string(),
            "title": name_of(&resource),
            "class_name": if class_name.is_empty() { class } else { class_name },
            "score": hit.score,
        }));
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// The URL that shows `subject` in the data-browser of the connected server,
/// for a webview. Errors when no server is connected (`open_ws_sync`).
#[frb(sync)]
pub fn resource_web_url(subject: String) -> Result<String, String> {
    let origin = connected_server().ok_or("Not connected to a server")?;
    let mut encoded = String::new();
    for b in subject.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char)
            }
            _ => encoded.push_str(&format!("%{b:02X}")),
        }
    }
    Ok(format!("{origin}/app/show?subject={encoded}"))
}
