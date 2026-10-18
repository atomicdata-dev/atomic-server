//! Read-only access for the assistant screens: AI chats, chat entries, search.
//!
//! Generic on purpose: everything works on resources of the drive it is given and
//! returns JSON, with no canvas logic. Chat messages are `ChatLog` entries, as
//! the web app stores them (`planning/chat-log.md`, "Step 3: AI chat").

#[cfg(test)]
mod tests;

use super::simple::state::{connected_server, db, err};
use crate::recents;
use atomic_lib::{storelike::Query, urls, Resource, Storelike, Subject};
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

/// The newest `limit` AI chats of `drive`, newest activity first, as JSON
/// `[{subject, name, last_activity}]` (`last_activity` in ms, 0 when empty).
/// Read from the recents index, not rebuilt from the chats' pages.
pub async fn list_ai_chats(drive: String, limit: u32) -> Result<String, String> {
    let chats = recents::recent_chats(&drive, limit as usize).await?;
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
        out.push(json!({
            "subject": subject,
            "title": name_of(&resource),
            "class_name": class_name_of(&resource).await,
            "opened_at": opened_at,
        }));
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
        let class_name = class_name_of(&resource).await;
        out.push(json!({
            "subject": hit.subject.to_string(),
            "title": name_of(&resource),
            "class_name": class_name,
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
