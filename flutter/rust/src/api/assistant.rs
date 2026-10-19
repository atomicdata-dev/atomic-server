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

/// A resource for a list row: the stored propvals only (`get_resource_shallow`),
/// which skips decoding the whole Loro history that `get_resource` does per
/// call. Rows need a title and a class, which the last commit materialized, so
/// this can only lag a Loro import that has not materialized yet. Falls back to
/// the full read when there is no stored row.
pub(crate) async fn row_resource(store: &atomic_lib::Db, subject: &Subject) -> Option<Resource> {
    match store.get_resource_shallow(subject) {
        Ok(r) => Some(r),
        Err(_) => store.get_resource(subject).await.ok(),
    }
}

/// The name of a resource's first class, its subject when the class has none.
pub(crate) async fn class_name_of(resource: &Resource) -> String {
    let class = match resource.get(urls::IS_A).map(|v| v.to_subjects(None)) {
        Ok(Ok(classes)) => classes.into_iter().next().unwrap_or_default(),
        _ => String::new(),
    };
    let Ok(store) = db() else { return class };
    match row_resource(&store, &Subject::from(class.as_str())).await {
        Some(c) if !name_of(&c).is_empty() => name_of(&c),
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

/// One line of the activity feed.
pub struct ActivityEntry {
    pub subject: String,
    pub drive: String,
    /// `created`, `changed` or `deleted`.
    pub kind: String,
    /// Unix ms.
    pub at: i64,
    /// Display name of the agent that did it; `None` when the store does not
    /// know who, or does not have that agent's resource.
    pub actor: Option<String>,
    pub name: String,
    pub class_name: String,
}

/// What changed lately in every drive, newest first, by whom. Read from the
/// recents index, which the store's change events keep.
pub async fn list_activity(limit: u32) -> Result<Vec<ActivityEntry>, String> {
    let store = db()?;
    let mut names: std::collections::HashMap<String, Option<String>> = Default::default();
    let mut out = Vec::new();
    for a in recents::activity(limit as usize) {
        let actor = match &a.actor {
            None => None,
            Some(agent) => match names.get(agent) {
                Some(name) => name.clone(),
                None => {
                    let name = row_resource(&store, &Subject::from(agent.as_str()))
                        .await
                        .map(|r| name_of(&r))
                        .filter(|n| !n.is_empty());
                    names.insert(agent.clone(), name.clone());
                    name
                }
            },
        };
        out.push(ActivityEntry {
            subject: a.subject,
            drive: a.drive,
            kind: a.kind.as_str().to_string(),
            at: a.at,
            actor,
            name: a.name,
            class_name: a.class_name,
        });
    }
    Ok(out)
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
        let Some(resource) = row_resource(&store, &Subject::from(subject.as_str())).await else {
            tracing::warn!("[recents] {subject} not readable");
            continue;
        };
        out.push(resource_row(&subject, &resource, ("opened_at", json!(opened_at))).await);
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// `favorites` on the private drive: what the web app's Favorites panel lists.
pub(crate) const FAVORITES: &str = "https://atomicdata.dev/properties/favorites";

/// The subjects in a list property of the agent's private drive (the web
/// app's "home index"), in stored order; empty when there is no such drive or
/// list yet.
async fn private_drive_list(property: &str) -> Result<Vec<String>, String> {
    let store = db()?;
    let home = store.private_drive_subject().map_err(err)?;
    // One full read: the list property must be the merged CRDT state.
    let Ok(drive) = store.get_resource(&Subject::from(home.as_str())).await else {
        return Ok(Vec::new());
    };
    Ok(drive
        .get(property)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default())
}

/// The person's favorites (all drives), newest added first, as JSON
/// `[{subject, title, class_name, opened_at}]` (`opened_at` is always 0).
/// Favorites that are gone or unreadable are left out.
pub async fn list_favorites(limit: u32) -> Result<String, String> {
    let store = db()?;
    let mut out = Vec::new();
    // The web app appends, so the last one listed is the newest.
    for subject in private_drive_list(FAVORITES).await?.into_iter().rev() {
        if out.len() >= limit as usize {
            break;
        }
        let Some(resource) = row_resource(&store, &Subject::from(subject.as_str())).await else {
            continue;
        };
        out.push(resource_row(&subject, &resource, ("opened_at", json!(0))).await);
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Shown for a conversation member whose name is not known (yet), instead of
/// the raw agent id.
pub(crate) const UNKNOWN_MEMBER: &str = "Unknown member";

/// How long a background lookup of one agent's name may take.
const AGENT_NAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a failed lookup is not repeated, so a slow or offline server does
/// not delay every refresh of the home screen.
const AGENT_NAME_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

/// Names fetched so far (`Ok`) and lookups that failed and when (`Err`).
static AGENT_NAMES: std::sync::Mutex<
    Option<std::collections::HashMap<String, Result<String, std::time::Instant>>>,
> = std::sync::Mutex::new(None);

/// The name of an agent this device does not hold, from the cache. Never
/// waits on the network: when the name is not cached (and no lookup ran in the
/// last minute) a lookup starts in the background and this returns empty, so
/// the next refresh of the list has the name. The lookup goes to the connected
/// server with the library's HTTP client (which carries the Android TLS setup).
fn fetched_agent_name(member: &str) -> String {
    if let Some(known) = AGENT_NAMES
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(member).cloned()))
    {
        match known {
            Ok(name) => return name,
            Err(at) if at.elapsed() < AGENT_NAME_RETRY => return String::new(),
            Err(_) => {}
        }
    }
    // Mark the lookup as tried now, so concurrent refreshes do not start more.
    if let Ok(mut guard) = AGENT_NAMES.lock() {
        guard
            .get_or_insert_with(Default::default)
            .insert(member.to_string(), Err(std::time::Instant::now()));
    }
    let member = member.to_string();
    tokio::spawn(async move {
        if let Some(name) = fetch_agent_name(&member).await {
            if let Ok(mut guard) = AGENT_NAMES.lock() {
                guard
                    .get_or_insert_with(Default::default)
                    .insert(member, Ok(name));
            }
        }
    });
    String::new()
}

async fn fetch_agent_name(member: &str) -> Option<String> {
    let origin = connected_server()?;
    let agent = db().ok()?.get_default_agent().ok();
    let url = format!("{origin}/{member}");
    let body = tokio::time::timeout(
        AGENT_NAME_TIMEOUT,
        atomic_lib::client::fetch_body(&url, atomic_lib::parse::JSON_AD_MIME, agent.as_ref()),
    )
    .await
    .ok()?
    .ok()?;
    name_from_json_ad(&body)
}

/// The name in a JSON-AD body: one resource or an array whose first is it.
fn name_from_json_ad(body: &str) -> Option<String> {
    let json: Json = serde_json::from_str(body).ok()?;
    let resource = json.as_array().and_then(|a| a.first()).unwrap_or(&json);
    [urls::NAME, urls::SHORTNAME]
        .iter()
        .find_map(|p| resource.get(*p).and_then(|v| v.as_str()))
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

/// The person's conversations (DMs and group chats), as JSON
/// `[{subject, title, class_name, opened_at}]`, in the order the private drive
/// lists them. A conversation has no name of its own: its title is who else is
/// in it (its `read` list minus this agent), as the web app shows it. Last
/// activity is not cheap to know, so `opened_at` is 0.
pub async fn list_conversations(limit: u32) -> Result<String, String> {
    let store = db()?;
    let me = store.get_default_agent().map_err(err)?.subject.to_string();
    let mut out = Vec::new();
    for subject in private_drive_list(urls::CONVERSATIONS).await? {
        if out.len() >= limit as usize {
            break;
        }
        let Some(conversation) = row_resource(&store, &Subject::from(subject.as_str())).await
        else {
            continue;
        };
        let members = conversation
            .get(urls::READ)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        let others: Vec<&String> = members.iter().filter(|m| **m != me).collect();
        let names = futures::future::join_all(others.into_iter().map(|member| async {
            let local = match row_resource(&store, &Subject::from(member.as_str())).await {
                Some(agent) => name_of(&agent),
                None => String::new(),
            };
            if !local.is_empty() {
                return local;
            }
            let fetched = fetched_agent_name(member);
            if fetched.is_empty() {
                UNKNOWN_MEMBER.to_string()
            } else {
                fetched
            }
        }))
        .await;
        let title = if names.is_empty() {
            "Only you".to_string()
        } else {
            names.join(", ")
        };
        out.push(json!({
            "subject": subject,
            "title": title,
            "class_name": "",
            "opened_at": 0,
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

/// Full-text search (type-ahead on the last word) across every drive of this
/// store, or only in `drive` when given. JSON
/// `[{subject, title, class_name, drive, score}]`, best first; `drive` is the
/// drive the hit lives in ("" when unknown).
pub async fn search(drive: Option<String>, query: String, limit: u32) -> Result<String, String> {
    let store = db()?;
    let opts = atomic_lib::client::search::SearchOpts {
        limit: Some(limit),
        parents: drive.filter(|d| !d.is_empty()).map(|d| vec![d]),
        ..Default::default()
    };
    let hits = atomic_lib::search::query(store.as_ref(), query.trim(), &opts).map_err(err)?;

    // Local propvals only, and each parent / class is looked up once per
    // query: a search never waits on the network and never decodes a Loro doc.
    let mut drives = DriveCache::default();
    let mut classes: std::collections::HashMap<String, String> = Default::default();
    let mut out = Vec::new();
    for hit in hits.into_iter().take(limit as usize) {
        let Ok(resource) = store.get_resource_shallow(&hit.subject) else {
            continue;
        };
        let class = first_class(&resource);
        let class_name = match classes.get(&class) {
            Some(name) => name.clone(),
            None => {
                let name = match store.get_resource_shallow(&Subject::from(class.as_str())) {
                    Ok(c) if !name_of(&c).is_empty() => name_of(&c),
                    _ => class.clone(),
                };
                classes.insert(class, name.clone());
                name
            }
        };
        out.push(json!({
            "subject": hit.subject.to_string(),
            "title": name_of(&resource),
            "class_name": class_name,
            "score": hit.score,
            "drive": drives.of(store.as_ref(), &resource),
        }));
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// The subject of a resource's first class, "" when it has none.
fn first_class(resource: &Resource) -> String {
    match resource.get(urls::IS_A).map(|v| v.to_subjects(None)) {
        Ok(Ok(classes)) => classes.into_iter().next().unwrap_or_default(),
        _ => String::new(),
    }
}

/// The drive of resources found by a search: their `drive` property, else the
/// one found by walking up the parents through local propvals only. Every
/// resource on a walked chain is remembered, so siblings cost one lookup.
#[derive(Default)]
struct DriveCache(std::collections::HashMap<String, String>);

impl DriveCache {
    fn of(&mut self, store: &atomic_lib::Db, resource: &Resource) -> String {
        let mut chain: Vec<String> = Vec::new();
        let mut current = resource.clone();
        let mut found = String::new();
        for _ in 0..32 {
            if let Some(drive) = current.get_drive() {
                found = drive.to_string();
                break;
            }
            let Ok(parent) = current.get(urls::PARENT).map(|v| v.to_string()) else {
                break;
            };
            if let Some(known) = self.0.get(&parent) {
                found = known.clone();
                break;
            }
            let Ok(next) = store.get_resource_shallow(&Subject::from(parent.as_str())) else {
                // Not local: unknown, and remembered so it is asked once.
                self.0.insert(parent, String::new());
                break;
            };
            chain.push(parent);
            current = next;
        }
        for subject in chain {
            self.0.insert(subject, found.clone());
        }
        found
    }
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
