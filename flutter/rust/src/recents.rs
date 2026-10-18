//! The home screen's two lists, kept so reading them is a lookup.
//!
//! Which chat spoke last used to be found by rebuilding every chat's Loro pages
//! in every drive. Now a listener on the store's change events keeps a small
//! index: the newest entry time of each AI chat (chats belong to the person,
//! so across all drives), and per drive the resources this device opened
//! recently. It lives in `recents.json` beside the store,
//! is local to the device (opening a resource commits nothing), and is
//! rebuilt from the store when it is missing or the listener fell behind.

use crate::api::assistant::{chat_entries, name_of, AI_CHAT};
use crate::api::simple::state::{db, err};
use atomic_lib::{db::DbEvent, urls, Db, Resource, Storelike, Subject};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Most recently opened resources kept per drive.
const OPENED_CAP: usize = 100;

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct DriveRecents {
    /// Resource subject → when this device opened it (ms).
    opened: HashMap<String, i64>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Recents {
    /// Chat subject → newest entry time (ms), 0 for a chat without entries.
    chats: HashMap<String, i64>,
    /// Whether `chats` was filled from the store (and not only from events).
    chats_scanned: bool,
    /// Opened resources, keyed by the drive's `pure_id`.
    drives: HashMap<String, DriveRecents>,
}

struct State {
    recents: Recents,
    path: Option<std::path::PathBuf>,
    dirty: bool,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State {
            recents: Recents::default(),
            path: None,
            dirty: false,
        })
    })
}

fn with<T>(f: impl FnOnce(&mut State) -> T) -> T {
    f(&mut state().lock().unwrap_or_else(|p| p.into_inner()))
}

fn drive_id(drive: &str) -> String {
    Subject::from(drive).pure_id()
}

/// Load the index from `dir` and keep it there from now on.
pub(crate) fn load(dir: &std::path::Path) {
    let path = dir.join("recents.json");
    let recents = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    with(|s| {
        s.recents = recents;
        s.path = Some(path);
        s.dirty = false;
    });
}

/// Write the index when it changed since the last write.
fn persist() {
    let Some((path, raw)) = with(|s| {
        if !s.dirty {
            return None;
        }
        s.dirty = false;
        let raw = serde_json::to_string(&s.recents).ok()?;
        Some((s.path.clone()?, raw))
    }) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, raw).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Entry time of the newest entry on a `ChatLog` page, 0 when it has none.
fn page_last_activity(page: &Resource) -> i64 {
    let Ok(doc) = page.build_state_doc() else {
        return 0;
    };
    doc.entries()
        .into_values()
        .filter_map(|entry| atomic_lib::chat_log::entry_created_at(&entry))
        .max()
        .unwrap_or(0)
}

fn is_ai_chat(resource: &Resource) -> bool {
    resource
        .get(urls::IS_A)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .is_some_and(|classes| classes.iter().any(|c| c == AI_CHAT))
}

fn bump_chat(chat: &str, at: i64) {
    with(|s| {
        let slot = s.recents.chats.entry(chat.to_string()).or_insert(0);
        *slot = (*slot).max(at);
        s.dirty = true;
    });
}

/// Fold one store event into the index.
pub(crate) async fn handle_event(store: &Db, event: DbEvent) {
    match event {
        DbEvent::Changed { subject, .. } => {
            let Ok(resource) = store.get_resource(&subject).await else {
                return;
            };
            if is_ai_chat(&resource) {
                bump_chat(&subject.to_string(), 0);
            } else if atomic_lib::hierarchy::is_chat_log(&resource) {
                let Ok(parent) = resource.get(urls::PARENT) else {
                    return;
                };
                bump_chat(&parent.to_string(), page_last_activity(&resource));
            }
        }
        DbEvent::Destroyed { subject, .. } => {
            let subject = subject.to_string();
            with(|s| {
                let mut removed = s.recents.chats.remove(&subject).is_some();
                for r in s.recents.drives.values_mut() {
                    removed |= r.opened.remove(&subject).is_some();
                }
                s.dirty |= removed;
            });
        }
        DbEvent::QueryMembershipChanged { .. } => {}
    }
}

/// Keep the index current for as long as the store lives.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn spawn_listener(store: std::sync::Arc<Db>) {
    use std::time::{Duration, Instant};
    use tokio::sync::broadcast::error::RecvError;

    let mut rx = store.subscribe_events();
    tokio::spawn(async move {
        let mut dirty_since: Option<Instant> = None;
        loop {
            match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Ok(event)) => handle_event(&store, event).await,
                // Events were dropped: what the index knows may be stale.
                Ok(Err(RecvError::Lagged(_))) => with(|s| s.recents.chats_scanned = false),
                Ok(Err(RecvError::Closed)) => break,
                Err(_) => {}
            }
            if with(|s| s.dirty) {
                let since = *dirty_since.get_or_insert_with(Instant::now);
                // Quiet for half a second, or two seconds of streaming.
                if since.elapsed() >= Duration::from_secs(2) || rx.is_empty() {
                    persist();
                    dirty_since = None;
                }
            }
        }
        persist();
    });
}

/// Fill the chat index from the store the first time it is asked for.
pub(crate) async fn ensure_scanned() -> Result<(), String> {
    if with(|s| s.recents.chats_scanned) {
        return Ok(());
    }
    let store = db()?;
    let found = store
        .query(&atomic_lib::storelike::Query::new_class(AI_CHAT))
        .await
        .map_err(err)?;
    for subject in &found.subjects {
        let subject = subject.to_string();
        let last = chat_entries(&subject).await?.last().map_or(0, |(c, _)| *c);
        bump_chat(&subject, last);
    }
    with(|s| {
        s.recents.chats_scanned = true;
        s.dirty = true;
    });
    Ok(())
}

/// The `limit` newest chats as `(subject, name, last_activity)`.
pub(crate) async fn recent_chats(limit: usize) -> Result<Vec<(String, String, i64)>, String> {
    ensure_scanned().await?;
    let mut chats: Vec<(String, i64)> = with(|s| {
        s.recents
            .chats
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    });
    chats.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let store = db()?;
    let mut out = Vec::new();
    for (subject, last) in chats {
        if out.len() >= limit {
            break;
        }
        // A chat that is gone (or not here yet) is left out, not an error.
        let Ok(resource) = store.get_resource(&Subject::from(subject.as_str())).await else {
            continue;
        };
        out.push((subject, name_of(&resource), last));
    }
    Ok(out)
}

/// Remember that this device opened `subject` in `drive`.
pub(crate) fn note_opened(drive: &str, subject: &str, at: i64) {
    with(|s| {
        let opened = &mut s.recents.drives.entry(drive_id(drive)).or_default().opened;
        opened.insert(subject.to_string(), at);
        if opened.len() > OPENED_CAP {
            let mut by_age: Vec<_> = opened.iter().map(|(k, v)| (k.clone(), *v)).collect();
            by_age.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
            for (k, _) in by_age.into_iter().skip(OPENED_CAP) {
                opened.remove(&k);
            }
        }
        s.dirty = true;
    });
}

/// The `limit` most recently opened resources of `drive`, newest first.
pub(crate) fn opened(drive: &str, limit: usize) -> Vec<(String, i64)> {
    let mut all: Vec<(String, i64)> = with(|s| {
        s.recents
            .drives
            .get(&drive_id(drive))
            .map(|r| r.opened.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default()
    });
    all.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    all.truncate(limit);
    all
}
