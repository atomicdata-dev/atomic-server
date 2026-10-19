//! The home screen's two lists, kept so reading them is a lookup.
//!
//! The index exists because building the chat list by reading every chat's
//! Loro pages at app start was too slow (seconds); the home screen now reads a
//! small persisted index instead.
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

/// Entries kept in the activity log.
const ACTIVITY_CAP: usize = 200;
/// Changes to one subject closer together than this share one entry (ms).
const BURST_MS: i64 = 60_000;

/// Most recently opened resources kept per drive.
const OPENED_CAP: usize = 100;

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct DriveRecents {
    /// Resource subject → when this device opened it (ms).
    opened: HashMap<String, i64>,
}

/// What happened to a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ActivityKind {
    Created,
    Changed,
    Deleted,
}

impl ActivityKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Changed => "changed",
            Self::Deleted => "deleted",
        }
    }
}

/// One entry of the activity log: the latest thing that happened to `subject`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Activity {
    pub subject: String,
    /// The resource's drive, as stored on it.
    pub drive: String,
    pub kind: ActivityKind,
    /// Unix ms.
    pub at: i64,
    /// Subject of the agent that signed the change, when the store knows it.
    pub actor: Option<String>,
    /// The resource's name at that time (for a deletion: the last known one).
    pub name: String,
    pub class_name: String,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Recents {
    /// What changed lately, newest first, one entry per subject.
    activity: Vec<Activity>,
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

fn read_from(path: &std::path::Path) -> Recents {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_to(path: &std::path::Path, raw: String) {
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, raw).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Load the index from `dir` and keep it there from now on.
pub(crate) fn load(dir: &std::path::Path) {
    let path = dir.join("recents.json");
    let recents = read_from(&path);
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
    write_to(&path, raw);
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

/// Put `new` in the log: one entry per subject, newest first, bounded.
///
/// Changes to a subject within [`BURST_MS`] of its entry update that entry; a
/// resource created a moment ago is still reported as created.
fn record_activity(recents: &mut Recents, mut new: Activity) {
    let log = &mut recents.activity;
    if let Some(i) = log.iter().position(|a| a.subject == new.subject) {
        let old = log.remove(i);
        let burst = new.kind == ActivityKind::Changed
            && old.kind != ActivityKind::Deleted
            && (new.at - old.at).abs() < BURST_MS;
        if burst {
            new.kind = old.kind;
        }
        if new.actor.is_none() && burst {
            new.actor = old.actor;
        }
        if new.name.is_empty() {
            new.name = old.name;
        }
        if new.class_name.is_empty() {
            new.class_name = old.class_name;
        }
    }
    let at = log.partition_point(|a| a.at > new.at);
    log.insert(at, new);
    log.truncate(ACTIVITY_CAP);
}

/// Resources whose changes are bookkeeping, not something a person did.
fn is_activity_noise(subject: &str, resource: &Resource) -> bool {
    if subject.starts_with("internal:") || is_ai_chat(resource) {
        return true;
    }
    if atomic_lib::hierarchy::is_chat_log(resource) {
        return true;
    }
    let classes = resource
        .get(urls::IS_A)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default();
    classes.iter().any(|c| {
        [
            urls::COMMIT,
            urls::PROPERTY,
            urls::CLASS,
            urls::ONTOLOGY,
            urls::AGENT,
        ]
        .contains(&c.as_str())
    })
}

/// The signer of the newest retained commit of `subject`. Cheap: it reads the
/// stored commit envelope, so it is `None` where the store keeps none.
fn latest_signer(store: &Db, subject: &str) -> Option<(String, i64)> {
    let envelope = atomic_lib::envelopes::latest_envelope(store, subject)?;
    let json: serde_json::Value = serde_json::from_str(&envelope.json).ok()?;
    let signer = json.get(urls::SIGNER)?.as_str()?.to_string();
    Some((signer, envelope.created_at))
}

async fn note_changed(store: &Db, subject: &Subject, resource: &Resource, is_new: bool) {
    let id = subject.to_string();
    if is_activity_noise(&id, resource) {
        return;
    }
    let drive = match resource.get(urls::DRIVE_PROP) {
        Ok(drive) => drive.to_string(),
        Err(_) => return,
    };
    let (actor, at) = match latest_signer(store, &id) {
        Some((actor, at)) => (Some(actor), at),
        None => (None, crate::api::simple::state::now_ms()),
    };
    let new = Activity {
        subject: id,
        drive,
        kind: if is_new {
            ActivityKind::Created
        } else {
            ActivityKind::Changed
        },
        at,
        actor,
        name: name_of(resource),
        class_name: crate::api::assistant::class_name_of(resource).await,
    };
    with(|s| {
        record_activity(&mut s.recents, new);
        s.dirty = true;
    });
}

/// A deletion is logged only for a resource the log already knows: once it is
/// gone its name cannot be read, and an entry without one says nothing.
fn note_destroyed(subject: &str, actor: Option<String>) {
    with(|s| {
        let Some(old) = s.recents.activity.iter().find(|a| a.subject == subject) else {
            return;
        };
        let new = Activity {
            kind: ActivityKind::Deleted,
            at: crate::api::simple::state::now_ms(),
            actor,
            ..old.clone()
        };
        record_activity(&mut s.recents, new);
        s.dirty = true;
    });
}

/// Fold one store event into the index.
pub(crate) async fn handle_event(store: &Db, event: DbEvent) {
    match event {
        DbEvent::Changed {
            subject, is_new, ..
        } => {
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
            } else {
                note_changed(store, &subject, &resource, is_new).await;
            }
        }
        DbEvent::Destroyed {
            subject,
            commit_json,
            ..
        } => {
            let subject = subject.to_string();
            let actor = commit_json
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                .and_then(|json| json.get(urls::SIGNER)?.as_str().map(str::to_string));
            note_destroyed(&subject, actor);
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
        let Some(resource) =
            crate::api::assistant::row_resource(&store, &Subject::from(subject.as_str())).await
        else {
            continue;
        };
        out.push((subject, name_of(&resource), last));
    }
    Ok(out)
}

/// The `limit` newest activity entries, newest first.
pub(crate) fn activity(limit: usize) -> Vec<Activity> {
    with(|s| s.recents.activity.iter().take(limit).cloned().collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(subject: &str, kind: ActivityKind, at: i64) -> Activity {
        Activity {
            subject: subject.into(),
            drive: "did:ad:drive".into(),
            kind,
            at,
            actor: Some("did:ad:agent:a".into()),
            name: format!("name of {subject}"),
            class_name: "Document".into(),
        }
    }

    fn log(recents: &Recents) -> Vec<(&str, ActivityKind, i64)> {
        recents
            .activity
            .iter()
            .map(|a| (a.subject.as_str(), a.kind, a.at))
            .collect()
    }

    #[test]
    fn activity_is_newest_first_with_one_entry_per_subject() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("a", ActivityKind::Created, 1_000));
        record_activity(&mut r, entry("b", ActivityKind::Created, 2_000));
        record_activity(&mut r, entry("a", ActivityKind::Changed, 500_000));
        assert_eq!(
            log(&r),
            vec![
                ("a", ActivityKind::Changed, 500_000),
                ("b", ActivityKind::Created, 2_000)
            ]
        );
    }

    #[test]
    fn a_burst_of_changes_updates_one_entry() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("a", ActivityKind::Created, 1_000));
        for i in 1..=5 {
            record_activity(
                &mut r,
                entry("a", ActivityKind::Changed, 1_000 + i * 10_000),
            );
        }
        // Still "created": the changes came within a minute of each other.
        assert_eq!(log(&r), vec![("a", ActivityKind::Created, 51_000)]);

        // A change a minute later is a change of its own.
        record_activity(&mut r, entry("a", ActivityKind::Changed, 51_000 + BURST_MS));
        assert_eq!(log(&r), vec![("a", ActivityKind::Changed, 111_000)]);
    }

    #[test]
    fn a_burst_keeps_the_actor_when_the_store_does_not_know_it() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("a", ActivityKind::Created, 1_000));
        let mut unknown = entry("a", ActivityKind::Changed, 2_000);
        unknown.actor = None;
        record_activity(&mut r, unknown);
        assert_eq!(r.activity[0].actor.as_deref(), Some("did:ad:agent:a"));
    }

    #[test]
    fn a_deletion_keeps_the_last_known_name_and_ends_the_burst() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("a", ActivityKind::Changed, 1_000));
        let mut gone = entry("a", ActivityKind::Deleted, 2_000);
        gone.name = String::new();
        record_activity(&mut r, gone);
        assert_eq!(r.activity.len(), 1);
        assert_eq!(r.activity[0].kind, ActivityKind::Deleted);
        assert_eq!(r.activity[0].name, "name of a");
        // Re-created within the minute: no longer deleted.
        record_activity(&mut r, entry("a", ActivityKind::Changed, 3_000));
        assert_eq!(r.activity[0].kind, ActivityKind::Changed);
    }

    #[test]
    fn activity_is_bounded_and_drops_the_oldest() {
        let mut r = Recents::default();
        for i in 0..(ACTIVITY_CAP as i64 + 50) {
            record_activity(
                &mut r,
                entry(&format!("s{i}"), ActivityKind::Changed, i * 1_000),
            );
        }
        assert_eq!(r.activity.len(), ACTIVITY_CAP);
        assert_eq!(r.activity[0].subject, format!("s{}", ACTIVITY_CAP + 49));
        assert!(r.activity.iter().all(|a| a.subject != "s0"));
        assert_eq!(activity_slice(&r, 3).len(), 3);
    }

    fn activity_slice(r: &Recents, n: usize) -> Vec<&Activity> {
        r.activity.iter().take(n).collect()
    }

    #[test]
    fn an_old_change_arriving_late_sorts_by_time() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("new", ActivityKind::Changed, 9_000_000));
        record_activity(&mut r, entry("old", ActivityKind::Changed, 1_000));
        assert_eq!(r.activity[0].subject, "new");
        assert_eq!(r.activity[1].subject, "old");
    }

    #[test]
    fn activity_survives_a_write_and_read() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("a", ActivityKind::Created, 1_000));
        record_activity(&mut r, entry("b", ActivityKind::Deleted, 2_000));
        let dir = std::env::temp_dir().join(format!("recents-activity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recents.json");
        write_to(&path, serde_json::to_string(&r).unwrap());
        let back = read_from(&path);
        assert_eq!(back.activity, r.activity);
        // An index written before the log existed still loads.
        write_to(&path, r#"{"chats":{}}"#.into());
        assert!(read_from(&path).activity.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
