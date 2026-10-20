//! The home screen's lists, kept so reading them is a lookup.
//!
//! The index exists because building the chat list by reading every chat's
//! Loro pages at app start was too slow (seconds); the home screen now reads a
//! small persisted index instead.
//!
//! Which chat spoke last used to be found by rebuilding every chat's Loro pages
//! in every drive. Now a listener on the store's change events keeps a small
//! index: the newest entry time of each AI chat (chats belong to the person,
//! so across all drives), per drive the resources this device opened
//! recently, and an activity log (every agent's changes, this device's own
//! included; [`super::lists::list_activity`] leaves those out). It lives in
//! `recents.json` in a directory the host names ([`RecentsIndex::load`]), is
//! local to the device (opening a resource commits nothing), and is rebuilt
//! from the store when it is missing or the listener fell behind.

use super::{
    chats::chat_last_activity,
    profiles::same_agent,
    rows::{class_name_of, name_of, row_resource, AI_CHAT},
};
use crate::{db::DbEvent, errors::AtomicResult, urls, Db, Resource, Storelike, Subject};
use std::collections::HashMap;
use std::sync::Mutex;

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
pub enum ActivityKind {
    Created,
    Changed,
    Deleted,
}

impl ActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Changed => "changed",
            Self::Deleted => "deleted",
        }
    }
}

/// One entry of the activity log: the latest thing that happened to `subject`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Activity {
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

#[derive(Default)]
struct State {
    recents: Recents,
    path: Option<std::path::PathBuf>,
    dirty: bool,
}

/// The recents index of one store. A host keeps one per store, feeds it the
/// store's events ([`RecentsIndex::spawn_listener`], or
/// [`RecentsIndex::handle_event`] by hand) and reads the lists from it.
#[derive(Default)]
pub struct RecentsIndex {
    state: Mutex<State>,
    /// Held while the chats are scanned, so the listener and a list never
    /// scan at the same time.
    scanning: tokio::sync::Mutex<()>,
    /// Whether [`RecentsIndex::spawn_listener`] runs: it rescans the chats
    /// itself once the events calm down, so a list need not wait for that.
    listening: std::sync::atomic::AtomicBool,
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

/// Entry time of the newest entry on a `ChatLog` page, 0 when it has none.
fn page_last_activity(page: &Resource) -> i64 {
    let Ok(doc) = page.build_state_doc() else {
        return 0;
    };
    doc.entries()
        .into_values()
        .filter_map(|entry| crate::chat_log::entry_created_at(&entry))
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

/// Whether two actors of the log are the same agent (both unknown counts as
/// the same).
fn same_actor(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => same_agent(a, b),
        (None, None) => true,
        _ => false,
    }
}

/// Put `new` in the log: one entry per subject and agent, newest first,
/// bounded. Two agents editing one resource are two entries; one agent
/// editing it many times is one, with the latest time.
///
/// Changes to a subject within [`BURST_MS`] of its entry update that entry; a
/// resource created a moment ago is still reported as created. A change whose
/// signer is not known joins the subject's entry of that burst. A deletion
/// replaces every entry of the subject: the resource is gone.
fn record_activity(recents: &mut Recents, mut new: Activity) {
    let log = &mut recents.activity;
    if new.kind == ActivityKind::Deleted {
        let mut i = 0;
        while i < log.len() {
            if log[i].subject == new.subject {
                let old = log.remove(i);
                if new.name.is_empty() {
                    new.name = old.name;
                }
                if new.class_name.is_empty() {
                    new.class_name = old.class_name;
                }
            } else {
                i += 1;
            }
        }
    } else if let Some(i) = log.iter().position(|a| {
        a.subject == new.subject
            && (same_actor(a.actor.as_deref(), new.actor.as_deref())
                || (new.actor.is_none() && (new.at - a.at).abs() < BURST_MS))
    }) {
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
        // An entry written before the agent was known keeps its place.
        new.at = new.at.max(old.at);
        if new.name.is_empty() {
            new.name = old.name;
        }
        if new.class_name.is_empty() {
            new.class_name = old.class_name;
        }
        // A deletion that is followed by a change: the resource is back, and
        // other agents' entries of it may no longer hold.
        if old.kind == ActivityKind::Deleted {
            log.retain(|a| a.subject != new.subject);
        }
    } else {
        // A resource that was deleted and is back.
        log.retain(|a| !(a.subject == new.subject && a.kind == ActivityKind::Deleted));
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
    if crate::hierarchy::is_chat_log(resource) {
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
    let envelope = crate::envelopes::latest_envelope(store, subject)?;
    let json: serde_json::Value = serde_json::from_str(&envelope.json).ok()?;
    let signer = json.get(urls::SIGNER)?.as_str()?.to_string();
    Some((signer, envelope.created_at))
}

/// How old the newest kept commit may be and still be taken for the signer
/// of a change that arrived as plain state (ms).
const FRESH_ENVELOPE_MS: i64 = 2 * 60_000;

/// Who made a change, when, and whether it made the resource.
///
/// - A change a commit made here (this device's own edit, or a commit frame)
///   is that commit's: its envelope is the newest one kept.
/// - A resource first seen as plain state (the server's `UPDATE` frames carry
///   no signer) and made a moment ago names its creator in its genesis
///   change (`createdBy`).
/// - Any other change that arrived as plain state is only attributed when a
///   commit envelope came with it (a sync push carries them), i.e. the
///   newest kept envelope is fresh. An older envelope describes an earlier
///   change, often this device's own, and would put the wrong name on it;
///   such a change stays unattributed.
///
/// The store is read when the event is handled, so a commit that lands
/// before the listener gets to the previous one's event lends it its signer;
/// the listener runs as the events come, so in practice that is a burst of
/// one agent's own edits.
fn attribute(
    store: &Db,
    subject: &str,
    resource: &Resource,
    is_new: bool,
    from_commit: bool,
    first_seen: bool,
) -> (Option<String>, i64, bool) {
    let now = crate::utils::now();
    let latest = latest_signer(store, subject);
    if from_commit {
        return match latest {
            Some((actor, at)) => (Some(actor), at, is_new),
            None => (None, now, is_new),
        };
    }
    let created_at = resource
        .get(urls::CREATED_AT)
        .ok()
        .and_then(|v| v.to_int().ok());
    let just_made =
        is_new || (first_seen && created_at.is_some_and(|at| (now - at).abs() < FRESH_ENVELOPE_MS));
    if just_made {
        let creator = resource
            .get(urls::CREATED_BY)
            .ok()
            .map(|v| v.to_string())
            .filter(|s| !s.is_empty());
        if creator.is_some() {
            return (creator, created_at.unwrap_or(now), true);
        }
    }
    match latest {
        Some((actor, at)) if now - at < FRESH_ENVELOPE_MS => (Some(actor), at, is_new),
        _ => (None, now, is_new),
    }
}

impl RecentsIndex {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Load the index from `dir` and keep it there from now on.
    pub fn load(&self, dir: &std::path::Path) {
        let path = dir.join("recents.json");
        let recents = read_from(&path);
        self.with(|s| {
            s.recents = recents;
            s.path = Some(path);
            s.dirty = false;
        });
    }

    /// Write the index when it changed since the last write.
    pub fn persist(&self) {
        let Some((path, raw)) = self.with(|s| {
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

    fn bump_chat(&self, chat: &str, at: i64) {
        self.with(|s| {
            let slot = s.recents.chats.entry(chat.to_string()).or_insert(0);
            *slot = (*slot).max(at);
            s.dirty = true;
        });
    }

    async fn note_changed(
        &self,
        store: &Db,
        subject: &Subject,
        resource: &Resource,
        is_new: bool,
        from_commit: bool,
    ) {
        let id = subject.to_string();
        if is_activity_noise(&id, resource) {
            return;
        }
        let drive = match resource.get(urls::DRIVE_PROP) {
            Ok(drive) => drive.to_string(),
            Err(_) => return,
        };
        let first_seen = self.with(|s| s.recents.activity.iter().all(|a| a.subject != id));
        let (actor, at, created) = attribute(store, &id, resource, is_new, from_commit, first_seen);
        let new = Activity {
            subject: id,
            drive,
            kind: if created {
                ActivityKind::Created
            } else {
                ActivityKind::Changed
            },
            at,
            actor,
            name: name_of(resource),
            class_name: class_name_of(store, resource).await,
        };
        self.with(|s| {
            record_activity(&mut s.recents, new);
            s.dirty = true;
        });
    }

    /// A deletion is logged only for a resource the log already knows: once it
    /// is gone its name cannot be read, and an entry without one says nothing.
    fn note_destroyed(&self, subject: &str, actor: Option<String>) {
        self.with(|s| {
            let Some(old) = s.recents.activity.iter().find(|a| a.subject == subject) else {
                return;
            };
            let new = Activity {
                kind: ActivityKind::Deleted,
                at: crate::utils::now(),
                actor,
                ..old.clone()
            };
            record_activity(&mut s.recents, new);
            s.dirty = true;
        });
    }

    /// Fold one store event into the index.
    pub async fn handle_event(&self, store: &Db, event: DbEvent) {
        match event {
            DbEvent::Changed {
                subject,
                is_new,
                from_commit,
                ..
            } => {
                let Ok(resource) = store.get_resource(&subject).await else {
                    return;
                };
                if is_ai_chat(&resource) {
                    self.bump_chat(&subject.to_string(), 0);
                } else if crate::hierarchy::is_chat_log(&resource) {
                    let Ok(parent) = resource.get(urls::PARENT) else {
                        return;
                    };
                    let parent = parent.to_string();
                    // A chat room or a meeting keeps its messages in the same
                    // log pages; only an AI chat's belong in this index. A
                    // parent not here yet is taken for one (its own event
                    // sorts it out).
                    let other_owner = store
                        .get_resource_shallow(&Subject::from(parent.as_str()))
                        .is_ok_and(|owner| !is_ai_chat(&owner));
                    if !other_owner {
                        self.bump_chat(&parent, page_last_activity(&resource));
                    }
                } else {
                    self.note_changed(store, &subject, &resource, is_new, from_commit)
                        .await;
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
                self.note_destroyed(&subject, actor);
                self.with(|s| {
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

    /// Keep the index current for as long as the store lives: fold its
    /// events in and write the index once it is quiet (half a second) or after
    /// two seconds of streaming. Needs a tokio runtime.
    pub fn spawn_listener(self: std::sync::Arc<Self>, store: std::sync::Arc<Db>) {
        use std::time::{Duration, Instant};
        use tokio::sync::broadcast::error::RecvError;

        let mut rx = store.subscribe_events();
        self.listening
            .store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            let mut dirty_since: Option<Instant> = None;
            loop {
                match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                    Ok(Ok(event)) => self.handle_event(&store, event).await,
                    // Events were dropped: what the index knows may be stale.
                    Ok(Err(RecvError::Lagged(_))) => self.with(|s| s.recents.chats_scanned = false),
                    Ok(Err(RecvError::Closed)) => break,
                    // Quiet: a good moment to rescan what a lag left stale.
                    Err(_) => {
                        if !self.with(|s| s.recents.chats_scanned) {
                            let _ = self.ensure_scanned(&store).await;
                        }
                    }
                }
                if self.with(|s| s.dirty) {
                    let since = *dirty_since.get_or_insert_with(Instant::now);
                    // Quiet for half a second, or two seconds of streaming.
                    if since.elapsed() >= Duration::from_secs(2) || rx.is_empty() {
                        self.persist();
                        dirty_since = None;
                    }
                }
            }
            self.persist();
        });
    }

    /// Fill the chat index from the store the first time it is asked for.
    pub async fn ensure_scanned(&self, store: &Db) -> AtomicResult<()> {
        if self.with(|s| s.recents.chats_scanned) {
            return Ok(());
        }
        let _scanning = self.scanning.lock().await;
        if self.with(|s| s.recents.chats_scanned) {
            return Ok(());
        }
        let found = store
            .query(&crate::storelike::Query::new_class(AI_CHAT))
            .await?;
        for subject in &found.subjects {
            let subject = subject.to_string();
            let last = chat_last_activity(store, &subject).await?;
            self.bump_chat(&subject, last);
        }
        self.with(|s| {
            s.recents.chats_scanned = true;
            s.dirty = true;
        });
        Ok(())
    }

    /// The `limit` newest chats as `(subject, name, last_activity)`.
    pub async fn recent_chats(
        &self,
        store: &Db,
        limit: usize,
    ) -> AtomicResult<Vec<(String, String, i64)>> {
        // An index that lost events (a lagged listener) still lists what it
        // has; the listener rescans every chat once the events calm down
        // (0.9 s for 1000 chats). Only an index without chats waits for it.
        let listening = self.listening.load(std::sync::atomic::Ordering::Relaxed);
        if !listening || self.with(|s| s.recents.chats.is_empty()) {
            self.ensure_scanned(store).await?;
        }
        let mut chats: Vec<(String, i64)> = self.with(|s| {
            s.recents
                .chats
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect()
        });
        chats.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut out = Vec::new();
        for (subject, last) in chats {
            if out.len() >= limit {
                break;
            }
            // A chat that is gone (or not here yet) is left out, not an error.
            let Some(resource) = row_resource(store, &Subject::from(subject.as_str())).await else {
                continue;
            };
            // Indexes written before chat rooms were told apart hold them.
            if !is_ai_chat(&resource) {
                continue;
            }
            out.push((subject, name_of(&resource), last));
        }
        Ok(out)
    }

    /// The `limit` newest activity entries, newest first.
    pub fn activity(&self, limit: usize) -> Vec<Activity> {
        self.with(|s| s.recents.activity.iter().take(limit).cloned().collect())
    }

    /// Remember that this device opened `subject` in `drive` at `at` (ms).
    pub fn note_opened(&self, drive: &str, subject: &str, at: i64) {
        self.with(|s| {
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

    /// When the person last used `drive` here (ms, 0 for never): the newest
    /// of the times this device opened the drive or anything in it, and of
    /// the changes `own` (the person's agent) made to the drive or in it.
    pub fn drive_last_used(&self, drive: &str, own: Option<&str>) -> i64 {
        let key = crate::identifiers::canonicalize_scheme(&drive_id(drive));
        self.with(|s| {
            let opened = s
                .recents
                .drives
                .iter()
                .filter(|(k, _)| crate::identifiers::canonicalize_scheme(k) == key)
                .flat_map(|(_, r)| r.opened.values().copied())
                .max()
                .unwrap_or(0);
            let edited = s
                .recents
                .activity
                .iter()
                .filter(|a| {
                    own.is_some_and(|own| {
                        a.actor
                            .as_deref()
                            .is_some_and(|actor| same_agent(actor, own))
                    }) && [&a.drive, &a.subject]
                        .iter()
                        .any(|d| crate::identifiers::canonicalize_scheme(&drive_id(d)) == key)
                })
                .map(|a| a.at)
                .max()
                .unwrap_or(0);
            opened.max(edited)
        })
    }

    /// The `limit` most recently opened resources of `drive`, newest first.
    pub fn opened(&self, drive: &str, limit: usize) -> Vec<(String, i64)> {
        let mut all: Vec<(String, i64)> = self.with(|s| {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{lists, test_support::Device};

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
    fn two_agents_on_one_resource_are_two_entries() {
        let mut r = Recents::default();
        record_activity(&mut r, entry("a", ActivityKind::Changed, 1_000));
        let mut other = entry("a", ActivityKind::Changed, 2_000);
        other.actor = Some("did:ad:agent:b".into());
        record_activity(&mut r, other.clone());
        // The first agent again, in the other spelling: still its own entry.
        let mut again = entry("a", ActivityKind::Changed, 3_000);
        again.actor = Some("atomic:agent:a".into());
        record_activity(&mut r, again);
        assert_eq!(
            log(&r),
            vec![
                ("a", ActivityKind::Changed, 3_000),
                ("a", ActivityKind::Changed, 2_000)
            ]
        );
        // A deletion ends them all.
        let mut gone = entry("a", ActivityKind::Deleted, 4_000);
        gone.name = String::new();
        record_activity(&mut r, gone);
        assert_eq!(log(&r), vec![("a", ActivityKind::Deleted, 4_000)]);
        assert_eq!(r.activity[0].name, "name of a");
    }

    #[tokio::test]
    async fn own_changes_are_left_out_in_any_spelling() {
        let d = Device::new().await;
        let own = d.store.get_default_agent().unwrap().subject.to_string();
        // The other spelling of the own agent than the store uses.
        let as_atomic = match own.strip_prefix("atomic:") {
            Some(rest) => format!("did:ad:{rest}"),
            None => crate::identifiers::canonicalize_scheme(&own),
        };
        assert_ne!(own, as_atomic);
        let other = crate::agents::Agent::new(None).unwrap().subject.to_string();
        d.recents.with(|s| {
            for (subject, actor, at) in [
                ("did:ad:mine", own.as_str(), 1_000),
                ("did:ad:mine-too", as_atomic.as_str(), 2_000),
                ("did:ad:theirs", other.as_str(), 3_000),
            ] {
                let mut e = entry(subject, ActivityKind::Changed, at);
                e.actor = Some(actor.into());
                e.drive = d.drive.clone();
                record_activity(&mut s.recents, e);
            }
            let mut unknown = entry("did:ad:nobody-knows", ActivityKind::Changed, 4_000);
            unknown.actor = None;
            record_activity(&mut s.recents, unknown);
        });
        let profiles = crate::host::profiles::AgentProfiles::none();
        let list = lists::list_activity(&d.store, &d.recents, &profiles, None, 500).await;
        let subjects: Vec<&str> = list.iter().map(|a| a.subject.as_str()).collect();
        assert_eq!(subjects, ["did:ad:theirs"]);
        assert_ne!(list[0].actor, "Someone");
        // The drive filter reads both spellings of the drive.
        let drive_atomic = crate::identifiers::canonicalize_scheme(&d.drive);
        assert_eq!(
            lists::list_activity(&d.store, &d.recents, &profiles, Some(&drive_atomic), 500)
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_resource_that_arrived_as_plain_state_is_its_creators() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        // Bob makes a folder in the drive on his own device.
        let elsewhere = Db::init_redb(None).await.unwrap();
        let bob = crate::agents::Agent::new(Some("Bob")).unwrap();
        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            crate::Value::ResourceArray(vec![urls::FOLDER.into()]),
        );
        builder.set(
            urls::NAME.into(),
            crate::Value::String("Bob's folder".into()),
        );
        builder.set(
            urls::PARENT.into(),
            crate::Value::AtomicUrl(d.drive.as_str().into()),
        );
        builder.set(
            urls::DRIVE_PROP.into(),
            crate::Value::AtomicUrl(d.drive.as_str().into()),
        );
        let commit = crate::Commit::create_did(builder, &bob, &elsewhere)
            .await
            .unwrap();
        let subject = commit.subject.to_string();
        elsewhere
            .apply_commit(
                commit,
                &crate::commit::CommitOpts::no_validations_no_index(),
            )
            .await
            .unwrap();
        let state = elsewhere.get_loro_snapshot_bytes(&subject).unwrap();
        // It reaches this device as the server sends it: state, no commit.
        crate::sync::ws_apply::apply_state_update(&d.store, &subject, &state)
            .await
            .unwrap();
        // And a resource that names nobody.
        let anonymous = d
            .synced("did:ad:anonymous-note", &d.drive, "Anonymous", None, None)
            .await;
        d.pump(&mut rx).await;

        let raw = d.recents.activity(500);
        let bobs = raw.iter().find(|a| a.subject == subject).unwrap();
        assert!(same_agent(
            bobs.actor.as_deref().unwrap(),
            &bob.subject.to_string()
        ));
        assert_eq!(bobs.kind, ActivityKind::Created);
        let profiles = crate::host::profiles::AgentProfiles::none();
        let list = lists::list_activity(&d.store, &d.recents, &profiles, None, 500).await;
        assert!(list
            .iter()
            .any(|a| a.subject == subject && a.name == "Bob's folder"));
        assert!(list.iter().all(|a| a.subject != anonymous));
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
        assert_eq!(r.activity.iter().take(3).count(), 3);
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
        let dir = std::env::temp_dir().join(format!(
            "recents-activity-{}-{}",
            std::process::id(),
            crate::utils::random_string(6)
        ));
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

    #[tokio::test]
    async fn the_index_is_kept_in_the_directory_it_was_loaded_from() {
        let dir = std::env::temp_dir().join(format!(
            "recents-load-{}-{}",
            std::process::id(),
            crate::utils::random_string(6)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let index = RecentsIndex::new();
        index.load(&dir);
        index.note_opened("did:ad:drive", "did:ad:a", 7);
        index.persist();

        let again = RecentsIndex::new();
        again.load(&dir);
        assert_eq!(
            again.opened("did:ad:drive", 10),
            [("did:ad:a".to_string(), 7)]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With a listener running, a list does not wait for the rescan a lag
    /// asked for: it shows what the index has, and the rescan (which the
    /// listener runs once the events calm down) adds the rest.
    #[tokio::test]
    async fn a_lagged_index_lists_what_it_has_until_the_rescan() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let known = d.new_chat("Known chat").await;
        d.pump(&mut rx).await;
        let missed = d.new_chat("Missed chat").await;
        d.recents
            .listening
            .store(true, std::sync::atomic::Ordering::Relaxed);
        d.recents.with(|s| s.recents.chats_scanned = false);

        let has = |chats: &[(String, String, i64)], chat: &str| chats.iter().any(|c| c.0 == chat);
        let chats = d.recents.recent_chats(&d.store, 500).await.unwrap();
        assert!(has(&chats, &known) && !has(&chats, &missed));

        d.recents.ensure_scanned(&d.store).await.unwrap();
        let chats = d.recents.recent_chats(&d.store, 500).await.unwrap();
        assert!(has(&chats, &known) && has(&chats, &missed));
    }

    #[tokio::test]
    async fn recents_follow_the_commits_without_rescanning() {
        let d = Device::new().await;
        // From here on only events can tell the index about new chats.
        d.recents.ensure_scanned(&d.store).await.unwrap();
        let mut rx = d.store.subscribe_events();

        let first = d.new_chat("Recents first").await;
        let second = d.new_chat("Recents second").await;
        d.add_page(
            &first,
            &[("1-00000001", d.ai_entry("user", "hi", 5_000_000))],
        )
        .await;
        d.add_page(
            &second,
            &[("1-00000001", d.ai_entry("user", "hi", 4_000_000))],
        )
        .await;
        d.add_page(
            &second,
            &[("2-00000002", d.ai_entry("user", "again", 6_000_000))],
        )
        .await;
        d.pump(&mut rx).await;

        let chats = d.recents.recent_chats(&d.store, 500).await.unwrap();
        let at = |chat: &str| chats.iter().position(|(subject, _, _)| subject == chat);
        let (second_at, first_at) = (at(&second).unwrap(), at(&first).unwrap());
        assert!(second_at < first_at);
        assert_eq!(
            chats[second_at],
            (second.clone(), "Recents second".to_string(), 6_000_000)
        );
        assert_eq!(
            chats[first_at],
            (first.clone(), "Recents first".to_string(), 5_000_000)
        );
        let one = d.recents.recent_chats(&d.store, 1).await.unwrap();
        assert_eq!(one.len(), 1);
    }

    #[tokio::test]
    async fn a_meetings_messages_do_not_make_it_an_ai_chat() {
        let d = Device::new().await;
        d.recents.ensure_scanned(&d.store).await.unwrap();
        let mut rx = d.store.subscribe_events();
        let meeting = d
            .store
            .create_resource(urls::FOLDER, &d.drive, "Standup", None)
            .await
            .unwrap();
        d.add_page(
            &meeting,
            &[("1-00000001", d.ai_entry("user", "hello team", 7_000_000))],
        )
        .await;
        d.pump(&mut rx).await;
        let chats = d.recents.recent_chats(&d.store, 500).await.unwrap();
        assert!(
            chats.iter().all(|(subject, _, _)| subject != &meeting),
            "{chats:?}"
        );
        // Also when an older index already holds it.
        d.recents
            .with(|s| s.recents.chats.insert(meeting.clone(), 7_000_000));
        let chats = d.recents.recent_chats(&d.store, 500).await.unwrap();
        assert!(chats.iter().all(|(subject, _, _)| subject != &meeting));
    }

    #[tokio::test]
    async fn recents_drop_destroyed_chats() {
        let d = Device::new().await;
        d.recents.ensure_scanned(&d.store).await.unwrap();
        let mut rx = d.store.subscribe_events();
        let chat = d.new_chat("Recents doomed").await;
        d.pump(&mut rx).await;
        let listed =
            |list: &[serde_json::Value]| list.iter().any(|c| c["subject"] == chat.as_str());
        assert!(listed(
            &lists::list_ai_chats(&d.store, &d.recents, 500)
                .await
                .unwrap()
        ));

        d.store
            .remove_resource(&chat.as_str().into())
            .await
            .unwrap();
        d.pump(&mut rx).await;
        assert!(!listed(
            &lists::list_ai_chats(&d.store, &d.recents, 500)
                .await
                .unwrap()
        ));
    }
}
