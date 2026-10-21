//! The home screen's lists and search, as JSON rows. Each list reads local
//! propvals only: it never waits on the network and never decodes a Loro doc
//! per row.

use super::{
    own_profile::own_profile,
    profiles::{same_agent, short_agent, AgentProfiles},
    recents::{ActivityKind, RecentsIndex},
    rows::{emoji_of, first_class, name_of, resource_row, row_resource, with_icon, DriveCache},
};
use crate::{errors::AtomicResult, Db, Storelike, Subject};
use serde_json::{json, Value as Json};
use std::collections::HashMap;

/// The emojis of `subjects` as `{subject: emoji}`, only for those that have
/// one. For rows that do not carry their icon themselves (the activity feed),
/// read from the stored propvals like the other rows.
pub async fn resource_icons(store: &Db, subjects: Vec<String>) -> serde_json::Map<String, Json> {
    let mut out = serde_json::Map::new();
    for subject in subjects {
        let Some(resource) = row_resource(store, &Subject::from(subject.as_str())).await else {
            continue;
        };
        let emoji = emoji_of(&resource);
        if !emoji.is_empty() {
            out.insert(subject, json!(emoji));
        }
    }
    out
}

/// The newest `limit` AI chats of the person (all drives), newest activity
/// first, as `[{subject, name, last_activity}]` (`last_activity` in ms, 0 when
/// empty). Read from the recents index, not rebuilt from the chats' pages.
pub async fn list_ai_chats(
    store: &Db,
    recents: &RecentsIndex,
    limit: usize,
) -> AtomicResult<Vec<Json>> {
    list_ai_chats_page(store, recents, 0, limit).await
}

/// [`list_ai_chats`] for paging: `limit` chats after the `offset` newest
/// ones. A page shorter than `limit` is the last.
pub async fn list_ai_chats_page(
    store: &Db,
    recents: &RecentsIndex,
    offset: usize,
    limit: usize,
) -> AtomicResult<Vec<Json>> {
    Ok(recents
        .recent_chats_page(store, offset, limit)
        .await?
        .into_iter()
        .map(|(subject, name, last)| json!({ "subject": subject, "name": name, "last_activity": last }))
        .collect())
}

/// One line of the activity feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRow {
    pub subject: String,
    pub drive: String,
    pub kind: ActivityKind,
    /// Unix ms.
    pub at: i64,
    /// Subject of the agent that did it (never this device's own agent).
    pub actor_subject: String,
    /// Display name of that agent: its name when the store or the server's
    /// profile has one, else the start of its key (`a3f9…`).
    pub actor: String,
    pub name: String,
    pub class_name: String,
}

/// How long [`list_activity`] waits for the server's profiles of agents it
/// cannot name from the store. The lookups go on after it; the next read has
/// the names.
const PROFILE_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// The name of `agent` as far as this device knows it without waiting: the
/// own agent's from its profile ([`own_profile`]), another agent's from its
/// resource in the store, else from the server's profile cache (starting a
/// lookup when it is not cached). `None` when nothing names it yet.
pub async fn agent_name(store: &Db, profiles: &AgentProfiles, agent: &str) -> Option<String> {
    let own = store.get_default_agent().ok();
    if own
        .as_ref()
        .is_some_and(|own| same_agent(&own.subject.to_string(), agent))
    {
        if let Some(name) = own.as_ref().and_then(|own| own.name.clone()) {
            if !name.trim().is_empty() {
                return Some(name);
            }
        }
        return own_profile(store, profiles)
            .await
            .ok()
            .and_then(|p| p["name"].as_str().map(str::to_string))
            .filter(|n| !n.trim().is_empty());
    }
    if let Some(name) = row_resource(store, &Subject::from(agent))
        .await
        .map(|r| name_of(&r))
        .filter(|n| !n.trim().is_empty())
    {
        return Some(name);
    }
    profiles
        .name_or_prefetch(agent)
        .filter(|n| !n.trim().is_empty())
}

/// What other agents changed lately in the person's drives, newest first, by
/// whom; `drive` keeps one drive's. This device's own agent's changes are
/// left out (they are in Recents), in any spelling of its subject, and so are
/// changes nobody can be named for (see [`super::recents`]). Read from the
/// recents index, which the store's change events keep.
pub async fn list_activity(
    store: &Db,
    recents: &RecentsIndex,
    profiles: &AgentProfiles,
    drive: Option<&str>,
    limit: usize,
) -> Vec<ActivityRow> {
    list_activity_with(store, recents, profiles, drive, limit, false).await
}

/// The feed's entries in paging order (newest first, ties by subject): those
/// after `before` (an entry's `(at, subject)`), at most `limit`.
fn activity_entries(
    recents: &RecentsIndex,
    own: Option<&str>,
    drive: Option<&str>,
    before: Option<(i64, &str)>,
    limit: usize,
    include_own: bool,
) -> Vec<super::recents::Activity> {
    let mut entries: Vec<_> = recents
        .activity(usize::MAX)
        .into_iter()
        .filter(|a| {
            let Some(actor) = a.actor.as_deref() else {
                return false;
            };
            if !include_own && own.is_some_and(|own| same_agent(own, actor)) {
                return false;
            }
            drive.is_none_or(|d| drive_key(&a.drive) == d)
        })
        .collect();
    entries.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.subject.cmp(&b.subject)));
    entries
        .into_iter()
        .filter(|a| {
            before.is_none_or(|(at, subject)| {
                a.at < at || (a.at == at && a.subject.as_str() > subject)
            })
        })
        .take(limit)
        .collect()
}

/// One page of the full Activity feed: the entries after `before` (the
/// `(at, subject)` of the last entry of the previous page; `None` for the
/// newest), newest first, at most `limit`. A page shorter than `limit` is the
/// end of the feed.
pub async fn list_activity_page(
    store: &Db,
    recents: &RecentsIndex,
    profiles: &AgentProfiles,
    before: Option<(i64, &str)>,
    limit: usize,
    include_own: bool,
) -> Vec<ActivityRow> {
    list_activity_rows(store, recents, profiles, None, before, limit, include_own).await
}

/// [`list_activity`], with the person's own changes too when `include_own`
/// (the feed's "Show mine"); those are by `You`.
pub async fn list_activity_with(
    store: &Db,
    recents: &RecentsIndex,
    profiles: &AgentProfiles,
    drive: Option<&str>,
    limit: usize,
    include_own: bool,
) -> Vec<ActivityRow> {
    list_activity_rows(store, recents, profiles, drive, None, limit, include_own).await
}

async fn list_activity_rows(
    store: &Db,
    recents: &RecentsIndex,
    profiles: &AgentProfiles,
    drive: Option<&str>,
    before: Option<(i64, &str)>,
    limit: usize,
    include_own: bool,
) -> Vec<ActivityRow> {
    let own = store
        .get_default_agent()
        .ok()
        .map(|a| a.subject.to_string());
    let drive = drive.map(drive_key);
    let entries = activity_entries(
        recents,
        own.as_deref(),
        drive.as_deref(),
        before,
        limit,
        include_own,
    );

    let mut names: HashMap<String, Option<String>> = Default::default();
    for a in &entries {
        let agent = a.actor.clone().unwrap_or_default();
        if let std::collections::hash_map::Entry::Vacant(slot) = names.entry(agent.clone()) {
            slot.insert(agent_name(store, profiles, &agent).await);
        }
    }
    // Give the server's profiles a moment; the lookups started above.
    let unnamed: Vec<String> = names
        .iter()
        .filter(|(_, n)| n.is_none())
        .map(|(a, _)| a.clone())
        .collect();
    if !unnamed.is_empty() {
        let lookups = futures::future::join_all(unnamed.iter().map(|a| profiles.get(a)));
        let _ = tokio::time::timeout(PROFILE_WAIT, lookups).await;
        for agent in unnamed {
            let name = profiles.name_or_prefetch(&agent);
            names.insert(agent, name);
        }
    }

    entries
        .into_iter()
        .map(|a| {
            let actor_subject = a.actor.unwrap_or_default();
            let actor = if own
                .as_deref()
                .is_some_and(|own| same_agent(own, &actor_subject))
            {
                "You".to_string()
            } else {
                names
                    .get(&actor_subject)
                    .cloned()
                    .flatten()
                    .unwrap_or_else(|| short_agent(&actor_subject))
            };
            ActivityRow {
                subject: a.subject,
                drive: a.drive,
                kind: a.kind,
                at: a.at,
                actor_subject,
                actor,
                name: a.name,
                class_name: a.class_name,
            }
        })
        .collect()
}

/// Put `drives` in the order every drive list shows them: the `active`
/// drive first, then the most recently used (opened here, or changed by the
/// person: [`RecentsIndex::drive_last_used`]), then the never-used ones by
/// name. `subject_and_name` reads a drive's subject and name.
pub fn order_drives_by_use<T>(
    store: &Db,
    recents: &RecentsIndex,
    drives: Vec<T>,
    subject_and_name: impl Fn(&T) -> (&str, &str),
) -> Vec<T> {
    let own = store
        .get_default_agent()
        .ok()
        .map(|a| a.subject.to_string());
    let active = store.get_active_drive().map(|d| drive_key(&d));
    let mut keyed: Vec<(bool, i64, String, T)> = drives
        .into_iter()
        .map(|d| {
            let (subject, name) = subject_and_name(&d);
            (
                active.as_deref() == Some(drive_key(subject).as_str()),
                recents.drive_last_used(subject, own.as_deref()),
                name.to_lowercase(),
                d,
            )
        })
        .collect();
    // Stable: equal drives keep the store's order.
    keyed.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(b.1.cmp(&a.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    keyed.into_iter().map(|k| k.3).collect()
}

/// A drive's subject in one spelling (`did:ad:` / `atomic:`, without a
/// query), for comparing drives.
fn drive_key(drive: &str) -> String {
    crate::identifiers::canonicalize_scheme(&Subject::from(drive).pure_id())
}

/// The `limit` resources of `drive` this device opened last, newest first, as
/// `[{subject, title, class_name, opened_at, emoji?}]`. Resources that are
/// gone are left out.
pub async fn list_recent_resources(
    store: &Db,
    recents: &RecentsIndex,
    drive: &str,
    limit: usize,
) -> Vec<Json> {
    let mut out = Vec::new();
    let opened = recents.opened(drive, limit * 2);
    tracing::info!("[recents] {} opened in {drive}", opened.len());
    for (subject, opened_at) in opened {
        if out.len() >= limit {
            break;
        }
        let Some(resource) = row_resource(store, &Subject::from(subject.as_str())).await else {
            tracing::warn!("[recents] {subject} not readable");
            continue;
        };
        out.push(resource_row(store, &subject, &resource, ("opened_at", json!(opened_at))).await);
    }
    out
}

/// The subjects in a list property of the agent's private drive (the web
/// app's "home index"), in stored order; empty when there is no such drive or
/// list yet.
pub async fn private_drive_list(store: &Db, property: &str) -> AtomicResult<Vec<String>> {
    let home = store.private_drive_subject()?;
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

/// The first subject in a single-valued link property of the private drive
/// (a "standard location" such as the Inbox), `None` when unset or when the
/// drive is not on this device.
pub async fn private_drive_list_one(store: &Db, property: &str) -> AtomicResult<Option<String>> {
    let home = store.private_drive_subject()?;
    let Ok(drive) = store.get_resource(&Subject::from(home.as_str())).await else {
        return Ok(None);
    };
    Ok(drive
        .get(property)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .and_then(|list| list.into_iter().next()))
}

/// The person's favorites (all drives), newest added first, as
/// `[{subject, title, class_name, opened_at, emoji?}]` (`opened_at` is always
/// 0). Favorites that are gone or unreadable are left out.
pub async fn list_favorites(store: &Db, limit: usize) -> AtomicResult<Vec<Json>> {
    let mut out = Vec::new();
    // The web app appends, so the last one listed is the newest.
    for subject in private_drive_list(store, super::rows::FAVORITES)
        .await?
        .into_iter()
        .rev()
    {
        if out.len() >= limit {
            break;
        }
        let Some(resource) = row_resource(store, &Subject::from(subject.as_str())).await else {
            continue;
        };
        out.push(resource_row(store, &subject, &resource, ("opened_at", json!(0))).await);
    }
    Ok(out)
}

/// Full-text search (type-ahead on the last word) across every drive of the
/// store, or only in `drive` when given (and not empty), as
/// `[{subject, title, class_name, drive, score, emoji?}]`, best first; `drive`
/// is the drive the hit lives in ("" when unknown).
///
/// Across every drive, what lives in a drive (the person's own things) comes
/// before what does not (the built-in ontologies' classes and properties):
/// otherwise a short query such as "re" listed only `requested-subject`-like
/// properties and never the person's "Recipes".
pub fn search(
    store: &Db,
    drive: Option<&str>,
    query: &str,
    limit: usize,
) -> AtomicResult<Vec<Json>> {
    search_classes(store, drive, query, limit, &[])
}

/// The class URL a search `class` names: a URL as is, or the shortname the
/// app uses for a kind of thing (`drive`, `aichat`, `conversation`,
/// `chatroom`; case and punctuation do not matter).
fn search_class_url(class: &str) -> AtomicResult<String> {
    if class.contains("://") {
        return Ok(class.to_string());
    }
    let key: String = class
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    Ok(match key.as_str() {
        "drive" => crate::urls::DRIVE,
        "aichat" => super::rows::AI_CHAT,
        "conversation" => crate::urls::CONVERSATION,
        "chatroom" => crate::urls::CHATROOM,
        _ => return Err(format!("Unknown search class {class:?}").into()),
    }
    .to_string())
}

/// [`search`] for only the resources of one of `classes` (none: any). The
/// class is filtered in the index, before the result limit: a query whose
/// best twenty are documents still finds the chat in place 21.
pub fn search_classes(
    store: &Db,
    drive: Option<&str>,
    query: &str,
    limit: usize,
    classes: &[String],
) -> AtomicResult<Vec<Json>> {
    let scoped = drive.is_some_and(|d| !d.is_empty());
    // Room to move the person's things forward past schema hits.
    let fetch = if scoped {
        limit
    } else {
        limit.saturating_mul(4)
    };
    let parents = drive.filter(|d| !d.is_empty()).map(|d| vec![d.to_string()]);
    let hits = if classes.is_empty() {
        let opts = crate::client::search::SearchOpts {
            limit: Some(fetch as u32),
            parents,
            ..Default::default()
        };
        crate::search::query(store, query.trim(), &opts)?
    } else {
        // One indexed filter per class (a kind can be two classes, such as
        // conversations and chat rooms), merged best first.
        let mut hits = Vec::new();
        for class in classes {
            let opts = crate::client::search::SearchOpts {
                limit: Some(fetch as u32),
                parents: parents.clone(),
                filter_pairs: Some(vec![(
                    crate::urls::IS_A.to_string(),
                    search_class_url(class)?,
                )]),
                ..Default::default()
            };
            hits.extend(crate::search::query(store, query.trim(), &opts)?);
        }
        if classes.len() > 1 {
            hits.sort_by(|a, b| b.score.total_cmp(&a.score));
            let mut seen = std::collections::HashSet::new();
            hits.retain(|h| seen.insert(h.subject.to_string()));
        }
        hits
    };

    // Local propvals only, and each parent / class is looked up once per
    // query: a search never waits on the network and never decodes a Loro doc.
    let mut drives = DriveCache::default();
    let mut classes: HashMap<String, String> = Default::default();
    let mut out = Vec::new();
    for hit in hits.into_iter().take(fetch) {
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
        out.push(with_icon(
            store,
            json!({
                "subject": hit.subject.to_string(),
                "title": name_of(&resource),
                "class_name": class_name,
                "score": hit.score,
                "drive": drives.of(store, &resource),
            }),
            &resource,
        ));
    }
    if !scoped {
        // Stable: within each group the search's own order stays.
        out.sort_by_key(|row| row["drive"].as_str().is_none_or(str::is_empty));
    }
    out.truncate(limit);
    Ok(out)
}

/// Read the search trees once so the first keystroke does not find them
/// cold (9-62 ms on a desktop, about 200 ms on a phone). Run it on a
/// background thread once the first screen is drawn: it only reads, with a
/// few short queries of the lengths people start with.
pub fn warm_search(store: &Db) {
    let opts = crate::client::search::SearchOpts {
        limit: Some(5),
        ..Default::default()
    };
    for probe in ["e", "a", "te", "sea", "meeting"] {
        let _ = crate::search::query(store, probe, &opts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{rows::FAVORITES, test_support::Device};
    use crate::urls;

    fn find(rows: &[Json], subject: &str) -> Json {
        rows.iter()
            .find(|r| r["subject"] == subject)
            .unwrap_or_else(|| panic!("{subject} not in {rows:?}"))
            .clone()
    }

    fn has(rows: &[Json], subject: &str) -> bool {
        rows.iter().any(|r| r["subject"] == subject)
    }

    #[tokio::test]
    async fn chats_are_listed_by_last_activity() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let old = d.new_chat("Assistant old chat").await;
        let new = d.new_chat("Assistant new chat").await;
        let empty = d.new_chat("Assistant empty chat").await;
        d.add_page(&old, &[("1-00000001", d.ai_entry("user", "hi", 1_000))])
            .await;
        d.add_page(&new, &[("1-00000001", d.ai_entry("user", "hi", 9_000))])
            .await;

        d.pump(&mut rx).await;
        let list = list_ai_chats(&d.store, &d.recents, 50).await.unwrap();
        let position = |subject: &str| list.iter().position(|c| c["subject"] == subject).unwrap();
        assert!(position(&new) < position(&old));
        assert!(position(&old) < position(&empty));
        assert_eq!(list[position(&new)]["name"], "Assistant new chat");
        assert_eq!(list[position(&new)]["last_activity"], 9_000);
        assert_eq!(list[position(&empty)]["last_activity"], 0);
    }

    #[tokio::test]
    async fn the_chat_list_leaves_out_other_classes() {
        let d = Device::new().await;
        let folder = d
            .store
            .create_resource(urls::FOLDER, &d.drive, "Not a chat", None)
            .await
            .unwrap();
        let list = list_ai_chats(&d.store, &d.recents, 50).await.unwrap();
        assert!(!has(&list, &folder));
    }

    #[tokio::test]
    async fn the_chats_of_every_drive_are_listed() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let second = d.store.create_drive("Second drive").await.unwrap();
        assert_ne!(second, d.drive);
        d.store.set_active_drive(&d.drive).unwrap();
        let there = d
            .store
            .create_resource(
                super::super::rows::AI_CHAT,
                &second,
                "Chat in the second drive",
                None,
            )
            .await
            .unwrap();
        let here = d.new_chat("Chat in the first drive").await;
        d.pump(&mut rx).await;
        let list = list_ai_chats(&d.store, &d.recents, 500).await.unwrap();
        assert!(has(&list, &there) && has(&list, &here));
    }

    #[tokio::test]
    async fn search_is_scoped_to_the_given_drive() {
        let d = Device::new().await;
        let chat = d.new_chat("Quokka scoping chat").await;
        let hits = search(
            &d.store,
            Some("https://example.test/not-this-drive"),
            "quokka",
            5,
        )
        .unwrap();
        assert!(!has(&hits, &chat));
        let hits = search(&d.store, Some(&d.drive), "quokka", 5).unwrap();
        assert!(has(&hits, &chat));
    }

    #[tokio::test]
    async fn search_finds_a_prefix_with_title_and_class() {
        let d = Device::new().await;
        let chat = d.new_chat("Zebrafinch migration notes").await;
        let hits = search(&d.store, Some(&d.drive), "zebraf", 5).unwrap();
        let hit = find(&hits, &chat);
        assert_eq!(hit["title"], "Zebrafinch migration notes");
        assert!(hit["score"].as_f64().unwrap() > 0.0);
        assert!(hit["class_name"].as_str().is_some_and(|c| !c.is_empty()));

        let none = search(&d.store, Some(&d.drive), "qqqxxnothing", 5).unwrap();
        assert!(none.is_empty());
    }

    fn sync_subject(tag: &str, n: u64) -> String {
        format!("did:ad:{tag}{:0>58}{n:0>6}==", std::process::id())
    }

    #[tokio::test]
    async fn chats_are_paged_without_gaps_or_repeats() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let mut chats = Vec::new();
        for i in 0..23 {
            let chat = d.new_chat(&format!("Paged chat {i}")).await;
            d.add_page(
                &chat,
                &[("1-00000001", d.ai_entry("user", "hi", 1_000 + i * 10))],
            )
            .await;
            chats.push(chat);
        }
        d.pump(&mut rx).await;

        let all = list_ai_chats(&d.store, &d.recents, 1000).await.unwrap();
        assert_eq!(all.len(), 23);
        let mut paged = Vec::new();
        loop {
            let page = list_ai_chats_page(&d.store, &d.recents, paged.len(), 10)
                .await
                .unwrap();
            let last = page.len() < 10;
            paged.extend(page);
            if last {
                break;
            }
        }
        assert_eq!(paged, all);
        // Newest first; a page past the end is empty.
        assert_eq!(paged[0]["subject"], chats[22].as_str());
        assert!(list_ai_chats_page(&d.store, &d.recents, 23, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn the_class_filter_applies_before_the_result_limit() {
        let d = Device::new().await;
        for i in 0..12 {
            d.store
                .create_resource(urls::FOLDER, &d.drive, &format!("Quokka folder {i}"), None)
                .await
                .unwrap();
        }
        let chat = d.new_chat("Quokka chat with a longer title").await;
        let room = d
            .store
            .create_resource(urls::CHATROOM, &d.drive, "Quokka room with a title", None)
            .await
            .unwrap();

        // The best three are folders: the chat is not among them...
        let any = search(&d.store, None, "quokka", 3).unwrap();
        assert!(!has(&any, &chat));
        // ...but a filter on the class finds it, and only it.
        let chats = search_classes(&d.store, None, "quokka", 3, &["aichat".into()]).unwrap();
        assert_eq!(chats.len(), 1, "{chats:?}");
        assert!(has(&chats, &chat));
        // Several classes are merged; a class URL works like a shortname.
        let both = search_classes(
            &d.store,
            None,
            "quokka",
            5,
            &["ai-chat".into(), urls::CHATROOM.into()],
        )
        .unwrap();
        assert!(
            has(&both, &chat) && has(&both, &room) && both.len() == 2,
            "{both:?}"
        );
        assert!(search_classes(&d.store, None, "quokka", 3, &["nonsense".into()]).is_err());
        // Typing nothing yet lists none of a class; the filter keeps a drive scope.
        let scoped =
            search_classes(&d.store, Some(&d.drive), "quokka", 3, &["aichat".into()]).unwrap();
        assert!(has(&scoped, &chat));
    }

    #[tokio::test]
    async fn warming_the_search_changes_nothing() {
        let d = Device::new().await;
        d.store
            .create_resource(urls::FOLDER, &d.drive, "Zyzzyva notes", None)
            .await
            .unwrap();
        warm_search(&d.store);
        assert_eq!(search(&d.store, None, "zyzzyva", 5).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn search_finds_resources_delivered_by_sync() {
        let d = Device::new().await;
        let page = d
            .synced(
                &sync_subject("syncpage", 1),
                &d.drive,
                "Okapi delivered by sync",
                None,
                None,
            )
            .await;
        let hits = search(&d.store, Some(&d.drive), "okapi", 5).unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0]["title"], "Okapi delivered by sync");
        assert!(hits[0]["subject"].as_str().unwrap().ends_with(&page[9..]));
    }

    #[tokio::test]
    async fn search_covers_every_drive_and_names_the_hit_drive() {
        // Two drives, as sync delivers them: pages carrying their `drive`.
        let d = Device::new().await;
        let first = d.drive.clone();
        let second = "did:ad:searchsecond0000000000000000000000000000000000000000000000000000==";
        let here = d
            .synced(
                &sync_subject("syncpage", 2),
                &first,
                "Pangolin in the first drive",
                None,
                Some(&first),
            )
            .await;
        let there = d
            .synced(
                &sync_subject("syncpage", 3),
                second,
                "Pangolin in the second drive",
                None,
                Some(second),
            )
            .await;

        let hits = search(&d.store, None, "pangolin", 10).unwrap();
        let drive_of = |subject: &str| {
            hits.iter()
                .find(|h| h["subject"].as_str().unwrap().ends_with(&subject[9..]))
                .map(|h| h["drive"].as_str().unwrap().replace("atomic:", "did:ad:"))
        };
        assert_eq!(
            drive_of(&here).as_deref(),
            Some(first.replace("atomic:", "did:ad:").as_str())
        );
        assert_eq!(drive_of(&there).as_deref(), Some(second));

        // Scoping to one drive still works.
        let only = search(&d.store, Some(second), "pangolin", 10).unwrap();
        assert_eq!(only.len(), 1);
        assert!(only[0]["subject"].as_str().unwrap().ends_with(&there[9..]));
    }

    #[tokio::test]
    async fn search_lists_the_persons_things_before_schema() {
        let d = Device::new().await;
        // Schema outside any drive, with a title the query matches best.
        let mut schema = Vec::new();
        for i in 0..6 {
            schema.push(
                d.synced(
                    &sync_subject("schema", 700 + i),
                    "https://example.test/not-local/ontology",
                    "Wombat",
                    Some(urls::PROPERTY),
                    None,
                )
                .await,
            );
        }
        let mine = d
            .synced(
                &sync_subject("mine", 701),
                &d.drive,
                "Wombat recipes for the weekend",
                Some(urls::FOLDER),
                Some(&d.drive),
            )
            .await;
        let hits = search(&d.store, None, "wombat", 3).unwrap();
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert!(
            hits[0]["subject"].as_str().unwrap().ends_with(&mine[9..]),
            "{hits:?}"
        );
        assert!(hits[1..].iter().all(|h| h["drive"] == ""), "{hits:?}");
    }

    #[tokio::test]
    async fn search_finds_the_drive_through_local_parents_without_full_reads() {
        let d = Device::new().await;
        let mut parent = d.drive.clone();
        for i in 0..4 {
            parent = d
                .synced(
                    &sync_subject("bench", 900_000 + i),
                    &parent,
                    &format!("Chain {i}"),
                    Some(urls::FOLDER),
                    None,
                )
                .await;
        }
        let here = d
            .synced(
                &sync_subject("bench", 900_010),
                &parent,
                "Narwhal deep in a chain",
                Some(urls::FOLDER),
                None,
            )
            .await;
        let orphan = d
            .synced(
                &sync_subject("bench", 900_011),
                "did:ad:benchgoneorphan000000000000000000000000000000000000000000000000==",
                "Narwhal orphan",
                Some("https://example.invalid/class/never-local"),
                None,
            )
            .await;

        d.store.reset_fetch_counters();
        let hits = search(&d.store, None, "narwhal", 20).unwrap();
        assert_eq!(
            d.store.get_resource_call_count(),
            0,
            "a search reads locally"
        );
        let find = |s: &str| {
            hits.iter()
                .find(|h| h["subject"].as_str().unwrap().ends_with(&s[9..]))
        };
        let norm = |v: &Json| v.as_str().unwrap().replace("atomic:", "did:ad:");
        assert_eq!(
            norm(&find(&here).unwrap()["drive"]),
            d.drive.replace("atomic:", "did:ad:")
        );
        assert_eq!(find(&here).unwrap()["class_name"], "folder");
        let o = find(&orphan).unwrap();
        assert_eq!(o["drive"], "");
        assert_eq!(o["class_name"], "https://example.invalid/class/never-local");

        // Capped to the limit.
        assert_eq!(search(&d.store, None, "narwhal", 1).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn opened_resources_are_listed_newest_first_and_stay_local() {
        let d = Device::new().await;
        let a = d.new_chat("Opened a").await;
        let b = d.new_chat("Opened b").await;
        let before = d.store.get_resource(&a.as_str().into()).await.unwrap();
        d.recents.note_opened(&d.drive, &a, 1_000);
        d.recents.note_opened(&d.drive, &b, 2_000);
        d.recents.note_opened(&d.drive, &a, 3_000);
        d.recents
            .note_opened(&d.drive, "https://example.test/gone", 4_000);

        let list = list_recent_resources(&d.store, &d.recents, &d.drive, 10).await;
        let subjects: Vec<&str> = list
            .iter()
            .map(|r| r["subject"].as_str().unwrap())
            .collect();
        assert_eq!(subjects, [a.as_str(), b.as_str()]);
        assert_eq!(list[0]["title"], "Opened a");
        assert_eq!(list[0]["opened_at"], 3_000);

        // Opening is not an edit: the resource itself did not change.
        let after = d.store.get_resource(&a.as_str().into()).await.unwrap();
        assert_eq!(
            before.get(urls::LAST_COMMIT).map(|v| v.to_string()).ok(),
            after.get(urls::LAST_COMMIT).map(|v| v.to_string()).ok()
        );

        let limited = list_recent_resources(&d.store, &d.recents, &d.drive, 1).await;
        assert_eq!(limited.len(), 1);
    }

    #[tokio::test]
    async fn favorites_come_from_the_private_drive_newest_first() {
        let d = Device::new().await;
        let a = d.new_chat("Fav a").await;
        let b = d.new_chat("Fav b").await;
        d.set_home_list(FAVORITES, &[&a, "https://example.test/gone", &b])
            .await;

        let list = list_favorites(&d.store, 10).await.unwrap();
        let titles: Vec<&str> = list.iter().map(|r| r["title"].as_str().unwrap()).collect();
        assert_eq!(titles, ["Fav b", "Fav a"]);
        assert_eq!(list[0]["subject"], b.as_str());
        assert_eq!(list_favorites(&d.store, 1).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rows_carry_the_resources_icon_file_and_its_url() {
        let d = Device::new().await;
        let with = d.new_chat("Picture with").await;
        let without = d.new_chat("Picture without").await;
        let file = d.new_picture("https://example.test/download/pic.png").await;
        d.set_icon(&with, &file).await;
        d.recents.note_opened(&d.drive, &with, 1);
        d.recents.note_opened(&d.drive, &without, 2);
        d.set_home_list(FAVORITES, &[&with, &without]).await;

        let recent = list_recent_resources(&d.store, &d.recents, &d.drive, 500).await;
        let favs = list_favorites(&d.store, 50).await.unwrap();
        let hits = search(&d.store, Some(&d.drive), "picture", 20).unwrap();
        for rows in [&recent, &favs, &hits] {
            let row = find(rows, &with);
            assert_eq!(row["icon_file"], file.as_str());
            assert_eq!(row["image_url"], "https://example.test/download/pic.png");
            let none = find(rows, &without);
            assert!(none.get("icon_file").is_none());
            assert!(none.get("image_url").is_none());
        }
    }

    #[tokio::test]
    async fn rows_carry_the_resources_own_emoji_when_it_has_one() {
        let d = Device::new().await;
        let with = d.new_chat("Icon with").await;
        let without = d.new_chat("Icon without").await;
        d.set_emoji(&with, "🦊").await;
        d.recents.note_opened(&d.drive, &with, 1);
        d.recents.note_opened(&d.drive, &without, 2);
        d.set_home_list(FAVORITES, &[&with, &without]).await;

        let recent = list_recent_resources(&d.store, &d.recents, &d.drive, 500).await;
        assert_eq!(find(&recent, &with)["emoji"], "🦊");
        assert!(find(&recent, &without).get("emoji").is_none());
        assert!(!find(&recent, &with)["class_name"]
            .as_str()
            .unwrap()
            .is_empty());

        let favs = list_favorites(&d.store, 50).await.unwrap();
        assert_eq!(find(&favs, &with)["emoji"], "🦊");
        assert!(find(&favs, &without).get("emoji").is_none());

        let hits = search(&d.store, Some(&d.drive), "icon", 20).unwrap();
        assert_eq!(find(&hits, &with)["emoji"], "🦊");
        assert!(find(&hits, &without).get("emoji").is_none());

        let icons = resource_icons(
            &d.store,
            vec![
                with.clone(),
                without.clone(),
                "https://example.test/gone".into(),
            ],
        )
        .await;
        assert_eq!(icons.len(), 1);
        assert_eq!(icons[&with], "🦊");
    }

    /// Answers one profile for every agent.
    struct Named(&'static str);

    #[async_trait::async_trait]
    impl crate::host::AgentProfileFetcher for Named {
        async fn fetch_agent_resource(&self, _agent: &str) -> Option<String> {
            Some(json!({ urls::NAME: self.0 }).to_string())
        }
    }

    /// `agent` renames `subject` with a commit applied here (as a commit frame
    /// would).
    async fn edit_as(d: &Device, agent: &crate::agents::Agent, subject: &str, name: &str) {
        let mut r = d.store.get_resource(&subject.into()).await.unwrap();
        r.set_string(urls::NAME.into(), name, &d.store)
            .await
            .unwrap();
        r.save_as(agent, &d.store).await.unwrap();
    }

    #[tokio::test]
    async fn activity_is_what_other_agents_did() {
        let d = Device::new().await;
        let none = AgentProfiles::none();
        let mut rx = d.store.subscribe_events();
        let folder = d
            .store
            .create_resource(urls::FOLDER, &d.drive, "Activity folder", None)
            .await
            .unwrap();
        let chat = d.new_chat("Activity chat").await;
        d.pump(&mut rx).await;
        // The index saw the own creation, signed by this device's agent...
        let raw = d.recents.activity(500);
        let own = raw.iter().find(|a| a.subject == folder).unwrap();
        assert_eq!(own.kind, ActivityKind::Created);
        assert!(own.actor.is_some());
        // ...but that is the person's own work, not activity.
        assert!(list_activity(&d.store, &d.recents, &none, None, 500)
            .await
            .is_empty());
        // With "Show mine" it is there, by You.
        let mine = list_activity_with(&d.store, &d.recents, &none, None, 500, true).await;
        let row = mine.iter().find(|a| a.subject == folder).unwrap();
        assert_eq!(row.actor, "You");

        // Another member edits it, a few times in a row: one entry.
        let bob = crate::agents::Agent::new(Some("Bob")).unwrap();
        for name in ["By Bob", "By Bob again", "By Bob, final"] {
            edit_as(&d, &bob, &folder, name).await;
        }
        d.pump(&mut rx).await;
        let list = list_activity(&d.store, &d.recents, &none, None, 500).await;
        assert_eq!(list.len(), 1, "{list:?}");
        let entry = &list[0];
        assert_eq!(entry.subject, folder);
        assert_eq!(entry.kind, ActivityKind::Changed);
        assert_eq!(entry.name, "By Bob, final");
        assert_eq!(entry.drive, d.drive);
        assert!(same_agent(&entry.actor_subject, &bob.subject.to_string()));
        // Nobody can name Bob here: the start of his key, never "someone".
        assert_eq!(entry.actor, short_agent(&bob.subject.to_string()));
        assert!(entry.actor.ends_with('…'));
        assert!(list.iter().all(|a| a.subject != chat));

        // A second member is a row of their own; the person's own edit after
        // them adds nothing and takes nothing away.
        let carol = crate::agents::Agent::new(Some("Carol")).unwrap();
        edit_as(&d, &carol, &folder, "By Carol").await;
        d.pump(&mut rx).await;
        let mut own_edit = d.store.get_resource(&folder.as_str().into()).await.unwrap();
        own_edit
            .set_string(urls::NAME.into(), "By me", &d.store)
            .await
            .unwrap();
        d.node.save_locally(&mut own_edit).await.unwrap();
        d.pump(&mut rx).await;
        let named = AgentProfiles::new(std::sync::Arc::new(Named("Carol")));
        let list = list_activity(&d.store, &d.recents, &named, None, 500).await;
        let actors: Vec<&str> = list.iter().map(|a| a.actor.as_str()).collect();
        assert_eq!(list.len(), 2, "{actors:?}");
        // Newest first; the server's profile names Carol (and here Bob too).
        assert!(same_agent(
            &list[0].actor_subject,
            &carol.subject.to_string()
        ));
        assert_eq!(list[0].actor, "Carol");
        assert!(same_agent(&list[1].actor_subject, &bob.subject.to_string()));

        // The drive filter.
        assert_eq!(
            list_activity(&d.store, &d.recents, &none, Some(&d.drive), 500)
                .await
                .len(),
            2
        );
        assert!(
            list_activity(&d.store, &d.recents, &none, Some("did:ad:elsewhere"), 500)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn drives_are_ordered_by_use_with_the_active_one_first() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let mut make = Vec::new();
        for name in ["Zebra", "apple", "Mango", "Kiwi"] {
            make.push(d.store.create_drive(name).await.unwrap());
        }
        let [zebra, apple, mango, kiwi] = <[String; 4]>::try_from(make).unwrap();
        d.pump(&mut rx).await;
        // Kiwi: a resource in it was opened; Mango: opened earlier. The rest
        // never (creating a drive is not using it).
        d.recents.note_opened(&kiwi, "did:ad:in-kiwi", i64::MAX / 2);
        d.recents.note_opened(&mango, &mango, i64::MAX / 4);
        let order = |active: &str| {
            d.store.set_active_drive(active).unwrap();
            let drives = vec![
                (zebra.clone(), "Zebra"),
                (apple.clone(), "apple"),
                (mango.clone(), "Mango"),
                (kiwi.clone(), "Kiwi"),
                (d.drive.clone(), "Test device"),
            ];
            order_drives_by_use(&d.store, &d.recents, drives, |(s, n)| (s.as_str(), *n))
                .into_iter()
                .map(|(_, n)| n)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            order(&zebra),
            ["Zebra", "Kiwi", "Mango", "apple", "Test device"]
        );
        // The active drive in the other spelling is still the active one.
        let atomic = crate::identifiers::canonicalize_scheme(&apple);
        let did = match atomic.strip_prefix("atomic:") {
            Some(rest) => format!("did:ad:{rest}"),
            None => atomic,
        };
        assert_eq!(order(&did)[0], "apple");

        // An edit by the person in a drive counts as using it.
        let mut rx = d.store.subscribe_events();
        let in_apple = d
            .store
            .create_resource(urls::FOLDER, &apple, "Apple notes", None)
            .await
            .unwrap();
        d.pump(&mut rx).await;
        assert!(
            d.recents.drive_last_used(
                &apple,
                Some(&d.store.get_default_agent().unwrap().subject.to_string())
            ) > 0,
            "{in_apple}"
        );
        d.recents.note_opened(&kiwi, "did:ad:in-kiwi", 1);
        d.recents.note_opened(&mango, &mango, 1);
        assert_eq!(
            order(&zebra),
            ["Zebra", "apple", "Kiwi", "Mango", "Test device"]
        );
    }

    #[tokio::test]
    async fn agents_are_named_from_the_own_profile_the_store_or_the_server() {
        let d = Device::new().await;
        let none = AgentProfiles::none();
        let own = d.store.get_default_agent().unwrap().subject.to_string();
        // The own agent, also when spelled `atomic:`.
        assert_eq!(
            agent_name(&d.store, &none, &own).await.as_deref(),
            Some("Test device")
        );
        let atomic = crate::identifiers::canonicalize_scheme(&own);
        assert_eq!(
            agent_name(&d.store, &none, &atomic).await.as_deref(),
            Some("Test device")
        );
        // Another agent the store does not hold: the server's profile.
        let bob = crate::agents::Agent::new(None).unwrap().subject.to_string();
        assert_eq!(agent_name(&d.store, &none, &bob).await, None);
        let named = AgentProfiles::new(std::sync::Arc::new(Named("Bob")));
        named.get(&bob).await;
        assert_eq!(
            agent_name(&d.store, &named, &bob).await.as_deref(),
            Some("Bob")
        );
    }

    /// Times the home lists over 3 drives x 20 resources (run with
    /// `--ignored --nocapture` to see the numbers). The lists read propvals
    /// only, so no resource row decodes a Loro snapshot.
    #[tokio::test]
    #[ignore = "timing"]
    async fn home_lists_do_not_decode_snapshots_per_row() {
        let d = Device::new().await;
        let store = &d.store;
        let mut rx = store.subscribe_events();
        let mut drives = vec![d.drive.clone()];
        for i in 0..2 {
            drives.push(
                store
                    .create_drive(&format!("Timing drive {i}"))
                    .await
                    .unwrap(),
            );
        }
        store.set_active_drive(&d.drive).unwrap();
        for (n, drive) in drives.iter().enumerate() {
            for i in 0..20 {
                let name = format!("Timing {n}-{i}");
                let subject = store
                    .create_resource(urls::FOLDER, drive, &name, None)
                    .await
                    .unwrap();
                // Some history, as a real resource has.
                for edit in 0..5 {
                    let mut r = store.get_resource(&subject.as_str().into()).await.unwrap();
                    r.set_string(urls::DESCRIPTION.into(), &format!("edit {edit}"), store)
                        .await
                        .unwrap();
                    r.save_locally(store).await.unwrap();
                }
                d.recents.note_opened(drive, &subject, 10_000 + i);
            }
        }
        d.pump(&mut rx).await;

        store.reset_fetch_counters();
        let t = std::time::Instant::now();
        let mut rows = 0;
        for drive in &drives {
            rows += list_recent_resources(store, &d.recents, drive, 10)
                .await
                .len();
        }
        let recents_ms = t.elapsed().as_secs_f64() * 1000.0;
        let (full, shallow) = (
            store.get_resource_call_count(),
            store.get_resource_shallow_call_count(),
        );
        let t = std::time::Instant::now();
        let activity = list_activity(store, &d.recents, &AgentProfiles::none(), None, 30)
            .await
            .len();
        let activity_ms = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "[timing] recents {rows} rows over {} drives: {recents_ms:.1} ms (full reads {full}, shallow {shallow}); activity {activity} rows: {activity_ms:.1} ms",
            drives.len()
        );
        assert!(rows >= 30);
    }

    /// Times `search` over 4 drives and ~3000 synced resources nested 6
    /// folders deep (no `drive` property on any of them), a tenth with a parent
    /// that is not local and a tenth with a class that is not local. Run with
    /// `--ignored --nocapture`. Prints the index query next to the whole call
    /// and the number of reads that could go over the network (`get_resource`).
    #[tokio::test]
    #[ignore = "timing; adds 3000 resources"]
    async fn search_cost_breakdown() {
        let d = Device::new().await;
        let store = &d.store;
        let roots = [
            d.drive.clone(),
            "did:ad:benchdrive1000000000000000000000000000000000000000000000000000000=="
                .to_string(),
            "did:ad:benchdrive2000000000000000000000000000000000000000000000000000000=="
                .to_string(),
            "did:ad:benchdrive3000000000000000000000000000000000000000000000000000000=="
                .to_string(),
        ];
        let mut n = 0u64;
        let mut leaves_parents = Vec::new();
        for root in &roots {
            for f in 0..25 {
                // A chain root > 6 folders; the folders carry no `drive`.
                let mut parent = root.clone();
                for depth in 0..6 {
                    n += 1;
                    parent = d
                        .synced(
                            &sync_subject("bench", n),
                            &parent,
                            &format!("Folder {f}-{depth}"),
                            Some(urls::FOLDER),
                            None,
                        )
                        .await;
                }
                leaves_parents.push(parent);
            }
        }
        let class_missing = "https://example.invalid/class/never-local";
        for i in 0..3000u64 {
            n += 1;
            let parent = if i % 10 == 0 {
                format!("did:ad:benchgone{:0>60}{i:0>4}==", 0)
            } else {
                leaves_parents[i as usize % leaves_parents.len()].clone()
            };
            let class = if i % 10 == 5 {
                class_missing
            } else {
                urls::FOLDER
            };
            d.synced(
                &sync_subject("bench", n),
                &parent,
                &format!("Quokka report {i} notes"),
                Some(class),
                None,
            )
            .await;
        }

        let opts = crate::client::search::SearchOpts {
            limit: Some(20),
            ..Default::default()
        };
        for q in [
            "q",
            "qu",
            "quo",
            "quok",
            "quokka",
            "quokka rep",
            "quokka report 12",
        ] {
            let reps = 10;
            let t = std::time::Instant::now();
            for _ in 0..reps {
                crate::search::query(store, q, &opts).unwrap();
            }
            let query_ms = t.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            store.reset_fetch_counters();
            let t = std::time::Instant::now();
            let mut hits = 0;
            for _ in 0..reps {
                hits = search(store, None, q, 20).unwrap().len();
            }
            let total_ms = t.elapsed().as_secs_f64() * 1000.0 / reps as f64;
            println!(
                "[timing] {q:?}: {hits} hits, index query {query_ms:.2} ms, whole search {total_ms:.2} ms, enrichment {:.2} ms, full reads/search {}, shallow reads/search {}",
                total_ms - query_ms,
                store.get_resource_call_count() / reps,
                store.get_resource_shallow_call_count() / reps,
            );
        }
    }
}
