//! The home screen's lists and search, as JSON rows. Each list reads local
//! propvals only: it never waits on the network and never decodes a Loro doc
//! per row.

use super::{
    recents::{ActivityKind, RecentsIndex},
    rows::{emoji_of, first_class, name_of, resource_row, row_resource, with_emoji, DriveCache},
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
    Ok(recents
        .recent_chats(store, limit)
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
    /// Display name of the agent that did it; `None` when the store does not
    /// know who, or does not have that agent's resource.
    pub actor: Option<String>,
    pub name: String,
    pub class_name: String,
}

/// What changed lately in every drive, newest first, by whom. Read from the
/// recents index, which the store's change events keep.
pub async fn list_activity(store: &Db, recents: &RecentsIndex, limit: usize) -> Vec<ActivityRow> {
    let mut names: HashMap<String, Option<String>> = Default::default();
    let mut out = Vec::new();
    for a in recents.activity(limit) {
        let actor = match &a.actor {
            None => None,
            Some(agent) => match names.get(agent) {
                Some(name) => name.clone(),
                None => {
                    let name = row_resource(store, &Subject::from(agent.as_str()))
                        .await
                        .map(|r| name_of(&r))
                        .filter(|n| !n.is_empty());
                    names.insert(agent.clone(), name.clone());
                    name
                }
            },
        };
        out.push(ActivityRow {
            subject: a.subject,
            drive: a.drive,
            kind: a.kind,
            at: a.at,
            actor,
            name: a.name,
            class_name: a.class_name,
        });
    }
    out
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
pub fn search(
    store: &Db,
    drive: Option<&str>,
    query: &str,
    limit: usize,
) -> AtomicResult<Vec<Json>> {
    let opts = crate::client::search::SearchOpts {
        limit: Some(limit as u32),
        parents: drive.filter(|d| !d.is_empty()).map(|d| vec![d.to_string()]),
        ..Default::default()
    };
    let hits = crate::search::query(store, query.trim(), &opts)?;

    // Local propvals only, and each parent / class is looked up once per
    // query: a search never waits on the network and never decodes a Loro doc.
    let mut drives = DriveCache::default();
    let mut classes: HashMap<String, String> = Default::default();
    let mut out = Vec::new();
    for hit in hits.into_iter().take(limit) {
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
        out.push(with_emoji(
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
    Ok(out)
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

    #[tokio::test]
    async fn activity_follows_creates_and_deletes_and_skips_chats() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let folder = d
            .store
            .create_resource(urls::FOLDER, &d.drive, "Activity folder", None)
            .await
            .unwrap();
        let chat = d.new_chat("Activity chat").await;
        d.pump(&mut rx).await;

        let list = list_activity(&d.store, &d.recents, 500).await;
        let entry = list.iter().find(|a| a.subject == folder).unwrap();
        assert_eq!(entry.kind, ActivityKind::Created);
        assert_eq!(entry.name, "Activity folder");
        assert!(entry.at > 0);
        assert!(list.iter().all(|a| a.subject != chat));
        // The signer comes from the stored commit, and is named.
        let raw = d
            .recents
            .activity(500)
            .into_iter()
            .find(|a| a.subject == folder)
            .unwrap();
        assert!(raw.actor.is_some());
        assert_eq!(entry.actor.as_deref(), Some("Test device"));

        d.store
            .remove_resource(&folder.as_str().into())
            .await
            .unwrap();
        d.pump(&mut rx).await;
        let list = list_activity(&d.store, &d.recents, 500).await;
        let entry = list.iter().find(|a| a.subject == folder).unwrap();
        assert_eq!(entry.kind, ActivityKind::Deleted);
        assert_eq!(entry.name, "Activity folder");
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
        let activity = list_activity(store, &d.recents, 30).await.len();
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
