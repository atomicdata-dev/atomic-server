//! One resource as a row of a list: title, class name and icon, read from the
//! stored propvals so a list never decodes a Loro history or waits on the
//! network.

use crate::{urls, Db, Resource, Storelike, Subject};
use serde_json::{json, Value as Json};
use std::collections::HashMap;

/// `ai.classes.aiChat` (`browser/lib/src/ontologies/ai.ts`).
pub const AI_CHAT: &str = "https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-chat";

/// `favorites` on the private drive: what the web app's Favorites panel lists.
pub const FAVORITES: &str = "https://atomicdata.dev/properties/favorites";

/// The resource's name, else its shortname, else "".
pub fn name_of(resource: &Resource) -> String {
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
/// the full read when there is a stored resource without a row, and to nothing
/// when this device does not hold the resource at all.
pub async fn row_resource(store: &Db, subject: &Subject) -> Option<Resource> {
    match store.get_resource_shallow(subject) {
        Ok(r) => Some(r),
        // The full read is for a stored resource whose row is not materialized
        // yet. For anything this device does not hold it would go and fetch
        // it over the network, one subject after the other: with dozens of
        // listed drives that is the app waiting seconds on every start.
        Err(_) if store.has_stored_resource(subject) => store.get_resource(subject).await.ok(),
        Err(_) => None,
    }
}

/// The subject of a resource's first class, "" when it has none.
pub fn first_class(resource: &Resource) -> String {
    match resource.get(urls::IS_A).map(|v| v.to_subjects(None)) {
        Ok(Ok(classes)) => classes.into_iter().next().unwrap_or_default(),
        _ => String::new(),
    }
}

/// The name of a resource's first class, its subject when the class has none.
pub async fn class_name_of(store: &Db, resource: &Resource) -> String {
    let class = first_class(resource);
    match row_resource(store, &Subject::from(class.as_str())).await {
        Some(c) if !name_of(&c).is_empty() => name_of(&c),
        _ => class,
    }
}

/// The resource's own icon: the emoji the web app's "Add icon" stores. Empty
/// when it has none.
pub fn emoji_of(resource: &Resource) -> String {
    resource
        .get(urls::EMOJI)
        .map(|v| v.to_string())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Add `emoji` to a row when the resource has one (absent otherwise).
pub fn with_emoji(mut row: Json, resource: &Resource) -> Json {
    let emoji = emoji_of(resource);
    if !emoji.is_empty() {
        row["emoji"] = json!(emoji);
    }
    row
}

/// A `{subject, title, class_name, <extra>, emoji?}` row of the resource lists.
pub async fn resource_row(
    store: &Db,
    subject: &str,
    resource: &Resource,
    extra: (&str, Json),
) -> Json {
    with_emoji(
        json!({
            "subject": subject,
            "title": name_of(resource),
            "class_name": class_name_of(store, resource).await,
            extra.0: extra.1,
        }),
        resource,
    )
}

/// The drive of resources found by a search: their `drive` property, else the
/// one found by walking up the parents through local propvals only. Every
/// resource on a walked chain is remembered, so siblings cost one lookup.
#[derive(Default)]
pub struct DriveCache(HashMap<String, String>);

impl DriveCache {
    /// The drive of `resource`, "" when it cannot be found locally.
    pub fn of(&mut self, store: &Db, resource: &Resource) -> String {
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
