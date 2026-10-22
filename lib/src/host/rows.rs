//! One resource as a row of a list: title, class name and icon, read from the
//! stored propvals so a list never decodes a Loro history or waits on the
//! network.

use super::own_profile::{ICON, IMAGE};
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

/// The File of the resource's own picture: its `icon` (what the web app's
/// icon editor writes). `agent` also reads the older `image` property, which
/// agent profiles still carry. Empty when it has none.
pub fn icon_file_of(resource: &Resource, agent: bool) -> String {
    let get = |p: &str| {
        resource
            .get(p)
            .map(|v| v.to_string())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    match get(ICON) {
        i if i.is_empty() && agent => get(IMAGE),
        i => i,
    }
}

/// The resource's own pictures as row fields: `emoji?`, `icon_file?` (the
/// File subject, whose bytes the host hands out when this device holds them)
/// and `image_url?` (a URL a server serves: the File's download URL when it
/// is stored here, else the resource's `imageUrl`). Nothing for a resource
/// without any. Reads propvals only, plus the File's own row.
pub fn picture_fields(
    store: &Db,
    resource: &Resource,
    agent: bool,
) -> serde_json::Map<String, Json> {
    let mut out = serde_json::Map::new();
    let emoji = emoji_of(resource);
    if !emoji.is_empty() {
        out.insert("emoji".into(), json!(emoji));
    }
    let file = icon_file_of(resource, agent);
    let from_file = (!file.is_empty())
        .then(|| {
            store
                .get_resource_shallow(&Subject::from(file.as_str()))
                .ok()
        })
        .flatten()
        .and_then(|f| f.get(urls::DOWNLOAD_URL).ok().map(|v| v.to_string()))
        .filter(|u| u.starts_with("http"));
    if !file.is_empty() {
        out.insert("icon_file".into(), json!(file));
    }
    let url = from_file.or_else(|| {
        resource
            .get(urls::IMAGE_URL)
            .ok()
            .map(|v| v.to_string())
            .filter(|u| u.starts_with("http"))
    });
    if let Some(url) = url {
        out.insert("image_url".into(), json!(url));
    }
    out
}

/// Add the resource's own pictures (see [`picture_fields`]) to a row.
pub fn with_icon(store: &Db, mut row: Json, resource: &Resource) -> Json {
    for (k, v) in picture_fields(store, resource, false) {
        row[k.as_str()] = v;
    }
    row
}

/// `{subject, name, emoji?, icon_file?, image_url?}` of an agent, as far as
/// this device holds its profile; `None` when it does not hold it. `name` is
/// "" when the profile has none.
pub async fn agent_picture(store: &Db, agent: &str) -> Option<Json> {
    let resource = row_resource(store, &Subject::from(agent)).await?;
    let mut out = picture_fields(store, &resource, true);
    out.insert("subject".into(), json!(agent));
    out.insert("name".into(), json!(name_of(&resource)));
    Some(Json::Object(out))
}

/// A `{subject, title, class_name, class_url, <extra>, emoji?, icon_file?, image_url?}` row of the resource lists.
pub async fn resource_row(
    store: &Db,
    subject: &str,
    resource: &Resource,
    extra: (&str, Json),
) -> Json {
    with_icon(
        store,
        json!({
            "subject": subject,
            "title": name_of(resource),
            "class_name": class_name_of(store, resource).await,
            "class_url": first_class(resource),
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
