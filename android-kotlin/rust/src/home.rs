//! The home screen's data: drives, the four lists and search, as typed rows.
//! Every function takes the store and index it reads, so the tests run them on
//! a temporary store; `api.rs` binds them to the process's store.

use crate::{
    error::CoreResult,
    types::{DriveRow, HomeList, ResourceRow, SearchHit},
};
use atomic_lib::{
    host::{
        lists,
        recents::RecentsIndex,
        rows::row_resource,
    },
    Db,
};
use serde::Deserialize;

/// Most recents merged over all drives (Flutter's `_maxRecents`).
pub(crate) const MAX_RECENTS: usize = 100;

/// A row as `atomic_lib::host::lists` writes it.
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawRow {
    subject: String,
    title: String,
    name: String,
    class_name: String,
    emoji: Option<String>,
    drive: String,
    opened_at: i64,
    last_activity: i64,
    last_message: String,
    score: f64,
}

fn parse_rows(rows: Vec<serde_json::Value>) -> Vec<RawRow> {
    rows.into_iter()
        .filter_map(|r| serde_json::from_value(r).ok())
        .collect()
}

impl RawRow {
    fn into_row(self, drive: &str) -> ResourceRow {
        let title = if self.title.is_empty() { self.name } else { self.title };
        ResourceRow {
            subject: self.subject,
            title,
            class_name: self.class_name,
            emoji: self.emoji.filter(|e| !e.is_empty()),
            drive: if self.drive.is_empty() { drive.to_string() } else { self.drive },
            opened_at: self.opened_at.max(self.last_activity),
            detail: self.last_message,
        }
    }
}

/// The agent's drives with their names and own icons.
pub(crate) async fn drives(store: &Db) -> CoreResult<Vec<DriveRow>> {
    let mut out = Vec::new();
    for info in store.list_drives().await? {
        let emoji = match row_resource(store, &info.subject.as_str().into()).await {
            Some(r) => Some(atomic_lib::host::rows::emoji_of(&r)).filter(|e| !e.is_empty()),
            None => None,
        };
        out.push(DriveRow { subject: info.subject, name: info.name, emoji });
    }
    Ok(out)
}

/// What was opened lately in every drive, newest first.
pub(crate) async fn recents(
    store: &Db,
    index: &RecentsIndex,
    limit: usize,
) -> CoreResult<Vec<ResourceRow>> {
    let mut all = Vec::new();
    for drive in store.list_drives().await? {
        let rows = lists::list_recent_resources(store, index, &drive.subject, limit).await;
        all.extend(parse_rows(rows).into_iter().map(|r| r.into_row(&drive.subject)));
    }
    all.sort_by(|a, b| b.opened_at.cmp(&a.opened_at).then_with(|| a.subject.cmp(&b.subject)));
    all.truncate(limit.min(MAX_RECENTS));
    Ok(all)
}

/// The person's AI chats (all drives), newest activity first.
pub(crate) async fn ai_chats(
    store: &Db,
    index: &RecentsIndex,
    limit: usize,
) -> CoreResult<Vec<ResourceRow>> {
    let rows = lists::list_ai_chats(store, index, limit).await?;
    Ok(parse_rows(rows)
        .into_iter()
        .map(|mut r| {
            r.class_name = "AiChat".into();
            r.into_row("")
        })
        .collect())
}

pub(crate) async fn favorites(store: &Db, limit: usize) -> CoreResult<Vec<ResourceRow>> {
    let rows = lists::list_favorites(store, limit).await?;
    Ok(parse_rows(rows).into_iter().map(|r| r.into_row("")).collect())
}

pub(crate) async fn messages(
    store: &Db,
    conversations: &atomic_lib::host::conversations::Conversations,
    limit: usize,
) -> CoreResult<Vec<ResourceRow>> {
    let rows = conversations.list(store, limit).await?;
    Ok(parse_rows(rows).into_iter().map(|r| r.into_row("")).collect())
}

/// Full-text search across every drive (type-ahead on the last word).
pub(crate) fn search(store: &Db, query: &str, limit: usize) -> CoreResult<Vec<SearchHit>> {
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rows = lists::search(store, None, query, limit)?;
    Ok(parse_rows(rows)
        .into_iter()
        .map(|r| SearchHit {
            subject: r.subject,
            title: r.title,
            class_name: r.class_name,
            emoji: r.emoji.filter(|e| !e.is_empty()),
            drive: r.drive,
            score: r.score,
        })
        .collect())
}

/// One of the four lists by name.
pub(crate) async fn list(
    store: &Db,
    index: &RecentsIndex,
    conversations: &atomic_lib::host::conversations::Conversations,
    which: HomeList,
    limit: usize,
) -> CoreResult<Vec<ResourceRow>> {
    match which {
        HomeList::Recents => recents(store, index, limit).await,
        HomeList::AiChats => ai_chats(store, index, limit).await,
        HomeList::Favorites => favorites(store, limit).await,
        HomeList::Messages => messages(store, conversations, limit).await,
    }
}

#[cfg(test)]
pub(crate) fn __row_for_test(rows: Vec<serde_json::Value>) -> ResourceRow {
    parse_rows(rows).remove(0).into_row("")
}
