//! AI chats as the web app stores them: an `AiChat` resource with `ChatLog`
//! pages under it, one entry per message (`planning/chat-log.md`, "Step 3: AI
//! chat").

use super::{own_commit_opts, rows::AI_CHAT, LocalWritePusher};
use crate::{
    chat_log::Entry, commit::CommitBuilder, errors::AtomicResult, loro::AtomicLoroDoc,
    runtime::AtomicNode, storelike::Query, urls, Commit, Db, Storelike, Value,
};
use serde_json::{json, Value as Json};

/// How many `ChatLog` page documents the host decoded (from a snapshot or a
/// full resource) since the process started: what a test or the stress
/// harness counts to tell an O(1) read or append from one that walks the log.
static PAGE_DECODES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// See [`PAGE_DECODES`].
pub fn page_decodes() -> u64 {
    PAGE_DECODES.load(std::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn count_page_decode() {
    PAGE_DECODES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The `ChatLog` pages under `chat` with their Loro docs, decoded once each
/// from the stored snapshot. A full `get_resource` decodes the snapshot too,
/// and `build_state_doc` on it then exports and re-imports the whole page:
/// three passes over every message instead of one.
async fn chat_log_pages(
    store: &Db,
    chat: &str,
) -> AtomicResult<Vec<(String, crate::loro::AtomicLoroDoc)>> {
    let pages = store
        .query(&Query::new_prop_val(urls::PARENT, chat))
        .await?;
    let mut out = Vec::with_capacity(pages.subjects.len());
    for subject in &pages.subjects {
        let page = match store.get_resource_shallow(subject) {
            Ok(page) => page,
            // A stored resource without a materialized row.
            Err(_) => match store.get_resource(subject).await {
                Ok(page) => page,
                Err(_) => continue,
            },
        };
        if !crate::hierarchy::is_chat_log(&page) {
            continue;
        }
        count_page_decode();
        let doc = match store.get_loro_snapshot(subject) {
            Some(snapshot) => AtomicLoroDoc::from_snapshot(&snapshot),
            None => page.build_state_doc(),
        };
        let Ok(doc) = doc else {
            continue;
        };
        out.push((page.get_subject().to_string(), doc));
    }
    Ok(out)
}

/// Every entry of the `ChatLog` pages under `chat`, oldest first (by `c`, then
/// key), as the entry's own fields plus `id` (`<page>#<key>`). `parts` is
/// stored as a JSON string and comes out parsed. An entry key that sits on two
/// pages is listed once. Each entry comes with its time (`c`, 0 when absent).
pub async fn chat_entries(store: &Db, chat: &str) -> AtomicResult<Vec<(i64, Json)>> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<(i64, String, Json)> = Vec::new();
    for (page, doc) in chat_log_pages(store, chat).await? {
        for (key, entry) in doc.entries() {
            if !seen.insert(key.clone()) {
                continue;
            }
            let Some((c, json)) = entry_json(&page, &key, &entry) else {
                continue;
            };
            out.push((c, key, json));
        }
    }
    out.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    Ok(out.into_iter().map(|(c, _, json)| (c, json)).collect())
}

/// An entry as JSON: its own fields plus `id` (`<page>#<key>`), `parts`
/// parsed from the JSON string it is stored as. With its time (`c`, 0 when
/// absent).
pub(crate) fn entry_json(page: &str, key: &str, entry: &loro::LoroValue) -> Option<(i64, Json)> {
    let Ok(Json::Object(mut fields)) = serde_json::to_value(entry) else {
        return None;
    };
    if let Some(Json::String(raw)) = fields.get("parts") {
        let parsed = serde_json::from_str(raw).unwrap_or_else(|_| json!([]));
        fields.insert("parts".into(), parsed);
    }
    fields.insert("id".into(), json!(format!("{page}#{key}")));
    let c = crate::chat_log::entry_created_at(entry).unwrap_or(0);
    Some((c, Json::Object(fields)))
}

/// The time (`c`, ms) of the newest entry of `chat`, 0 when it has none.
/// Reads only the newest page (an entry on an older page with a later time,
/// from a device whose clock ran ahead, is not looked for).
pub async fn chat_last_activity(store: &Db, chat: &str) -> AtomicResult<i64> {
    let Some(page) = older_pages(store, chat, None, 1).await?.into_iter().next() else {
        return Ok(0);
    };
    Ok(decode_page(store, &page.subject)
        .map(|doc| {
            doc.entries()
                .into_values()
                .filter_map(|entry| crate::chat_log::entry_created_at(&entry))
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0))
}

// ── Windows of a long log ────────────────────────────────────────────────
//
// A chat can hold hundreds of thousands of entries on ~256-entry pages. The
// app reads it in windows: the newest `limit` entries, then older windows as
// it scrolls up, then whatever is newer than what it has (a poll). The
// pages are found through the sorted query index (`parent = chat`, `isA =
// ChatLog`, by `createdAt`), read only as far as the window reaches, so a
// window costs a few page decodes whatever the length of the chat.

/// A `ChatLog` page of a chat: its `createdAt` (ms) and subject, the order
/// pages are kept in (the same as the web app's `pageWithRoom`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogPage {
    pub created_at: i64,
    pub subject: String,
}

/// A position in a chat's log: an entry (its page and key). Encoded for the
/// app as an opaque string, `<page createdAt>|<page>#<key>`; stable when
/// entries are added, since keys and pages never move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogCursor {
    pub page: LogPage,
    pub key: String,
}

impl LogCursor {
    pub fn encode(&self) -> String {
        format!(
            "{}|{}#{}",
            self.page.created_at, self.page.subject, self.key
        )
    }

    pub fn decode(cursor: &str) -> AtomicResult<Self> {
        let bad = || format!("Not a chat cursor: {cursor}");
        let (at, rest) = cursor.split_once('|').ok_or_else(bad)?;
        let (page, key) = rest.rsplit_once('#').ok_or_else(bad)?;
        Ok(Self {
            page: LogPage {
                created_at: at.parse().map_err(|_| bad())?,
                subject: page.to_string(),
            },
            key: key.to_string(),
        })
    }
}

/// One window of a chat's log, oldest first.
#[derive(Clone, Debug, Default)]
pub struct LogWindow {
    /// `(cursor, entry)`, oldest first.
    pub entries: Vec<(LogCursor, loro::LoroValue)>,
    /// Whether there are entries older than the first one (for a window read
    /// backwards) or newer than the last one (for a window read forwards)
    /// that did not fit.
    pub more: bool,
}

/// How many pages a sorted index read asks for beyond the ones it needs:
/// pages made in the same millisecond as the cursor's page are skipped by
/// hand.
const PAGE_SLACK: usize = 4;

/// The drive a sorted query over the children of `chat` is scoped to (the
/// query index is per drive): the chat's own drive stamp, else the chat.
pub(crate) fn drive_scope(store: &Db, chat: &str) -> crate::Subject {
    let subject = crate::Subject::from(chat);
    store
        .get_resource_shallow(&subject)
        .ok()
        .and_then(|r| r.get_drive())
        .unwrap_or(subject)
}

fn log_pages_query(store: &Db, chat: &str, desc: bool, bound: Option<i64>, limit: usize) -> Query {
    let mut q = Query::new_prop_val(urls::PARENT, chat).class_filter(urls::CHAT_LOG);
    q.drive = Some(drive_scope(store, chat));
    q.sort_by = Some(urls::CREATED_AT.to_string());
    q.sort_desc = desc;
    q.limit = Some(limit);
    if let Some(at) = bound {
        if desc {
            q.end_val = Some(Value::Timestamp(at));
        } else {
            q.start_val = Some(Value::Timestamp(at));
        }
    }
    q
}

fn log_page_of(store: &Db, subject: &crate::Subject) -> Option<LogPage> {
    let page = store.get_resource_shallow(subject).ok()?;
    let created_at = page
        .get(urls::CREATED_AT)
        .ok()
        .and_then(|v| v.to_int().ok())
        .unwrap_or(0);
    Some(LogPage {
        created_at,
        subject: subject.to_string(),
    })
}

/// Up to `limit` pages of `chat` older than `before` (all pages when
/// `None`), newest first.
async fn older_pages(
    store: &Db,
    chat: &str,
    before: Option<&LogPage>,
    limit: usize,
) -> AtomicResult<Vec<LogPage>> {
    let q = log_pages_query(
        store,
        chat,
        true,
        before.map(|p| p.created_at),
        limit + PAGE_SLACK,
    );
    let mut out: Vec<LogPage> = store
        .query_page(&q)
        .await?
        .iter()
        .filter_map(|s| log_page_of(store, s))
        .filter(|p| before.is_none_or(|b| p < b))
        .collect();
    out.sort_by(|a, b| b.cmp(a));
    out.truncate(limit);
    Ok(out)
}

/// Up to `limit` pages of `chat` newer than `after`, oldest first.
async fn newer_pages(
    store: &Db,
    chat: &str,
    after: &LogPage,
    limit: usize,
) -> AtomicResult<Vec<LogPage>> {
    let q = log_pages_query(
        store,
        chat,
        false,
        Some(after.created_at),
        limit + PAGE_SLACK,
    );
    let mut out: Vec<LogPage> = store
        .query_page(&q)
        .await?
        .iter()
        .filter_map(|s| log_page_of(store, s))
        .filter(|p| p > after)
        .collect();
    out.sort();
    out.truncate(limit);
    Ok(out)
}

/// The Loro doc of one page, from its stored snapshot.
fn decode_page(store: &Db, page: &str) -> Option<AtomicLoroDoc> {
    count_page_decode();
    let snapshot = store.get_loro_snapshot(&crate::Subject::from(page))?;
    AtomicLoroDoc::from_snapshot(&snapshot).ok()
}

/// The newest `limit` entries of `chat` older than `before` (the newest of
/// all when `None`), oldest first. Decodes the pages the window covers and
/// no others. An entry key that sits on two pages is listed once per window.
pub async fn read_log_before(
    store: &Db,
    chat: &str,
    before: Option<&LogCursor>,
    limit: usize,
) -> AtomicResult<LogWindow> {
    let limit = limit.max(1);
    // Newest first while collecting.
    let mut got: Vec<(LogCursor, loro::LoroValue)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut more = false;
    let take = |page: &LogPage,
                entries: Vec<(String, loro::LoroValue)>,
                got: &mut Vec<(LogCursor, loro::LoroValue)>,
                seen: &mut std::collections::HashSet<String>|
     -> bool {
        // Newest first; true when the window filled up with entries left.
        let mut iter = entries.into_iter().rev().peekable();
        while let Some((key, entry)) = iter.next() {
            if !seen.insert(key.clone()) {
                continue;
            }
            got.push((
                LogCursor {
                    page: page.clone(),
                    key,
                },
                entry,
            ));
            if got.len() >= limit {
                return iter.peek().is_some();
            }
        }
        false
    };

    let mut from = before.map(|c| c.page.clone());
    if let Some(cursor) = before {
        if let Some(doc) = decode_page(store, &cursor.page.subject) {
            let entries: Vec<_> = doc
                .entries()
                .range(..cursor.key.clone())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if take(&cursor.page, entries, &mut got, &mut seen) {
                more = true;
            } else if got.len() >= limit {
                more = !older_pages(store, chat, from.as_ref(), 1).await?.is_empty();
            }
        }
    }
    // A window of `limit` entries spans about limit / 256 + 1 pages.
    let batch = limit / crate::chat_log::CHAT_LOG_CAPACITY + 2;
    'pages: while got.len() < limit {
        let pages = older_pages(store, chat, from.as_ref(), batch).await?;
        let last_batch = pages.len() < batch;
        for (i, page) in pages.iter().enumerate() {
            from = Some(page.clone());
            let Some(doc) = decode_page(store, &page.subject) else {
                continue;
            };
            if take(
                page,
                doc.entries().into_iter().collect(),
                &mut got,
                &mut seen,
            ) {
                more = true;
                break 'pages;
            }
            if got.len() >= limit {
                more = i + 1 < pages.len()
                    || (!last_batch
                        && !older_pages(store, chat, from.as_ref(), 1).await?.is_empty());
                break 'pages;
            }
        }
        if last_batch {
            break;
        }
    }
    got.reverse();
    Ok(LogWindow { entries: got, more })
}

/// Up to `limit` entries of `chat` newer than `after`, oldest first: what a
/// reader that has everything up to `after` has not seen yet. Reads the
/// cursor's page and the pages made after it. An entry added since to an
/// older page (another device still filling it) is not looked for.
pub async fn read_log_after(
    store: &Db,
    chat: &str,
    after: &LogCursor,
    limit: usize,
) -> AtomicResult<LogWindow> {
    let limit = limit.max(1);
    let mut got: Vec<(LogCursor, loro::LoroValue)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(after.key.clone());
    let mut push = |page: &LogPage, key: String, entry, got: &mut Vec<_>| {
        if seen.insert(key.clone()) {
            got.push((
                LogCursor {
                    page: page.clone(),
                    key,
                },
                entry,
            ));
        }
    };
    if let Some(doc) = decode_page(store, &after.page.subject) {
        for (key, entry) in doc.entries().into_iter() {
            if key > after.key {
                push(&after.page, key, entry, &mut got);
            }
        }
    }
    let mut from = after.page.clone();
    loop {
        if got.len() > limit {
            break;
        }
        let pages = newer_pages(store, chat, &from, 4).await?;
        if pages.is_empty() {
            break;
        }
        for page in &pages {
            from = page.clone();
            if let Some(doc) = decode_page(store, &page.subject) {
                for (key, entry) in doc.entries() {
                    push(page, key, entry, &mut got);
                }
            }
        }
    }
    let more = got.len() > limit;
    got.truncate(limit);
    Ok(LogWindow { entries: got, more })
}

/// A window of an AI chat as the app reads it: JSON `{entries, older,
/// newest}`. `entries` as [`read_chat`] gives them (oldest first), `older`
/// the cursor to pass as `before` for the window before this one (null at
/// the start of the chat), `newest` the cursor of the last entry (to pass to
/// [`read_chat_after`]; null for an empty chat).
pub async fn read_chat_page(
    store: &Db,
    chat: &str,
    before: Option<&str>,
    limit: usize,
) -> AtomicResult<Json> {
    let before = before.map(LogCursor::decode).transpose()?;
    let window = read_log_before(store, chat, before.as_ref(), limit).await?;
    Ok(window_json(&window, window.more, true))
}

/// The entries of an AI chat after `after` (a cursor from [`read_chat_page`]
/// or an earlier call), as JSON `{entries, newest, more}`: `newest` the
/// cursor to pass next time (`after` itself when nothing is new), `more` when
/// `limit` cut the list.
pub async fn read_chat_after(
    store: &Db,
    chat: &str,
    after: &str,
    limit: usize,
) -> AtomicResult<Json> {
    let cursor = LogCursor::decode(after)?;
    let window = read_log_after(store, chat, &cursor, limit).await?;
    let mut out = window_json(&window, false, false);
    if window.entries.is_empty() {
        out["newest"] = json!(after);
    }
    out["more"] = json!(window.more);
    Ok(out)
}

fn window_json(window: &LogWindow, older: bool, with_older: bool) -> Json {
    let entries: Vec<Json> = window
        .entries
        .iter()
        .filter_map(|(cursor, entry)| entry_json(&cursor.page.subject, &cursor.key, entry))
        .map(|(_, json)| json)
        .collect();
    let mut out = json!({
        "entries": entries,
        "newest": window.entries.last().map(|(c, _)| c.encode()),
    });
    if with_older {
        out["older"] = json!(if older {
            window.entries.first().map(|(c, _)| c.encode())
        } else {
            None
        });
    }
    out
}

/// The entries of a chat, oldest first: the fields the web app stores, `id`,
/// `a`, `c`, `role`, `parts` (array) and the rest as is.
pub async fn read_chat(store: &Db, chat: &str) -> AtomicResult<Vec<Json>> {
    Ok(chat_entries(store, chat)
        .await?
        .into_iter()
        .map(|(_, json)| json)
        .collect())
}

/// Start an AI chat named `name` in the agent's private drive, as the web
/// app's AI sidebar does. Returns the chat's subject.
pub async fn create_ai_chat(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    name: &str,
) -> AtomicResult<String> {
    let store = node.db();
    let agent = store.get_default_agent()?;
    let home = store.ensure_private_drive().await?;

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![AI_CHAT.into()]),
    );
    builder.set(urls::NAME.into(), Value::String(name.to_string()));
    builder.set(urls::PARENT.into(), Value::AtomicUrl(home.as_str().into()));
    let commit = Commit::create_did(builder, &agent, store).await?;
    let subject = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok(subject)
}

/// Add a message to a chat: `role` is `user` or `assistant`, `parts_json` the
/// message's parts as the web app stores them (`[{"type":"text","text":…}]`).
/// It goes on the newest page with room, or on a new page. Returns the entry's
/// id (`<page>#<key>`).
pub async fn append_chat_entry(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    role: &str,
    parts_json: &str,
) -> AtomicResult<String> {
    let author = node.db().get_default_agent()?.subject.to_string();
    let mut entry = Entry::new(author, "", crate::utils::now());
    entry.extra.insert("role".into(), role.into());
    entry.extra.insert("parts".into(), parts_json.into());
    append_entry(node, pusher, chat, &entry).await
}

/// Add `entry` to the log of `chat`: on the newest `ChatLog` page with room
/// (the same rule as the web app, so both fill one page), or on a new page.
/// Returns the entry's id (`<page>#<key>`).
pub async fn append_entry(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    entry: &Entry,
) -> AtomicResult<String> {
    let store = node.db();

    // The newest page, if it has room: one index read and one page decode,
    // however long the chat is.
    if let Some(newest) = older_pages(store, chat, None, 1).await?.into_iter().next() {
        count_page_decode();
        let mut page = store
            .get_resource(&crate::Subject::from(newest.subject.as_str()))
            .await?;
        let room = page
            .live_doc()?
            .doc()
            .get_map(crate::chat_log::ENTRIES)
            .len()
            < crate::chat_log::CHAT_LOG_CAPACITY;
        if room {
            let key = page.add_chat_entry(entry)?;
            let response = node.save_locally(&mut page).await?;
            pusher.push(&response).await;
            return Ok(format!("{}#{key}", newest.subject));
        }
    }

    // A first page.
    let (page, keys) = new_page(node, pusher, chat, std::slice::from_ref(entry)).await?;
    Ok(format!("{page}#{}", keys[0]))
}

/// A new `ChatLog` page under `chat` holding `entries`, in one commit by the
/// device's agent. Returns the page's subject and the entries' keys.
async fn new_page(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    entries: &[Entry],
) -> AtomicResult<(String, Vec<String>)> {
    let store = node.db();
    let agent = store.get_default_agent()?;
    let doc = AtomicLoroDoc::new();
    let keys = entries
        .iter()
        .map(|entry| doc.add_entry(entry))
        .collect::<AtomicResult<Vec<_>>>()?;
    let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
    let parent = Value::AtomicUrl(chat.into());
    doc.set_property(urls::IS_A, &is_a)?;
    doc.set_property(urls::PARENT, &parent)?;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = Commit::create_did(builder, &agent, store).await?;
    let page = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok((page, keys))
}

/// Import a whole AI chat at once: an `AiChat` named `name` in the agent's
/// private drive with `entries` (oldest first) on as few `ChatLog` pages as
/// the page capacity allows. One commit for the chat and one per page,
/// instead of one per message as [`append_chat_entry`] does; for importing a
/// conversation from elsewhere and for seeding a store in performance tests.
/// Returns the chat's subject.
pub async fn import_ai_chat(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    name: &str,
    entries: &[Entry],
) -> AtomicResult<String> {
    let chat = create_ai_chat(node, pusher, name).await?;
    import_entries(node, pusher, &chat, entries).await?;
    Ok(chat)
}

/// Add many entries (oldest first) to the log of `chat` at once, on new
/// `ChatLog` pages filled to capacity: one commit per page. For any chat with
/// a log (an AI chat, a chat room, a meeting); importing history and seeding
/// performance tests. Each page is made at a later millisecond than the one
/// before, so the pages keep their order (pages are ordered by `createdAt`,
/// then subject). Returns the pages' subjects, oldest first.
pub async fn import_entries(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    entries: &[Entry],
) -> AtomicResult<Vec<String>> {
    let mut pages = Vec::new();
    let mut last = 0;
    for page in entries.chunks(crate::chat_log::CHAT_LOG_CAPACITY) {
        while crate::utils::now() <= last {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        last = crate::utils::now();
        pages.push(new_page(node, pusher, chat, page).await?.0);
    }
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{lists, test_support::Device};

    /// A realistic time: entry keys sort by time only while the hex of the
    /// times has one length.
    const T0: i64 = 1_700_000_000_000;

    fn text_of(entry: &Json) -> String {
        entry["parts"][0]["text"].as_str().unwrap().to_string()
    }

    /// Walk a chat backwards window by window, appending new entries in
    /// between: every original entry comes exactly once, in order, and the
    /// appended ones come from `read_chat_after`.
    #[tokio::test]
    async fn windows_cover_a_long_chat_without_gaps_or_duplicates_while_it_grows() {
        let d = Device::new().await;
        let n = 10_000;
        let entries: Vec<Entry> = (0..n)
            .map(|i| d.ai_entry("user", &format!("m{i}"), T0 + i as i64))
            .collect();
        let chat = import_ai_chat(&d.node, &crate::host::NoPush, "Long", &entries)
            .await
            .unwrap();

        let first = read_chat_page(&d.store, &chat, None, 50).await.unwrap();
        let newest = first["newest"].as_str().unwrap().to_string();
        let mut seen: Vec<String> = first["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(text_of)
            .collect();
        assert_eq!(seen.len(), 50);
        assert_eq!(seen.last().unwrap(), &format!("m{}", n - 1));
        let mut older = first["older"].as_str().map(str::to_string);
        let mut appended = 0;
        while let Some(cursor) = older {
            let window = read_chat_page(&d.store, &chat, Some(&cursor), 173)
                .await
                .unwrap();
            let mut texts: Vec<String> = window["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(text_of)
                .collect();
            texts.extend(seen);
            seen = texts;
            older = window["older"].as_str().map(str::to_string);
            if appended < 3 {
                append_chat_entry(
                    &d.node,
                    &crate::host::NoPush,
                    &chat,
                    "user",
                    &json!([{ "type": "text", "text": format!("new{appended}") }]).to_string(),
                )
                .await
                .unwrap();
                appended += 1;
            }
        }
        let want: Vec<String> = (0..n).map(|i| format!("m{i}")).collect();
        assert_eq!(seen, want);

        let after = read_chat_after(&d.store, &chat, &newest, 100)
            .await
            .unwrap();
        let texts: Vec<String> = after["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(text_of)
            .collect();
        assert_eq!(texts, ["new0", "new1", "new2"]);
        assert_eq!(after["more"], false);
        // Nothing newer: the same cursor back.
        let cursor = after["newest"].as_str().unwrap();
        let again = read_chat_after(&d.store, &chat, cursor, 100).await.unwrap();
        assert!(again["entries"].as_array().unwrap().is_empty());
        assert_eq!(again["newest"], cursor);
        // A limit cuts the list and says so.
        let cut = read_chat_after(&d.store, &chat, &newest, 2).await.unwrap();
        assert_eq!(cut["entries"].as_array().unwrap().len(), 2);
        assert_eq!(cut["more"], true);
    }

    /// Appending to a long chat reads the newest page only, and so does the
    /// last-activity lookup the recents index makes.
    #[tokio::test]
    async fn appending_to_a_long_chat_reads_one_page() {
        let d = Device::new().await;
        let n = 40 * crate::chat_log::CHAT_LOG_CAPACITY - 3;
        let entries: Vec<Entry> = (0..n)
            .map(|i| d.ai_entry("user", "x", T0 + i as i64))
            .collect();
        let chat = import_ai_chat(&d.node, &crate::host::NoPush, "Long", &entries)
            .await
            .unwrap();
        // What one append costs in a chat of one page (the commit's own
        // reads included); the first query of a filter builds its index, so
        // count after one append each.
        let short = import_ai_chat(&d.node, &crate::host::NoPush, "Short", &entries[..3])
            .await
            .unwrap();
        let reads = |chat: String| {
            let d = &d;
            async move {
                d.store.reset_fetch_counters();
                append_chat_entry(&d.node, &crate::host::NoPush, &chat, "user", "[]")
                    .await
                    .unwrap();
                (
                    d.store.get_resource_call_count(),
                    d.store.get_resource_shallow_call_count(),
                )
            }
        };
        reads(short.clone()).await;
        reads(chat.clone()).await;
        let one_page = reads(short.clone()).await;
        for _ in 0..5 {
            let (full, shallow) = reads(chat.clone()).await;
            // Starting the next page (once here) costs a few reads more.
            assert!(full <= one_page.0 + 4, "{full} full reads");
            // The page query reads a few pages beyond the newest one.
            assert!(
                shallow <= one_page.1 + 2 * PAGE_SLACK,
                "{shallow} shallow reads"
            );
        }
        // The page filled up and a new one was started: still 40 + 1 pages.
        let pages = older_pages(&d.store, &chat, None, 100).await.unwrap();
        assert_eq!(pages.len(), 41);
        d.store.reset_fetch_counters();
        assert!(chat_last_activity(&d.store, &chat).await.unwrap() > T0);
        let shallow = d.store.get_resource_shallow_call_count();
        // The index read and the page list each look at 1 + PAGE_SLACK pages.
        assert!(
            shallow <= 2 * (1 + PAGE_SLACK) + 1,
            "{shallow} shallow reads"
        );
    }

    #[test]
    fn cursors_round_trip() {
        let c = LogCursor {
            page: LogPage {
                created_at: 42,
                subject: "did:ad:abc?drive=did:ad:x#y".into(),
            },
            key: "1a-00000001".into(),
        };
        assert_eq!(LogCursor::decode(&c.encode()).unwrap(), c);
        assert!(LogCursor::decode("nope").is_err());
    }

    #[tokio::test]
    async fn chat_entries_are_read_oldest_first_across_pages() {
        let d = Device::new().await;
        let chat = d.new_chat("Entries").await;
        d.add_page(
            &chat,
            &[
                ("2-00000002", d.ai_entry("assistant", "second", 2_000)),
                ("1-00000001", d.ai_entry("user", "first", 1_000)),
            ],
        )
        .await;
        d.add_page(&chat, &[("3-00000003", d.ai_entry("user", "third", 3_000))])
            .await;

        let entries = read_chat(&d.store, &chat).await.unwrap();
        let texts: Vec<&str> = entries
            .iter()
            .map(|e| e["parts"][0]["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts, ["first", "second", "third"]);
        assert_eq!(entries[0]["role"], "user");
        assert_eq!(entries[1]["role"], "assistant");
        assert_eq!(entries[0]["c"], 1_000);
        assert!(entries[0]["id"].as_str().unwrap().ends_with("#1-00000001"));
    }

    #[tokio::test]
    async fn an_imported_chat_fills_pages_up_to_their_capacity() {
        let d = Device::new().await;
        let n = crate::chat_log::CHAT_LOG_CAPACITY + 10;
        let entries: Vec<Entry> = (0..n)
            .map(|i| d.ai_entry("user", &format!("message {i}"), 1_000 + i as i64))
            .collect();
        let chat = import_ai_chat(&d.node, &crate::host::NoPush, "Imported", &entries)
            .await
            .unwrap();
        let read = read_chat(&d.store, &chat).await.unwrap();
        assert_eq!(read.len(), n);
        assert_eq!(read[0]["parts"][0]["text"], "message 0");
        assert_eq!(
            read[n - 1]["parts"][0]["text"],
            format!("message {}", n - 1)
        );
        let pages: std::collections::HashSet<&str> = read
            .iter()
            .map(|e| e["id"].as_str().unwrap().split('#').next().unwrap())
            .collect();
        assert_eq!(pages.len(), 2);
        // A message added later goes on the page with room.
        append_chat_entry(&d.node, &crate::host::NoPush, &chat, "user", "[]")
            .await
            .unwrap();
        assert_eq!(read_chat(&d.store, &chat).await.unwrap().len(), n + 1);
    }

    #[tokio::test]
    async fn a_chat_started_here_takes_messages_in_order_on_one_page() {
        let d = Device::new().await;
        let mut rx = d.store.subscribe_events();
        let chat = create_ai_chat(&d.node, &crate::host::NoPush, "Phone chat")
            .await
            .unwrap();
        let parts = |text: &str| json!([{ "type": "text", "text": text }]).to_string();
        let user = append_chat_entry(
            &d.node,
            &crate::host::NoPush,
            &chat,
            "user",
            &parts("Hallo"),
        )
        .await
        .unwrap();
        let assistant = append_chat_entry(
            &d.node,
            &crate::host::NoPush,
            &chat,
            "assistant",
            &parts("Hoi!"),
        )
        .await
        .unwrap();
        // Both entries sit on the same page, the second after the first.
        assert_eq!(user.split('#').next(), assistant.split('#').next());

        let entries = read_chat(&d.store, &chat).await.unwrap();
        let texts: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| {
                (
                    e["role"].as_str().unwrap(),
                    e["parts"][0]["text"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(texts, [("user", "Hallo"), ("assistant", "Hoi!")]);

        // It is in the private drive, and shows up in the recents.
        d.pump(&mut rx).await;
        let list = lists::list_ai_chats(&d.store, &d.recents, 500)
            .await
            .unwrap();
        assert!(list
            .iter()
            .any(|c| c["subject"] == chat.as_str() && c["name"] == "Phone chat"));
    }
}
