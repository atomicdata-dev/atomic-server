//! The chat of a meeting or chat room, as the web app's `ChatRoomView` shows
//! it: a `ChatLog` log under the room (`planning/chat-log.md`), plus the old
//! `Message` resources an older client wrote. A `Meeting` is a chat room of its
//! own, so its chat is the log under the meeting itself.
//!
//! Entries come in two kinds, as in the web app:
//!
//! - `text`: a message with an author, shown as a bubble;
//! - `event`: a system line of a meeting (entry kind `FollowEvent`: "Viewing
//!   [title](subject)" trail lines, "Started the meeting."). A trail line
//!   carries `about` (the viewed resource) and `about_title`.
//!
//! An entry of any other kind, or without a text of its own, is shown as a
//! `text` message with whatever text it holds (`t`, else a `description`, else
//! the text parts of an AI-style entry); an entry without any text is left out.

use super::{
    chats::{
        append_entry, chat_entries, entry_json, read_log_after, read_log_before, LogCursor,
        LogWindow,
    },
    conversations::{agent_name, same_agent},
    profiles::AgentProfiles,
    rows::{name_of, row_resource},
    LocalWritePusher,
};
use crate::{
    chat_log::Entry, errors::AtomicResult, runtime::AtomicNode, storelike::Query, urls, Db,
    Storelike, Subject,
};
use serde_json::{json, Value as Json};

/// The kind of an ordinary message.
pub const KIND_TEXT: &str = "text";
/// The kind of a system line of a meeting.
pub const KIND_EVENT: &str = "event";

/// One line of a chat room before names are resolved.
#[derive(Clone, Debug, PartialEq)]
struct Line {
    id: String,
    author: String,
    text: String,
    created_at: i64,
    event: bool,
    reply_to: Option<String>,
}

/// Reads chat rooms. Keeps the shared [`AgentProfiles`] to name authors this
/// device does not hold (looked up in the background, never waited for).
pub struct ChatRooms {
    profiles: AgentProfiles,
}

impl ChatRooms {
    pub fn new(profiles: AgentProfiles) -> Self {
        Self { profiles }
    }

    /// The lines of `chat`, oldest first, as JSON `[{id, author, author_name,
    /// mine, kind, text, c, reply_to?, about?, about_title?}]`. `kind` is
    /// `text` or `event` (see the module docs), `author_name` the cached name
    /// or "Unknown member", `c` the time in ms. Read from the local store only.
    pub async fn read(&self, store: &Db, chat: &str) -> AtomicResult<Vec<Json>> {
        let lines = read_lines(store, chat).await?;
        self.lines_json(store, lines).await
    }

    /// A window of the room's lines, as JSON `{messages, older, newest}`:
    /// `messages` the newest `limit` lines before the `before` cursor (the
    /// newest of all when `None`), oldest first, as [`Self::read`] gives
    /// them; `older` the cursor for the window before this one (null at the
    /// start), `newest` the log cursor of the last entry (for
    /// [`Self::read_after`]). Old `Message` resources are merged in by time:
    /// those in the time span of the window's log entries, and below the
    /// oldest entry once the log is exhausted (`limit` at a time). Reads the
    /// pages the window covers, whatever the length of the room.
    pub async fn read_page(
        &self,
        store: &Db,
        chat: &str,
        before: Option<&str>,
        limit: usize,
    ) -> AtomicResult<Json> {
        let limit = limit.max(1);
        let cursor = before.map(RoomCursor::decode).transpose()?;
        let (log_before, log_done, hi) = match &cursor {
            Some(c) => (c.log.clone(), c.log.is_none(), Some((c.at, c.id.clone()))),
            None => (None, false, None),
        };
        let window = if log_done {
            LogWindow::default()
        } else {
            read_log_before(store, chat, log_before.as_ref(), limit).await?
        };
        let mut keys = std::collections::HashSet::new();
        let mut lines: Vec<Line> = Vec::new();
        for (c, entry) in &window.entries {
            keys.insert(c.key.clone());
            if let Some((at, json)) = entry_json(&c.page.subject, &c.key, entry) {
                lines.extend(line_of_entry(&json, at));
            }
        }
        // The log's window spans [lo, hi); below lo is the next window's.
        let lo = window
            .more
            .then(|| {
                window
                    .entries
                    .first()
                    .and_then(|(_, e)| crate::chat_log::entry_created_at(e))
            })
            .flatten();
        let cap = if window.more { usize::MAX } else { limit };
        let (legacy, legacy_more) = legacy_lines(store, chat, lo, hi.as_ref(), &keys, cap).await?;
        let oldest_legacy = legacy
            .iter()
            .min_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)))
            .map(|l| (l.created_at, l.id.clone()));
        lines.extend(legacy);
        lines.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));

        let older = if window.more {
            Some(RoomCursor {
                log: window.entries.first().map(|(c, _)| c.clone()),
                at: lo.unwrap_or(0),
                id: String::new(),
            })
        } else if legacy_more {
            oldest_legacy.map(|(at, id)| RoomCursor { log: None, at, id })
        } else {
            None
        };
        let newest = window.entries.last().map(|(c, _)| c.encode());
        Ok(json!({
            "messages": self.lines_json(store, lines).await?,
            "older": older.map(|c| c.encode()),
            "newest": newest,
        }))
    }

    /// The log entries of the room after `after` (a `newest` cursor), as
    /// JSON `{messages, newest, more}` like [`crate::host::chats::read_chat_after`].
    /// Old `Message` resources are not polled: only older clients write them.
    pub async fn read_after(
        &self,
        store: &Db,
        chat: &str,
        after: &str,
        limit: usize,
    ) -> AtomicResult<Json> {
        let cursor = LogCursor::decode(after)?;
        let window = read_log_after(store, chat, &cursor, limit).await?;
        let mut lines = Vec::new();
        for (c, entry) in &window.entries {
            if let Some((at, json)) = entry_json(&c.page.subject, &c.key, entry) {
                lines.extend(line_of_entry(&json, at));
            }
        }
        let newest = window
            .entries
            .last()
            .map(|(c, _)| c.encode())
            .unwrap_or_else(|| after.to_string());
        Ok(json!({
            "messages": self.lines_json(store, lines).await?,
            "newest": newest,
            "more": window.more,
        }))
    }

    async fn lines_json(&self, store: &Db, lines: Vec<Line>) -> AtomicResult<Vec<Json>> {
        let me = store
            .get_default_agent()
            .map(|a| a.subject.to_string())
            .unwrap_or_default();
        let mut names: std::collections::HashMap<String, String> = Default::default();
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            if !line.author.is_empty() && !names.contains_key(&line.author) {
                let name = agent_name(store, &self.profiles, &line.author).await;
                names.insert(line.author.clone(), name);
            }
            let mut message = json!({
                "id": line.id,
                "author": line.author,
                "author_name": names.get(&line.author).cloned().unwrap_or_default(),
                "mine": !me.is_empty() && same_agent(&line.author, &me),
                "kind": if line.event { KIND_EVENT } else { KIND_TEXT },
                "text": line.text,
                "c": line.created_at,
            });
            if let Some(reply_to) = &line.reply_to {
                message["reply_to"] = json!(reply_to);
            }
            if line.event {
                if let Some((title, subject)) = parse_trail(&line.text) {
                    let title = if title.is_empty() {
                        local_title(store, &subject).await.unwrap_or_default()
                    } else {
                        title
                    };
                    message["about"] = json!(subject);
                    message["about_title"] = json!(title);
                }
            }
            out.push(message);
        }
        Ok(out)
    }
}

/// Post `text` in `chat` as this device's agent, as an entry of its log that
/// the web app's chat shows like its own. `reply_to` is the `id` of the message
/// answered. Returns the entry's id (`<page>#<key>`).
pub async fn send_message(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    chat: &str,
    text: &str,
    reply_to: Option<&str>,
) -> AtomicResult<String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Cannot send an empty message".into());
    }
    let author = node.db().get_default_agent()?.subject.to_string();
    let mut entry = Entry::new(author, text, crate::utils::now());
    // The web app stores the entry key / message subject it replies to.
    entry.reply_to = reply_to.filter(|r| !r.is_empty()).map(str::to_string);
    append_entry(node, pusher, chat, &entry).await
}

/// `Viewing [title](subject)`, the trail text the follow logger writes: the
/// title (may be empty) and the subject.
fn parse_trail(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("Viewing [")?;
    let (title, rest) = rest.split_once("](")?;
    let subject = rest.strip_suffix(')')?;
    if subject.is_empty() || subject.contains(char::is_whitespace) {
        return None;
    }
    Some((title.to_string(), subject.to_string()))
}

async fn local_title(store: &Db, subject: &str) -> Option<String> {
    let resource = row_resource(store, &Subject::from(subject)).await?;
    Some(name_of(&resource)).filter(|n| !n.is_empty())
}

/// Whether the entry kind `k` (a string or a list) names `FollowEvent`.
fn is_follow_event(kinds: Option<&Json>) -> bool {
    match kinds {
        Some(Json::String(k)) => k == urls::FOLLOW_EVENT,
        Some(Json::Array(list)) => list.iter().any(|k| k.as_str() == Some(urls::FOLLOW_EVENT)),
        _ => false,
    }
}

/// The text of an entry whatever its type: `t`, else `description`, else the
/// text parts of an AI-style entry.
fn entry_text(entry: &Json) -> String {
    for field in ["t", "description"] {
        if let Some(text) = entry.get(field).and_then(Json::as_str) {
            if !text.trim().is_empty() {
                return text.to_string();
            }
        }
    }
    entry
        .get("parts")
        .and_then(Json::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Json::as_str))
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn line_of_entry(entry: &Json, created_at: i64) -> Option<Line> {
    let text = entry_text(entry);
    if text.trim().is_empty() {
        return None;
    }
    Some(Line {
        id: entry.get("id")?.as_str()?.to_string(),
        author: entry
            .get("a")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string(),
        text,
        created_at,
        event: is_follow_event(entry.get("k")),
        reply_to: entry.get("r").and_then(Json::as_str).map(str::to_string),
    })
}

/// Where a window of a room ends: the log cursor of its oldest entry (`None`
/// once the log is exhausted) and the bound below which old `Message`
/// resources go to the next window: `(at, id)`, exclusive (an empty `id`
/// excludes every message at `at` or later). Opaque to the app.
#[derive(Clone, Debug, PartialEq)]
struct RoomCursor {
    log: Option<LogCursor>,
    at: i64,
    id: String,
}

impl RoomCursor {
    fn encode(&self) -> String {
        json!({ "l": self.log.as_ref().map(LogCursor::encode), "t": self.at, "s": self.id })
            .to_string()
    }

    fn decode(cursor: &str) -> AtomicResult<Self> {
        let bad = || format!("Not a chat room cursor: {cursor}");
        let json: Json = serde_json::from_str(cursor).map_err(|_| bad())?;
        let log = match json.get("l").and_then(Json::as_str) {
            Some(log) => Some(LogCursor::decode(log)?),
            None => None,
        };
        Ok(Self {
            log,
            at: json.get("t").and_then(Json::as_i64).ok_or_else(bad)?,
            id: json
                .get("s")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

/// The line of an old `Message` (or `FollowEvent`) resource; `None` for any
/// other child, one without text, or one moved into the log (its migrated
/// key is in `keys`).
fn legacy_line(
    subject: &Subject,
    resource: &crate::Resource,
    keys: &std::collections::HashSet<String>,
) -> Option<Line> {
    let classes = resource
        .get(urls::IS_A)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default();
    let event = classes.iter().any(|c| c == urls::FOLLOW_EVENT);
    if !event && !classes.iter().any(|c| c == urls::MESSAGE) {
        return None;
    }
    let text = resource
        .get(urls::DESCRIPTION)
        .map(|v| v.to_string())
        .unwrap_or_default();
    if text.trim().is_empty() {
        return None;
    }
    let at = resource
        .get(urls::CREATED_AT)
        .ok()
        .and_then(|v| v.to_int().ok())
        .unwrap_or(0);
    let id = subject.to_string();
    if keys.contains(&crate::chat_log::migrated_entry_key(at, &id)) {
        return None;
    }
    let author = resource
        .get(urls::CREATED_BY)
        .map(|v| v.to_string())
        .ok()
        .or_else(|| resource.genesis_signer())
        .unwrap_or_default();
    let reply_to = resource
        .get(urls::REPLY_TO)
        .ok()
        .map(|v| v.to_string())
        .filter(|r| !r.is_empty());
    Some(Line {
        id,
        author,
        text,
        created_at: at,
        event,
        reply_to,
    })
}

/// Old `Message` (and `FollowEvent`) resources under `chat` made at `lo` or
/// later (any time when `None`) and before `hi` (exclusive, see
/// [`RoomCursor`]), newest first, at most `cap`; and whether more were left.
/// Through a sorted index per class, so the cost follows the window, not the
/// room (the log pages, whose `createdAt` says nothing about their entries'
/// times when history was imported, are not in it).
async fn legacy_lines(
    store: &Db,
    chat: &str,
    lo: Option<i64>,
    hi: Option<&(i64, String)>,
    keys: &std::collections::HashSet<String>,
    cap: usize,
) -> AtomicResult<(Vec<Line>, bool)> {
    const BATCH: usize = 64;
    let drive = crate::host::chats::drive_scope(store, chat);
    let mut out: Vec<Line> = Vec::new();
    let mut more = false;
    for class in [urls::MESSAGE, urls::FOLLOW_EVENT] {
        let mut taken = 0;
        let mut offset = 0;
        'class: loop {
            let mut q = Query::new_prop_val(urls::PARENT, chat).class_filter(class);
            q.drive = Some(drive.clone());
            q.sort_by = Some(urls::CREATED_AT.to_string());
            q.sort_desc = true;
            q.start_val = lo.map(crate::Value::Timestamp);
            q.end_val = hi.map(|(at, _)| crate::Value::Timestamp(*at));
            q.offset = offset;
            q.limit = Some(BATCH);
            let subjects = store.query_page(&q).await?;
            let n = subjects.len();
            for subject in subjects {
                let Ok(resource) = store.get_resource(&subject).await else {
                    continue;
                };
                let Some(line) = legacy_line(&subject, &resource, keys) else {
                    continue;
                };
                if let Some((at, id)) = hi {
                    // `(at, "")` sorts below every `(at, id)`: all at `at` go.
                    if (line.created_at, line.id.as_str()) >= (*at, id.as_str()) {
                        continue;
                    }
                }
                if taken >= cap {
                    more = true;
                    break 'class;
                }
                taken += 1;
                out.push(line);
            }
            if n < BATCH {
                break;
            }
            offset += BATCH;
        }
    }
    // Newest first, cut to `cap` over both classes.
    out.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
    // A resource of both classes.
    out.dedup_by(|a, b| a.id == b.id);
    if out.len() > cap {
        out.truncate(cap);
        more = true;
    }
    Ok((out, more))
}

/// The lines of the log under `chat` and its old `Message` resources, oldest
/// first. An old message whose entry exists (it was moved into the log) is
/// left out, as in the web app.
async fn read_lines(store: &Db, chat: &str) -> AtomicResult<Vec<Line>> {
    let entries = chat_entries(store, chat).await?;
    let mut keys = std::collections::HashSet::new();
    let mut lines: Vec<Line> = Vec::new();
    for (at, entry) in &entries {
        if let Some((_, key)) = entry
            .get("id")
            .and_then(Json::as_str)
            .and_then(|i| i.split_once('#'))
        {
            keys.insert(key.to_string());
        }
        lines.extend(line_of_entry(entry, *at));
    }

    let children = store
        .query(&Query::new_prop_val(urls::PARENT, chat))
        .await?;
    for subject in &children.subjects {
        let Ok(resource) = store.get_resource(subject).await else {
            continue;
        };
        lines.extend(legacy_line(subject, &resource, &keys));
    }
    lines.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{test_support::Device, NoPush};
    use crate::Value;

    fn rooms() -> ChatRooms {
        ChatRooms::new(AgentProfiles::none())
    }

    fn entry(d: &Device, text: &str, at: i64) -> Entry {
        let author = d.store.get_default_agent().unwrap().subject.to_string();
        Entry::new(author, text, at)
    }

    fn event(d: &Device, text: &str, at: i64) -> Entry {
        let mut e = entry(d, text, at);
        e.kinds = Some(urls::FOLLOW_EVENT.into());
        e
    }

    #[test]
    fn trail_lines_are_parsed() {
        assert_eq!(
            parse_trail("Viewing [Roadmap](did:ad:abc)"),
            Some(("Roadmap".into(), "did:ad:abc".into()))
        );
        assert_eq!(
            parse_trail("Viewing [](https://x.test/a)"),
            Some((String::new(), "https://x.test/a".into()))
        );
        assert_eq!(parse_trail("Started the meeting."), None);
        assert_eq!(parse_trail("Viewing [x](a b)"), None);
    }

    #[tokio::test]
    async fn messages_and_events_are_read_oldest_first_and_classified() {
        let d = Device::new().await;
        let room = d.new_chat("Standup").await;
        let other = entry(&d, "Hi all", 1_000);
        let mut reply = entry(&d, "Hello!", 4_000);
        reply.reply_to = Some("x#1-00000001".into());
        d.add_page(
            &room,
            &[
                ("1-00000001", other),
                (
                    "2-00000002",
                    event(&d, &format!("Viewing [Roadmap]({})", room), 2_000),
                ),
                ("3-00000003", event(&d, "Started the meeting.", 3_000)),
                ("4-00000004", reply),
            ],
        )
        .await;

        let lines = rooms().read(&d.store, &room).await.unwrap();
        let kinds: Vec<&str> = lines.iter().map(|l| l["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["text", "event", "event", "text"]);
        assert_eq!(lines[0]["text"], "Hi all");
        assert_eq!(lines[0]["mine"], true);
        assert_eq!(lines[0]["author_name"], "Test device");
        assert_eq!(lines[1]["about"], room.as_str());
        assert_eq!(lines[1]["about_title"], "Roadmap");
        assert!(lines[2].get("about").is_none());
        assert_eq!(lines[2]["text"], "Started the meeting.");
        assert_eq!(lines[3]["mine"], true);
        assert_eq!(lines[3]["author_name"], "Test device");
        assert_eq!(lines[3]["reply_to"], "x#1-00000001");
        assert_eq!(lines[3]["c"], 4_000);
    }

    #[tokio::test]
    async fn an_author_this_device_does_not_hold_is_an_unknown_member() {
        let d = Device::new().await;
        let name = agent_name(&d.store, &AgentProfiles::none(), "did:ad:agent:nobody").await;
        assert_eq!(name, "Unknown member");
    }

    #[tokio::test]
    async fn a_trail_line_without_a_title_takes_the_local_name() {
        let d = Device::new().await;
        let room = d.new_chat("Named room").await;
        d.add_page(
            &room,
            &[(
                "1-00000001",
                event(&d, &format!("Viewing []({room})"), 1_000),
            )],
        )
        .await;
        let lines = rooms().read(&d.store, &room).await.unwrap();
        assert_eq!(lines[0]["about_title"], "Named room");
    }

    #[tokio::test]
    async fn unknown_kinds_show_whatever_text_they_hold() {
        let d = Device::new().await;
        let room = d.new_chat("Odd").await;
        let mut other_kind = entry(&d, "Hi", 1_000);
        other_kind.kinds = Some(vec!["https://example.com/classes/Poll".to_string()].into());
        let mut described = entry(&d, "", 2_000);
        described
            .extra
            .insert("description".into(), "From a description".into());
        // An AI-style entry: parts, no `t`.
        let ai = d.ai_entry("assistant", "From parts", 3_000);
        // Nothing to show.
        let empty = entry(&d, "", 4_000);
        d.add_page(
            &room,
            &[
                ("1-00000001", other_kind),
                ("2-00000002", described),
                ("3-00000003", ai),
                ("4-00000004", empty),
            ],
        )
        .await;
        let lines = rooms().read(&d.store, &room).await.unwrap();
        let shown: Vec<(&str, &str)> = lines
            .iter()
            .map(|l| (l["kind"].as_str().unwrap(), l["text"].as_str().unwrap()))
            .collect();
        assert_eq!(
            shown,
            [
                ("text", "Hi"),
                ("text", "From a description"),
                ("text", "From parts")
            ]
        );
    }

    #[tokio::test]
    async fn old_message_resources_are_listed_unless_they_were_moved_into_the_log() {
        let d = Device::new().await;
        let room = d.new_chat("Old").await;
        let author = d.store.get_default_agent().unwrap().subject.to_string();
        let mut kept = crate::Resource::new_generate_subject(&d.store).unwrap();
        kept.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(room.as_str().into()))
            .unwrap();
        kept.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::MESSAGE.into()]),
        )
        .unwrap();
        kept.set_unsafe(
            urls::DESCRIPTION.into(),
            Value::String("Old message".into()),
        )
        .unwrap();
        kept.set_unsafe(urls::CREATED_AT.into(), Value::Integer(500))
            .unwrap();
        kept.set_unsafe(
            urls::CREATED_BY.into(),
            Value::AtomicUrl(author.as_str().into()),
        )
        .unwrap();
        kept.save_locally(&d.store).await.unwrap();
        d.add_page(&room, &[("1-00000001", entry(&d, "New message", 900))])
            .await;

        let lines = rooms().read(&d.store, &room).await.unwrap();
        let texts: Vec<&str> = lines.iter().map(|l| l["text"].as_str().unwrap()).collect();
        assert_eq!(texts, ["Old message", "New message"]);
        assert_eq!(lines[0]["mine"], true);
    }

    const T0: i64 = 1_700_000_000_000;

    async fn old_message(d: &Device, room: &str, text: &str, at: i64) {
        let author = d.store.get_default_agent().unwrap().subject.to_string();
        let mut r = crate::Resource::new_generate_subject(&d.store).unwrap();
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(room.into()))
            .unwrap();
        r.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::MESSAGE.into()]),
        )
        .unwrap();
        r.set_unsafe(urls::DESCRIPTION.into(), Value::String(text.into()))
            .unwrap();
        r.set_unsafe(urls::CREATED_AT.into(), Value::Integer(at))
            .unwrap();
        r.set_unsafe(
            urls::CREATED_BY.into(),
            Value::AtomicUrl(author.as_str().into()),
        )
        .unwrap();
        r.save_locally(&d.store).await.unwrap();
    }

    /// A room read window by window: log entries and old `Message`
    /// resources merged by time, each line once, also the old messages from
    /// before the log began.
    #[tokio::test]
    async fn room_windows_merge_old_messages_by_time() {
        let d = Device::new().await;
        let room = d.new_chat("Long room").await;
        let entries: Vec<Entry> = (0..700)
            .map(|i| entry(&d, &format!("e{i:04}"), T0 + 10_000 + i * 10))
            .collect();
        crate::host::chats::import_entries(&d.node, &NoPush, &room, &entries)
            .await
            .unwrap();
        // Between entries, and long before the log.
        for (i, at) in [10_005i64, 13_335, 16_995, 17_000_000]
            .iter()
            .chain((0..30).map(|i| 100 + i * 10).collect::<Vec<_>>().iter())
            .map(|at| T0 + at)
            .enumerate()
        {
            old_message(&d, &room, &format!("old{i:02}@{at}"), at).await;
        }

        let all = rooms().read(&d.store, &room).await.unwrap();
        let want: Vec<&str> = all.iter().map(|l| l["text"].as_str().unwrap()).collect();
        assert_eq!(want.len(), 734);

        let mut texts: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let window = rooms()
                .read_page(&d.store, &room, cursor.as_deref(), 64)
                .await
                .unwrap();
            let mut page: Vec<String> = window["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l["text"].as_str().unwrap().to_string())
                .collect();
            page.extend(texts);
            texts = page;
            cursor = window["older"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(texts, want);

        let first = rooms().read_page(&d.store, &room, None, 10).await.unwrap();
        let newest = first["newest"].as_str().unwrap().to_string();
        send_message(&d.node, &NoPush, &room, "fresh", None)
            .await
            .unwrap();
        let after = rooms()
            .read_after(&d.store, &room, &newest, 50)
            .await
            .unwrap();
        assert_eq!(after["messages"][0]["text"], "fresh");
    }

    #[tokio::test]
    async fn a_sent_message_is_in_the_log_a_web_client_reads() {
        let d = Device::new().await;
        let room = d.new_chat("Send").await;
        let first = send_message(&d.node, &NoPush, &room, "  Hello  ", None)
            .await
            .unwrap();
        let second = send_message(&d.node, &NoPush, &room, "Again", Some(&first))
            .await
            .unwrap();
        assert_eq!(first.split('#').next(), second.split('#').next());

        // The raw entry has the fields the web app reads: a, t, c, r.
        let raw = chat_entries(&d.store, &room).await.unwrap();
        assert_eq!(raw.len(), 2);
        let agent = d.store.get_default_agent().unwrap().subject.to_string();
        assert_eq!(raw[0].1["t"], "Hello");
        assert_eq!(raw[0].1["a"], agent.as_str());
        assert_eq!(raw[1].1["r"], first.as_str());

        let lines = rooms().read(&d.store, &room).await.unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["reply_to"], first.as_str());
        assert_eq!(lines[0]["mine"], true);

        assert!(send_message(&d.node, &NoPush, &room, "   ", None)
            .await
            .is_err());
    }
}
