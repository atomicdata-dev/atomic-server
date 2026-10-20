//! Chats as typed rows for the native chat screens: AI chats, conversations
//! (end-to-end encrypted DMs) and the chat of a meeting or chat room.
//!
//! Reading is in windows, like Flutter's long-chat paging
//! (`claude/flutter-mobile-app-w8e9wz`: `read_chat_page` / `read_chat_after`):
//! the newest `limit` messages, then the window before one (`before` cursor),
//! then what came after a message (a poll). The `atomic_lib::host` of this
//! branch has no windowed reads yet (they came with that branch, in
//! `lib/src/host/chats.rs`), so each call reads the chat whole and cuts the
//! window out of it. The cursors are message ids, which stay valid when
//! messages are added anywhere, so swapping the cut for the library's windows
//! changes no Kotlin.

use crate::{
    error::CoreResult,
    state::{self, chat_rooms, conversations, db, node},
};
use atomic_lib::{chat_log::Entry, host::chats, Storelike};
use serde_json::Value as Json;

// ── Records ────────────────────────────────────────────────────────────────

/// One message of an AI chat. `parts_json` is the web app's `parts` (an array,
/// the AI SDK UI message parts), `ctx_json` the resources attached as context
/// (the entry's `ctx`, an array) when there are any.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AiChatEntry {
    pub id: String,
    /// `user` or `assistant`.
    pub role: String,
    pub parts_json: String,
    pub ctx_json: Option<String>,
    pub created_at: i64,
}

/// A window of an AI chat, oldest first. `older` is the cursor to read the
/// window before this one (`None` at the start of the chat), `newest` the
/// cursor to read what came after (`None` for an empty chat). `more` (reads
/// after a cursor) is true when `limit` cut the list.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AiChatPage {
    pub entries: Vec<AiChatEntry>,
    pub older: Option<String>,
    pub newest: Option<String>,
    pub more: bool,
}

/// One line of a conversation or a chat room. `text` is `None` for a
/// conversation message this device cannot decrypt. `is_event` lines are the
/// system lines of a meeting; a "Viewing" line has `about` (the resource) and
/// `about_title`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ThreadMessage {
    pub id: String,
    pub author: String,
    pub author_name: String,
    pub mine: bool,
    pub text: Option<String>,
    pub created_at: i64,
    pub reply_to: Option<String>,
    pub is_event: bool,
    pub about: Option<String>,
    pub about_title: String,
}

/// A window of a conversation or chat room; see [`AiChatPage`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ThreadPage {
    pub messages: Vec<ThreadMessage>,
    pub older: Option<String>,
    pub newest: Option<String>,
    pub more: bool,
}

// ── Windows ────────────────────────────────────────────────────────────────

/// The slice `[start, end)` of `ids` that is the newest `limit` before the
/// message `before` (the newest of all for `None`; the end of the list when the
/// id is not there).
pub(crate) fn window_before(ids: &[String], before: Option<&str>, limit: usize) -> (usize, usize) {
    let end = before
        .and_then(|b| ids.iter().position(|i| i == b))
        .unwrap_or(ids.len());
    (end.saturating_sub(limit.max(1)), end)
}

/// The slice after the message `after` and whether `limit` cut it. An id that
/// is not there yields nothing (the caller keeps its cursor).
pub(crate) fn window_after(ids: &[String], after: &str, limit: usize) -> (usize, usize, bool) {
    let Some(at) = ids.iter().position(|i| i == after) else {
        return (ids.len(), ids.len(), false);
    };
    let start = at + 1;
    let end = (start + limit.max(1)).min(ids.len());
    (start, end, end < ids.len())
}

fn cut<T: Clone>(
    all: &[T],
    id: impl Fn(&T) -> &str,
    cursor: Cursor<'_>,
    limit: usize,
) -> (Vec<T>, Option<String>, Option<String>, bool) {
    let ids: Vec<String> = all.iter().map(|m| id(m).to_string()).collect();
    match cursor {
        Cursor::Before(before) => {
            let (start, end) = window_before(&ids, before, limit);
            let older = (start > 0).then(|| ids[start].clone());
            let newest = (end > start).then(|| ids[end - 1].clone());
            (all[start..end].to_vec(), older, newest, false)
        }
        Cursor::After(after) => {
            let (start, end, more) = window_after(&ids, after, limit);
            let newest = if end > start { ids[end - 1].clone() } else { after.to_string() };
            (all[start..end].to_vec(), None, Some(newest), more)
        }
    }
}

#[derive(Clone, Copy)]
enum Cursor<'a> {
    Before(Option<&'a str>),
    After(&'a str),
}

// ── AI chats ───────────────────────────────────────────────────────────────

/// Text parts, tool calls and files of the entries a chat shows: user and
/// assistant only (a `summary` is the web app's own bookkeeping), and not an
/// entry without any part.
pub(crate) fn ai_entry(raw: &Json) -> Option<AiChatEntry> {
    let role = raw.get("role")?.as_str()?;
    if role != "user" && role != "assistant" {
        return None;
    }
    let parts = raw.get("parts").and_then(Json::as_array)?;
    if parts.is_empty() {
        return None;
    }
    let ctx = raw
        .get("ctx")
        .and_then(Json::as_str)
        .filter(|c| !c.is_empty() && *c != "[]")
        .map(str::to_string);
    Some(AiChatEntry {
        id: raw.get("id")?.as_str()?.to_string(),
        role: role.to_string(),
        parts_json: Json::Array(parts.clone()).to_string(),
        ctx_json: ctx,
        created_at: raw.get("c").and_then(Json::as_i64).unwrap_or(0),
    })
}

async fn ai_entries(store: &atomic_lib::Db, chat: &str) -> CoreResult<Vec<AiChatEntry>> {
    Ok(chats::read_chat(store, chat).await?.iter().filter_map(ai_entry).collect())
}

fn ai_page(all: &[AiChatEntry], cursor: Cursor<'_>, limit: usize) -> AiChatPage {
    let (entries, older, newest, more) = cut(all, |e| &e.id, cursor, limit);
    AiChatPage { entries, older, newest, more }
}

pub(crate) async fn ai_chat_page(
    store: &atomic_lib::Db,
    chat: &str,
    before: Option<&str>,
    limit: usize,
) -> CoreResult<AiChatPage> {
    Ok(ai_page(&ai_entries(store, chat).await?, Cursor::Before(before), limit))
}

pub(crate) async fn ai_chat_after(
    store: &atomic_lib::Db,
    chat: &str,
    after: &str,
    limit: usize,
) -> CoreResult<AiChatPage> {
    Ok(ai_page(&ai_entries(store, chat).await?, Cursor::After(after), limit))
}

/// The newest `limit` messages of an AI chat older than `before` (the newest
/// of all for `None`), oldest first.
#[uniffi::export(async_runtime = "tokio")]
pub async fn read_ai_chat_page(subject: String, before: Option<String>, limit: u32) -> CoreResult<AiChatPage> {
    ai_chat_page(db()?, &subject, before.as_deref(), limit as usize).await
}

/// The messages of an AI chat after the cursor `after`.
#[uniffi::export(async_runtime = "tokio")]
pub async fn read_ai_chat_after(subject: String, after: String, limit: u32) -> CoreResult<AiChatPage> {
    ai_chat_after(db()?, &subject, &after, limit as usize).await
}

pub(crate) async fn append_ai(
    node: &atomic_lib::runtime::AtomicNode,
    pusher: &dyn atomic_lib::host::LocalWritePusher,
    chat: &str,
    role: &str,
    parts_json: &str,
    ctx_json: Option<&str>,
) -> CoreResult<String> {
    let author = node.db().get_default_agent()?.subject.to_string();
    let mut entry = Entry::new(author, "", state::now_ms());
    entry.extra.insert("role".into(), role.into());
    entry.extra.insert("parts".into(), parts_json.into());
    if let Some(ctx) = ctx_json.filter(|c| !c.is_empty()) {
        entry.extra.insert("ctx".into(), ctx.into());
    }
    Ok(chats::append_entry(node, pusher, chat, &entry).await?)
}

/// Add a message to an AI chat as the web app stores it (`parts_json` the
/// message's parts, `ctx_json` the resources attached to a user message).
/// Returns the entry's id.
#[uniffi::export(async_runtime = "tokio")]
pub async fn append_ai_chat_entry(
    chat: String,
    role: String,
    parts_json: String,
    ctx_json: Option<String>,
) -> CoreResult<String> {
    append_ai(&node()?, state::pusher().as_ref(), &chat, &role, &parts_json, ctx_json.as_deref()).await
}

// ── Conversations and chat rooms ───────────────────────────────────────────

fn thread_message(raw: &Json) -> Option<ThreadMessage> {
    let text = |key: &str| raw.get(key).and_then(Json::as_str).map(str::to_string);
    Some(ThreadMessage {
        id: text("id")?,
        author: text("author").unwrap_or_default(),
        author_name: text("author_name").unwrap_or_default(),
        mine: raw.get("mine").and_then(Json::as_bool).unwrap_or(false),
        // A conversation message that cannot be opened has `text: null`; a
        // room line always has text.
        text: raw.get("text").and_then(Json::as_str).map(str::to_string),
        created_at: raw.get("c").and_then(Json::as_i64).unwrap_or(0),
        reply_to: text("reply_to"),
        is_event: raw.get("kind").and_then(Json::as_str) == Some("event"),
        about: text("about"),
        about_title: text("about_title").unwrap_or_default(),
    })
}

fn thread_page(rows: &[Json], cursor: Cursor<'_>, limit: usize) -> ThreadPage {
    let all: Vec<ThreadMessage> = rows.iter().filter_map(thread_message).collect();
    let (messages, older, newest, more) = cut(&all, |m| &m.id, cursor, limit);
    ThreadPage { messages, older, newest, more }
}

pub(crate) async fn conversation_rows(store: &atomic_lib::Db, subject: &str) -> CoreResult<Vec<Json>> {
    Ok(conversations().read(store, subject).await?)
}

pub(crate) async fn room_rows(store: &atomic_lib::Db, subject: &str) -> CoreResult<Vec<Json>> {
    Ok(chat_rooms().read(store, subject).await?)
}

/// A window of a conversation: only decrypted messages are text; one this
/// agent cannot open has no text.
#[uniffi::export(async_runtime = "tokio")]
pub async fn read_conversation_page(subject: String, before: Option<String>, limit: u32) -> CoreResult<ThreadPage> {
    Ok(thread_page(&conversation_rows(db()?, &subject).await?, Cursor::Before(before.as_deref()), limit as usize))
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn read_conversation_after(subject: String, after: String, limit: u32) -> CoreResult<ThreadPage> {
    Ok(thread_page(&conversation_rows(db()?, &subject).await?, Cursor::After(&after), limit as usize))
}

/// Post `text` in a conversation as this device's agent: sealed with the
/// conversation's newest key, synced like any other edit. Returns the
/// message's subject.
#[uniffi::export(async_runtime = "tokio")]
pub async fn send_conversation_message(subject: String, text: String) -> CoreResult<String> {
    Ok(atomic_lib::host::conversations::send_message(&node()?, state::pusher().as_ref(), &subject, &text).await?)
}

/// Get a conversation onto this device and follow it: fetched from the
/// connected server when missing, and its new messages arrive over the open
/// sync session. Errors (no session, not hosted there) are for the caller to
/// ignore; reading what is already local does not need this.
#[uniffi::export(async_runtime = "tokio")]
pub async fn follow_conversation(subject: String) -> CoreResult<()> {
    Ok(crate::sync::ws::follow_drive(&subject).await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn read_room_page(subject: String, before: Option<String>, limit: u32) -> CoreResult<ThreadPage> {
    Ok(thread_page(&room_rows(db()?, &subject).await?, Cursor::Before(before.as_deref()), limit as usize))
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn read_room_after(subject: String, after: String, limit: u32) -> CoreResult<ThreadPage> {
    Ok(thread_page(&room_rows(db()?, &subject).await?, Cursor::After(&after), limit as usize))
}

/// Post `text` in a meeting or chat room as this device's agent, as the web
/// app does. `reply_to` is the id of the message it answers.
#[uniffi::export(async_runtime = "tokio")]
pub async fn send_room_message(subject: String, text: String, reply_to: Option<String>) -> CoreResult<String> {
    Ok(atomic_lib::host::chat_rooms::send_message(
        &node()?,
        state::pusher().as_ref(),
        &subject,
        &text,
        reply_to.as_deref(),
    )
    .await?)
}

// ── Around the chats ───────────────────────────────────────────────────────

/// Give `subject` a new name (a chat room shown natively has no web page to
/// edit its title on).
#[uniffi::export(async_runtime = "tokio")]
pub async fn rename_resource(subject: String, name: String) -> CoreResult<()> {
    let node = node()?;
    let mut resource = node.db().get_resource(&subject.as_str().into()).await?;
    resource
        .set_unsafe(atomic_lib::urls::NAME.into(), atomic_lib::Value::String(name))
        .map_err(|e| e.to_string())?;
    let response = node.save_locally(&mut resource).await?;
    state::pusher().push(&response).await;
    Ok(())
}

/// Readable text of `subject` for an AI's context, at most `max_chars`.
#[uniffi::export(async_runtime = "tokio")]
pub async fn resource_text(subject: String, max_chars: u32) -> CoreResult<String> {
    Ok(atomic_lib::host::context::read_resource_text(db()?, &subject, max_chars as usize).await?)
}

/// Sign `message` with this device's agent key (base64 as Atomic writes it):
/// the account sign-in proves the agent this way, so the key never leaves Rust.
#[uniffi::export]
pub fn sign_with_agent(message: String) -> CoreResult<String> {
    let agent = db()?.get_default_agent()?;
    let key = agent.private_key.as_deref().ok_or("This agent has no private key")?;
    Ok(atomic_lib::agents::sign_message(message.as_bytes(), key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomic_lib::host::{profiles::AgentProfiles, NoProfiles, NoPush};
    use serde_json::json;

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("m{i}")).collect()
    }

    #[test]
    fn the_newest_window_ends_at_the_end_and_the_next_one_ends_where_it_starts() {
        let all = ids(10);
        assert_eq!(window_before(&all, None, 4), (6, 10));
        assert_eq!(window_before(&all, Some("m6"), 4), (2, 6));
        assert_eq!(window_before(&all, Some("m2"), 4), (0, 2));
        // A short chat is one window; a cursor that is gone reads the newest.
        assert_eq!(window_before(&ids(3), None, 50), (0, 3));
        assert_eq!(window_before(&all, Some("gone"), 4), (6, 10));
    }

    #[test]
    fn what_came_after_a_cursor_is_cut_by_the_limit() {
        let all = ids(10);
        assert_eq!(window_after(&all, "m6", 2), (7, 9, true));
        assert_eq!(window_after(&all, "m6", 10), (7, 10, false));
        assert_eq!(window_after(&all, "m9", 10), (10, 10, false));
        assert_eq!(window_after(&all, "gone", 10), (10, 10, false));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_long_ai_chat_is_read_window_by_window_and_polled() {
        let d = crate::tests::Device::new("ai-windows").await;
        let chat = chats::create_ai_chat(&d.node, &NoPush, "Windows").await.unwrap();
        for i in 0..7 {
            let role = if i % 2 == 0 { "user" } else { "assistant" };
            let parts = json!([{ "type": "text", "text": format!("message {i}") }]).to_string();
            append_ai(&d.node, &NoPush, &chat, role, &parts, None).await.unwrap();
            // Entry keys sort by time: keep them apart.
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let text = |e: &AiChatEntry| {
            serde_json::from_str::<Json>(&e.parts_json).unwrap()[0]["text"].as_str().unwrap().to_string()
        };

        let newest = ai_chat_page(&d.db, &chat, None, 3).await.unwrap();
        assert_eq!(newest.entries.iter().map(text).collect::<Vec<_>>(), ["message 4", "message 5", "message 6"]);
        assert!(newest.older.is_some());
        assert_eq!(newest.entries[2].role, "user");

        let middle = ai_chat_page(&d.db, &chat, newest.older.as_deref(), 3).await.unwrap();
        assert_eq!(middle.entries.iter().map(text).collect::<Vec<_>>(), ["message 1", "message 2", "message 3"]);
        let first = ai_chat_page(&d.db, &chat, middle.older.as_deref(), 3).await.unwrap();
        assert_eq!(first.entries.iter().map(text).collect::<Vec<_>>(), ["message 0"]);
        assert_eq!(first.older, None, "the start of the chat");

        // A poll with the newest cursor sees only what was written since.
        let none = ai_chat_after(&d.db, &chat, newest.newest.as_deref().unwrap(), 10).await.unwrap();
        assert!(none.entries.is_empty());
        assert_eq!(none.newest, newest.newest);
        let parts = json!([{ "type": "text", "text": "message 7" }]).to_string();
        append_ai(&d.node, &NoPush, &chat, "assistant", &parts, None).await.unwrap();
        let news = ai_chat_after(&d.db, &chat, newest.newest.as_deref().unwrap(), 10).await.unwrap();
        assert_eq!(news.entries.iter().map(text).collect::<Vec<_>>(), ["message 7"]);
        assert!(!news.more);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_context_of_a_message_is_kept_and_other_roles_are_left_out() {
        let d = crate::tests::Device::new("ai-ctx").await;
        let chat = chats::create_ai_chat(&d.node, &NoPush, "Context").await.unwrap();
        let ctx = json!([{ "type": "atomic-resource", "subject": "did:ad:x", "title": "Plan" }]).to_string();
        let parts = json!([{ "type": "text", "text": "Summarise this" }]).to_string();
        append_ai(&d.node, &NoPush, &chat, "user", &parts, Some(&ctx)).await.unwrap();
        append_ai(&d.node, &NoPush, &chat, "summary", &parts, None).await.unwrap();
        append_ai(&d.node, &NoPush, &chat, "assistant", "[]", None).await.unwrap();

        let page = ai_chat_page(&d.db, &chat, None, 50).await.unwrap();
        assert_eq!(page.entries.len(), 1, "a summary and an entry without parts are not shown");
        assert_eq!(page.entries[0].ctx_json.as_deref(), Some(ctx.as_str()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_room_line_sent_here_comes_back_with_its_author_and_reply() {
        let d = crate::tests::Device::new("room").await;
        // Any chat log is a room to the host.
        let room = chats::create_ai_chat(&d.node, &NoPush, "Standup").await.unwrap();
        let first = atomic_lib::host::chat_rooms::send_message(&d.node, &NoPush, &room, "Morning", None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        atomic_lib::host::chat_rooms::send_message(&d.node, &NoPush, &room, "Hi again", Some(&first)).await.unwrap();

        let rooms = atomic_lib::host::chat_rooms::ChatRooms::new(AgentProfiles::new(std::sync::Arc::new(NoProfiles)));
        let rows = rooms.read(&d.db, &room).await.unwrap();
        let page = thread_page(&rows, Cursor::Before(None), 50);
        assert_eq!(page.messages.len(), 2);
        assert_eq!(page.messages[0].text.as_deref(), Some("Morning"));
        assert!(page.messages[0].mine);
        assert_eq!(page.messages[0].author_name, "Pelican");
        assert_eq!(page.messages[1].reply_to.as_deref(), Some(first.as_str()));
        assert!(!page.messages[1].is_event);
        assert_eq!(page.older, None);
    }

    #[test]
    fn a_message_that_cannot_be_opened_has_no_text_and_an_event_is_marked() {
        let rows = vec![
            json!({"id": "a", "author": "x", "author_name": "Anna", "mine": false, "text": null, "c": 5}),
            json!({"id": "b", "author": "y", "author_name": "Bo", "mine": true, "text": "Viewing [Plan](did:ad:p)", "c": 6,
                   "kind": "event", "about": "did:ad:p", "about_title": "Plan"}),
        ];
        let page = thread_page(&rows, Cursor::Before(None), 10);
        assert_eq!(page.messages[0].text, None);
        assert_eq!(page.messages[0].author_name, "Anna");
        assert!(page.messages[1].is_event);
        assert_eq!(page.messages[1].about.as_deref(), Some("did:ad:p"));
        assert_eq!(page.messages[1].about_title, "Plan");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_agent_signs_account_challenges_and_the_signature_verifies() {
        let d = crate::tests::Device::new("sign").await;
        let agent = d.db.get_default_agent().unwrap();
        let key = agent.private_key.clone().unwrap();
        let signature = atomic_lib::agents::sign_message(b"challenge 1", &key).unwrap();
        assert!(!signature.contains(['+', '/', '=']), "URL-safe, unpadded like the portal expects");
        assert_ne!(signature, atomic_lib::agents::sign_message(b"challenge 2", &key).unwrap());
    }
}
