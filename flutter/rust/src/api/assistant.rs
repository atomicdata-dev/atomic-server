//! The assistant and home screens: AI chats, conversations, the home lists and
//! search, as JSON for the Dart side.
//!
//! The logic is `atomic_lib::host` (lists, chats, conversations, recents);
//! these functions bind it to the store `open_db` opened, push what they write
//! like every other local write of this app, and keep the Dart-facing names
//! and shapes.

#[cfg(test)]
mod tests;

use super::simple::state::{connected_server, db, err, node};
use crate::host::{chat_rooms, conversations, profiles, pusher, recents, to_json};
use atomic_lib::host::{chats, lists, notifications};
use flutter_rust_bridge::frb;

/// The emojis of `subjects` as JSON `{subject: emoji}`, only for those that
/// have one. For rows that do not carry their icon themselves (the activity
/// feed), read from the stored propvals like the other rows.
pub async fn resource_icons(subjects: Vec<String>) -> Result<String, String> {
    to_json(&lists::resource_icons(db()?, subjects).await)
}

/// `limit` AI chats of the person (all drives) after the `offset` newest
/// ones, newest activity first, as JSON `[{subject, name, last_activity}]`
/// (`last_activity` in ms, 0 when empty). A page shorter than `limit` is the
/// last. Read from the recents index, not rebuilt from the chats' pages.
pub async fn list_ai_chats(limit: u32, offset: u32) -> Result<String, String> {
    let list = lists::list_ai_chats_page(db()?, recents(), offset as usize, limit as usize)
        .await
        .map_err(err)?;
    to_json(&list)
}

/// The notifications in the Inbox of the person's private drive (what the web
/// app recorded there), newest first, one per source, as JSON `[{subject,
/// title, body, about, kind, actor, source, occurred_at, read}]`. Read from the
/// local store; empty when there is no Inbox on this device.
pub async fn list_notifications(limit: u32) -> Result<String, String> {
    to_json(
        &notifications::list_notifications(db()?, limit as usize)
            .await
            .map_err(err)?,
    )
}

/// Mark a notification read (`readAt`, as the web app does), and the other
/// copies of the same event in the Inbox. Synced like any other edit.
pub async fn mark_notification_read(subject: String) -> Result<(), String> {
    notifications::mark_notification_read(
        &node()?,
        pusher().as_ref(),
        &subject,
        super::simple::state::now_ms(),
    )
    .await
    .map(|_| ())
    .map_err(err)
}

/// One line of the activity feed.
pub struct ActivityEntry {
    pub subject: String,
    pub drive: String,
    /// `created`, `changed` or `deleted`.
    pub kind: String,
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
pub async fn list_activity(limit: u32) -> Result<Vec<ActivityEntry>, String> {
    // Other agents' changes only (the person's own are Recents), each named:
    // by the store, the server's profile, or the start of its key.
    let rows = lists::list_activity(db()?, recents(), &profiles(), None, limit as usize).await;
    Ok(rows
        .into_iter()
        .map(|a| ActivityEntry {
            subject: a.subject,
            drive: a.drive,
            kind: a.kind.as_str().to_string(),
            at: a.at,
            actor: Some(a.actor),
            name: a.name,
            class_name: a.class_name,
        })
        .collect())
}

/// Record that this device opened `subject` in `drive`. Local to the device:
/// nothing is committed or synced.
#[frb(sync)]
pub fn note_resource_opened(drive: String, subject: String) {
    recents().note_opened(&drive, &subject, super::simple::state::now_ms());
}

/// The `limit` resources of `drive` this device opened last, newest first, as
/// JSON `[{subject, title, class_name, opened_at}]`. Resources that are gone
/// are left out.
pub async fn list_recent_resources(drive: String, limit: u32) -> Result<String, String> {
    to_json(&lists::list_recent_resources(db()?, recents(), &drive, limit as usize).await)
}

/// The person's favorites (all drives), newest added first, as JSON
/// `[{subject, title, class_name, opened_at}]` (`opened_at` is always 0).
/// Favorites that are gone or unreadable are left out.
pub async fn list_favorites(limit: u32) -> Result<String, String> {
    to_json(
        &lists::list_favorites(db()?, limit as usize)
            .await
            .map_err(err)?,
    )
}

/// The person's conversations (DMs and group chats), as JSON
/// `[{subject, title, class_name, opened_at, last_message, emoji?}]`, newest
/// activity first (`opened_at` is the time of the last message in ms, 0 for an
/// empty or unreadable one, which come last in the order the private drive
/// lists them). A conversation has no name of its own: its title is who else is
/// in it, as the web app shows it. `last_message` is the text of the newest
/// message ("" when there is none or it cannot be opened). `class_name` is
/// `conversation`, which the app opens natively.
pub async fn list_conversations(limit: u32) -> Result<String, String> {
    to_json(
        &conversations()
            .list(db()?, limit as usize)
            .await
            .map_err(err)?,
    )
}

/// The messages of a conversation, oldest first, as JSON `[{id, author,
/// author_name, mine, text, c, reply_to?}]`: `id` the message's subject,
/// `author` who signed it (an agent subject), `author_name` their name (the
/// cached name or "Unknown member", never waiting on the network), `mine` when
/// this device's agent wrote it, `text` the decrypted text (null when this
/// agent cannot open it) and `c` its time in ms. Read from the local store;
/// see [`follow_conversation`] to get the conversation onto this device.
pub async fn read_conversation(subject: String) -> Result<String, String> {
    to_json(&conversations().read(db()?, &subject).await.map_err(err)?)
}

/// Post `text` in a conversation as this device's agent: sealed with the
/// conversation's newest epoch key, saved as a `SealedMessage` under it that
/// only the author may write (as the web app does), and synced like any
/// other edit. Returns the message's subject.
pub async fn send_conversation_message(subject: String, text: String) -> Result<String, String> {
    atomic_lib::host::conversations::send_message(&node()?, pusher().as_ref(), &subject, &text)
        .await
        .map_err(err)
}

/// Get a conversation onto this device and follow it: fetched from the
/// connected server when missing, and its new messages arrive over the open
/// sync session. Errors (no session, not hosted there) are for the caller to
/// ignore; reading what is already local does not need this.
pub async fn follow_conversation(subject: String) -> Result<(), String> {
    super::simple::ws_sync::follow_drive(&subject).await
}

/// The entries of a chat, oldest first, as a JSON array of the fields the web
/// app stores: `id`, `a`, `c`, `role`, `parts` (array) and the rest as is.
pub async fn read_chat(subject: String) -> Result<String, String> {
    to_json(&chats::read_chat(db()?, &subject).await.map_err(err)?)
}

/// The chat of a meeting or chat room, oldest first, as JSON `[{id, author,
/// author_name, mine, kind, text, c, reply_to?, about?, about_title?}]`:
/// `kind` is `text` (a message) or `event` (a system line of a meeting; a
/// "Viewing" trail line has `about`, the resource viewed, and `about_title`).
/// Read from the local store, never waiting on the network.
pub async fn read_chat_room(subject: String) -> Result<String, String> {
    to_json(&chat_rooms().read(db()?, &subject).await.map_err(err)?)
}

// ── Windows of long chats ────────────────────────────────────────────────
//
// A chat can hold hundreds of thousands of messages. The chat screens read it
// in windows: `*_page(subject, None, 50)` for the newest 50, then
// `*_page(subject, older, 50)` with the `older` cursor of the window before
// as the person scrolls up, and `*_after(subject, newest, limit)` to pick up
// what arrived since (a poll). Cursors are opaque strings; each call reads
// only what its window covers.

/// A window of an AI chat: JSON `{entries, older, newest}`, `entries` as
/// [`read_chat`] gives them (oldest first), `older` the cursor of the window
/// before (null at the start of the chat), `newest` the cursor of the last
/// entry (null for an empty chat).
pub async fn read_chat_page(
    subject: String,
    before: Option<String>,
    limit: u32,
) -> Result<String, String> {
    to_json(
        &chats::read_chat_page(db()?, &subject, before.as_deref(), limit as usize)
            .await
            .map_err(err)?,
    )
}

/// The entries of an AI chat after the `after` cursor: JSON `{entries,
/// newest, more}`, `newest` the cursor for the next call, `more` when
/// `limit` cut the list.
pub async fn read_chat_after(subject: String, after: String, limit: u32) -> Result<String, String> {
    to_json(
        &chats::read_chat_after(db()?, &subject, &after, limit as usize)
            .await
            .map_err(err)?,
    )
}

/// A window of a meeting or chat room: JSON `{messages, older, newest}`,
/// `messages` as [`read_chat_room`] gives them. See [`read_chat_page`].
pub async fn read_chat_room_page(
    subject: String,
    before: Option<String>,
    limit: u32,
) -> Result<String, String> {
    to_json(
        &chat_rooms()
            .read_page(db()?, &subject, before.as_deref(), limit as usize)
            .await
            .map_err(err)?,
    )
}

/// The messages of a meeting or chat room after `after`: JSON `{messages,
/// newest, more}`. See [`read_chat_after`].
pub async fn read_chat_room_after(
    subject: String,
    after: String,
    limit: u32,
) -> Result<String, String> {
    to_json(
        &chat_rooms()
            .read_after(db()?, &subject, &after, limit as usize)
            .await
            .map_err(err)?,
    )
}

/// A window of a conversation: JSON `{messages, older, newest}`, `messages`
/// as [`read_conversation`] gives them; only the window is decrypted.
pub async fn read_conversation_page(
    subject: String,
    before: Option<String>,
    limit: u32,
) -> Result<String, String> {
    to_json(
        &conversations()
            .read_page(db()?, &subject, before.as_deref(), limit as usize)
            .await
            .map_err(err)?,
    )
}

/// The messages of a conversation after `after`: JSON `{messages, newest,
/// more}`.
pub async fn read_conversation_after(
    subject: String,
    after: String,
    limit: u32,
) -> Result<String, String> {
    to_json(
        &conversations()
            .read_after(db()?, &subject, &after, limit as usize)
            .await
            .map_err(err)?,
    )
}

/// Post `text` in a meeting or chat room as this device's agent, as the web
/// app does, so web clients show it. `reply_to` is the `id` of the message it
/// answers. Returns the entry's id (`<page>#<key>`).
pub async fn send_chat_room_message(
    subject: String,
    text: String,
    reply_to: Option<String>,
) -> Result<String, String> {
    atomic_lib::host::chat_rooms::send_message(
        &node()?,
        pusher().as_ref(),
        &subject,
        &text,
        reply_to.as_deref(),
    )
    .await
    .map_err(err)
}

/// Full-text search (type-ahead on the last word) across every drive of this
/// store, or only in `drive` when given. JSON
/// `[{subject, title, class_name, drive, score}]`, best first; `drive` is the
/// drive the hit lives in ("" when unknown). `classes` (`drive`, `aichat`,
/// `conversation`, `chatroom`, or class URLs; empty: any) keeps only
/// resources of those classes, applied before the limit.
pub async fn search(
    drive: Option<String>,
    query: String,
    limit: u32,
    classes: Vec<String>,
) -> Result<String, String> {
    to_json(
        &lists::search_classes(db()?, drive.as_deref(), &query, limit as usize, &classes)
            .map_err(err)?,
    )
}

/// Read the search index once so the first keystroke is not cold. Call it
/// after the first frame; it runs on a blocking thread and never fails.
pub async fn warm_search() -> Result<(), String> {
    let store = db()?.clone();
    let _ = tokio::task::spawn_blocking(move || lists::warm_search(&store)).await;
    Ok(())
}

/// The URL that shows `subject` in the data-browser of the connected server,
/// for a webview. Errors when no server is connected (`open_ws_sync`).
#[frb(sync)]
pub fn resource_web_url(subject: String) -> Result<String, String> {
    let origin = connected_server().ok_or("Not connected to a server")?;
    Ok(format!(
        "{origin}/app/show?subject={}",
        urlencoding::encode(&subject)
    ))
}

/// Start an AI chat named `name` in the agent's private drive, as the web
/// app's AI sidebar does. Returns the chat's subject.
pub async fn create_ai_chat(name: String) -> Result<String, String> {
    chats::create_ai_chat(&node()?, pusher().as_ref(), &name)
        .await
        .map_err(err)
}

/// Add a message to a chat: `role` is `user` or `assistant`, `parts_json` the
/// message's parts as the web app stores them (`[{"type":"text","text":…}]`).
/// It goes on the newest page with room, or on a new page. Returns the entry's
/// id (`<page>#<key>`).
pub async fn append_chat_entry(
    chat: String,
    role: String,
    parts_json: String,
) -> Result<String, String> {
    chats::append_chat_entry(&node()?, pusher().as_ref(), &chat, &role, &parts_json)
        .await
        .map_err(err)
}

/// Create a resource of `class_url` named `name` ("Untitled" when empty)
/// under `drive`, signed by this device's agent, and push it like every other
/// local write. Returns its subject.
pub async fn create_resource_of_class(
    drive: String,
    class_url: String,
    name: String,
) -> Result<String, String> {
    atomic_lib::host::create::create_resource_of_class(
        &node()?,
        pusher().as_ref(),
        &drive,
        &class_url,
        &name,
    )
    .await
    .map_err(err)
}

/// Import a whole AI chat at once: an AI chat named `name` in the agent's
/// private drive with every message of `entries_json`, a JSON array of
/// `{role, parts, c}` (`parts` as `append_chat_entry` takes them, as an array
/// or its JSON string; `c` the message's time in ms, now when absent), oldest
/// first. One commit per 256 messages instead of one per message. Returns the
/// chat's subject.
pub async fn import_ai_chat(name: String, entries_json: String) -> Result<String, String> {
    use atomic_lib::Storelike;
    let node = node()?;
    let author = node
        .db()
        .get_default_agent()
        .map_err(err)?
        .subject
        .to_string();
    let raw: Vec<serde_json::Value> = serde_json::from_str(&entries_json).map_err(|e| e.to_string())?;
    let now = super::simple::state::now_ms();
    let entries: Vec<atomic_lib::chat_log::Entry> = raw
        .iter()
        .map(|e| {
            let mut entry =
                atomic_lib::chat_log::Entry::new(author.clone(), "", e["c"].as_i64().unwrap_or(now));
            let role = e["role"].as_str().unwrap_or("user");
            let parts = match &e["parts"] {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            entry.extra.insert("role".into(), role.into());
            entry.extra.insert("parts".into(), parts.as_str().into());
            entry
        })
        .collect();
    chats::import_ai_chat(&node, pusher().as_ref(), &name, &entries)
        .await
        .map_err(err)
}
