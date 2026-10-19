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
use crate::host::{conversations, pusher, recents, to_json};
use atomic_lib::host::{chats, lists};
use flutter_rust_bridge::frb;

/// The emojis of `subjects` as JSON `{subject: emoji}`, only for those that
/// have one. For rows that do not carry their icon themselves (the activity
/// feed), read from the stored propvals like the other rows.
pub async fn resource_icons(subjects: Vec<String>) -> Result<String, String> {
    to_json(&lists::resource_icons(db()?, subjects).await)
}

/// The newest `limit` AI chats of the person (all drives), newest activity first, as JSON
/// `[{subject, name, last_activity}]` (`last_activity` in ms, 0 when empty).
/// Read from the recents index, not rebuilt from the chats' pages.
pub async fn list_ai_chats(limit: u32) -> Result<String, String> {
    let list = lists::list_ai_chats(db()?, recents(), limit as usize)
        .await
        .map_err(err)?;
    to_json(&list)
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
    let rows = lists::list_activity(db()?, recents(), limit as usize).await;
    Ok(rows
        .into_iter()
        .map(|a| ActivityEntry {
            subject: a.subject,
            drive: a.drive,
            kind: a.kind.as_str().to_string(),
            at: a.at,
            actor: a.actor,
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

/// Full-text search (type-ahead on the last word) across every drive of this
/// store, or only in `drive` when given. JSON
/// `[{subject, title, class_name, drive, score}]`, best first; `drive` is the
/// drive the hit lives in ("" when unknown).
pub async fn search(drive: Option<String>, query: String, limit: u32) -> Result<String, String> {
    to_json(&lists::search(db()?, drive.as_deref(), &query, limit as usize).map_err(err)?)
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
