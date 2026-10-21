//! End-to-end encrypted conversations (DMs and group chats) as this device's
//! agent sees them: listed with the newest message, read back decrypted, and
//! written to. A conversation is a drive of its own whose messages are
//! `SealedMessage`s, sealed with the epoch keys of its keyring, as the web app
//! makes them.

use super::{
    lists::private_drive_list,
    own_commit_opts,
    profiles::AgentProfiles,
    rows::{agent_picture, name_of, row_resource, with_icon},
    LocalWritePusher,
};
use crate::{
    agents::Agent, commit::CommitBuilder, conversation::ConversationKey, errors::AtomicResult,
    runtime::AtomicNode, storelike::Query, urls, Commit, Db, Resource, Storelike, Subject, Value,
};
use serde_json::{json, Value as Json};
use std::collections::HashMap;
use std::sync::Mutex;

/// Shown for a conversation member whose name is not known (yet), instead of
/// the raw agent id.
pub const UNKNOWN_MEMBER: &str = "Unknown member";

/// The name in a JSON-AD body: one resource or an array whose first is it.
pub fn name_from_json_ad(body: &str) -> Option<String> {
    let json: Json = serde_json::from_str(body).ok()?;
    let resource = json.as_array().and_then(|a| a.first()).unwrap_or(&json);
    [urls::NAME, urls::SHORTNAME]
        .iter()
        .find_map(|p| resource.get(*p).and_then(|v| v.as_str()))
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

/// The display name of an agent: the agent resource when this device holds
/// it, else the cached name of a background lookup, else [`UNKNOWN_MEMBER`].
/// Never waits on the network.
pub(crate) async fn agent_name(store: &Db, profiles: &AgentProfiles, agent: &str) -> String {
    let local = match row_resource(store, &Subject::from(agent)).await {
        Some(resource) => name_of(&resource),
        None => String::new(),
    };
    if !local.is_empty() {
        return local;
    }
    // A missing profile is looked up in the background, so the next refresh
    // has the name.
    profiles
        .name_or_prefetch(agent)
        .unwrap_or_else(|| UNKNOWN_MEMBER.to_string())
}

/// How many opened messages [`Conversations`] keeps.
const OPENED_CACHE_CAP: usize = 5_000;

/// A sealed message after opening.
#[derive(Clone)]
struct OpenedMessage {
    author: String,
    text: Option<String>,
    created_at: i64,
    reply_to: Option<String>,
}

/// Reads conversations, with the caches that keep it quick: the profiles of
/// agents this device does not hold (the host's shared [`AgentProfiles`],
/// looked up in the background) and messages opened before (a message is
/// sealed once). A host keeps one for the life of the process.
pub struct Conversations {
    profiles: AgentProfiles,
    opened: Mutex<HashMap<String, OpenedMessage>>,
}

impl Conversations {
    pub fn new(profiles: AgentProfiles) -> Self {
        Self {
            profiles,
            opened: Default::default(),
        }
    }

    /// The display name of a conversation member: see [`agent_name`].
    async fn member_name(&self, store: &Db, member: &str) -> String {
        agent_name(store, &self.profiles, member).await
    }

    /// A conversation has no name of its own: its title is who else is in it
    /// (its `read` list minus this agent), as the web app shows it.
    async fn title(&self, store: &Db, conversation: &Resource, me: &str) -> String {
        let members = members_of(conversation);
        let others = members.iter().filter(|m| !same_agent(m, me));
        let names =
            futures::future::join_all(others.map(|member| self.member_name(store, member))).await;
        if names.is_empty() {
            "Only you".to_string()
        } else {
            names.join(", ")
        }
    }

    /// Open one sealed message: from the cache, else decrypted with `keys`.
    /// `None` when `subject` is not a sealed message (this device has not got
    /// it, or it is something else). A message this reader cannot open has
    /// `text: None`.
    async fn open_message(
        &self,
        store: &Db,
        me: &str,
        conversation: &str,
        keys: &[ConversationKey],
        subject: &Subject,
    ) -> Option<OpenedMessage> {
        let cache_key = format!("{me}|{subject}");
        if let Some(known) = self
            .opened
            .lock()
            .ok()
            .and_then(|m| m.get(&cache_key).cloned())
        {
            return Some(known);
        }
        let mut resource = row_resource(store, subject).await?;
        if resource.get(urls::SEALED).is_err() {
            resource = store.get_resource(subject).await.ok()?;
        }
        let sealed = resource.get(urls::SEALED).ok()?.to_string();
        let author = resource
            .get(urls::CREATED_BY)
            .map(|v| v.to_string())
            .ok()
            .or_else(|| resource.genesis_signer())
            .or_else(|| {
                resource
                    .get(urls::WRITE)
                    .ok()
                    .and_then(|v| v.to_subjects(None).ok())
                    .and_then(|w| w.into_iter().next())
            })
            .unwrap_or_default();
        let created_at = resource
            .get(urls::CREATED_AT)
            .ok()
            .and_then(|v| v.to_int().ok())
            .unwrap_or(0);
        let payload = crate::conversation::open_message(keys, conversation, &sealed)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Json>(&bytes).ok());
        let text = payload
            .as_ref()
            .and_then(|p| p.get("text"))
            .and_then(|t| t.as_str())
            .map(str::to_string);
        let reply_to = payload
            .as_ref()
            .and_then(|p| p.get("replyTo"))
            .and_then(|t| t.as_str())
            .map(str::to_string);
        let opened = OpenedMessage {
            author,
            text,
            created_at,
            reply_to,
        };
        // A message that failed to open may open after the keyring grows:
        // only successes are remembered.
        if opened.text.is_some() {
            if let Ok(mut cache) = self.opened.lock() {
                // Bounded: a long conversation scrolled through end to end
                // must not keep every message in memory. Dropping it all is
                // crude but cheap; the window on screen is opened again.
                if cache.len() >= OPENED_CACHE_CAP {
                    cache.clear();
                }
                cache.insert(cache_key, opened.clone());
            }
        }
        Some(opened)
    }

    /// The person's conversations, as
    /// `[{subject, title, class_name, opened_at, last_message, emoji?,
    /// icon_file?, image_url?, peer?, group?}]`,
    /// newest activity first (`opened_at` is the time of the last message in
    /// ms, 0 for an empty or unreadable one, which come last in the order the
    /// private drive lists them). `last_message` is the text of the newest
    /// message ("" when there is none or it cannot be opened). `class_name` is
    /// `conversation`. `peer` (`{subject, name, emoji?, icon_file?,
    /// image_url?}`, from the agent's profile on this device) is the other
    /// member of a DM; `group` is true when there are several others.
    pub async fn list(&self, store: &Db, limit: usize) -> AtomicResult<Vec<Json>> {
        let agent = store.get_default_agent()?;
        let me = agent.subject.to_string();
        let proof = vault_proof(&agent).ok();
        let mut out: Vec<(i64, Json)> = Vec::new();
        let mut subjects = private_drive_list(store, urls::CONVERSATIONS).await?;
        // Conversations someone else started are not in the private drive's
        // list (the web app only lists them once opened, and otherwise asks
        // the server): every one this device holds and this agent is in is
        // listed too.
        for held in held_conversations(store, &me).await {
            if !subjects.iter().any(|s| drive_key(s) == drive_key(&held)) {
                subjects.push(held);
            }
        }
        for subject in subjects {
            if out.len() >= limit {
                break;
            }
            let Some(conversation) = row_resource(store, &Subject::from(subject.as_str())).await
            else {
                continue;
            };
            let title = self.title(store, &conversation, &me).await;
            let (mut last_at, mut last_text) = (0, String::new());
            if let Some(proof) = &proof {
                let keys = open_keyring(&keyring_of(&conversation), &me, proof);
                if let Ok(newest) = message_subjects(store, &subject, Some(1)).await {
                    if let Some(message) = newest.first() {
                        if let Some(m) = self
                            .open_message(store, &me, &subject, &keys, message)
                            .await
                        {
                            last_at = m.created_at;
                            last_text = m.text.unwrap_or_default();
                        }
                    }
                }
            }
            let mut row = with_icon(
                store,
                json!({
                    "subject": subject,
                    "title": title,
                    "class_name": "conversation",
                    "opened_at": last_at,
                    "last_message": last_text,
                }),
                &conversation,
            );
            // A DM shows the other person's picture, a group is marked as one.
            let others: Vec<String> = members_of(&conversation)
                .into_iter()
                .filter(|m| !same_agent(m, &me))
                .collect();
            match others.as_slice() {
                [] => {}
                [other] => {
                    row["peer"] = agent_picture(store, other)
                        .await
                        .unwrap_or_else(|| json!({ "subject": other, "name": "" }));
                }
                _ => row["group"] = json!(true),
            }
            out.push((last_at, row));
        }
        // Stable: conversations without activity keep the drive's order.
        out.sort_by_key(|row| std::cmp::Reverse(row.0));
        Ok(out.into_iter().map(|(_, row)| row).collect())
    }

    /// The messages of a conversation, oldest first, as `[{id, author,
    /// author_name, mine, text, c, reply_to?}]`: `id` the message's subject,
    /// `author` who signed it (an agent subject), `author_name` their name
    /// (never waiting on the network), `mine` when this device's agent wrote
    /// it, `text` the decrypted text (null when this agent cannot open it) and
    /// `c` its time in ms. Read from the local store.
    pub async fn read(&self, store: &Db, subject: &str) -> AtomicResult<Vec<Json>> {
        let agent = store.get_default_agent()?;
        let me = agent.subject.to_string();
        let proof = vault_proof(&agent)?;
        let conversation = row_resource(store, &Subject::from(subject))
            .await
            .ok_or("This conversation is not on this device yet")?;
        let keys = open_keyring(&keyring_of(&conversation), &me, &proof);
        let mut messages: Vec<(i64, String, OpenedMessage)> = Vec::new();
        for message in message_subjects(store, subject, None).await? {
            if let Some(m) = self
                .open_message(store, &me, subject, &keys, &message)
                .await
            {
                messages.push((m.created_at, message.to_string(), m));
            }
        }
        messages.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        Ok(self.rows(store, &me, messages).await)
    }

    /// A window of a conversation, as JSON `{messages, older, newest}`:
    /// `messages` the newest `limit` messages before the `before` cursor (the
    /// newest of all when `None`), oldest first, as [`Self::read`] gives
    /// them; `older` the cursor for the window before (null at the start),
    /// `newest` the cursor of the last message (for [`Self::read_after`]).
    /// Only the window's messages are decrypted; the messages are found
    /// through the sorted index, read only as far as the window reaches.
    pub async fn read_page(
        &self,
        store: &Db,
        subject: &str,
        before: Option<&str>,
        limit: usize,
    ) -> AtomicResult<Json> {
        let limit = limit.max(1);
        let before = before.map(decode_message_cursor).transpose()?;
        let (me, keys) = self.reader(store, subject).await?;
        let mut messages = Vec::new();
        let mut more = false;
        let mut offset = 0;
        // Messages made in the cursor's millisecond come back again and are
        // skipped by hand; the loop reads on past them.
        'read: loop {
            let batch = limit + 4;
            let subjects = message_window(
                store,
                subject,
                true,
                before.as_ref().map(|b| b.0),
                offset,
                batch,
            )
            .await?;
            for message in &subjects {
                let Some(m) = self.open_message(store, &me, subject, &keys, message).await else {
                    continue;
                };
                let id = message.to_string();
                if let Some((at, cursor_id)) = &before {
                    if (m.created_at, id.as_str()) >= (*at, cursor_id.as_str()) {
                        continue;
                    }
                }
                if messages.len() >= limit {
                    more = true;
                    break 'read;
                }
                messages.push((m.created_at, id, m));
            }
            if subjects.len() < batch {
                break;
            }
            offset += batch;
        }
        messages.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        let older = more
            .then(|| messages.first().map(|(at, id, _)| format!("{at}|{id}")))
            .flatten();
        let newest = messages.last().map(|(at, id, _)| format!("{at}|{id}"));
        Ok(json!({
            "messages": self.rows(store, &me, messages).await,
            "older": older,
            "newest": newest,
        }))
    }

    /// The messages of a conversation after `after` (a `newest` cursor), as
    /// JSON `{messages, newest, more}`: at most `limit`, oldest first.
    pub async fn read_after(
        &self,
        store: &Db,
        subject: &str,
        after: &str,
        limit: usize,
    ) -> AtomicResult<Json> {
        let limit = limit.max(1);
        let (at, cursor_id) = decode_message_cursor(after)?;
        let (me, keys) = self.reader(store, subject).await?;
        let mut messages = Vec::new();
        let mut more = false;
        let mut offset = 0;
        'read: loop {
            let batch = limit + 4;
            let subjects = message_window(store, subject, false, Some(at), offset, batch).await?;
            for message in &subjects {
                let Some(m) = self.open_message(store, &me, subject, &keys, message).await else {
                    continue;
                };
                let id = message.to_string();
                if (m.created_at, id.as_str()) <= (at, cursor_id.as_str()) {
                    continue;
                }
                if messages.len() >= limit {
                    more = true;
                    break 'read;
                }
                messages.push((m.created_at, id, m));
            }
            if subjects.len() < batch {
                break;
            }
            offset += batch;
        }
        messages.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        let newest = messages
            .last()
            .map(|(at, id, _)| format!("{at}|{id}"))
            .unwrap_or_else(|| after.to_string());
        Ok(json!({
            "messages": self.rows(store, &me, messages).await,
            "newest": newest,
            "more": more,
        }))
    }

    /// This agent and the epoch keys it can open in `subject`.
    async fn reader(
        &self,
        store: &Db,
        subject: &str,
    ) -> AtomicResult<(String, Vec<ConversationKey>)> {
        let agent = store.get_default_agent()?;
        let me = agent.subject.to_string();
        let proof = vault_proof(&agent)?;
        let conversation = row_resource(store, &Subject::from(subject))
            .await
            .ok_or("This conversation is not on this device yet")?;
        let keys = open_keyring(&keyring_of(&conversation), &me, &proof);
        Ok((me, keys))
    }

    /// Opened messages (oldest first) as the JSON rows of [`Self::read`].
    async fn rows(
        &self,
        store: &Db,
        me: &str,
        messages: Vec<(i64, String, OpenedMessage)>,
    ) -> Vec<Json> {
        let me = me.to_string();
        let mut names: HashMap<String, String> = Default::default();
        let mut out = Vec::new();
        for (_, id, m) in messages {
            if !names.contains_key(&m.author) {
                let name = self.member_name(store, &m.author).await;
                names.insert(m.author.clone(), name);
            }
            let mut row = json!({
                "id": id,
                "author": m.author,
                "author_name": names[&m.author],
                "mine": same_agent(&m.author, &me),
                "text": m.text,
                "c": m.created_at,
            });
            if let Some(reply) = m.reply_to {
                row["reply_to"] = json!(reply);
            }
            out.push(row);
        }
        out
    }
}

/// Post `text` in a conversation as this device's agent: sealed with the
/// conversation's newest epoch key, saved as a `SealedMessage` under it that
/// only the author may write (as the web app does), and handed to `pusher`
/// like any other local write. Returns the message's subject.
pub async fn send_message(
    node: &AtomicNode,
    pusher: &dyn LocalWritePusher,
    subject: &str,
    text: &str,
) -> AtomicResult<String> {
    let store = node.db();
    let agent = store.get_default_agent()?;
    let me = agent.subject.to_string();
    let proof = vault_proof(&agent)?;
    let conversation = store
        .get_resource(&Subject::from(subject))
        .await
        .map_err(|_| "This conversation is not on this device yet")?;
    let keys = open_keyring(&keyring_of(&conversation), &me, &proof);
    let current = keys
        .into_iter()
        .max_by_key(|k| k.epoch)
        .ok_or("You are not a member of this conversation's current keys")?;
    let sealed = crate::conversation::seal_message(
        &current,
        subject,
        json!({ "text": text }).to_string().as_bytes(),
    )?;

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::SEALED_MESSAGE.into()]),
    );
    builder.set(urls::PARENT.into(), Value::AtomicUrl(subject.into()));
    builder.set(urls::SEALED.into(), Value::String(sealed));
    builder.set(
        urls::WRITE.into(),
        Value::ResourceArray(vec![me.as_str().into()]),
    );
    let commit = Commit::create_did(builder, &agent, store).await?;
    let message = commit.subject.to_string();
    let response = node.apply_local_commit(commit, &own_commit_opts()).await?;
    pusher.push(&response).await;
    Ok(message)
}

/// The conversations this device holds that `me` is a member of, in no
/// particular order.
async fn held_conversations(store: &Db, me: &str) -> Vec<String> {
    let mut query = Query::new_prop_val(urls::IS_A, urls::CONVERSATION);
    query.limit = Some(500);
    let Ok(found) = store.query(&query).await else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for subject in found.subjects {
        let Some(conversation) = row_resource(store, &subject).await else {
            continue;
        };
        if members_of(&conversation).iter().any(|m| same_agent(m, me)) {
            out.push(subject.to_string());
        }
    }
    out
}

/// A conversation's subject without query or drive hint, for comparing.
fn drive_key(subject: &str) -> String {
    crate::identifiers::canonicalize_scheme(&Subject::from(subject).pure_id())
}

/// The members of a conversation: its `read` list.
fn members_of(conversation: &Resource) -> Vec<String> {
    conversation
        .get(urls::READ)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default()
}

/// Whether two subjects name the same agent, in any spelling (`did:ad:agent:X`,
/// `atomic:agent:X`, legacy `https://host/agents/X`, `internal:/agents/X`;
/// standard or URL-safe base64, padded or not). The one comparison behind every
/// `mine` flag and "is this me" check.
pub(crate) fn same_agent(a: &str, b: &str) -> bool {
    super::profiles::same_agent(a, b)
}

/// `vault_proof` of an agent: its signature over the fixed vault message, the
/// key material of its conversation keys (the web app derives the same).
pub fn vault_proof(agent: &Agent) -> AtomicResult<Vec<u8>> {
    let secret = agent
        .private_key
        .as_ref()
        .ok_or("This device has no agent key to read messages with")?;
    let signature = crate::agents::sign_message(
        crate::vault::secret_envelope::AGENT_VAULT_PROOF_MESSAGE,
        secret,
    )?;
    crate::agents::decode_base64(&signature)
}

/// The spellings the keyring may know `agent` by.
fn agent_spellings(agent: &str) -> Vec<String> {
    let mut out = vec![agent.to_string()];
    for other in [
        crate::identifiers::canonicalize_scheme(agent),
        crate::identifiers::to_legacy_scheme(agent),
    ] {
        if !out.contains(&other) {
            out.push(other);
        }
    }
    out
}

/// The epoch keys of `keyring` that `agent` can open (oldest first); empty
/// when this agent is not in it.
fn open_keyring(keyring: &str, agent: &str, proof: &[u8]) -> Vec<ConversationKey> {
    let Ok(keyring) = crate::conversation::Keyring::from_json(keyring) else {
        return Vec::new();
    };
    for spelling in agent_spellings(agent) {
        if let Ok(keys) = keyring.open(&spelling, proof) {
            if !keys.is_empty() {
                return keys;
            }
        }
    }
    Vec::new()
}

/// The conversation's keyring.
fn keyring_of(conversation: &Resource) -> String {
    conversation
        .get(urls::CONVERSATION_KEYS)
        .map(|v| v.to_string())
        .unwrap_or_default()
}

/// The subjects of the messages in a conversation (children of it), oldest
/// first by creation time; the newest `limit` only (still oldest first) when
/// given.
async fn message_subjects(
    store: &Db,
    conversation: &str,
    limit: Option<usize>,
) -> AtomicResult<Vec<Subject>> {
    let mut query = Query::new_prop_val(urls::PARENT, conversation);
    // A conversation is a drive of its own, and its messages live in it.
    query.drive = Some(Subject::from(conversation));
    query.sort_by = Some(urls::CREATED_AT.to_string());
    query.sort_desc = limit.is_some();
    query.limit = limit;
    let mut subjects = match limit {
        Some(_) => store.query_page(&query).await?,
        None => store.query(&query).await?.subjects,
    };
    if limit.is_some() {
        subjects.reverse();
    }
    Ok(subjects)
}

/// `<createdAt>|<message subject>`, the cursor of a conversation window.
fn decode_message_cursor(cursor: &str) -> AtomicResult<(i64, String)> {
    let bad = || format!("Not a conversation cursor: {cursor}");
    let (at, id) = cursor.split_once('|').ok_or_else(bad)?;
    Ok((at.parse().map_err(|_| bad())?, id.to_string()))
}

/// Message subjects of a conversation by creation time from `bound`
/// (inclusive; descending: at or before it, ascending: at or after it),
/// `offset` and `limit` into that order. Reads the index only as far as the
/// page reaches.
async fn message_window(
    store: &Db,
    conversation: &str,
    desc: bool,
    bound: Option<i64>,
    offset: usize,
    limit: usize,
) -> AtomicResult<Vec<Subject>> {
    let mut query = Query::new_prop_val(urls::PARENT, conversation);
    query.drive = Some(Subject::from(conversation));
    query.sort_by = Some(urls::CREATED_AT.to_string());
    query.sort_desc = desc;
    query.offset = offset;
    query.limit = Some(limit);
    if let Some(at) = bound {
        if desc {
            query.end_val = Some(Value::Timestamp(at));
        } else {
            query.start_val = Some(Value::Timestamp(at));
        }
    }
    store.query_page(&query).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::{
        encryption_public_key, open_message as open_sealed, seal_message, Keyring, Member,
    };
    use crate::host::{test_support::Device, NoPush};
    use std::{sync::Arc, time::Duration};

    fn conversations() -> Conversations {
        Conversations::new(AgentProfiles::none())
    }

    #[test]
    fn agent_name_is_read_from_json_ad() {
        let body = format!(r#"{{"{}":"Ada","@id":"x"}}"#, urls::NAME);
        assert_eq!(name_from_json_ad(&body).as_deref(), Some("Ada"));
        let arr = format!(r#"[{{"{}":"Bo"}}]"#, urls::SHORTNAME);
        assert_eq!(name_from_json_ad(&arr).as_deref(), Some("Bo"));
        assert_eq!(name_from_json_ad(r#"{"@id":"x"}"#), None);
        assert_eq!(name_from_json_ad("nope"), None);
    }

    /// A fetcher that knows one name.
    struct Knows(&'static str);

    #[async_trait::async_trait]
    impl crate::host::AgentProfileFetcher for Knows {
        async fn fetch_agent_resource(&self, _agent: &str) -> Option<String> {
            Some(json!({ urls::NAME: self.0 }).to_string())
        }
    }

    #[tokio::test]
    async fn a_name_looked_up_in_the_background_is_there_on_the_next_read() {
        let d = Device::new().await;
        let c = Conversations::new(AgentProfiles::new(Arc::new(Knows("Dora"))));
        let stranger = "https://example.test/agent";
        // The first read does not wait for the lookup.
        assert_eq!(c.member_name(&d.store, stranger).await, UNKNOWN_MEMBER);
        for _ in 0..100 {
            if c.member_name(&d.store, stranger).await == "Dora" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the looked-up name never arrived");
    }

    #[tokio::test]
    async fn conversations_are_titled_by_the_other_members() {
        let d = Device::new().await;
        let me = d.store.get_default_agent().unwrap().subject.to_string();
        let convo = d.new_chat("Ignored name").await;
        let mut resource = d
            .store
            .get_resource(&Subject::from(convo.as_str()))
            .await
            .unwrap();
        let members = Value::ResourceArray(vec![
            me.as_str().into(),
            "https://example.test/agent".into(),
        ]);
        resource.set_unsafe(urls::READ.into(), members).unwrap();
        d.node.save_locally(&mut resource).await.unwrap();
        let alone = d.new_chat("Alone").await;
        d.set_home_list(urls::CONVERSATIONS, &[&convo, &alone])
            .await;

        let list = conversations().list(&d.store, 10).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["subject"], convo.as_str());
        assert_eq!(list[0]["title"], UNKNOWN_MEMBER);
        assert_eq!(list[1]["title"], "Only you");
    }

    #[tokio::test]
    async fn a_dm_carries_the_other_members_picture_and_a_group_is_marked() {
        let d = Device::new().await;
        let me = d.store.get_default_agent().unwrap().subject.to_string();
        let add_agent = |name: &'static str| {
            let store = d.store.clone();
            async move {
                let agent = Agent::new(Some(name)).unwrap();
                store
                    .add_resource(&agent.to_resource().unwrap())
                    .await
                    .unwrap();
                agent.subject.to_string()
            }
        };
        let (bob, carol) = (add_agent("Bob").await, add_agent("Carol").await);
        let file = d.new_picture("https://example.test/download/bob.png").await;
        d.set_icon(&bob, &file).await;
        let with_members = |members: Vec<String>| {
            let d = &d;
            async move {
                let convo = d.new_chat("c").await;
                let mut r = d
                    .store
                    .get_resource(&Subject::from(convo.as_str()))
                    .await
                    .unwrap();
                let members =
                    Value::ResourceArray(members.iter().map(|m| m.as_str().into()).collect());
                r.set_unsafe(urls::READ.into(), members).unwrap();
                d.node.save_locally(&mut r).await.unwrap();
                convo
            }
        };
        let dm = with_members(vec![me.clone(), bob.clone()]).await;
        let plain = with_members(vec![me.clone(), carol.clone()]).await;
        let group = with_members(vec![me.clone(), bob.clone(), carol.clone()]).await;
        d.set_home_list(urls::CONVERSATIONS, &[&dm, &plain, &group])
            .await;

        let list = conversations().list(&d.store, 10).await.unwrap();
        let row = |s: &str| list.iter().find(|r| r["subject"] == s).unwrap();
        assert_eq!(row(&dm)["peer"]["name"], "Bob");
        assert_eq!(row(&dm)["peer"]["subject"], bob.as_str());
        assert_eq!(row(&dm)["peer"]["icon_file"], file.as_str());
        assert_eq!(
            row(&dm)["peer"]["image_url"],
            "https://example.test/download/bob.png"
        );
        assert_eq!(row(&plain)["peer"]["name"], "Carol");
        assert!(row(&plain)["peer"].get("icon_file").is_none());
        assert!(row(&dm).get("group").is_none());
        assert_eq!(row(&group)["group"], true);
        assert!(row(&group).get("peer").is_none());
    }

    struct Talk {
        conversation: String,
        keyring: Keyring,
        other: Agent,
        other_proof: Vec<u8>,
    }

    /// A conversation between the device's agent and a new agent called
    /// `name` (whose Agent resource this device holds, so the name is known),
    /// with a keyring both can open, as the web app makes them.
    async fn new_talk(d: &Device, name: &str) -> Talk {
        let me = d.store.get_default_agent().unwrap();
        let other = Agent::new(Some(name)).unwrap();
        d.store
            .add_resource(&other.to_resource().unwrap())
            .await
            .unwrap();
        let (my_proof, other_proof) = (vault_proof(&me).unwrap(), vault_proof(&other).unwrap());
        let mut keyring = Keyring::default();
        keyring
            .add_epoch(&[
                Member {
                    agent: me.subject.to_string(),
                    encryption_key: encryption_public_key(&my_proof),
                },
                Member {
                    agent: other.subject.to_string(),
                    encryption_key: encryption_public_key(&other_proof),
                },
            ])
            .unwrap();

        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::CONVERSATION.into(), urls::DRIVE.into()]),
        );
        builder.set(urls::NAME.into(), Value::String("Conversation".into()));
        builder.set(
            urls::READ.into(),
            Value::ResourceArray(vec![
                me.subject.to_string().into(),
                other.subject.to_string().into(),
            ]),
        );
        builder.set(
            urls::CONVERSATION_KEYS.into(),
            Value::String(keyring.to_json().unwrap()),
        );
        let commit = Commit::create_did(builder, &me, &d.store).await.unwrap();
        let conversation = commit.subject.to_string();
        d.node
            .apply_local_commit(commit, &own_commit_opts())
            .await
            .unwrap();
        Talk {
            conversation,
            keyring,
            other,
            other_proof,
        }
    }

    impl Talk {
        /// A message the other agent signed and sealed with the shared keyring.
        async fn say_as_other(&self, d: &Device, text: &str) {
            let key = self
                .keyring
                .open_current(&self.other.subject.to_string(), &self.other_proof)
                .unwrap();
            let sealed = seal_message(
                &key,
                &self.conversation,
                json!({ "text": text }).to_string().as_bytes(),
            )
            .unwrap();
            let mut builder = CommitBuilder::new("placeholder".into());
            builder.set(
                urls::IS_A.into(),
                Value::ResourceArray(vec![urls::SEALED_MESSAGE.into()]),
            );
            builder.set(
                urls::PARENT.into(),
                Value::AtomicUrl(self.conversation.as_str().into()),
            );
            builder.set(urls::SEALED.into(), Value::String(sealed));
            let commit = Commit::create_did(builder, &self.other, &d.store)
                .await
                .unwrap();
            d.store
                .apply_commit(commit, &own_commit_opts())
                .await
                .unwrap();
        }
    }

    /// Messages are ordered by their creation time in ms.
    async fn tick() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    /// Windows walk a conversation without gaps or duplicates (many
    /// messages share a millisecond here), decrypt only what they return,
    /// and `read_after` picks up what was sent since.
    #[tokio::test]
    async fn conversation_windows_page_and_decrypt_only_the_window() {
        let d = Device::new().await;
        let talk = new_talk(&d, "Alice").await;
        for i in 0..120 {
            send_message(&d.node, &NoPush, &talk.conversation, &format!("m{i}"))
                .await
                .unwrap();
        }
        let all: Vec<Json> = conversations()
            .read(&d.store, &talk.conversation)
            .await
            .unwrap();
        let want: Vec<&str> = all.iter().map(|m| m["id"].as_str().unwrap()).collect();

        let c = conversations();
        let first = c
            .read_page(&d.store, &talk.conversation, None, 25)
            .await
            .unwrap();
        let opened = c.opened.lock().unwrap().len();
        assert!(
            opened <= 25 + 5,
            "{opened} messages decrypted for a window of 25"
        );
        let newest = first["newest"].as_str().unwrap().to_string();
        let mut ids: Vec<String> = Vec::new();
        let mut window = first;
        loop {
            let mut page: Vec<String> = window["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["id"].as_str().unwrap().to_string())
                .collect();
            assert!(page.len() <= 25);
            page.extend(ids);
            ids = page;
            let Some(older) = window["older"].as_str() else {
                break;
            };
            window = c
                .read_page(&d.store, &talk.conversation, Some(older), 25)
                .await
                .unwrap();
        }
        assert_eq!(ids, want);

        tick().await;
        send_message(&d.node, &NoPush, &talk.conversation, "later")
            .await
            .unwrap();
        let after = c
            .read_after(&d.store, &talk.conversation, &newest, 50)
            .await
            .unwrap();
        let texts: Vec<&str> = after["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts, ["later"]);
    }

    #[tokio::test]
    async fn a_conversation_reads_back_both_sides_in_order_with_names() {
        let d = Device::new().await;
        let talk = new_talk(&d, "Alice").await;
        talk.say_as_other(&d, "Hoi!").await;
        tick().await;
        send_message(&d.node, &NoPush, &talk.conversation, "Hallo Alice")
            .await
            .unwrap();
        tick().await;
        talk.say_as_other(&d, "Hoe gaat het?").await;

        let messages = conversations()
            .read(&d.store, &talk.conversation)
            .await
            .unwrap();
        let seen: Vec<(&str, &str, bool)> = messages
            .iter()
            .map(|m| {
                (
                    m["author_name"].as_str().unwrap(),
                    m["text"].as_str().unwrap(),
                    m["mine"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(seen[0], ("Alice", "Hoi!", false));
        assert_eq!(seen[2], ("Alice", "Hoe gaat het?", false));
        assert_eq!(seen[1].1, "Hallo Alice");
        assert!(seen[1].2);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["author"], talk.other.subject.to_string());
        assert!(messages[0]["c"].as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn a_sent_message_is_sealed_and_attributed_to_the_device_agent() {
        let d = Device::new().await;
        let talk = new_talk(&d, "Bob").await;
        let id = send_message(&d.node, &NoPush, &talk.conversation, "Geheim")
            .await
            .unwrap();

        let me = d.store.get_default_agent().unwrap().subject.to_string();
        let message = d
            .store
            .get_resource(&Subject::from(id.as_str()))
            .await
            .unwrap();
        // Stored as ciphertext under the conversation, writable by its author only.
        let sealed = message.get(urls::SEALED).unwrap().to_string();
        assert!(!sealed.contains("Geheim"));
        assert_eq!(
            message.get(urls::PARENT).unwrap().to_string(),
            talk.conversation
        );
        assert_eq!(message.get(urls::CREATED_BY).unwrap().to_string(), me);
        let write = message.get(urls::WRITE).unwrap().to_subjects(None).unwrap();
        assert_eq!(write, [me.as_str()]);
        // The other member opens it with their own key.
        let keys = talk
            .keyring
            .open(&talk.other.subject.to_string(), &talk.other_proof)
            .unwrap();
        let opened = open_sealed(&keys, &talk.conversation, &sealed).unwrap();
        let payload: Json = serde_json::from_slice(&opened).unwrap();
        assert_eq!(payload["text"], "Geheim");

        let messages = conversations()
            .read(&d.store, &talk.conversation)
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["author"], me.as_str());
        assert_eq!(messages[0]["mine"], true);
    }

    #[tokio::test]
    async fn conversations_list_the_last_message_newest_first() {
        let d = Device::new().await;
        let quiet = new_talk(&d, "Quiet").await;
        let busy = new_talk(&d, "Busy").await;
        quiet.say_as_other(&d, "old news").await;
        tick().await;
        busy.say_as_other(&d, "first").await;
        tick().await;
        busy.say_as_other(&d, "latest word").await;
        // The one with the older message is listed first in the private drive.
        d.set_home_list(
            urls::CONVERSATIONS,
            &[&quiet.conversation, &busy.conversation],
        )
        .await;

        let list = conversations().list(&d.store, 10).await.unwrap();
        assert_eq!(list[0]["subject"], busy.conversation.as_str());
        assert_eq!(list[0]["last_message"], "latest word");
        assert_eq!(list[0]["title"], "Busy");
        assert_eq!(list[0]["class_name"], "conversation");
        assert_eq!(list[1]["last_message"], "old news");
        assert!(list[0]["opened_at"].as_i64().unwrap() > list[1]["opened_at"].as_i64().unwrap());
    }

    #[tokio::test]
    async fn a_message_sealed_for_someone_else_reads_as_unopenable() {
        let d = Device::new().await;
        let talk = new_talk(&d, "Carol").await;
        // Sealed under a key that is not in the conversation's keyring.
        let stranger = Agent::new(None).unwrap();
        let proof = vault_proof(&stranger).unwrap();
        let mut other_ring = Keyring::default();
        other_ring
            .add_epoch(&[Member {
                agent: stranger.subject.to_string(),
                encryption_key: encryption_public_key(&proof),
            }])
            .unwrap();
        let key = other_ring
            .open_current(&stranger.subject.to_string(), &proof)
            .unwrap();
        let sealed = seal_message(&key, &talk.conversation, br#"{"text":"nope"}"#).unwrap();
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::SEALED_MESSAGE.into()]),
        );
        builder.set(
            urls::PARENT.into(),
            Value::AtomicUrl(talk.conversation.as_str().into()),
        );
        builder.set(urls::SEALED.into(), Value::String(sealed));
        let commit = Commit::create_did(builder, &talk.other, &d.store)
            .await
            .unwrap();
        d.store
            .apply_commit(commit, &own_commit_opts())
            .await
            .unwrap();

        let messages = conversations()
            .read(&d.store, &talk.conversation)
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0]["text"].is_null());
    }

    // ── Two devices: A and B are different agents sharing a conversation ──

    /// The state of `subject` on `from`, applied on `to` as a sync UPDATE
    /// (what the WebSocket and Iroh paths deliver).
    async fn ship(from: &Device, to: &Device, subject: &str) {
        use crate::db::trees::Tree;
        let key = Subject::from(subject).pure_id();
        let state = from
            .store
            .kv
            .get(Tree::LoroSnapshots, key.as_bytes())
            .unwrap()
            .expect("the sender holds a state for the subject");
        crate::sync::ws_apply::apply_state_update(&to.store, subject, &state)
            .await
            .unwrap();
    }

    /// A conversation started on `a` with `b`'s agent, shipped to `b`.
    async fn start_between(a: &Device, b: &Device) -> String {
        let me = a.store.get_default_agent().unwrap();
        let other = b.store.get_default_agent().unwrap();
        let (pa, pb) = (vault_proof(&me).unwrap(), vault_proof(&other).unwrap());
        let mut keyring = Keyring::default();
        keyring
            .add_epoch(&[
                Member {
                    agent: me.subject.to_string(),
                    encryption_key: encryption_public_key(&pa),
                },
                Member {
                    agent: other.subject.to_string(),
                    encryption_key: encryption_public_key(&pb),
                },
            ])
            .unwrap();
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::CONVERSATION.into(), urls::DRIVE.into()]),
        );
        builder.set(urls::NAME.into(), Value::String("Conversation".into()));
        builder.set(
            urls::READ.into(),
            Value::ResourceArray(vec![
                me.subject.to_string().into(),
                other.subject.to_string().into(),
            ]),
        );
        builder.set(
            urls::CONVERSATION_KEYS.into(),
            Value::String(keyring.to_json().unwrap()),
        );
        let commit = Commit::create_did(builder, &me, &a.store).await.unwrap();
        let conversation = commit.subject.to_string();
        a.node
            .apply_local_commit(commit, &own_commit_opts())
            .await
            .unwrap();
        ship(a, b, &conversation).await;
        conversation
    }

    fn texts(page: &Json) -> Vec<String> {
        page["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["text"].as_str().unwrap_or("<unopenable>").to_string())
            .collect()
    }

    /// `mine` holds for the device agent in every spelling (DID, legacy
    /// `https://host/agents/K`, URL-safe base64, trailing slash) and not for
    /// another agent.
    #[tokio::test]
    async fn mine_matches_the_device_agent_in_every_spelling() {
        let d = Device::new().await;
        let me = d.store.get_default_agent().unwrap();
        let key = me.public_key.clone();
        let url_safe = key.trim_end_matches('=').replace('+', "-").replace('/', "_");
        let authors = [
            me.subject.to_string(),
            format!("https://example.test/agents/{key}"),
            format!("https://example.test/agents/{key}/"),
            format!("did:ad:agent:{url_safe}"),
            format!("atomic:agent:{key}"),
            "did:ad:agent:SomeoneElseEntirely".to_string(),
        ];
        let messages = authors
            .iter()
            .enumerate()
            .map(|(i, a)| {
                (
                    i as i64,
                    format!("did:ad:message{i}"),
                    OpenedMessage {
                        author: a.clone(),
                        text: Some("x".into()),
                        created_at: i as i64,
                        reply_to: None,
                    },
                )
            })
            .collect();
        let rows = conversations()
            .rows(&d.store, &me.subject.to_string(), messages)
            .await;
        let mine: Vec<bool> = rows.iter().map(|r| r["mine"].as_bool().unwrap()).collect();
        assert_eq!(mine, [true, true, true, true, true, false]);
    }

    /// A sends, B reads, B replies, A reads: first message and reply, each
    /// side seeing the other's as not `mine`.
    #[tokio::test]
    async fn a_message_and_its_reply_reach_the_other_device() {
        let (a, b) = (Device::new().await, Device::new().await);
        let conversation = start_between(&a, &b).await;

        let m1 = send_message(&a.node, &NoPush, &conversation, "hoi")
            .await
            .unwrap();
        ship(&a, &b, &m1).await;
        let seen = conversations().read(&b.store, &conversation).await.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["text"], "hoi");
        assert_eq!(seen[0]["mine"], false);

        tick().await;
        let m2 = send_message(&b.node, &NoPush, &conversation, "hallo")
            .await
            .unwrap();
        ship(&b, &a, &m2).await;
        let on_a = conversations().read(&a.store, &conversation).await.unwrap();
        assert_eq!(on_a.len(), 2);
        assert_eq!(on_a[1]["text"], "hallo");
        assert_eq!(on_a[1]["mine"], false);
        assert_eq!(on_a[0]["mine"], true);
    }

    /// Both sides send at the same time; after exchanging, both read the same
    /// order, in the window and through the cursor.
    #[tokio::test]
    async fn concurrent_sends_converge_to_one_order_on_both_devices() {
        let (a, b) = (Device::new().await, Device::new().await);
        let conversation = start_between(&a, &b).await;
        let mut sent = Vec::new();
        for i in 0..3 {
            let ma = send_message(&a.node, &NoPush, &conversation, &format!("a{i}"))
                .await
                .unwrap();
            let mb = send_message(&b.node, &NoPush, &conversation, &format!("b{i}"))
                .await
                .unwrap();
            sent.push((ma, mb));
        }
        for (ma, mb) in &sent {
            ship(&a, &b, ma).await;
            ship(&b, &a, mb).await;
        }
        let (c1, c2) = (conversations(), conversations());
        let on_a = c1
            .read_page(&a.store, &conversation, None, 50)
            .await
            .unwrap();
        let on_b = c2
            .read_page(&b.store, &conversation, None, 50)
            .await
            .unwrap();
        assert_eq!(texts(&on_a).len(), 6);
        assert_eq!(texts(&on_a), texts(&on_b));
    }

    /// B has the conversation open (cursor at its newest) while A's messages
    /// arrive: each poll picks up exactly the new ones.
    #[tokio::test]
    async fn an_open_conversation_picks_up_what_arrives() {
        let (a, b) = (Device::new().await, Device::new().await);
        let conversation = start_between(&a, &b).await;
        let m0 = send_message(&a.node, &NoPush, &conversation, "one")
            .await
            .unwrap();
        ship(&a, &b, &m0).await;
        let c = conversations();
        let first = c
            .read_page(&b.store, &conversation, None, 50)
            .await
            .unwrap();
        let mut cursor = first["newest"].as_str().unwrap().to_string();
        for i in 0..5 {
            tick().await;
            let m = send_message(&a.node, &NoPush, &conversation, &format!("next{i}"))
                .await
                .unwrap();
            ship(&a, &b, &m).await;
            let after = c
                .read_after(&b.store, &conversation, &cursor, 50)
                .await
                .unwrap();
            assert_eq!(texts(&after), vec![format!("next{i}")]);
            cursor = after["newest"].as_str().unwrap().to_string();
        }
    }

    /// A message written earlier (by its author's clock) than one B already
    /// shows, but arriving later (A was offline, or its clock is behind), is
    /// older than the poll's cursor: `read_after` is strict, so the app's
    /// poll also looks at the newest window (`ChatWindow.poll`), where it is.
    #[tokio::test]
    async fn a_late_arriving_older_message_shows_in_the_newest_window() {
        let (a, b) = (Device::new().await, Device::new().await);
        let conversation = start_between(&a, &b).await;
        let early = send_message(&a.node, &NoPush, &conversation, "written first")
            .await
            .unwrap();
        tick().await;
        send_message(&b.node, &NoPush, &conversation, "written second")
            .await
            .unwrap();
        let c = conversations();
        let open = c
            .read_page(&b.store, &conversation, None, 50)
            .await
            .unwrap();
        assert_eq!(texts(&open), vec!["written second"]);
        let cursor = open["newest"].as_str().unwrap().to_string();
        ship(&a, &b, &early).await;
        let after = c
            .read_after(&b.store, &conversation, &cursor, 50)
            .await
            .unwrap();
        assert!(texts(&after).is_empty(), "the cursor is strict");
        let fresh = c
            .read_page(&b.store, &conversation, None, 50)
            .await
            .unwrap();
        assert_eq!(texts(&fresh), vec!["written first", "written second"]);
    }

    /// B's list shows a conversation A started, with A's latest message,
    /// although B never listed it in its own private drive.
    #[tokio::test]
    async fn a_conversation_someone_else_started_is_listed() {
        let (a, b) = (Device::new().await, Device::new().await);
        let conversation = start_between(&a, &b).await;
        let m = send_message(&a.node, &NoPush, &conversation, "hi from A")
            .await
            .unwrap();
        ship(&a, &b, &m).await;
        let list = conversations().list(&b.store, 10).await.unwrap();
        assert_eq!(list.len(), 1, "B holds the conversation, so it lists it");
        assert_eq!(list[0]["subject"], conversation.as_str());
        assert_eq!(list[0]["last_message"], "hi from A");
    }
}
