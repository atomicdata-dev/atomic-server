//! End-to-end encrypted conversations (DMs and group chats) as this device's
//! agent sees them: listed with the newest message, read back decrypted, and
//! written to. A conversation is a drive of its own whose messages are
//! `SealedMessage`s, sealed with the epoch keys of its keyring, as the web app
//! makes them.

use super::{
    lists::private_drive_list,
    own_commit_opts,
    profiles::AgentProfiles,
    rows::{name_of, row_resource, with_emoji},
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

    /// The display name of a conversation member: the agent resource when
    /// this device holds it, else the cached name of a background lookup,
    /// else [`UNKNOWN_MEMBER`]. Never waits on the network.
    async fn member_name(&self, store: &Db, member: &str) -> String {
        let local = match row_resource(store, &Subject::from(member)).await {
            Some(agent) => name_of(&agent),
            None => String::new(),
        };
        if !local.is_empty() {
            return local;
        }
        // Never waits on the network: a missing profile is looked up in the
        // background, so the next refresh has the name.
        self.profiles
            .name_or_prefetch(member)
            .unwrap_or_else(|| UNKNOWN_MEMBER.to_string())
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
                cache.insert(cache_key, opened.clone());
            }
        }
        Some(opened)
    }

    /// The person's conversations, as
    /// `[{subject, title, class_name, opened_at, last_message, emoji?}]`,
    /// newest activity first (`opened_at` is the time of the last message in
    /// ms, 0 for an empty or unreadable one, which come last in the order the
    /// private drive lists them). `last_message` is the text of the newest
    /// message ("" when there is none or it cannot be opened). `class_name` is
    /// `conversation`.
    pub async fn list(&self, store: &Db, limit: usize) -> AtomicResult<Vec<Json>> {
        let agent = store.get_default_agent()?;
        let me = agent.subject.to_string();
        let proof = vault_proof(&agent).ok();
        let mut out: Vec<(i64, Json)> = Vec::new();
        for subject in private_drive_list(store, urls::CONVERSATIONS).await? {
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
            out.push((
                last_at,
                with_emoji(
                    json!({
                        "subject": subject,
                        "title": title,
                        "class_name": "conversation",
                        "opened_at": last_at,
                        "last_message": last_text,
                    }),
                    &conversation,
                ),
            ));
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
        Ok(out)
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

/// The members of a conversation: its `read` list.
fn members_of(conversation: &Resource) -> Vec<String> {
    conversation
        .get(urls::READ)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .unwrap_or_default()
}

/// Whether two spellings name the same agent (`did:ad:agent:X`, `atomic:agent:X`).
pub(crate) fn same_agent(a: &str, b: &str) -> bool {
    use crate::identifiers::agent_public_key;
    a == b || matches!((agent_public_key(a), agent_public_key(b)), (Some(x), Some(y)) if x == y)
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
    let mut subjects = store.query(&query).await?.subjects;
    if limit.is_some() {
        subjects.reverse();
    }
    Ok(subjects)
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
}
