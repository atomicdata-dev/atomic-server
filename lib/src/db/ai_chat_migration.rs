//! Moves the messages of existing AI chats into `ChatLog` pages.
//!
//! An AI chat used to keep every message as an `ai-message` resource with one
//! resource per part (text, reasoning, tool call, file, source) and a
//! `messages` list on the chat: a dozen rows per message. Now a message is one
//! entry in a `ChatLog` page whose parent is the chat (`planning/chat-log.md`,
//! "AI chat"). This migration packs the old ones into pages and removes the
//! old resources.
//!
//! - **Order** comes from the chat's `messages` list, not from `createdAt`.
//!   Entries sort by `c`, so `c` is the creation time raised, where needed, to
//!   one millisecond after the entry before it.
//! - **Entry:** `a` the original author, `t` empty, `c` as above, `role` the
//!   role as a word (`user`, `assistant`, `summary`, ...), `parts` the parts as
//!   a JSON string (the same shape the app writes: see `part_json`), `ctx` the
//!   provided context as JSON, `sc` the context the server provided, `err`
//!   why a reply stopped. The key is [`crate::chat_log::migrated_entry_key`]
//!   of the old subject and its creation time, so a message that already has
//!   its entry is recognised and not written twice.
//! - **Removal:** a chat's pages are written first. Then each old message and
//!   everything under it (parts, context items) goes, and the chat's
//!   `messages` list is cleared. A restart in between finds the entries by key
//!   and only removes what is left.
//! - **Where pages are made, state, progress:** like the `Message` migration
//!   (`chat_migration.rs`), with its own marker `ai-chat-log-migration-v1`.

use std::collections::HashMap;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::{
    chat_log::{migrated_entry_key, Entry},
    errors::{AtomicErrorType, AtomicResult},
    storelike::Storelike,
    urls, Resource, Subject, Value,
};

use super::chat_migration::{creator_of, id_body, MessageMigration, PAGE_SIZE};
use super::prop_val_sub_index::find_in_prop_val_sub_index;
use super::trees::Tree;
use super::Db;

macro_rules! ai {
    ($s:literal) => {
        concat!("https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/", $s)
    };
}

const AI_CHAT: &str = ai!("class/ai-chat");
const AI_MESSAGE: &str = ai!("class/ai-message");
const FILE_PART: &str = ai!("class/file-part");
const MCP_RESOURCE: &str = ai!("class/mcp-resource");
const REASONING_PART: &str = ai!("class/reasoning-part");
const SOURCE_URL_PART: &str = ai!("class/source-url-part");
const TEXT_PART: &str = ai!("class/text-part");
const TOOL_CALL_PART: &str = ai!("class/tool-call-part");

const MESSAGES: &str = ai!("property/messages");
const CONTENT: &str = ai!("property/content");
const PROVIDED_CONTEXT: &str = ai!("property/provided-context");
const ROLE: &str = ai!("property/role");
const DATA: &str = ai!("property/data");
const MCP_URI: &str = ai!("property/mcp-uri");
const MCP_SERVER_ID: &str = ai!("property/mcp-server-id");
const TOOL_INPUT: &str = ai!("property/tool-arguments");
const TOOL_ID: &str = ai!("property/tool-id");
const TOOL_NAME: &str = ai!("property/tool-name");
const TOOL_OUTPUT: &str = ai!("property/tool-result");
const TOOL_IS_ERROR: &str = ai!("property/tool-result-is-error");
const SERVER_CONTEXT: &str = "https://atomicdata.dev/properties/serverProvidedContext";
const SOURCE_URL: &str = "https://atomicdata.dev/property/url";

/// Set when the AI chats are migrated.
pub const AI_DONE_KEY: &[u8] = b"ai-chat-log-migration-v1";
/// Present while a run is under way.
const AI_STATE_KEY: &[u8] = b"ai-chat-log-migration-v1-state";

#[derive(Serialize, Deserialize)]
struct AiGroup {
    chat: String,
    count: u64,
}

#[derive(Serialize, Deserialize)]
struct AiState {
    done: u64,
    total: u64,
    next: usize,
    chats: Vec<AiGroup>,
}

/// What one old message becomes.
struct OldAi {
    subject: String,
    key: String,
    created_at: i64,
    entry: Entry,
}

fn has_class(resource: &Resource, class: &str) -> bool {
    resource
        .get(urls::IS_A)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .is_some_and(|classes| classes.iter().any(|c| c == class))
}

/// A stored value as plain JSON: the datatype of the property decides how the
/// app wrote it, here only the shape counts.
fn value_json(value: &Value) -> Json {
    match value {
        Value::Json(json) => json.clone(),
        Value::Integer(i) | Value::Timestamp(i) => json!(i),
        Value::Float(f) => json!(f),
        Value::Boolean(b) => json!(b),
        other => Json::String(other.to_string()),
    }
}

fn string_prop(resource: &Resource, property: &str) -> Option<String> {
    resource.get(property).ok().map(|v| v.to_string())
}

/// One part resource as the part JSON the app stores in an entry: the shape
/// `restoreToolPart` and friends in `chatConversionUtils.ts` produce. Parts of
/// a kind the app does not know are dropped.
fn part_json(part: &Resource) -> Option<Json> {
    let text = || string_prop(part, urls::DESCRIPTION).unwrap_or_default();
    if has_class(part, TEXT_PART) {
        return Some(json!({ "type": "text", "text": text() }));
    }
    if has_class(part, REASONING_PART) {
        return Some(json!({ "type": "reasoning", "text": text() }));
    }
    if has_class(part, FILE_PART) {
        let mut file = json!({
            "type": "file",
            "url": string_prop(part, DATA).unwrap_or_default(),
            "mediaType": string_prop(part, urls::MIMETYPE).unwrap_or_default(),
        });
        if let Some(filename) = string_prop(part, urls::FILENAME) {
            file["filename"] = Json::String(filename);
        }
        return Some(file);
    }
    if has_class(part, SOURCE_URL_PART) {
        let mut source = json!({
            "type": "source-url",
            "url": string_prop(part, SOURCE_URL).unwrap_or_default(),
        });
        if let Some(title) = string_prop(part, urls::NAME) {
            source["title"] = Json::String(title);
        }
        return Some(source);
    }
    if has_class(part, TOOL_CALL_PART) {
        let name = string_prop(part, TOOL_NAME)?;
        let input = part.get(TOOL_INPUT).ok().map(value_json);
        let output = part.get(TOOL_OUTPUT).ok().map(value_json);
        let is_error = part
            .get(TOOL_IS_ERROR)
            .ok()
            .and_then(|v| v.to_bool().ok())
            .unwrap_or(false);
        let mut tool = json!({
            "type": format!("tool-{name}"),
            "toolCallId": string_prop(part, TOOL_ID).unwrap_or_default(),
        });
        if let Some(input) = &input {
            tool["input"] = input.clone();
        }
        if is_error {
            tool["state"] = json!("output-error");
            tool["errorText"] = match output {
                Some(Json::String(text)) => Json::String(text),
                _ => json!("Tool failed; no error details were recorded."),
            };
        } else if let Some(output) = output {
            tool["state"] = json!("output-available");
            tool["output"] = output;
        } else {
            tool["state"] = json!(if input.is_none() {
                "input-streaming"
            } else {
                "input-available"
            });
        }
        return Some(tool);
    }
    None
}

/// `…/tag/assistant` to `assistant`.
fn role_word(tag: &str) -> String {
    tag.rsplit('/').next().unwrap_or(tag).to_string()
}

impl Db {
    /// Whether old `ai-message` resources may be left to move: not marked done,
    /// and the index lists at least one.
    pub fn ai_chat_migration_pending(&self) -> AtomicResult<bool> {
        if self.kv.get(Tree::PluginMeta, AI_DONE_KEY)?.is_some() {
            return Ok(false);
        }
        let class = Value::AtomicUrl(AI_MESSAGE.into());
        Ok(find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .next()
            .is_some())
    }

    /// Migrates whole chats until `limit` messages are done (at least one
    /// chat). Call until `finished`. `create_in` is as for
    /// [`Db::migrate_messages_step`].
    pub async fn migrate_ai_chats_step(
        &self,
        limit: usize,
        create_in: Option<&HashSet<String>>,
    ) -> AtomicResult<MessageMigration> {
        if !self.ai_chat_migration_pending()? {
            return Ok(MessageMigration {
                done: 0,
                total: 0,
                finished: true,
            });
        }

        let mut state = match self.kv.get(Tree::PluginMeta, AI_STATE_KEY)? {
            Some(bytes) => serde_json::from_slice::<AiState>(&bytes)
                .map_err(|e| format!("Unreadable AI chat migration state: {e}"))?,
            None => {
                let state = self.plan_ai_chat_migration().await?;
                if state.total == 0 {
                    return self.finish_ai_chat_migration(0);
                }
                state
            }
        };

        let mut handled = 0usize;
        while state.next < state.chats.len() && handled < limit.max(1) {
            let group = &state.chats[state.next];
            self.migrate_ai_chat(&group.chat, true, create_in).await?;
            handled += group.count as usize;
            state.done += group.count;
            state.next += 1;
        }

        if state.next >= state.chats.len() {
            return self.finish_ai_chat_migration(state.total);
        }

        self.kv.insert(
            Tree::PluginMeta,
            AI_STATE_KEY,
            &serde_json::to_vec(&state).map_err(|e| e.to_string())?,
        )?;

        Ok(MessageMigration {
            done: state.done,
            total: state.total,
            finished: false,
        })
    }

    fn finish_ai_chat_migration(&self, total: u64) -> AtomicResult<MessageMigration> {
        // Nothing to move: leave the store untouched.
        if total > 0 {
            self.kv.insert(Tree::PluginMeta, AI_DONE_KEY, b"1")?;
            self.kv.remove(Tree::PluginMeta, AI_STATE_KEY)?;
            self.kv.flush()?;
        }
        Ok(MessageMigration {
            done: total,
            total,
            finished: true,
        })
    }

    /// Runs the migration to the end, logging as it goes.
    pub async fn migrate_ai_chats(&self) -> AtomicResult<()> {
        if !self.ai_chat_migration_pending()? {
            return Ok(());
        }
        loop {
            let step = self.migrate_ai_chats_step(2000, None).await?;
            if step.finished {
                if step.total > 0 {
                    tracing::info!("AI chat messages moved into chat logs ({})", step.total);
                }
                return Ok(());
            }
            tracing::info!(
                "Moving AI chat messages into chat logs: {}/{}",
                step.done,
                step.total
            );
        }
    }

    /// Lists the chats that still keep messages in their `messages` list.
    async fn plan_ai_chat_migration(&self) -> AtomicResult<AiState> {
        let class = Value::AtomicUrl(AI_CHAT.into());
        let subjects: Vec<Subject> = find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .map(|atom| atom.subject)
            .collect();
        let mut chats = Vec::new();
        let mut total = 0u64;
        for subject in subjects {
            let Ok(chat) = self.get_resource_shallow(&subject) else {
                continue;
            };
            let count = chat
                .get(MESSAGES)
                .ok()
                .and_then(|v| v.to_subjects(None).ok())
                .map_or(0, |list| list.len() as u64);
            if count > 0 {
                chats.push(AiGroup {
                    chat: subject.to_string(),
                    count,
                });
                total += count;
            }
        }
        chats.sort_by(|a, b| a.chat.cmp(&b.chat));
        Ok(AiState {
            done: 0,
            total,
            next: 0,
            chats,
        })
    }

    /// The pages a chat already has: entry key to (page subject, `c`).
    async fn existing_ai_entries(
        &self,
        chat: &str,
    ) -> AtomicResult<HashMap<String, (String, i64)>> {
        let candidates: Vec<Subject> =
            find_in_prop_val_sub_index(self, urls::PARENT, Some(&Value::AtomicUrl(chat.into())))
                .flatten()
                .map(|atom| atom.subject)
                .collect();
        let mut existing = HashMap::new();
        for subject in candidates {
            let Ok(page) = Storelike::get_resource(self, &subject).await else {
                continue;
            };
            if !crate::hierarchy::is_chat_log(&page) {
                continue;
            }
            let Ok(doc) = page.build_state_doc() else {
                continue;
            };
            let page_subject = page.get_subject().pure_id();
            for (key, entry) in doc.entries() {
                let c = crate::chat_log::entry_created_at(&entry).unwrap_or(0);
                existing
                    .entry(key)
                    .or_insert_with(|| (page_subject.clone(), c));
            }
        }
        Ok(existing)
    }

    /// The part resources of a message, in order. A part that is gone is
    /// skipped.
    async fn ai_parts(&self, message: &Resource) -> AtomicResult<Vec<Json>> {
        let subjects = message
            .get(CONTENT)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        let mut parts = Vec::new();
        for subject in subjects {
            match Storelike::get_resource(self, &subject.as_str().into()).await {
                Ok(part) => parts.extend(part_json(&part)),
                Err(e) if e.error_type == AtomicErrorType::NotFoundError => {}
                Err(e) => return Err(e),
            }
        }
        Ok(parts)
    }

    /// The provided context of a message: an `mcp-resource` item is a resource
    /// of its own, anything else is a plain reference.
    async fn ai_context(&self, message: &Resource) -> Vec<Json> {
        let subjects = message
            .get(PROVIDED_CONTEXT)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        let mut context = Vec::new();
        for subject in subjects {
            match Storelike::get_resource(self, &subject.as_str().into()).await {
                Ok(item) if has_class(&item, MCP_RESOURCE) => {
                    let mut mcp = json!({
                        "type": "mcp-resource",
                        "name": string_prop(&item, urls::NAME).unwrap_or_default(),
                        "uri": string_prop(&item, MCP_URI).unwrap_or_default(),
                        "serverId": string_prop(&item, MCP_SERVER_ID).unwrap_or_default(),
                    });
                    if let Some(mimetype) = string_prop(&item, urls::MIMETYPE) {
                        mcp["mimetype"] = Json::String(mimetype);
                    }
                    context.push(mcp);
                }
                _ => context.push(json!({ "type": "atomic-resource", "subject": subject })),
            }
        }
        context
    }

    /// The old messages of a chat, in the order of its `messages` list. Those
    /// already removed (an earlier run) are not in it.
    async fn old_ai_messages(&self, list: &[String]) -> AtomicResult<Vec<OldAi>> {
        let mut old = Vec::new();
        for subject in list {
            let message = match Storelike::get_resource(self, &subject.as_str().into()).await {
                Ok(message) => message,
                Err(e) if e.error_type == AtomicErrorType::NotFoundError => continue,
                Err(e) => return Err(e),
            };
            if !has_class(&message, AI_MESSAGE) {
                continue;
            }
            let created_at = message
                .get(urls::CREATED_AT)
                .ok()
                .and_then(|v| v.to_int().ok())
                .unwrap_or(0);
            let key_subject = message.get_subject().pure_id();
            let role = message
                .get(ROLE)
                .map(|v| role_word(&v.to_string()))
                .unwrap_or_else(|_| "assistant".into());
            let parts = self.ai_parts(&message).await?;
            let context = self.ai_context(&message).await;

            let mut entry = Entry::new(creator_of(&message), "", created_at);
            entry.extra.insert("role".into(), role.as_str().into());
            entry.extra.insert(
                "parts".into(),
                serde_json::to_string(&parts)
                    .map_err(|e| e.to_string())?
                    .as_str()
                    .into(),
            );
            if !context.is_empty() {
                entry.extra.insert(
                    "ctx".into(),
                    serde_json::to_string(&context)
                        .map_err(|e| e.to_string())?
                        .as_str()
                        .into(),
                );
            }
            if let Some(server_context) = string_prop(&message, SERVER_CONTEXT) {
                entry
                    .extra
                    .insert("sc".into(), server_context.as_str().into());
            }
            if let Some(error) = string_prop(&message, urls::DESCRIPTION) {
                entry.extra.insert("err".into(), error.as_str().into());
            }
            old.push(OldAi {
                key: migrated_entry_key(created_at, &key_subject),
                subject: key_subject,
                created_at,
                entry,
            });
        }
        Ok(old)
    }

    /// Moves the old messages of one chat into pages and, with `remove_old`,
    /// removes them. (Tests stop before the removal to simulate a crash.)
    pub(super) async fn migrate_ai_chat(
        &self,
        chat_subject: &str,
        remove_old: bool,
        create_in: Option<&HashSet<String>>,
    ) -> AtomicResult<()> {
        let Ok(mut chat) = Storelike::get_resource(self, &chat_subject.into()).await else {
            return Ok(());
        };
        let list = chat
            .get(MESSAGES)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        if list.is_empty() {
            return Ok(());
        }
        let drive = chat
            .get(urls::DRIVE_PROP)
            .map(|d| d.to_string())
            .unwrap_or_else(|_| chat_subject.to_string());
        let create = create_in.is_none_or(|drives| drives.contains(&id_body(&drive)));
        let mut old = self.old_ai_messages(&list).await?;
        let existing = self.existing_ai_entries(chat_subject).await?;

        // `c` follows the list: the creation time, raised to one millisecond
        // after the entry before it. An entry that exists keeps its own.
        let mut previous = i64::MIN;
        for message in &mut old {
            let c = match existing.get(&message.key) {
                Some((_, c)) => *c,
                None => message.created_at.max(previous.saturating_add(1)),
            };
            message.entry.created_at = c;
            previous = previous.max(c);
        }

        let missing: Vec<&OldAi> = old
            .iter()
            .filter(|m| create && !existing.contains_key(&m.key))
            .collect();
        let signer = if create && (!missing.is_empty() || remove_old) {
            Some(self.page_signer()?)
        } else {
            None
        };

        for chunk in missing.chunks(PAGE_SIZE) {
            let signer = signer
                .as_ref()
                .expect("pages are only written with a signer");
            let page = signer.plan_page(chunk[0].entry.created_at.max(1), chat_subject, &drive)?;
            let entries: Vec<(String, Entry)> = chunk
                .iter()
                .map(|m| {
                    let mut entry = m.entry.clone();
                    if entry.author.is_empty() {
                        entry.author = signer.agent.subject.to_string();
                    }
                    (m.key.clone(), entry)
                })
                .collect();
            self.write_log_page(signer, &page, chat_subject, None, &entries)
                .await?;
        }

        if !remove_old {
            return Ok(());
        }
        // Every entry of this chat is in a page now. Remove the old messages,
        // each after what hangs under it. Without `create` (a cache of a hosted
        // drive), only those that have their entry.
        for message in old
            .iter()
            .filter(|m| create || existing.contains_key(&m.key))
        {
            self.remove_old_ai_message(&message.subject).await?;
        }

        // The chat itself keeps its name and `about`; only the list goes. A
        // cache leaves it to the server's change.
        if let (true, Some(signer)) = (create, &signer) {
            if !matches!(chat.get_subject(), Subject::External(_)) {
                chat.remove_propval(MESSAGES)?;
                chat.save_as(&signer.agent, self).await?;
            }
        }
        Ok(())
    }

    /// Removes an old `ai-message`, its parts and its context items.
    async fn remove_old_ai_message(&self, subject: &str) -> AtomicResult<()> {
        let message = Subject::from(subject);
        let mut below: Vec<String> = Vec::new();
        if let Ok(resource) = self.get_resource_shallow(&message) {
            for property in [CONTENT, PROVIDED_CONTEXT] {
                if let Some(list) = resource
                    .get(property)
                    .ok()
                    .and_then(|v| v.to_subjects(None).ok())
                {
                    below.extend(list);
                }
            }
        }
        // Children that the lists do not name (a part that was replaced).
        below.extend(
            find_in_prop_val_sub_index(self, urls::PARENT, Some(&Value::AtomicUrl(subject.into())))
                .flatten()
                .map(|atom| atom.subject.to_string()),
        );
        let own = id_body(subject);
        let mut seen: HashSet<String> = HashSet::new();
        for child in below {
            let body = id_body(&child);
            // A context item may be an ordinary resource of the user's: only
            // what hangs under this message goes.
            let is_child = self
                .get_resource_shallow(&Subject::from(child.as_str()))
                .ok()
                .and_then(|r| r.get(urls::PARENT).ok().map(|p| id_body(&p.to_string())))
                .is_some_and(|parent| parent == own);
            if is_child && seen.insert(body) {
                self.remove_old_message(&child).await?;
            }
        }
        self.remove_old_message(subject).await
    }
}
