//! Moves the messages of existing conversations into `ChatLog` pages.
//!
//! A direct message used to be a `SealedMessage` resource of its own (3 KB of
//! rows, like a plain `Message`). Now a conversation keeps its messages as
//! entries of `ChatLog` pages whose parent is the `Conversation`
//! (`planning/chat-log.md`, "Step 4: direct messages"). This migration packs the
//! old ones into pages and removes the old resources.
//!
//! - **The server cannot read a message and does not need to.** The entry
//!   carries the sealed payload as it was stored (`s`, the `sealed` string,
//!   byte for byte). Nothing in the sealed format names the resource: the
//!   "message id" inside it is 16 random bytes chosen at sealing, and the
//!   associated data is the header plus the conversation's subject, which does
//!   not change. So a moved message opens, and reveals, exactly as before.
//! - **Entry:** `a` the original author (`createdBy`), `t` empty, `c` the
//!   creation time, `s` the sealed payload, `e` when it was edited. No `r`: a
//!   reply target is inside the encrypted payload and keeps naming the old
//!   subject; the reader finds the moved message by the hash part of its key
//!   (`planning/chat-log.md`).
//! - **Key:** [`crate::chat_log::migrated_entry_key`] of the old subject, as for
//!   the other chats.
//! - **Where pages are made, state, progress, removal:** like the `Message`
//!   migration (`chat_migration.rs`), with its own marker
//!   `conversation-log-migration-v1`. A conversation is a drive of its own and
//!   has no `drive` stamp, so its pages are stamped with the conversation.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    chat_log::{migrated_entry_key, Entry},
    errors::AtomicResult,
    storelike::Storelike,
    urls, Subject, Value,
};

use super::chat_migration::{creator_of, id_body, MessageMigration, PAGE_SIZE};
use super::prop_val_sub_index::find_in_prop_val_sub_index;
use super::trees::Tree;
use super::Db;

/// Set when the conversations are migrated.
pub const CONVERSATION_DONE_KEY: &[u8] = b"conversation-log-migration-v1";
/// Present while a run is under way.
const CONVERSATION_STATE_KEY: &[u8] = b"conversation-log-migration-v1-state";

#[derive(Serialize, Deserialize)]
struct ConversationGroup {
    conversation: String,
    count: u64,
}

#[derive(Serialize, Deserialize)]
struct ConversationState {
    done: u64,
    total: u64,
    next: usize,
    conversations: Vec<ConversationGroup>,
}

/// What one old message becomes.
struct OldSealed {
    subject: String,
    key: String,
    entry: Entry,
}

impl Db {
    /// Whether old `SealedMessage` resources may be left to move: not marked
    /// done, and the index lists at least one.
    pub fn conversation_migration_pending(&self) -> AtomicResult<bool> {
        if self
            .kv
            .get(Tree::PluginMeta, CONVERSATION_DONE_KEY)?
            .is_some()
        {
            return Ok(false);
        }
        let class = Value::AtomicUrl(urls::SEALED_MESSAGE.into());
        Ok(find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .next()
            .is_some())
    }

    /// Migrates whole conversations until `limit` messages are done (at least
    /// one conversation). Call until `finished`. `create_in` is as for
    /// [`Db::migrate_messages_step`].
    pub async fn migrate_conversations_step(
        &self,
        limit: usize,
        create_in: Option<&HashSet<String>>,
    ) -> AtomicResult<MessageMigration> {
        if !self.conversation_migration_pending()? {
            return Ok(MessageMigration {
                done: 0,
                total: 0,
                finished: true,
            });
        }

        let mut state = match self.kv.get(Tree::PluginMeta, CONVERSATION_STATE_KEY)? {
            Some(bytes) => serde_json::from_slice::<ConversationState>(&bytes)
                .map_err(|e| format!("Unreadable conversation migration state: {e}"))?,
            None => {
                let state = self.plan_conversation_migration().await?;
                if state.total == 0 {
                    return self.finish_conversation_migration(0);
                }
                state
            }
        };

        let mut handled = 0usize;
        while state.next < state.conversations.len() && handled < limit.max(1) {
            let group = &state.conversations[state.next];
            self.migrate_conversation(&group.conversation, true, create_in)
                .await?;
            handled += group.count as usize;
            state.done += group.count;
            state.next += 1;
        }

        if state.next >= state.conversations.len() {
            return self.finish_conversation_migration(state.total);
        }

        self.kv.insert(
            Tree::PluginMeta,
            CONVERSATION_STATE_KEY,
            &serde_json::to_vec(&state).map_err(|e| e.to_string())?,
        )?;

        Ok(MessageMigration {
            done: state.done,
            total: state.total,
            finished: false,
        })
    }

    fn finish_conversation_migration(&self, total: u64) -> AtomicResult<MessageMigration> {
        // Nothing to move: leave the store untouched.
        if total > 0 {
            self.kv
                .insert(Tree::PluginMeta, CONVERSATION_DONE_KEY, b"1")?;
            self.kv.remove(Tree::PluginMeta, CONVERSATION_STATE_KEY)?;
            self.kv.flush()?;
        }
        Ok(MessageMigration {
            done: total,
            total,
            finished: true,
        })
    }

    /// Runs the migration to the end, logging as it goes.
    pub async fn migrate_conversations(&self) -> AtomicResult<()> {
        if !self.conversation_migration_pending()? {
            return Ok(());
        }
        loop {
            let step = self.migrate_conversations_step(2000, None).await?;
            if step.finished {
                if step.total > 0 {
                    tracing::info!(
                        "Conversation messages moved into chat logs ({})",
                        step.total
                    );
                }
                return Ok(());
            }
            tracing::info!(
                "Moving conversation messages into chat logs: {}/{}",
                step.done,
                step.total
            );
        }
    }

    /// Lists the conversations that still hold old messages.
    async fn plan_conversation_migration(&self) -> AtomicResult<ConversationState> {
        let class = Value::AtomicUrl(urls::SEALED_MESSAGE.into());
        let subjects: Vec<Subject> = find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .map(|atom| atom.subject)
            .collect();
        let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
        let mut total = 0u64;
        for subject in subjects {
            let Ok(message) = self.get_resource_shallow(&subject) else {
                continue;
            };
            let Ok(parent) = message.get(urls::PARENT).map(|p| p.to_string()) else {
                continue;
            };
            *counts.entry(parent).or_default() += 1;
            total += 1;
        }
        Ok(ConversationState {
            done: 0,
            total,
            next: 0,
            conversations: counts
                .into_iter()
                .map(|(conversation, count)| ConversationGroup {
                    conversation,
                    count,
                })
                .collect(),
        })
    }

    /// The old messages of one conversation, oldest first.
    async fn old_sealed_messages(&self, conversation: &str) -> AtomicResult<Vec<OldSealed>> {
        let candidates: Vec<Subject> = find_in_prop_val_sub_index(
            self,
            urls::PARENT,
            Some(&Value::AtomicUrl(conversation.into())),
        )
        .flatten()
        .map(|atom| atom.subject)
        .collect();

        let mut old: Vec<OldSealed> = Vec::new();
        for subject in candidates {
            let Ok(message) = Storelike::get_resource(self, &subject).await else {
                continue;
            };
            let is_sealed = message
                .get(urls::IS_A)
                .ok()
                .and_then(|v| v.to_subjects(None).ok())
                .is_some_and(|classes| classes.iter().any(|c| c == urls::SEALED_MESSAGE));
            if !is_sealed {
                continue;
            }
            // A message without ciphertext has nothing to carry over.
            let Ok(sealed) = message.get(urls::SEALED).map(|s| s.to_string()) else {
                continue;
            };
            let created_at = message
                .get(urls::CREATED_AT)
                .ok()
                .and_then(|v| v.to_int().ok())
                .unwrap_or(0);
            let mut entry = Entry::new(creator_of(&message), "", created_at);
            entry.extra.insert("s".into(), sealed.as_str().into());
            let key_subject = subject.pure_id();
            if let Some(latest) = crate::envelopes::latest_envelope(self, &key_subject) {
                if latest.created_at > created_at + 1000 {
                    entry.edited_at = Some(latest.created_at);
                }
            }
            old.push(OldSealed {
                key: migrated_entry_key(created_at, &key_subject),
                subject: key_subject,
                entry,
            });
        }
        old.sort_by(|a, b| (a.entry.created_at, &a.subject).cmp(&(b.entry.created_at, &b.subject)));
        Ok(old)
    }

    /// Moves the old messages of one conversation into pages and, with
    /// `remove_old`, removes them. (Tests stop before the removal to simulate a
    /// crash.)
    pub(super) async fn migrate_conversation(
        &self,
        conversation: &str,
        remove_old: bool,
        create_in: Option<&HashSet<String>>,
    ) -> AtomicResult<()> {
        let old = self.old_sealed_messages(conversation).await?;
        if old.is_empty() {
            return Ok(());
        }
        // A conversation that is gone has nowhere to put a page.
        let Ok(parent) = Storelike::get_resource(self, &conversation.into()).await else {
            tracing::warn!(
                conversation,
                "Conversation messages left as they are: the conversation is missing"
            );
            return Ok(());
        };
        let drive = parent
            .get(urls::DRIVE_PROP)
            .map(|d| d.to_string())
            .unwrap_or_else(|_| conversation.to_string());
        let create = create_in.is_none_or(|drives| drives.contains(&id_body(&drive)));
        let existing = self.existing_ai_entries(conversation).await?;
        let missing: Vec<&OldSealed> = old
            .iter()
            .filter(|m| create && !existing.contains_key(&m.key))
            .collect();
        let signer = if missing.is_empty() {
            None
        } else {
            Some(self.page_signer()?)
        };

        for chunk in missing.chunks(PAGE_SIZE) {
            let signer = signer
                .as_ref()
                .expect("pages are only written with a signer");
            let page = signer.plan_page(chunk[0].entry.created_at.max(1), conversation, &drive)?;
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
            self.write_log_page(signer, &page, conversation, None, &entries)
                .await?;
        }

        if !remove_old {
            return Ok(());
        }
        // Every entry of this conversation is in a page now. Without `create`
        // (a cache of a hosted drive), only the messages that have their entry
        // go.
        let mut gone: HashSet<&str> = HashSet::new();
        for message in old
            .iter()
            .filter(|m| create || existing.contains_key(&m.key))
        {
            if gone.insert(message.subject.as_str()) {
                self.remove_old_message(&message.subject).await?;
            }
        }
        Ok(())
    }
}
