//! Moves existing `Message` resources into `ChatLog` pages.
//!
//! Every chat message used to be a resource of its own (3 KB of rows). Now a
//! chat keeps up to 256 messages per `ChatLog` page (`planning/chat-log.md`,
//! "Existing messages"). This migration packs the old ones into pages and
//! removes the old resources.
//!
//! - **Scope:** every `Message` resource: group chat, comments, meeting chat,
//!   follow events. Not `SealedMessage` and not AI chat.
//! - **Groups:** by `(parent, about)`. Inside a group the messages are sorted by
//!   `createdAt` and cut into pages of [`PAGE_SIZE`].
//! - **Entry:** `a` the original author (`createdBy`), `t` the description, `c`
//!   the creation time, `k` FollowEvent for follow events, `e` when the message
//!   was edited, `r` the new `<page>#<key>` id of the replied-to message (the old
//!   subject when that one was not migrated). The key is
//!   [`crate::chat_log::migrated_entry_key`], so a message that already has its
//!   entry is recognised and not written twice.
//! - **Authority:** the pages are signed by an agent that belongs to this store
//!   and written with rights checks off, like a server-internal write. The
//!   author of an entry is attested by this host; the per-message signature is
//!   not carried over. The page gives its creator no `write`, so the normal rule
//!   for later commits holds: members only change their own entries.
//! - **Order of work:** a group's pages are written first, then its old
//!   resources are removed (resource row, Loro snapshot, envelopes, genesis
//!   commit row, index and search rows). A restart in between finds the entries
//!   by key and only removes what is left.
//!
//! - **Where pages are made:** a store that is the only copy of a drive writes
//!   the pages itself. A store that only caches a drive the server hosts does
//!   not: the server makes the pages, and the cache just drops its old
//!   `Message` rows whose entry is already in a page it holds
//!   (`create_in` in [`Db::migrate_messages_step`]).
//!
//! State lives in `Tree::PluginMeta`, like the index migration: the server runs
//! it to the end when it opens the store, the browser worker runs it one slice
//! at a time and shows how far it got. A slice handles whole groups.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    agents::Agent,
    chat_log::{migrated_entry_key, Entry},
    commit::{Commit, CommitBuilder, CommitOpts},
    errors::AtomicResult,
    genesis::GenesisCert,
    loro::AtomicLoroDoc,
    storelike::Storelike,
    urls, Subject, Value,
};

use super::prop_val_sub_index::find_in_prop_val_sub_index;
use super::trees::Tree;
use super::Db;

/// Messages per page.
pub const PAGE_SIZE: usize = 256;

/// Set when the messages are migrated.
pub const DONE_KEY: &[u8] = b"chat-log-migration-v1";
/// Present while a run is under way.
const STATE_KEY: &[u8] = b"chat-log-migration-v1-state";
/// Private key of the agent that signs the pages.
const AGENT_KEY: &[u8] = b"chat-log-migration-agent";

/// How far the migration is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageMigration {
    /// Messages handled so far.
    pub done: u64,
    /// Messages to handle.
    pub total: u64,
    /// Nothing left to do.
    pub finished: bool,
}

#[derive(Serialize, Deserialize)]
struct Group {
    parent: String,
    about: Option<String>,
    count: u64,
}

#[derive(Serialize, Deserialize)]
struct State {
    done: u64,
    total: u64,
    next: usize,
    groups: Vec<Group>,
}

/// What one old message becomes.
struct Old {
    subject: String,
    key: String,
    entry: Entry,
    reply_to: Option<String>,
}

/// An identifier without scheme, query and fragment: both spellings of a DID
/// give one string. Other subjects are compared as they are.
pub(super) fn id_body(subject: &str) -> String {
    let pure = Subject::from(subject).pure_id();
    crate::identifiers::identifier_body(&pure)
        .unwrap_or(&pure)
        .to_string()
}

/// The creator of an old resource: `createdBy`, else the agent its genesis
/// change names. Empty when neither is known.
pub(super) fn creator_of(resource: &crate::Resource) -> String {
    match resource.get(urls::CREATED_BY) {
        Ok(v) => v.to_string(),
        Err(_) => resource
            .build_state_doc()
            .ok()
            .and_then(|doc| doc.genesis_change())
            .and_then(|genesis| genesis.message)
            .unwrap_or_default(),
    }
}

/// The agent that signs migrated pages, with its raw key material.
pub(super) struct PageSigner {
    pub agent: Agent,
    pub public_key: [u8; 32],
    pub private_key: String,
}

/// A page that is planned: its certificate is signed, so its subject is known
/// before it is written.
pub(super) struct PlannedPage {
    pub cert: GenesisCert,
    pub subject: String,
}

impl PageSigner {
    /// Plans a page for `parent` in `drive`, created at `created_at`.
    pub(super) fn plan_page(
        &self,
        created_at: i64,
        parent: &str,
        drive: &str,
    ) -> AtomicResult<PlannedPage> {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let cert = GenesisCert::new_v2(self.public_key, created_at, nonce, None, parent, drive);
        let signature = cert.sign(&self.private_key)?;
        let subject = GenesisCert::subject_for_signature(&signature);
        Ok(PlannedPage { cert, subject })
    }
}

fn has_class(classes: &[String], class: &str) -> bool {
    classes.iter().any(|c| c == class)
}

impl Db {
    /// Whether old `Message` resources are left to move: not marked done, and
    /// the index lists at least one. A store without any writes nothing at all
    /// (not even a marker), so opening it costs one index lookup.
    pub fn message_migration_pending(&self) -> AtomicResult<bool> {
        if self.kv.get(Tree::PluginMeta, DONE_KEY)?.is_some() {
            return Ok(false);
        }
        let class = Value::AtomicUrl(urls::MESSAGE.into());
        Ok(find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .next()
            .is_some())
    }

    /// Migrates whole groups until `limit` messages are done (at least one
    /// group). Call until `finished`.
    ///
    /// `create_in` names the drives this store may write pages for: `None` for
    /// all (a server), the drives that exist only here for a browser store.
    /// Messages of other drives are only removed when their entry is already
    /// in a page of this store.
    pub async fn migrate_messages_step(
        &self,
        limit: usize,
        create_in: Option<&HashSet<String>>,
    ) -> AtomicResult<MessageMigration> {
        if !self.message_migration_pending()? {
            return Ok(MessageMigration {
                done: 0,
                total: 0,
                finished: true,
            });
        }

        let mut state = match self.kv.get(Tree::PluginMeta, STATE_KEY)? {
            Some(bytes) => serde_json::from_slice::<State>(&bytes)
                .map_err(|e| format!("Unreadable chat migration state: {e}"))?,
            None => {
                let state = self.plan_message_migration().await?;
                if state.total == 0 {
                    return self.finish_message_migration(0);
                }
                state
            }
        };

        let mut handled = 0usize;
        while state.next < state.groups.len() && handled < limit.max(1) {
            let group = &state.groups[state.next];
            self.migrate_group(&group.parent, group.about.as_deref(), true, create_in)
                .await?;
            handled += group.count as usize;
            state.done += group.count;
            state.next += 1;
        }

        if state.next >= state.groups.len() {
            return self.finish_message_migration(state.total);
        }

        self.kv.insert(
            Tree::PluginMeta,
            STATE_KEY,
            &serde_json::to_vec(&state).map_err(|e| e.to_string())?,
        )?;

        Ok(MessageMigration {
            done: state.done,
            total: state.total,
            finished: false,
        })
    }

    fn finish_message_migration(&self, total: u64) -> AtomicResult<MessageMigration> {
        // Nothing to move: leave the store untouched.
        if total > 0 {
            self.kv.insert(Tree::PluginMeta, DONE_KEY, b"1")?;
            self.kv.remove(Tree::PluginMeta, STATE_KEY)?;
            self.kv.flush()?;
        }
        Ok(MessageMigration {
            done: total,
            total,
            finished: true,
        })
    }

    /// Runs the migration to the end, logging as it goes.
    pub async fn migrate_messages(&self) -> AtomicResult<()> {
        if !self.message_migration_pending()? {
            return Ok(());
        }
        loop {
            let step = self.migrate_messages_step(2000, None).await?;
            if step.finished {
                if step.total > 0 {
                    tracing::info!("Chat messages moved into chat logs ({})", step.total);
                }
                return Ok(());
            }
            tracing::info!(
                "Moving chat messages into chat logs: {}/{}",
                step.done,
                step.total
            );
        }
    }

    /// Lists the groups of old messages.
    async fn plan_message_migration(&self) -> AtomicResult<State> {
        let class = Value::AtomicUrl(urls::MESSAGE.into());
        let subjects: Vec<Subject> = find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .map(|atom| atom.subject)
            .collect();
        let mut groups: BTreeMap<(String, Option<String>), u64> = BTreeMap::new();
        let mut total = 0u64;
        for subject in subjects {
            let Ok(message) = self.get_resource_shallow(&subject) else {
                continue;
            };
            let Ok(parent) = message.get(urls::PARENT).map(|p| p.to_string()) else {
                continue;
            };
            let about = message.get(urls::ABOUT).ok().map(|a| a.to_string());
            *groups.entry((parent, about)).or_default() += 1;
            total += 1;
        }
        Ok(State {
            done: 0,
            total,
            next: 0,
            groups: groups
                .into_iter()
                .map(|((parent, about), count)| Group {
                    parent,
                    about,
                    count,
                })
                .collect(),
        })
    }

    /// The agent that signs migrated pages. Made on first use and kept in the
    /// store, so a resumed run and later runs sign as the same one.
    pub(super) fn chat_migration_agent(&self) -> AtomicResult<Agent> {
        if let Some(bytes) = self.kv.get(Tree::PluginMeta, AGENT_KEY)? {
            let private_key = String::from_utf8(bytes.to_vec())
                .map_err(|e| format!("Unreadable chat migration agent: {e}"))?;
            return Agent::new_from_private_key(Some("Chat log migration"), &private_key);
        }
        let agent = Agent::new(Some("Chat log migration"))?;
        let private_key = agent
            .private_key
            .clone()
            .ok_or("A new agent has a private key")?;
        self.kv
            .insert(Tree::PluginMeta, AGENT_KEY, private_key.as_bytes())?;
        Ok(agent)
    }

    /// The old messages of one chat, oldest first.
    async fn old_messages(&self, parent: &str, about: Option<&str>) -> AtomicResult<Vec<Old>> {
        let candidates: Vec<Subject> = match about {
            Some(about) => {
                find_in_prop_val_sub_index(self, urls::ABOUT, Some(&Value::AtomicUrl(about.into())))
            }
            None => find_in_prop_val_sub_index(
                self,
                urls::PARENT,
                Some(&Value::AtomicUrl(parent.into())),
            ),
        }
        .flatten()
        .map(|atom| atom.subject)
        .collect();

        let mut old: Vec<Old> = Vec::new();
        for subject in candidates {
            let Ok(message) = Storelike::get_resource(self, &subject).await else {
                continue;
            };
            let classes = message
                .get(urls::IS_A)
                .ok()
                .and_then(|v| v.to_subjects(None).ok())
                .unwrap_or_default();
            if !has_class(&classes, urls::MESSAGE) {
                continue;
            }
            if message
                .get(urls::PARENT)
                .map(|p| p.to_string())
                .ok()
                .as_deref()
                != Some(parent)
            {
                continue;
            }
            let message_about = message.get(urls::ABOUT).ok().map(|a| a.to_string());
            if message_about.as_deref() != about {
                continue;
            }
            let created_at = message
                .get(urls::CREATED_AT)
                .ok()
                .and_then(|v| v.to_int().ok())
                .unwrap_or(0);
            let author = creator_of(&message);
            let text = message
                .get(urls::DESCRIPTION)
                .map(|v| v.to_string())
                .unwrap_or_default();
            let mut entry = Entry::new(author, text, created_at);
            if has_class(&classes, urls::FOLLOW_EVENT) {
                entry.kinds = Some(urls::FOLLOW_EVENT.into());
            }
            // Edited: a later commit than the creation is retained.
            let key_subject = subject.pure_id();
            if let Some(latest) = crate::envelopes::latest_envelope(self, &key_subject) {
                if latest.created_at > entry.created_at + 1000 {
                    entry.edited_at = Some(latest.created_at);
                }
            }
            old.push(Old {
                key: migrated_entry_key(created_at, &key_subject),
                subject: key_subject,
                entry,
                reply_to: message.get(urls::REPLY_TO).ok().map(|r| r.to_string()),
            });
        }
        old.sort_by(|a, b| (a.entry.created_at, &a.subject).cmp(&(b.entry.created_at, &b.subject)));
        Ok(old)
    }

    /// Entry key to page subject for the pages a chat already has.
    async fn existing_entries(
        &self,
        parent: &str,
        about: Option<&str>,
    ) -> AtomicResult<HashMap<String, String>> {
        let candidates: Vec<Subject> = match about {
            Some(about) => {
                find_in_prop_val_sub_index(self, urls::ABOUT, Some(&Value::AtomicUrl(about.into())))
            }
            None => find_in_prop_val_sub_index(
                self,
                urls::PARENT,
                Some(&Value::AtomicUrl(parent.into())),
            ),
        }
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
            if page
                .get(urls::PARENT)
                .map(|p| p.to_string())
                .ok()
                .as_deref()
                != Some(parent)
            {
                continue;
            }
            if page.get(urls::ABOUT).ok().map(|a| a.to_string()).as_deref() != about {
                continue;
            }
            let Ok(doc) = page.build_state_doc() else {
                continue;
            };
            let page_subject = page.get_subject().pure_id();
            for key in doc.entries().into_keys() {
                existing.entry(key).or_insert_with(|| page_subject.clone());
            }
        }
        Ok(existing)
    }

    /// Moves the old messages of one chat into pages and, with `remove_old`,
    /// removes them. (Tests stop before the removal to simulate a crash.)
    pub(super) async fn migrate_group(
        &self,
        parent: &str,
        about: Option<&str>,
        remove_old: bool,
        create_in: Option<&HashSet<String>>,
    ) -> AtomicResult<()> {
        let old = self.old_messages(parent, about).await?;
        if old.is_empty() {
            return Ok(());
        }
        // A chat whose parent is gone has nowhere to put a page. Its messages
        // were unreachable anyway; leave them.
        let Ok(parent_resource) = Storelike::get_resource(self, &parent.into()).await else {
            tracing::warn!(
                parent,
                "Chat messages left as they are: their chat is missing"
            );
            return Ok(());
        };
        let drive = parent_resource
            .get(urls::DRIVE_PROP)
            .map(|d| d.to_string())
            .unwrap_or_else(|_| parent.to_string());
        let create = create_in.is_none_or(|drives| drives.contains(&id_body(&drive)));
        let existing = self.existing_entries(parent, about).await?;
        let missing: Vec<&Old> = old
            .iter()
            .filter(|m| create && !existing.contains_key(&m.key))
            .collect();
        // Only a store that writes pages needs the agent that signs them.
        let signer = if missing.is_empty() {
            None
        } else {
            Some(self.page_signer()?)
        };

        // Where each message ends up: a page that has its entry, or a page
        // this run will write. The page subject follows from the certificate,
        // so replies inside one page can point at it before it is written.
        let mut location: HashMap<String, String> = HashMap::new();
        for message in &old {
            if let Some(page) = existing.get(&message.key) {
                location.insert(message.subject.clone(), format!("{page}#{}", message.key));
            }
        }
        struct Planned<'a> {
            page: PlannedPage,
            messages: Vec<&'a Old>,
        }
        let mut planned: Vec<Planned> = Vec::new();
        for chunk in missing.chunks(PAGE_SIZE) {
            let Some(signer) = &signer else {
                break;
            };
            // Pages sort by creation time: the first message's.
            let created_at = chunk[0].entry.created_at.max(1);
            let page = signer.plan_page(created_at, parent, &drive)?;
            for message in chunk {
                location.insert(
                    message.subject.clone(),
                    format!(
                        "{}#{}",
                        Subject::from(page.subject.as_str()).pure_id(),
                        message.key
                    ),
                );
            }
            planned.push(Planned {
                page,
                messages: chunk.to_vec(),
            });
        }

        for page in &planned {
            let signer = signer
                .as_ref()
                .expect("pages are only planned with a signer");
            let mut entries: Vec<(String, Entry)> = Vec::new();
            for message in &page.messages {
                let mut entry = message.entry.clone();
                if entry.author.is_empty() {
                    entry.author = signer.agent.subject.to_string();
                }
                entry.reply_to = message.reply_to.as_ref().map(|r| {
                    location
                        .get(&Subject::from(r.as_str()).pure_id())
                        .cloned()
                        .unwrap_or_else(|| r.clone())
                });
                entries.push((message.key.clone(), entry));
            }
            self.write_log_page(signer, &page.page, parent, about, &entries)
                .await?;
        }

        if !remove_old {
            return Ok(());
        }
        // Every entry of this group is in a page now. Remove the old ones.
        // Without `create`, only those that have their entry.
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

    /// The signer for migrated pages (made on first use, see
    /// [`Self::chat_migration_agent`]).
    pub(super) fn page_signer(&self) -> AtomicResult<PageSigner> {
        let agent = self.chat_migration_agent()?;
        let public_key: [u8; 32] = crate::agents::decode_base64(&agent.public_key)?
            .try_into()
            .map_err(|_| "Agent public key must be 32 bytes")?;
        let private_key = agent.private_key.clone().ok_or("No private key")?;
        Ok(PageSigner {
            agent,
            public_key,
            private_key,
        })
    }

    /// Writes one planned page with `entries` in it: signed by `signer`, applied
    /// with rights checks off.
    pub(super) async fn write_log_page(
        &self,
        signer: &PageSigner,
        page: &PlannedPage,
        parent: &str,
        about: Option<&str>,
        entries: &[(String, Entry)],
    ) -> AtomicResult<()> {
        let opts = CommitOpts {
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };
        let doc = AtomicLoroDoc::new();
        let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
        let parent_value = Value::AtomicUrl(parent.into());
        doc.set_property(urls::IS_A, &is_a)?;
        doc.set_property(urls::PARENT, &parent_value)?;
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(urls::PARENT.into(), parent_value);
        if let Some(about) = about {
            let about = Value::AtomicUrl(about.into());
            doc.set_property(urls::ABOUT, &about)?;
            builder.set(urls::ABOUT.into(), about);
        }
        for (key, entry) in entries {
            doc.put_entry(key, entry)?;
        }
        builder.set_loro_update(doc.export_snapshot());
        let commit =
            Commit::create_did_with_cert(builder, &signer.agent, self, Some(page.cert.clone()))
                .await?;
        debug_assert_eq!(
            Subject::from(commit.subject.as_str()).pure_id(),
            Subject::from(page.subject.as_str()).pure_id()
        );
        self.apply_commit(commit, &opts).await?;
        Ok(())
    }

    /// Removes an old message and everything stored for it.
    pub(super) async fn remove_old_message(&self, subject: &str) -> AtomicResult<()> {
        let message = Subject::from(subject);
        let body = |s: &str| {
            crate::identifiers::identifier_body(s)
                .unwrap_or(s)
                .to_string()
        };
        // The genesis commit is kept as a row of its own. Find it before the
        // message goes: its `lastCommit` (when never edited), the retained
        // envelopes, and the commit named after a pre-certificate DID. A row of
        // an edited message that none of these lead to stays (about 1 KB).
        let mut commits: Vec<String> = Vec::new();
        if let Ok(message) = self.get_resource_shallow(&message) {
            if let Ok(last) = message.get(urls::LAST_COMMIT) {
                commits.push(last.to_string());
            }
        }
        for envelope in crate::envelopes::envelopes(self, subject) {
            commits.push(crate::identifiers::commit_subject(&envelope.signature));
        }
        commits.push(crate::identifiers::commit_subject(&body(subject)));
        commits.sort();
        commits.dedup();

        self.remove_resource(&message).await?;
        crate::envelopes::clear_envelopes(self, subject);
        for commit_id in commits {
            let canonical = crate::identifiers::canonicalize_scheme(&commit_id);
            let Ok(row) = self.get_propvals(&canonical) else {
                continue;
            };
            let names_message = row
                .get(urls::SUBJECT)
                .is_some_and(|s| body(&s.to_string()) == body(subject));
            if !names_message {
                continue;
            }
            // Not a resource anyone destroyed: no tombstone for it.
            if self
                .remove_resource(&Subject::from(canonical.as_str()))
                .await
                .is_ok()
            {
                crate::sync::tombstones::clear_tombstone(self, &canonical);
            }
            crate::envelopes::clear_envelopes(self, &canonical);
        }
        Ok(())
    }
}
