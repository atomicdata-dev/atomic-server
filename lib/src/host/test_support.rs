//! A device for the host tests: its own in-memory store with an agent and a
//! private drive (as the Flutter bridge's `setup` makes them), a node over it
//! and a recents index. Every test gets its own, so tests that rewrite the
//! private drive's lists do not race.

use super::recents::RecentsIndex;
use crate::{
    chat_log::Entry,
    commit::{CommitBuilder, CommitOpts},
    db::DbEvent,
    loro::AtomicLoroDoc,
    runtime::AtomicNode,
    urls, Commit, Db, Storelike, Subject, Value,
};
use serde_json::json;

pub(crate) struct Device {
    pub store: Db,
    pub node: AtomicNode,
    pub recents: RecentsIndex,
    /// The private drive `setup` made and made active.
    pub drive: String,
}

impl Device {
    pub async fn new() -> Self {
        let store = Db::init_redb(None).await.unwrap();
        let (_agent, drive) = store.setup("Test device").await.unwrap();
        Device {
            node: AtomicNode::from_db(store.clone()),
            store,
            recents: RecentsIndex::new(),
            drive,
        }
    }

    /// An AI chat in the device's drive.
    pub async fn new_chat(&self, name: &str) -> String {
        self.store
            .create_resource(super::rows::AI_CHAT, &self.drive, name, None)
            .await
            .unwrap()
    }

    /// A `ChatLog` page under `chat`, signed by the agent like the web app's.
    pub async fn add_page(&self, chat: &str, entries: &[(&str, Entry)]) {
        let agent = self.store.get_default_agent().unwrap();
        let doc = AtomicLoroDoc::new();
        for (key, entry) in entries {
            doc.put_entry(key, entry).unwrap();
        }
        let is_a = Value::ResourceArray(vec![urls::CHAT_LOG.to_string().into()]);
        let parent = Value::AtomicUrl(chat.into());
        doc.set_property(urls::IS_A, &is_a).unwrap();
        doc.set_property(urls::PARENT, &parent).unwrap();
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(urls::PARENT.into(), parent);
        builder.set_loro_update(doc.export_snapshot());
        let commit = Commit::create_did(builder, &agent, &self.store)
            .await
            .unwrap();
        let opts = CommitOpts {
            validate_signature: true,
            validate_rights: true,
            validate_for_agent: Some(agent.subject.to_string()),
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };
        self.store.apply_commit(commit, &opts).await.unwrap();
    }

    /// A chat message by the device's agent.
    pub fn ai_entry(&self, role: &str, text: &str, c: i64) -> Entry {
        let author = self.store.get_default_agent().unwrap().subject.to_string();
        let mut entry = Entry::new(author, "", c);
        entry.extra.insert("role".into(), role.into());
        let parts = json!([{ "type": "text", "text": text }]).to_string();
        entry.extra.insert("parts".into(), parts.as_str().into());
        entry
    }

    /// Feed the store's pending change events to the recents index, as the
    /// listener does in an app.
    pub async fn pump(&self, rx: &mut tokio::sync::broadcast::Receiver<DbEvent>) {
        loop {
            match rx.try_recv() {
                Ok(event) => self.recents.handle_event(&self.store, event).await,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    }

    /// Put `subjects` in a list property of the private drive, as the web app
    /// does.
    pub async fn set_home_list(&self, property: &str, subjects: &[&str]) {
        let home = self.store.ensure_private_drive().await.unwrap();
        let mut drive = self
            .store
            .get_resource(&Subject::from(home.as_str()))
            .await
            .unwrap();
        let list = Value::ResourceArray(subjects.iter().map(|s| (*s).into()).collect());
        drive.set_unsafe(property.into(), list).unwrap();
        self.node.save_locally(&mut drive).await.unwrap();
    }

    /// Give `subject` an icon the way the web app's "Add icon" does.
    pub async fn set_emoji(&self, subject: &str, emoji: &str) {
        let mut r = self.store.get_resource(&subject.into()).await.unwrap();
        r.set_string(urls::EMOJI.into(), emoji, &self.store)
            .await
            .unwrap();
        r.save_locally(&self.store).await.unwrap();
    }

    /// A File in the device's drive with a download URL, as a server-hosted
    /// picture is.
    pub async fn new_picture(&self, download_url: &str) -> String {
        let file = self
            .store
            .create_resource(urls::FILE, &self.drive, "pic.png", None)
            .await
            .unwrap();
        let mut f = self
            .store
            .get_resource(&file.as_str().into())
            .await
            .unwrap();
        f.set_unsafe(
            urls::DOWNLOAD_URL.into(),
            Value::String(download_url.into()),
        )
        .unwrap();
        self.node.save_locally(&mut f).await.unwrap();
        file
    }

    /// Give `subject` a picture the way the web app's icon editor does: its
    /// `icon` names a File.
    pub async fn set_icon(&self, subject: &str, file: &str) {
        let mut r = self.store.get_resource(&subject.into()).await.unwrap();
        r.set_unsafe(
            super::own_profile::ICON.into(),
            Value::AtomicUrl(file.into()),
        )
        .unwrap();
        self.node.save_locally(&mut r).await.unwrap();
    }

    /// A resource as the server's sync delivers it: a Loro state with a
    /// parent, a name, maybe a class and maybe a `drive` of its own.
    pub async fn synced(
        &self,
        subject: &str,
        parent: &str,
        name: &str,
        class: Option<&str>,
        drive: Option<&str>,
    ) -> String {
        let mut authored = crate::Resource::new(subject.to_string());
        authored
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent.into()))
            .unwrap();
        if let Some(drive) = drive {
            authored
                .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
                .unwrap();
        }
        authored
            .set_unsafe(urls::NAME.into(), Value::String(name.into()))
            .unwrap();
        if let Some(class) = class {
            authored
                .set_unsafe(urls::IS_A.into(), Value::ResourceArray(vec![class.into()]))
                .unwrap();
        }
        let state = authored.build_state_doc().unwrap().export_snapshot();
        crate::sync::ws_apply::apply_state_update(&self.store, subject, &state)
            .await
            .unwrap();
        subject.to_string()
    }
}
