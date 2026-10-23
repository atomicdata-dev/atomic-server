//! What a third-party app needs around a store, per handle: devices (peers),
//! drives, the signed-in agent and sharing. The same logic the atomic.place
//! app runs on the default store (`simple/*`), but on the [`AtomicStore`] it is
//! called on, so a node from `AtomicStore::open` can use it.
//!
//! Peers are the exception to "per handle": Iroh is one endpoint per process.
//! The first handle that calls [`AtomicStore::start_peer`] is the store the
//! peer serves; every other handle is refused (see `simple::peers`).

use super::error::AtomicError;
use super::resources::AtomicStore;
use super::simple::{peers::start_peer_for, sync::dial_all};
use atomic_lib::{urls, Storelike};
use flutter_rust_bridge::frb;

/// A device this store has paired with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPeerInfo {
    /// The Iroh node id (64 hex characters).
    pub node_id: String,
    /// The name the person gave it, or the device announced; may be empty.
    pub name: String,
    /// Unix milliseconds of the last successful sync, if there was one.
    pub last_synced: Option<i64>,
    /// Resources the last sync sent to / received from it.
    pub last_sent: Option<u32>,
    pub last_received: Option<u32>,
}

/// A device connected right now that is not paired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePeerInfo {
    pub node_id: String,
    /// What it announced, empty when nothing.
    pub name: String,
}

/// What one sync with one device did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSyncOutcome {
    /// Resources received.
    pub imported: u32,
    /// Resources sent.
    pub pushed: u32,
    /// Both sides already had everything.
    pub in_sync: bool,
    /// The name the device announced.
    pub peer_name: Option<String>,
}

/// What syncing with all known and connected devices did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeersSyncOutcome {
    /// Resources received, over all devices.
    pub imported: u32,
    /// Devices that answered.
    pub answered: u32,
    /// One line per device that did not: `<short id>: <why>`.
    pub failures: Vec<String>,
}

/// A drive of the signed-in agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveSummary {
    pub subject: String,
    pub name: String,
    /// The drive's own icon, when it has one.
    pub emoji: Option<String>,
    /// A server refused this agent the drive.
    pub unreadable: bool,
    /// The drive this handle works in.
    pub active: bool,
}

/// The profile of the signed-in agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInfo {
    pub subject: String,
    pub name: String,
    pub description: String,
    pub emoji: Option<String>,
    pub image_url: Option<String>,
}

fn other(e: impl ToString) -> AtomicError {
    AtomicError {
        kind: super::error::ErrorKind::Other,
        message: e.to_string(),
    }
}

impl AtomicStore {
    // ── Peers ──

    /// Start the Iroh peer (once per process) and return this device's node
    /// id. The peer serves this handle's store when it is the first to start
    /// one; later handles on other stores get an `Other` error. Search for the
    /// account's other devices starts with it.
    pub async fn start_peer(&self) -> Result<String, AtomicError> {
        start_peer_for(self.db.clone()).await.map_err(AtomicError::network)
    }

    /// The paired devices.
    #[frb(sync)]
    pub fn known_peers(&self) -> Vec<KnownPeerInfo> {
        atomic_lib::sync::peer::get_known_peers(&self.db)
            .into_iter()
            .map(|p| KnownPeerInfo {
                node_id: p.node_id,
                name: p.name,
                last_synced: p.last_synced,
                last_sent: p.last_sent,
                last_received: p.last_received,
            })
            .collect()
    }

    /// Remember a paired device. A non-empty `name` renames a known one.
    #[frb(sync)]
    pub fn add_known_peer(&self, node_id: String, name: String) {
        atomic_lib::sync::peer::add_known_peer(&self.db, &node_id, &name);
    }

    /// Forget a paired device.
    #[frb(sync)]
    pub fn remove_known_peer(&self, node_id: String) {
        atomic_lib::sync::peer::remove_known_peer(&self.db, &node_id);
    }

    /// Devices connected right now that are not paired.
    #[frb(sync)]
    pub fn live_unpaired_peers(&self) -> Vec<LivePeerInfo> {
        atomic_lib::sync::peer::live_unsaved_peers(&self.db)
            .into_iter()
            .map(|(node_id, name)| LivePeerInfo {
                node_id,
                name: name.unwrap_or_default(),
            })
            .collect()
    }

    /// The name this device shows other devices.
    #[frb(sync)]
    pub fn device_name(&self) -> String {
        atomic_lib::sync::peer::get_device_name(&self.db)
    }

    /// Change the name this device shows other devices.
    #[frb(sync)]
    pub fn set_device_name(&self, name: String) {
        atomic_lib::sync::peer::set_device_name(&self.db, &name);
    }

    /// Sync this handle's drive with one device, in both directions.
    pub async fn sync_with_peer(&self, node_id: String) -> Result<PeerSyncOutcome, AtomicError> {
        let drive = self.drive().ok_or_else(|| AtomicError::invalid("No drive to sync"))?;
        if atomic_lib::sync::peer::get_node_id().is_none() {
            return Err(AtomicError::invalid("Peer not started. Call start_peer first."));
        }
        let outcome =
            atomic_lib::sync::peer::sync_drive_with_peer_outcome(&node_id, &drive, &self.db)
                .await
                .map_err(|e| AtomicError::network(e.to_string()))?;
        Ok(PeerSyncOutcome {
            imported: outcome.count as u32,
            pushed: outcome.pushed as u32,
            in_sync: outcome.in_sync,
            peer_name: outcome.peer_name,
        })
    }

    /// Sync this handle's drive with every paired and every connected device,
    /// at once, each bounded in time. Starts the peer when needed.
    pub async fn sync_with_peers(&self) -> Result<PeersSyncOutcome, AtomicError> {
        let drive = self.drive().ok_or_else(|| AtomicError::invalid("No drive to sync"))?;
        self.start_peer().await?;
        atomic_lib::sync::dial_gate::reset_unreachable_peers();
        let mut ids: Vec<String> = atomic_lib::sync::peer::live_peer_ids();
        for peer in atomic_lib::sync::peer::get_known_peers(&self.db) {
            if !peer.node_id.is_empty() && !ids.contains(&peer.node_id) {
                ids.push(peer.node_id);
            }
        }
        let store = self.db.as_ref();
        let drive_ref = drive.as_str();
        let results = dial_all(
            &ids,
            super::simple::PEER_SYNC_ATTEMPT_TIMEOUT,
            |node_id| async move {
                atomic_lib::sync::peer::sync_drive_with_peer_if_needed(&node_id, drive_ref, store)
                    .await
                    .map_err(|e| e.to_string())
            },
        )
        .await;
        let mut outcome = PeersSyncOutcome {
            imported: 0,
            answered: 0,
            failures: vec![],
        };
        for (node_id, result) in results {
            match result {
                Ok(count) => {
                    outcome.imported += count as u32;
                    outcome.answered += 1;
                }
                Err(e) => outcome
                    .failures
                    .push(format!("{}: {e}", super::simple::short_id(&node_id))),
            }
        }
        Ok(outcome)
    }

    // ── Drives ──

    /// The agent's drives in the order a drive list shows them: the one in
    /// use, the most recently used, the rest by name.
    pub async fn list_drives_info(&self) -> Result<Vec<DriveSummary>, AtomicError> {
        let drives = self.db.list_drives().await.map_err(other)?;
        let drives = atomic_lib::host::lists::order_drives_by_use(
            &self.db,
            &self.recents,
            drives,
            |d| (d.subject.as_str(), d.name.as_str()),
        );
        let current = self.drive();
        let mut rows = Vec::with_capacity(drives.len());
        for d in drives {
            let mut emoji = None;
            if let Some(resource) =
                atomic_lib::host::rows::row_resource(&self.db, &d.subject.as_str().into()).await
            {
                let row = atomic_lib::host::rows::with_icon(
                    &self.db,
                    serde_json::json!({}),
                    &resource,
                );
                emoji = row["emoji"].as_str().map(str::to_string);
            }
            rows.push(DriveSummary {
                unreadable: self.sync.is_drive_denied(&self.db, &d.subject),
                active: current.as_deref() == Some(d.subject.as_str()),
                subject: d.subject,
                name: d.name,
                emoji,
            });
        }
        Ok(rows)
    }

    /// Work in `drive` from now on, and remember it: the next
    /// [`AtomicStore::open`] of this file starts there.
    pub fn switch_drive(&self, drive: String) -> Result<(), AtomicError> {
        self.db.set_active_drive(&drive).map_err(other)?;
        self.set_drive(drive);
        Ok(())
    }

    // ── Identity ──

    /// Stop signing: the agent is forgotten by this handle (the data stays in
    /// the store; keep the secret to sign in again). Closes the server session.
    pub async fn sign_out(&self) {
        self.sync.close().await;
        self.db.clear_default_agent();
    }

    /// The profile of the signing agent: what the store holds, else what the
    /// connected server has.
    pub async fn profile(&self) -> Result<ProfileInfo, AtomicError> {
        let json = atomic_lib::host::own_profile::own_profile(&self.db, &self.profiles)
            .await
            .map_err(other)?;
        let text = |key: &str| json[key].as_str().map(str::to_string);
        Ok(ProfileInfo {
            subject: text("subject").unwrap_or_default(),
            name: text("name").unwrap_or_default(),
            description: text("description").unwrap_or_default(),
            emoji: text("emoji"),
            image_url: text("imageUrl"),
        })
    }

    /// Save the signing agent's name and description (empty removes the
    /// description) as a signed commit, synced like any edit.
    pub async fn set_profile(&self, name: String, description: String) -> Result<(), AtomicError> {
        atomic_lib::host::own_profile::set_own_profile(
            &self.node(),
            self.pusher().as_ref(),
            &name,
            &description,
            None,
        )
        .await
        .map_err(other)
    }

    // ── Sharing ──

    /// A signed invite for `target` (a drive or any resource): whoever opens
    /// the link `<server>/app/invite?token=<token>` and accepts gets read, or
    /// with `write` read and write, access. Stateless, like `generateInviteToken`
    /// of `@tomic/lib` (nothing is stored here); the server that hosts `target`
    /// checks the signature and that this agent may share it.
    ///
    /// `expires_at` is Unix milliseconds (default: 30 days from now);
    /// `max_usages` limits how many agents may accept (default: unlimited).
    #[frb(sync)]
    pub fn create_invite_token(
        &self,
        target: String,
        write: bool,
        expires_at: Option<i64>,
        max_usages: Option<i64>,
    ) -> Result<String, AtomicError> {
        use serde_json::Value;
        if matches!(max_usages, Some(n) if n < 1) {
            return Err(AtomicError::invalid(
                "The usage limit of an invite must be a whole number of at least 1.",
            ));
        }
        let agent = self.db.get_default_agent().map_err(other)?;
        let expires = expires_at
            .unwrap_or_else(|| atomic_lib::utils::now() + 30 * 24 * 60 * 60 * 1000);
        // Sorted keys, no whitespace: the bytes `@tomic/lib` and the server sign
        // and verify.
        let mut signable = std::collections::BTreeMap::<String, Value>::new();
        signable.insert(urls::TARGET.into(), target.into());
        signable.insert(urls::WRITE_BOOL.into(), write.into());
        signable.insert(urls::EXPIRES_AT.into(), expires.into());
        signable.insert(urls::SIGNER.into(), agent.subject.to_string().into());
        if let Some(max) = max_usages {
            signable.insert(urls::USAGES_LEFT.into(), max.into());
        }
        let message = serde_json::to_string(&signable).map_err(other)?;
        let private_key = agent
            .private_key
            .as_deref()
            .ok_or_else(|| AtomicError::invalid("This agent cannot sign"))?;
        let signature =
            atomic_lib::commit::sign_message(&message, private_key, &agent.public_key)
                .map_err(other)?;
        signable.insert(urls::SIGNATURE.into(), signature.into());
        let json = serde_json::to_vec(&signable).map_err(other)?;
        Ok(standard_base64(&json))
    }
}

/// `btoa`: standard alphabet, padded (the server decodes with this).
fn standard_base64(bytes: &[u8]) -> String {
    let mut text: String = atomic_lib::agents::encode_base64(bytes)
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while text.len() % 4 != 0 {
        text.push('=');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::simple::peers::peer_serves;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-bridge-node-{name}-{}-{}",
            std::process::id(),
            crate::api::simple::state::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn open_with_agent(name: &str) -> (AtomicStore, std::path::PathBuf) {
        let dir = temp_dir(name);
        let store = AtomicStore::open(dir.to_string_lossy().into_owned(), None, None)
            .await
            .unwrap();
        store.setup(name.into()).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn known_peers_are_per_store_and_can_be_renamed_and_removed() {
        let (a, dir_a) = open_with_agent("alice").await;
        let (b, dir_b) = open_with_agent("bob").await;
        let id = "ab".repeat(32);
        a.add_known_peer(id.clone(), "Laptop".into());
        assert_eq!(a.known_peers().len(), 1);
        assert_eq!(a.known_peers()[0].name, "Laptop");
        assert_eq!(a.known_peers()[0].last_synced, None);
        assert!(b.known_peers().is_empty(), "another store has its own list");
        a.add_known_peer(id.clone(), "Desk".into());
        assert_eq!(a.known_peers().len(), 1);
        assert_eq!(a.known_peers()[0].name, "Desk");
        a.add_known_peer(id.clone(), String::new());
        assert_eq!(a.known_peers()[0].name, "Desk", "an empty name keeps the old one");
        a.remove_known_peer(id);
        assert!(a.known_peers().is_empty());
        a.set_device_name("Kitchen tablet".into());
        assert_eq!(a.device_name(), "Kitchen tablet");
        std::fs::remove_dir_all(dir_a).ok();
        std::fs::remove_dir_all(dir_b).ok();
    }

    #[test]
    fn the_peer_serves_the_first_store_only() {
        assert!(peer_serves(None, 1).is_ok());
        assert!(peer_serves(Some(1), 1).is_ok());
        assert!(peer_serves(Some(1), 2).is_err());
    }

    #[tokio::test]
    async fn drives_list_with_names_and_switching_is_remembered() {
        let (store, dir) = open_with_agent("drives").await;
        let first = store.drive().unwrap();
        let second = store.new_drive("Second".into()).await.unwrap();
        assert_eq!(store.drive().as_deref(), Some(second.as_str()));

        let drives = store.list_drives_info().await.unwrap();
        let find = |s: &str| drives.iter().find(|d| d.subject == s).unwrap();
        assert_eq!(find(&second).name, "Second");
        assert!(find(&second).active);
        assert!(!find(&first).active);

        store.switch_drive(first.clone()).unwrap();
        assert_eq!(store.drive().as_deref(), Some(first.as_str()));
        let drives = store.list_drives_info().await.unwrap();
        assert!(drives.iter().find(|d| d.subject == first).unwrap().active);
        assert!(store.db.get_active_drive() == Some(first));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn the_profile_is_saved_and_signing_out_forgets_the_agent() {
        let (store, dir) = open_with_agent("profile").await;
        store
            .set_profile("Pelican".into(), "Likes fish".into())
            .await
            .unwrap();
        let profile = store.profile().await.unwrap();
        assert_eq!(profile.name, "Pelican");
        assert_eq!(profile.description, "Likes fish");
        assert_eq!(Some(profile.subject), store.agent_subject());
        assert!(store.set_profile(" ".into(), String::new()).await.is_err());

        store.sign_out().await;
        assert_eq!(store.agent_subject(), None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn an_invite_token_is_what_the_server_verifies() {
        let (store, dir) = open_with_agent("inviter").await;
        let drive = store.drive().unwrap();
        let token = store
            .create_invite_token(drive.clone(), true, Some(4_102_444_800_000), Some(3))
            .unwrap();
        let bytes = base64_decode_standard(&token);
        let mut json: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json[urls::TARGET], drive.as_str());
        assert_eq!(json[urls::WRITE_BOOL], true);
        assert_eq!(json[urls::USAGES_LEFT], 3);
        let agent = store.db.get_default_agent().unwrap();
        assert_eq!(json[urls::SIGNER], agent.subject.to_string().as_str());

        // The signature covers the other fields, sorted, without whitespace.
        let signature = json.remove(urls::SIGNATURE).unwrap();
        let sorted: std::collections::BTreeMap<_, _> = json.into_iter().collect();
        let message = serde_json::to_string(&sorted).unwrap();
        let expected =
            atomic_lib::commit::sign_message(&message, agent.private_key.as_ref().unwrap(), &agent.public_key)
                .unwrap();
        assert_eq!(signature, expected.as_str());

        assert!(store
            .create_invite_token(drive.clone(), false, None, Some(0))
            .is_err());
        // Default expiry is in the future, and unlimited tokens carry no limit.
        let open = store.create_invite_token(drive, false, None, None).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&base64_decode_standard(&open)).unwrap();
        assert!(json[urls::EXPIRES_AT].as_i64().unwrap() > atomic_lib::utils::now());
        assert!(json.get(urls::USAGES_LEFT).is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    fn base64_decode_standard(text: &str) -> Vec<u8> {
        assert!(text.len() % 4 == 0, "padded like btoa");
        assert!(!text.contains('-') && !text.contains('_'));
        atomic_lib::agents::decode_base64(text).unwrap()
    }

    #[tokio::test]
    async fn rights_set_on_a_resource_are_what_the_store_checks() {
        // Sharing a resource is a normal write of its `read`/`write` lists
        // (what `useShareRights` does in the web app); the lib then answers
        // `check_read` / `check_write` from them.
        let (owner, dir) = open_with_agent("owner").await;
        let guest = atomic_lib::agents::Agent::new(Some("guest")).unwrap();
        let drive = owner.drive().unwrap();
        let drive_resource = owner.db.get_resource(&drive.as_str().into()).await.unwrap();
        let guest_agent = atomic_lib::agents::ForAgent::AgentSubject(guest.subject.clone());
        assert!(atomic_lib::hierarchy::check_read(owner.db.as_ref(), &drive_resource, &guest_agent)
            .await
            .is_err());

        let mut builder = atomic_lib::commit::CommitBuilder::new(drive.as_str().into());
        builder.set(
            urls::READ.into(),
            atomic_lib::Value::ResourceArray(vec![
                owner.agent_subject().unwrap().into(),
                guest.subject.to_string().into(),
            ]),
        );
        let agent = owner.db.get_default_agent().unwrap();
        let commit = builder.sign(&agent, owner.db.as_ref(), &drive_resource).await.unwrap();
        owner
            .node()
            .apply_local_commit(commit, &atomic_lib::host::own_commit_opts())
            .await
            .unwrap();
        let drive_resource = owner.db.get_resource(&drive.as_str().into()).await.unwrap();
        assert!(atomic_lib::hierarchy::check_read(owner.db.as_ref(), &drive_resource, &guest_agent)
            .await
            .is_ok());
        assert!(atomic_lib::hierarchy::check_write(owner.db.as_ref(), &drive_resource, &guest_agent)
            .await
            .is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
