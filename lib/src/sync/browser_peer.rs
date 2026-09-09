//! Drive-scoped peer ingress for the browser's local node. Transport authentication
//! is mandatory; cache ingest must never be used for untrusted peer frames.
use super::{engine, protocol};
use crate::{
    agents::ForAgent, db::trees::Tree, errors::AtomicResult, loro::AtomicLoroDoc, Db, Resource,
    Storelike, Subject,
};

pub struct BrowserPeerSession {
    drive: String,
    expected_peer: Option<String>,
    proof_subject: String,
    agent: ForAgent,
    closed: bool,
    pending_blobs: std::collections::HashSet<[u8; 32]>,
}

#[derive(Default, serde::Serialize)]
pub struct BrowserPeerOutput {
    pub frames: Vec<Vec<u8>>,
    pub changed: Vec<String>,
    pub ephemeral: Option<Vec<u8>>,
}

impl BrowserPeerSession {
    pub fn new(
        drive: String,
        expected_peer: Option<String>,
        challenge: String,
    ) -> AtomicResult<Self> {
        if !drive.starts_with("did:ad:") || drive.contains(['#', '?']) || challenge.len() < 32 {
            return Err(
                "Peer sessions require a canonical drive DID and a fresh channel-bound challenge"
                    .into(),
            );
        }
        Ok(Self {
            proof_subject: format!("{drive}#{challenge}"),
            drive,
            expected_peer,
            agent: ForAgent::Public,
            closed: false,
            pending_blobs: Default::default(),
        })
    }

    fn in_drive(&self, resource: &Resource) -> bool {
        resource.get_subject().to_string() == self.drive
            || resource
                .get(crate::urls::DRIVE_PROP)
                .is_ok_and(|value| value.to_string() == self.drive)
    }

    async fn candidate(&self, db: &Db, subject: &str, bytes: &[u8]) -> AtomicResult<Resource> {
        if Subject::from(subject).pure_id() != subject {
            return Err("Noncanonical peer subject".into());
        }
        if let Ok(existing) = db.get_resource(&subject.into()).await {
            if !self.in_drive(&existing) {
                return Err("Peer frame targets another drive".into());
            }
        }
        let doc = match db.kv.get(Tree::LoroSnapshots, subject.as_bytes())? {
            Some(snapshot) => AtomicLoroDoc::from_snapshot(&snapshot)?,
            None => AtomicLoroDoc::new(),
        };
        doc.import_update(bytes)?;
        let mut resource = Resource::new(subject.into());
        resource.apply_state_doc(doc)?;
        if !self.in_drive(&resource) {
            return Err("Peer frame moves data outside its drive".into());
        }
        Ok(resource)
    }

    pub async fn can_send(&self, db: &Db, subject: &str) -> bool {
        if self.closed || matches!(self.agent, ForAgent::Public) {
            return false;
        }
        let Ok(resource) = db.get_resource(&subject.into()).await else {
            return false;
        };
        self.in_drive(&resource)
            && crate::hierarchy::check_read(db, &resource, &self.agent)
                .await
                .is_ok()
    }

    pub async fn handle(&mut self, db: &Db, frame: &[u8]) -> AtomicResult<BrowserPeerOutput> {
        if self.closed {
            return Err("Peer session closed".into());
        }
        let result = self.handle_inner(db, frame).await;
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    async fn handle_inner(&mut self, db: &Db, frame: &[u8]) -> AtomicResult<BrowserPeerOutput> {
        let (&tag, payload) = frame.split_first().ok_or("Empty peer frame")?;
        let cap = if matches!(self.agent, ForAgent::Public) {
            8192
        } else {
            16 * 1024 * 1024
        };
        if frame.len() > cap {
            return Err("Peer frame exceeds session budget".into());
        }
        let mut out = BrowserPeerOutput::default();
        if tag == protocol::tag::AUTH {
            if !matches!(self.agent, ForAgent::Public) {
                return Err("Peer already authenticated".into());
            }
            let auth: crate::authentication::AuthValues = serde_json::from_slice(payload)?;
            if auth.requested_subject != self.proof_subject {
                return Err("Wrong drive or channel challenge".into());
            }
            if self
                .expected_peer
                .as_ref()
                .is_some_and(|expected| expected != &auth.agent_subject)
            {
                return Err("Unexpected peer identity".into());
            }
            self.agent =
                crate::authentication::get_agent_from_auth_values_and_check(Some(auth), db).await?;
            if let Ok(drive) = db.get_resource(&self.drive.as_str().into()).await {
                crate::hierarchy::check_read(db, &drive, &self.agent).await?;
            } else if self.expected_peer.is_none() {
                return Err("An unknown drive requires an explicitly selected peer".into());
            }
            out.frames.push(protocol::encode_auth_ok());
            return Ok(out);
        }
        if matches!(self.agent, ForAgent::Public) {
            return Err("Peer AUTH required".into());
        }
        match tag {
            protocol::tag::SYNC => {
                let sync = protocol::decode_sync(payload).ok_or("Invalid SYNC")?;
                if sync.drive != self.drive {
                    return Err("Wrong sync drive".into());
                }
                // Unknown local drive has nothing to serve yet. The selected
                // peer's independent SYNC response will bootstrap it.
                if db.get_resource(&self.drive.as_str().into()).await.is_ok() {
                    out.frames = engine::handle_frame(frame, db, &mut self.agent).await;
                }
            }
            protocol::tag::SYNC_PUSH => {
                let push = protocol::decode_sync_push(payload).ok_or("Invalid SYNC_PUSH")?;
                if push.drive != self.drive {
                    return Err("Wrong push drive".into());
                }
                // Preflight the entire batch before the shared importer writes.
                for entry in &push.entries {
                    let candidate = self
                        .candidate(db, &entry.subject, &entry.loro_bytes)
                        .await?;
                    if entry.subject == self.drive
                        && db.get_resource(&self.drive.as_str().into()).await.is_err()
                    {
                        crate::hierarchy::check_write(db, &candidate, &self.agent).await?;
                    }
                }
                let (_, requests) = engine::import_sync_push(&push, db, &self.agent, false)
                    .await
                    .map_err(|e| e.to_string())?;
                for request in requests {
                    if let Some(hash) = protocol::decode_blob_request(&request[1..]) {
                        self.pending_blobs.insert(hash);
                        out.frames.push(request);
                    }
                }
                out.changed = push
                    .entries
                    .iter()
                    .map(|entry| entry.subject.clone())
                    .collect();
                out.frames.push(protocol::encode_sync_ok(&self.drive));
            }
            protocol::tag::SYNC_DIFF => {
                let diff = protocol::decode_sync_diff(payload).ok_or("Invalid SYNC_DIFF")?;
                if diff.drive != self.drive {
                    return Err("Wrong diff drive".into());
                }
                // Apply signed parents before considering cascaded tombstones.
                for subject in &diff.remove {
                    if let Some(envelope) = diff.remove_commits.get(subject) {
                        self.apply_commit(db, envelope, &mut out).await?;
                    }
                }
                for subject in &diff.remove {
                    if !super::tombstones::is_tombstoned(db, subject) {
                        return Err("Unsigned peer deletion".into());
                    }
                    out.changed.push(subject.clone());
                }
                let mut entries = Vec::new();
                for subject in &diff.pull {
                    let resource = db.get_resource(&subject.as_str().into()).await?;
                    if !self.in_drive(&resource) {
                        return Err("Peer requested another drive".into());
                    }
                    crate::hierarchy::check_read(db, &resource, &self.agent).await?;
                    if let Some(bytes) = db.kv.get(Tree::LoroSnapshots, subject.as_bytes())? {
                        entries.push((subject.clone(), bytes));
                    }
                }
                if !entries.is_empty() {
                    let refs: Vec<_> = entries
                        .iter()
                        .map(|(s, b)| (s.as_str(), b.as_slice()))
                        .collect();
                    out.frames
                        .extend(protocol::encode_sync_push_chunks(&self.drive, &refs));
                }
            }
            protocol::tag::COMMIT => {
                let commit = protocol::decode_commit(payload).ok_or("Invalid COMMIT")?;
                self.apply_commit(db, commit.commit_json, &mut out).await?;
                out.frames.push(protocol::encode_commit_ok(
                    commit.request_id,
                    commit.commit_json,
                ));
            }
            protocol::tag::BLOB_REQUEST => {
                let hash = protocol::decode_blob_request(payload).ok_or("Invalid blob request")?;
                let subjects =
                    engine::collect_drive_subjects(db, &self.drive.as_str().into()).await;
                let mut permitted = false;
                for subject in subjects {
                    let resource = db.get_resource(&subject.as_str().into()).await?;
                    if let Ok(blob) = resource.get(crate::urls::BLOB) {
                        if Subject::from(blob.to_string()).blob_hash_hex().as_deref()
                            == Some(hex::encode(hash).as_str())
                            && crate::hierarchy::check_read(db, &resource, &self.agent)
                                .await
                                .is_ok()
                        {
                            permitted = true;
                            break;
                        }
                    }
                }
                if !permitted {
                    return Err("Blob is not readable in this drive".into());
                }
                out.frames = engine::handle_frame(frame, db, &mut self.agent).await;
            }
            protocol::tag::BLOB_RESPONSE => {
                let response =
                    protocol::decode_blob_response(payload).ok_or("Invalid blob response")?;
                if !self.pending_blobs.remove(&response.hash)
                    || blake3::hash(&response.bytes).as_bytes() != &response.hash
                {
                    return Err("Unsolicited or corrupt blob response".into());
                }
                out.frames = engine::handle_frame(frame, db, &mut self.agent).await;
            }
            protocol::tag::EPHEMERAL => {
                let message = protocol::decode_ephemeral(payload).ok_or("Invalid EPHEMERAL")?;
                if message.agent != self.agent.to_string() {
                    return Err("Spoofed ephemeral identity".into());
                }
                let resource = db.get_resource(&message.drive.as_str().into()).await?;
                if !self.in_drive(&resource) {
                    return Err("Wrong ephemeral drive".into());
                }
                crate::hierarchy::check_read(db, &resource, &self.agent).await?;
                // DOC edits require write access; cursors/presence require read.
                if message.kind == protocol::ephemeral_kind::DOC {
                    crate::hierarchy::check_write(db, &resource, &self.agent).await?;
                }
                out.ephemeral = Some(frame.to_vec());
            }
            protocol::tag::SYNC_OK | protocol::tag::COMMIT_OK => {}
            _ => return Err("Unsupported browser peer frame".into()),
        }
        Ok(out)
    }

    async fn apply_commit(
        &self,
        db: &Db,
        json: &str,
        out: &mut BrowserPeerOutput,
    ) -> AtomicResult<()> {
        let value: serde_json::Value = serde_json::from_str(json)?;
        let subject = value[crate::urls::SUBJECT]
            .as_str()
            .ok_or("Missing commit subject")?;
        if value[crate::urls::DESTROY].as_bool() == Some(true) {
            // A live COMMIT and a concurrent reconcile can carry the same
            // signed tombstone. Its previously validated signature is a
            // receipt; do not try to read the now-deleted resource again.
            if let Some(previous) = super::tombstones::destroy_envelope(db, subject) {
                let previous: serde_json::Value = serde_json::from_str(&previous)?;
                if previous[crate::urls::SIGNATURE].is_string()
                    && previous[crate::urls::SIGNATURE] == value[crate::urls::SIGNATURE]
                {
                    out.changed.push(subject.into());
                    return Ok(());
                }
            }
            let resource = db.get_resource(&subject.into()).await?;
            if !self.in_drive(&resource) {
                return Err("Wrong deletion drive".into());
            }
        } else {
            let bytes = crate::agents::decode_base64(
                value[crate::urls::LORO_UPDATE]
                    .as_str()
                    .ok_or("Missing Loro update")?,
            )?;
            self.candidate(db, subject, &bytes).await?;
        }
        engine::ingest_commit_json(db, json, &engine::CommitIngestOpts::peer()).await?;
        out.changed.push(subject.into());
        Ok(())
    }
}

#[cfg(all(test, feature = "db-redb"))]
mod tests {
    use super::*;
    async fn fixture() -> (Db, crate::agents::Agent, String, BrowserPeerSession) {
        let db = Db::init_temp(&format!(
            "browser-peer-{}-{}",
            {
                static NEXT: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            },
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .await
        .unwrap();
        let (agent, drive) = db.setup("Alice").await.unwrap();
        let session = BrowserPeerSession::new(drive.clone(), None, "a".repeat(64)).unwrap();
        (db, agent, drive, session)
    }
    async fn authenticate(db: &Db, agent: &crate::agents::Agent, session: &mut BrowserPeerSession) {
        let auth = protocol::encode_auth(agent, &session.proof_subject).unwrap();
        let output = session.handle(db, &auth).await.unwrap();
        assert_eq!(output.frames[0][0], protocol::tag::AUTH_OK);
    }
    #[tokio::test]
    async fn refuses_pre_auth_and_closes_session() {
        let (db, agent, _, mut session) = fixture().await;
        assert!(session
            .handle(&db, &[protocol::tag::SYNC_OK])
            .await
            .is_err());
        let auth = protocol::encode_auth(&agent, &session.proof_subject).unwrap();
        assert!(session.handle(&db, &auth).await.is_err());
    }
    #[tokio::test]
    async fn refuses_replayed_channel_proof() {
        let (db, agent, drive, mut session) = fixture().await;
        let wrong = protocol::encode_auth(&agent, &format!("{drive}#{}", "b".repeat(64))).unwrap();
        assert!(session.handle(&db, &wrong).await.is_err());
    }
    #[tokio::test]
    async fn refuses_unexpected_identity() {
        let (db, agent, _, mut session) = fixture().await;
        session.expected_peer = Some("did:ad:agent:someone-else".into());
        let auth = protocol::encode_auth(&agent, &session.proof_subject).unwrap();
        assert!(session.handle(&db, &auth).await.is_err());
    }
    #[tokio::test]
    async fn refuses_cross_drive_snapshot_before_writing() {
        let (db, agent, drive, mut session) = fixture().await;
        authenticate(&db, &agent, &mut session).await;
        let foreign = db.create_drive("Other").await.unwrap();
        let bytes = db
            .kv
            .get(Tree::LoroSnapshots, foreign.as_bytes())
            .unwrap()
            .unwrap();
        let frames =
            protocol::encode_sync_push_chunks(&drive, &[(foreign.as_str(), bytes.as_slice())]);
        assert!(session.handle(&db, &frames[0]).await.is_err());
    }
    #[tokio::test]
    async fn accepts_authenticated_same_drive_snapshot() {
        let (db, agent, drive, mut session) = fixture().await;
        authenticate(&db, &agent, &mut session).await;
        let bytes = db
            .kv
            .get(Tree::LoroSnapshots, drive.as_bytes())
            .unwrap()
            .unwrap();
        let frames =
            protocol::encode_sync_push_chunks(&drive, &[(drive.as_str(), bytes.as_slice())]);
        let result = session.handle(&db, &frames[0]).await.unwrap();
        assert_eq!(result.changed, vec![drive]);
        assert_eq!(result.frames[0][0], protocol::tag::SYNC_OK);
    }
    #[tokio::test]
    async fn reader_cannot_push_snapshots() {
        let (db, owner, drive, mut session) = fixture().await;
        let reader = crate::agents::Agent::new(Some("Reader")).unwrap();
        let mut resource = db.get_resource(&drive.as_str().into()).await.unwrap();
        resource
            .set_unsafe(
                crate::urls::READ.into(),
                crate::Value::ResourceArray(vec![
                    owner.subject.to_string().into(),
                    reader.subject.to_string().into(),
                ]),
            )
            .unwrap();
        db.persist_replicated_resource(&resource).await.unwrap();
        authenticate(&db, &reader, &mut session).await;
        let bytes = db
            .kv
            .get(Tree::LoroSnapshots, drive.as_bytes())
            .unwrap()
            .unwrap();
        let frame =
            protocol::encode_sync_push_chunks(&drive, &[(drive.as_str(), bytes.as_slice())])
                .remove(0);
        assert!(session.handle(&db, &frame).await.is_err());
        assert_eq!(
            db.kv
                .get(Tree::LoroSnapshots, drive.as_bytes())
                .unwrap()
                .unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn forged_commit_is_rejected_without_changing_state() {
        let (db, agent, drive, mut session) = fixture().await;
        authenticate(&db, &agent, &mut session).await;
        let bytes = db
            .kv
            .get(Tree::LoroSnapshots, drive.as_bytes())
            .unwrap()
            .unwrap();
        let json = serde_json::json!({
            crate::urls::SUBJECT: drive,
            crate::urls::SIGNER: agent.subject.to_string(),
            crate::urls::LORO_UPDATE: crate::agents::encode_base64(&bytes),
            crate::urls::SIGNATURE: "invalid-signature",
            crate::urls::CREATED_AT: 1,
        })
        .to_string();
        let frame = protocol::encode_commit(1, &json);
        assert!(session.handle(&db, &frame).await.is_err());
        assert_eq!(
            db.kv
                .get(Tree::LoroSnapshots, drive.as_bytes())
                .unwrap()
                .unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn outgoing_access_is_rechecked_after_revocation() {
        let (db, owner, drive, mut session) = fixture().await;
        let reader = crate::agents::Agent::new(Some("Reader")).unwrap();
        let mut resource = db.get_resource(&drive.as_str().into()).await.unwrap();
        resource
            .set_unsafe(
                crate::urls::READ.into(),
                crate::Value::ResourceArray(vec![reader.subject.to_string().into()]),
            )
            .unwrap();
        db.persist_replicated_resource(&resource).await.unwrap();
        authenticate(&db, &reader, &mut session).await;
        assert!(session.can_send(&db, &drive).await);
        resource
            .set_unsafe(
                crate::urls::READ.into(),
                crate::Value::ResourceArray(vec![owner.subject.to_string().into()]),
            )
            .unwrap();
        db.persist_replicated_resource(&resource).await.unwrap();
        assert!(!session.can_send(&db, &drive).await);
    }
}
