//! Describe changes / mutations to data

use crate::{
    agents::{decode_base64, encode_base64},
    datatype::DataType,
    errors::AtomicResult,
    urls,
    values::SubResource,
    Atom, Resource, Storelike, Subject, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use urls::SIGNER;
/// The `resource_new`, `resource_old` and `commit_resource` fields are only created if the Commit is persisted.
/// When the Db is only notifying other of changes (e.g. if a new Message was added to a ChatRoom), these fields are not created.
/// When deleting a resource, the `resource_new` field is None.
#[derive(Clone, Debug)]
pub struct CommitResponse {
    pub commit: Commit,
    pub commit_resource: Resource,
    pub resource_new: Option<Resource>,
    pub resource_old: Option<Resource>,
    pub add_atoms: Vec<Atom>,
    pub remove_atoms: Vec<Atom>,
    /// The property URLs that were changed by this commit's Loro update.
    pub changed_props: HashSet<String>,
    /// Optional transport/source identity for echo suppression.
    pub source_id: Option<String>,
}

impl CommitResponse {
    /// The authorization relevance of this commit — which authority-defining
    /// facts it establishes or mutates. See [`crate::hierarchy::AuthImpact`].
    pub fn auth_impact(&self) -> crate::hierarchy::AuthImpact {
        // A creation is genesis whether or not the client flagged it: Rust
        // `save_locally`, agent first-commits and HTTP-subject creations
        // arrive with `is_genesis: None`, and the commit that brought a
        // resource into being is retained like an explicit genesis.
        let created = self.resource_old.is_none() && self.resource_new.is_some();
        crate::hierarchy::classify_auth_impact(
            &self.changed_props,
            self.commit.is_genesis == Some(true) || created,
            self.commit.destroy.unwrap_or(false),
        )
    }
}

pub struct CommitApplied {
    /// The resource before the Commit was applied
    pub resource_old: Resource,
    /// The modified resources where the commit has been applied to
    pub resource_new: Resource,
    /// The atoms that should be added to the store (for updating indexes)
    pub add_atoms: Vec<Atom>,
    /// The atoms that should be removed from the store (for updating indexes)
    pub remove_atoms: Vec<Atom>,
    /// The property URLs that were changed by this commit's Loro update.
    pub changed_props: HashSet<String>,
    /// True when importing the commit's `loroUpdate` actually advanced the
    /// doc's oplog — i.e. the ops were new. False means every op was already
    /// present (an idempotent replay), so producing no state change is
    /// expected and correct, not a silent LWW loss.
    pub imported_new_ops: bool,
}

#[derive(Clone, Debug)]
/// Describes options for applying a Commit.
/// Skip the checks you don't need to get better performance, or if you want to break the rules a little.
pub struct CommitOpts {
    /// Makes sure all `required` properties are present.
    pub validate_schema: bool,
    /// Checks the public key and the signature of the Commit.
    pub validate_signature: bool,
    /// Checks whether the Commit isn't too old, or has been created in the future.
    pub validate_timestamp: bool,
    /// Checks whether the creator of the Commit has the rights to edit the Resource.
    pub validate_rights: bool,
    /// Detects commits whose Loro update's writes silently lost LWW against
    /// the stored state — i.e. the client's Loro doc wasn't seeded from the
    /// server's current state, so its ops are concurrent with stored ops and
    /// get dropped by Loro's conflict resolution. When this happens, the
    /// commit would "succeed" but the server-visible state wouldn't reflect
    /// the client's intent. With this enabled, we reject such commits so the
    /// client can refetch and retry.
    ///
    /// Turn off for true multi-peer sync (mesh/Iroh) where concurrent writes
    /// are expected and LWW is the correct resolution.
    pub validate_loro_causality: bool,
    /// Updates the indexes in the Store. Is a bit more costly.
    pub update_index: bool,
    /// For who the right checks will be perormed. If empty, the signer of the Commit will be used.
    pub validate_for_agent: Option<String>,
    /// Optional transport/source identity for echo suppression.
    pub source_id: Option<String>,
}

impl CommitOpts {
    pub fn no_validations_no_index() -> Self {
        Self {
            validate_schema: false,
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            validate_loro_causality: false,
            update_index: false,
            validate_for_agent: None,
            source_id: None,
        }
    }
}

/// A Commit is a set of changes to a Resource.
/// Use CommitBuilder if you're programmatically constructing a Delta.
#[derive(Clone, Serialize)]
pub struct Commit {
    /// The subject URL that is to be modified by this Delta
    #[serde(rename = "https://atomicdata.dev/properties/subject")]
    pub subject: Subject,
    /// The date it was created, as a unix timestamp
    #[serde(rename = "https://atomicdata.dev/properties/createdAt")]
    pub created_at: i64,
    /// The URL of the one signing this Commit
    #[serde(rename = "https://atomicdata.dev/properties/signer")]
    pub signer: Subject,
    /// A Loro CRDT binary update for the entire resource document
    #[serde(rename = "https://atomicdata.dev/properties/loroUpdate")]
    pub loro_update: Option<Vec<u8>>,
    /// If set to true, deletes the entire resource
    #[serde(rename = "https://atomicdata.dev/properties/destroy")]
    pub destroy: Option<bool>,
    /// Base64 encoded signature of the JSON serialized Commit
    #[serde(rename = "https://atomicdata.dev/properties/signature")]
    pub signature: Option<String>,
    /// Optional audit pointer at an earlier envelope. Not a causal gate.
    #[serde(rename = "https://atomicdata.dev/properties/previousCommit")]
    pub previous_commit: Option<String>,
    /// Whether this is the first commit for a Resource.
    #[serde(rename = "https://atomicdata.dev/properties/isGenesis")]
    pub is_genesis: Option<bool>,
    /// The URL of the Commit
    pub url: Option<String>,
}

impl std::fmt::Debug for Commit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Commit")
            .field("subject", &self.subject)
            .field("created_at", &self.created_at)
            .field("signer", &self.signer)
            .field(
                "loro_update",
                &self
                    .loro_update
                    .as_ref()
                    .map(|v| format!("<{} bytes>", v.len())),
            )
            .field("destroy", &self.destroy)
            .field("signature", &self.signature)
            .field("previous_commit", &self.previous_commit)
            .field("is_genesis", &self.is_genesis)
            .field("url", &self.url)
            .finish()
    }
}

impl Commit {
    /// Throws an error if the parent is set to itself
    pub fn check_for_circular_parents(&self) -> AtomicResult<()> {
        // Check if the Loro update contains a parent property that matches the subject.
        if let Some(loro_bytes) = &self.loro_update {
            let doc = crate::loro::AtomicLoroDoc::from_snapshot(loro_bytes).or_else(|_| {
                let doc = crate::loro::AtomicLoroDoc::new();
                doc.import_update(loro_bytes)?;
                Ok::<_, crate::errors::AtomicError>(doc)
            })?;
            if let Some(parent) = doc.get_string_property(urls::PARENT) {
                if parent == self.subject {
                    return Err("Circular parent reference".into());
                }
            }
        }

        Ok(())
    }

    /// Creates a new Commit with a `did:ad` Subject.
    /// The ID of the Subject is the signature of the Commit.
    pub async fn create_did(
        commit_builder: CommitBuilder,
        agent: &crate::agents::Agent,
        store: &impl Storelike,
    ) -> AtomicResult<Commit> {
        Self::create_did_with_cert(commit_builder, agent, store, None).await
    }

    /// Like [`Self::create_did`], but uses `cert` when given instead of a
    /// random-nonce certificate. The private drive path passes
    /// [`crate::genesis::GenesisCert::for_private_drive`] so every device
    /// mints the same subject.
    pub async fn create_did_with_cert(
        mut commit_builder: CommitBuilder,
        agent: &crate::agents::Agent,
        store: &impl Storelike,
        cert: Option<crate::genesis::GenesisCert>,
    ) -> AtomicResult<Commit> {
        let now = crate::utils::now();
        // Create a temporary commit with empty signature and subject
        // The subject is needed for serialization, but it will be removed for the signature check (and thus creation)
        let temp_subject = "did:ad:genesis".to_string();
        commit_builder.subject = temp_subject.clone().into();

        // Race-free rights: stamp the resource's `drive` at genesis so a child's
        // rights check can consult the (stable) drive grant directly instead of
        // walking a parent chain that may not be materialized yet under
        // concurrent creation (the parent-before-child 401 race). The drive is
        // the parent's drive, or the parent itself when the parent is a drive
        // root. Top-level resources (no parent) ARE their own drive — skip.
        if !commit_builder.set.contains_key(urls::DRIVE_PROP) {
            if let Some(parent_val) = commit_builder.set.get(urls::PARENT).cloned() {
                let parent_subject = crate::Subject::from(parent_val.to_string());
                if let Ok(parent_res) = store.get_resource(&parent_subject).await {
                    let drive = match parent_res.get(urls::DRIVE_PROP) {
                        Ok(d) => d.to_string(),
                        Err(_) => parent_subject.to_string(),
                    };
                    commit_builder.set.insert(
                        urls::DRIVE_PROP.into(),
                        crate::values::Value::AtomicUrl(drive.into()),
                    );
                }
            }
        }

        // ---- Self-verifying genesis certificate ----
        // The resource's identity (DID) is the agent's Ed25519 signature over a
        // compact binary cert (signer, createdAt, nonce, parent, drive), stored
        // inline as the immutable `genesis` propval. This makes authorship +
        // identity verifiable offline, with no commit fetch. The cert — NOT the
        // commit — is what the DID is derived from. See
        // `planning/genesis-self-verifying.md`.
        let private_key = agent.private_key.clone().ok_or("No private key in agent")?;
        let signer_pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)?
            .try_into()
            .map_err(|_| "Agent public key must be 32 bytes for the genesis certificate")?;
        let cert = match cert {
            Some(cert) => {
                if cert.signer_pubkey != signer_pubkey {
                    return Err(
                        "Genesis certificate signer does not match the creating agent".into(),
                    );
                }
                cert
            }
            None => {
                let mut nonce = [0u8; 16];
                {
                    use rand::RngCore;
                    rand::thread_rng().fill_bytes(&mut nonce);
                }
                let parent = commit_builder
                    .set
                    .get(urls::PARENT)
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let drive = commit_builder
                    .set
                    .get(urls::DRIVE_PROP)
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                crate::genesis::GenesisCert {
                    signer_pubkey,
                    created_at: now,
                    nonce,
                    state_hash: None,
                    parent,
                    drive,
                }
            }
        };
        let cert_b64 = crate::agents::encode_base64(&cert.encode());
        let genesis_signature = cert.sign(&private_key)?;
        let did = crate::genesis::GenesisCert::subject_for_signature(&genesis_signature);

        // Build the loro snapshot WITH the `genesis` propval — whether or not a
        // loro_update was pre-set (e.g. by `save_remote`). The cert rides inline.
        let doc = crate::loro::AtomicLoroDoc::new();
        if let Some(update) = &commit_builder.loro_update {
            doc.import_update(update)?;
        } else {
            for (prop, val) in &commit_builder.set {
                doc.set_property(prop, val)?;
            }
            for prop in &commit_builder.remove {
                doc.remove_property(prop)?;
            }
        }
        doc.set_property(urls::GENESIS, &crate::values::Value::String(cert_b64))?;
        // The genesis change carries the creator's subject as its message,
        // exactly as the browser writes it: `createdBy` reads it, and the
        // signed genesis envelope is matched back to this change by it
        // (`crate::envelopes::attribute_history`).
        doc.commit_with_message(agent.subject.as_str());
        let loro_update = Some(doc.export_snapshot());

        let mut commit = Commit {
            subject: temp_subject.into(),
            signer: agent.subject.clone(),
            loro_update,
            destroy: Some(commit_builder.destroy),
            created_at: now,
            previous_commit: None,
            is_genesis: Some(true),
            signature: None,
            url: None,
        };

        // The commit also carries a CONTENT signature (authorship of the initial
        // state) — distinct from the cert signature that mints the DID. Genesis
        // commits serialize without the subject, so deriving the subject from the
        // cert below does not affect this signature.
        let stringified = commit
            .serialize_deterministically_json_ad(store)
            .await
            .map_err(|e| format!("Failed serializing commit: {}", e))?;

        let signature =
            sign_message(&stringified, &private_key, &agent.public_key).map_err(|e| {
                format!(
                    "Failed to sign message for new did:ad commit with agent {}: {}",
                    agent.subject, e
                )
            })?;

        commit.signature = Some(signature);
        commit.subject = did.into();

        Ok(commit)
    }

    /// Check if the Commit's signature matches the signer's public key.
    pub async fn validate_signature(&self, store: &impl Storelike) -> AtomicResult<()> {
        let commit = self;
        let signature = match commit.signature.as_ref() {
            Some(sig) => sig,
            None => return Err("No signature set".into()),
        };
        let signer_subject = store.normalize_subject(&commit.signer);
        // For agent DIDs, the public key IS the DID — extract directly.
        let pubkey_b64 = if commit.signer.is_agent_did() {
            commit
                .signer
                .as_str()
                .strip_prefix("did:ad:agent:")
                .ok_or("Invalid did:ad:agent signer")?
                .to_string()
        } else if let Ok(resource) = store.get_resource(&signer_subject).await {
            resource.get(urls::PUBLIC_KEY)?.to_string()
        } else if let crate::Subject::Internal { url, .. } = &signer_subject {
            // Legacy HTTP agents: extract key from URL path
            let path = url.path();
            if path.starts_with("/agents/") {
                path.strip_prefix("/agents/").unwrap().to_string()
            } else {
                return Err(format!("Signer {} not found in store", commit.signer).into());
            }
        } else {
            return Err(format!(
                "Signer {} not found and cannot extract public key",
                commit.signer
            )
            .into());
        };
        let agent_pubkey = decode_base64(&pubkey_b64)?;
        let stringified_commit = commit.serialize_deterministically_json_ad(store).await?;
        let pubkey_bytes: [u8; 32] = agent_pubkey
            .try_into()
            .map_err(|_| "Ed25519 public key must be 32 bytes")?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let signature_bytes = decode_base64(signature)?;
        let sig_bytes: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| "Ed25519 signature must be 64 bytes")?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(stringified_commit.as_bytes(), &sig)
            .map_err(|_e| {
                format!(
                    "Incorrect signature for Commit. This could be due to an error during signing or serialization of the commit. Compare this to the serialized commit in the server: {}",
                    stringified_commit,
                )
            })?;

        // For a genesis DID resource, identity is verified one of two ways
        // (dual-accept, during the migration to self-verifying certs):
        //
        //  1. SELF-VERIFYING CERTIFICATE (preferred): the subject `did:ad:<sig>`
        //     is the agent's signature over a compact binary `GenesisCert`,
        //     carried inline as the `genesis` propval. Verify the cert and that
        //     its signer is this commit's signer. Server-minted resources take
        //     this path (see planning/genesis-self-verifying.md).
        //
        //  2. LEGACY commit-signature DID: the subject `did:ad:<sig>` is the
        //     agent's signature over the genesis *commit* itself. Browser-minted
        //     resources still take this path until the client mints certs.
        //
        // The discriminator is the explicit `is_genesis: true` flag — NOT
        // `previous_commit.is_none()`, which is also true for destroy and other
        // non-genesis commits. Agent DIDs (did:ad:agent:{pubkey}) are
        // identity-based and exempt.
        if commit.is_genesis == Some(true)
            && commit.subject.is_did()
            && !commit.subject.is_agent_did()
        {
            let subject_val = commit
                .subject
                .as_str()
                .strip_prefix("did:ad:")
                .ok_or("Invalid did:ad subject")?;

            let cert_b64 = commit
                .loro_update
                .as_ref()
                .and_then(|u| crate::Resource::genesis_cert_b64_from_loro_update(u));

            if let Some(cert_b64) = cert_b64 {
                // Path 1: self-verifying genesis certificate.
                let cert_bytes = decode_base64(&cert_b64)?;
                let cert = crate::genesis::GenesisCert::decode(&cert_bytes)?;
                cert.verify(subject_val)?;
                if cert.signer_pubkey != pubkey_bytes {
                    return Err(
                        "Genesis certificate signer does not match the commit signer".into(),
                    );
                }
            } else if subject_val != signature {
                // Path 2: legacy commit-signature DID.
                return Err(format!(
                    "Invalid did:ad subject. Expected 'did:ad:{}' but got '{}'",
                    signature, commit.subject
                )
                .into());
            }
        }
        Ok(())
    }

    /// A second genesis for an existing subject is mergeable when it carries a
    /// self-verifying cert for this subject whose signer is this commit's
    /// signer. That is the personal-drive case: every device mints the same
    /// cert, so the same DID, and Loro merges the two docs.
    fn repeat_genesis_is_mergeable(&self) -> AtomicResult<bool> {
        if !self.subject.is_did() || self.subject.is_agent_did() {
            return Ok(false);
        }
        let subject_val = self
            .subject
            .as_str()
            .strip_prefix("did:ad:")
            .ok_or("Invalid did:ad subject")?;
        let Some(cert_b64) = self
            .loro_update
            .as_ref()
            .and_then(|u| crate::Resource::genesis_cert_b64_from_loro_update(u))
        else {
            return Ok(false);
        };
        let cert_bytes = decode_base64(&cert_b64)?;
        let cert = crate::genesis::GenesisCert::decode(&cert_bytes)?;
        if cert.verify(subject_val).is_err() {
            return Ok(false);
        }
        let signer_key = self
            .signer
            .as_str()
            .strip_prefix("did:ad:agent:")
            .ok_or("Repeat genesis requires a did:ad:agent signer")?;
        let signer_bytes: [u8; 32] = decode_base64(signer_key)?
            .try_into()
            .map_err(|_| "Agent public key must be 32 bytes")?;
        if cert.signer_pubkey != signer_bytes {
            return Ok(false);
        }
        Ok(true)
    }

    /// Performs the checks specified in CommitOpts and constructs a new Resource.
    /// Warning: Does not save the new resource to the Store - doet not delete if it `destroy: true`.
    /// Use [Storelike::apply_commit] to save the resource to the Store.
    pub async fn validate_and_build_response(
        self,
        opts: &CommitOpts,
        store: &impl Storelike,
    ) -> AtomicResult<CommitResponse> {
        let commit = self;
        let subject = commit.subject.clone();

        if subject.is_did() && subject.as_str().starts_with("did:ad:") {
            let pure_id = subject.pure_id();
            let b64_part = if subject.is_agent_did() {
                pure_id.strip_prefix("did:ad:agent:")
            } else if subject.is_commit_did() {
                pure_id.strip_prefix("did:ad:commit:")
            } else {
                pure_id.strip_prefix("did:ad:")
            }
            .ok_or("Invalid DID format")?;

            let decoded = crate::agents::decode_base64(b64_part)
                .map_err(|_| "Invalid DID: not valid base64")?;

            let expected_len = if subject.is_agent_did() { 32 } else { 64 };
            if decoded.len() != expected_len {
                return Err(format!(
                    "Invalid DID: expected {} bytes, got {}. DID subjects cannot contain a path.",
                    expected_len,
                    decoded.len()
                )
                .into());
            }
        }

        let subject_url = match &subject {
            Subject::Internal { url, .. } => url.clone(),
            Subject::External(u) => u.clone(),
            Subject::Did { url, .. } => url.clone(),
        };

        if subject_url.query().is_some() {
            return Err("Subject URL cannot have query parameters".into());
        }

        if opts.validate_signature {
            commit.validate_signature(store).await?;
        }
        if opts.validate_timestamp {
            commit.validate_timestamp()?;
        }

        commit.check_for_circular_parents()?;

        // Create a new resource if it doesn't exist yet.
        // For agent DIDs, get_resource() returns a synthetic "just-in-time" agent
        // even when no data is stored. Detect this by checking for a lastCommit —
        // a real stored resource always has one after its genesis commit.
        let (resource_old, is_new) = match store.get_resource(&commit.subject.clone()).await {
            Ok(rs) => {
                let is_synthetic_agent =
                    commit.subject.is_agent_did() && rs.get(urls::LAST_COMMIT).is_err();
                if is_synthetic_agent {
                    // Treat synthetic fallback agents as non-existent so genesis
                    // commits work and the Loro doc is built from scratch.
                    (
                        Resource::new(store.normalize_subject(&commit.subject.clone()).to_string()),
                        true,
                    )
                } else {
                    (rs, false)
                }
            }
            Err(_) => (
                Resource::new(store.normalize_subject(&commit.subject.clone()).to_string()),
                true,
            ),
        };

        if let Some(explicit_genesis) = commit.is_genesis {
            if explicit_genesis && !is_new {
                // Deterministic subjects (private drive) emit a repeat genesis
                // from every device. Accept when the cert verifies and names
                // this commit's signer; apply_changes merges the Loro update.
                if !commit.repeat_genesis_is_mergeable()? {
                    return Err(format!(
                        "Commit for {} has is_genesis: true, but the resource already exists.",
                        commit.subject
                    )
                    .into());
                }
            }
            if !explicit_genesis && is_new {
                return Err(format!(
                    "Commit for {} has is_genesis: false, but the resource does not exist yet.",
                    commit.subject
                )
                .into());
            }
        }

        // `previous_commit` is optional audit metadata. It is NOT a
        // validation gate. Concurrency is handled by the Loro CRDT:
        // each commit's `loro_update` carries the op's peer-scoped
        // Lamport clock, and concurrent edits merge deterministically.

        // Reject commits that carry no Loro update and aren't a destroy.
        // Loro is the single source of truth for all user data; a commit
        // without it cannot change any searchable state. Previously, such
        // commits (typically legacy `set`/`push` bodies from old client code)
        // appeared to succeed but left the resource un-indexed — the search
        // index read from propvals, which only get materialized when Loro
        // imports fire. A destroy commit is the one exception.
        let is_destroy = commit.destroy.unwrap_or(false);
        if commit.loro_update.is_none() && !is_destroy {
            return Err(format!(
                "Commit for {} has no `loroUpdate` and is not a destroy. Loro \
                 is required for all state-changing commits — legacy `set` / \
                 `push` / `remove` maps are not applied. Please upgrade the \
                 client to send Loro updates.",
                commit.subject
            )
            .into());
        }

        let mut applied = commit
            .apply_changes(resource_old.clone())
            .await
            .map_err(|e| {
                format!(
                    "Error applying changes to Resource {}. {}",
                    commit.subject, e
                )
            })?;

        // NOTE: `createdAt` / `createdBy` are server-managed creation metadata
        // (materialized from the genesis oplog change). We do NOT reject commits
        // that carry them: the materialized values round-trip back to clients in
        // JSON-AD, so a later edit legitimately re-sends them (e.g. saving an
        // agent's name). Rejecting broke those saves. Forge-resistance is the
        // job of the genesis certificate (`planning/genesis-self-verifying.md`),
        // where identity metadata is signed into the DID, not a settable propval.

        // Causality guard: a commit with a non-trivial loroUpdate that
        // produces ZERO net state change.
        //
        // Two cases look identical at the projection level but mean opposite
        // things, so they must be distinguished:
        //
        //  1. Idempotent replay — the commit's ops are already in the doc's
        //     oplog (importing the update did not advance the version
        //     vector). Re-applying it changed nothing because there was
        //     nothing new to apply. This is correct and safe — Loro
        //     deduplicates ops by ID — so ACCEPT. The browser outbox relies
        //     on this when it retransmits a commit the server already has.
        //
        //  2. Silent LWW loss — the commit's ops ARE new (the VV advanced)
        //     but lost last-writer-wins against stored state, contributing
        //     nothing. Happens when the client's Loro doc was not seeded
        //     from the server's state (fresh peer ID, concurrent writes).
        //     REJECT so the silent data loss surfaces.
        //
        // Exemptions:
        // - destroy commits (no Loro merge to evaluate).
        // - tiny/empty loroUpdate (client didn't really try to write).
        // - genesis commits (is_new): no stored state to lose to.
        // - REPEAT genesis: a second genesis for a subject that already exists
        //   is legitimate (`repeat_genesis_is_mergeable`) — every device mints
        //   the same cert for a private drive, so the same DID. Its propvals
        //   are the creation defaults, and losing them to whatever the resource
        //   has since become is the expected outcome, not evidence that the
        //   client failed to seed from server state. Without this, a device
        //   that renamed its home drive rejected its own stashed genesis
        //   forever: the intent says `name = "My drive"`, the stored state says
        //   the chosen name, they do not match, and the outbox retries every
        //   30s for as long as the app is open.
        if opts.validate_loro_causality
            && !is_new
            && commit.is_genesis != Some(true)
            // ...and not a repeat materialization that merely forgot to say so.
            // A second device deriving the same private drive builds its doc
            // from the creation defaults; whether that reaches us flagged
            // `is_genesis` or as an ordinary commit is an accident of which
            // client path drained it. The cert decides, not the flag: it has to
            // verify against this subject AND name this signer, which for a
            // `did:ad:` subject can only be the same author. Observed in the
            // field as a 500 loop on the owner's own home drive, from their
            // second browser.
            && !commit.repeat_genesis_is_mergeable().unwrap_or(false)
            && !commit.destroy.unwrap_or(false)
            && commit.loro_update.as_ref().map(|b| b.len()).unwrap_or(0) > 16
            && applied.add_atoms.is_empty()
            && applied.remove_atoms.is_empty()
        {
            if !applied.imported_new_ops {
                // Case 1: every op was already present — idempotent replay.
                tracing::debug!(
                    subject = %commit.subject,
                    "[causality-guard] accepting idempotent replay (ops already in oplog)"
                );
            } else {
                // The ops were new but produced no atom change. Decode the
                // incoming update in isolation to see what the client
                // INTENDED to write. Works cleanly for snapshots; may be
                // empty for pure deltas.
                let incoming_intent = commit
                    .loro_update
                    .as_ref()
                    .map(|bytes| {
                        let doc = crate::loro::AtomicLoroDoc::new();
                        let _ = doc.import_update(bytes);
                        doc.get_all_properties()
                    })
                    .unwrap_or_default();
                let merged_doc = applied.resource_new.build_state_doc()?;
                let merged_state = merged_doc.get_all_properties();

                // Semantic no-op: the client re-set values that already match
                // stored state (e.g. a UI flow calls `set(x, v)` with the
                // current `v`, then saves). New ops, but no real change —
                // accept rather than reject.
                //
                // `lastCommit` and `createdAt` are SERVER-MANAGED in the
                // client snapshot: the client's `setLastCommitValue` writes
                // its own view of the latest commit (whichever commit it
                // last received via WS). With concurrent peers (e.g. two
                // tabs on the same agent), the server's `lastCommit`
                // races ahead of the client's between Tab A's save landing
                // and Tab B's snapshot export. Comparing those values is
                // guaranteed to mismatch under concurrent writes and
                // produce a spurious reject — the client never *intended*
                // to write that value, it's just a side-effect of how
                // `applyIncoming` stores commit metadata in the Loro doc.
                // Skip both in the all-match check; only user-controlled
                // properties need to round-trip cleanly for the guard to
                // mean what its name claims.
                let server_managed: &[&str] = &[crate::urls::LAST_COMMIT, crate::urls::CREATED_AT];

                // Empty `incoming_intent` means the loroUpdate didn't write
                // any *propvals* — but Loro docs can carry non-propval state
                // (TipTap document body via `loro-prosemirror` containers,
                // canvas stroke trees, etc.) that lives outside the
                // `properties` map this guard reads from. Rejecting on
                // empty intent would block every document/canvas content
                // edit (`documents.spec.ts:25` regression — heading inserts
                // never reach the server). The fact that `imported_new_ops`
                // was true here proves the commit *did* contribute work to
                // the Loro doc; we just can't observe it through the
                // propval projection. Accept and trust Loro CRDT.
                let all_match = if incoming_intent.is_empty() {
                    true
                } else {
                    incoming_intent.iter().all(|(key, incoming_val)| {
                        if server_managed.contains(&key.as_str()) {
                            return true;
                        }
                        merged_state.get(key).is_some_and(|mv| mv == incoming_val)
                    })
                };

                if all_match {
                    tracing::debug!(
                        subject = %commit.subject,
                        keys = ?incoming_intent.keys().collect::<Vec<_>>(),
                        empty_intent = incoming_intent.is_empty(),
                        "[causality-guard] accepting commit (propval intent is empty or matches stored state)"
                    );
                } else {
                    tracing::warn!(
                        subject = %commit.subject,
                        loro_bytes = commit.loro_update.as_ref().map(|b| b.len()).unwrap_or(0),
                        incoming_intent = ?incoming_intent,
                        merged_state = ?merged_state,
                        "[causality-guard] rejecting commit with non-trivial loroUpdate that produced no state changes (silent LWW loss)"
                    );

                    return Err(format!(
                        "Commit's Loro update produced no state changes — its writes were \
                         silently dropped by LWW against stored state. The client's Loro doc \
                         wasn't seeded from the server's current state. Refetch the resource \
                         and retry the commit. subject={} incoming_intent={:?} merged_state_keys={:?}",
                        commit.subject,
                        incoming_intent
                            .iter()
                            .map(|(k, v)| format!("{k} = {v:?}"))
                            .collect::<Vec<_>>(),
                        merged_state.keys().collect::<Vec<_>>(),
                    )
                    .into());
                }
            }
        }

        // F11 (planning/unified-sync.md): this subject is being (re)created —
        // if it was previously destroyed (and thus tombstoned to stop
        // bulk-sync from resurrecting it), that invariant is now stale. Clear
        // it so a legitimate re-create isn't invisible to future
        // `SYNC_PUSH`/`SYNC_VV` bulk-sync with other replicas (`is_tombstoned`
        // would otherwise keep skipping it there forever). Not gated on
        // `validate_rights`: a repeat genesis of a deterministic subject
        // (the private drive) is applied locally without it. No-op if there
        // was nothing to clear.
        if is_new {
            store.clear_tombstone(commit.subject.as_str());
        }

        if opts.validate_rights {
            let signer_str = commit.signer.to_string();
            let validate_for = opts.validate_for_agent.as_ref().unwrap_or(&signer_str);
            if is_new {
                crate::hierarchy::check_append(store, &applied.resource_new, &validate_for.into())
                    .await?;

                // For new DID resources, grant the signer explicit write access so future
                // commits don't need drive-level rights. Agents are excluded because they
                // already have self-write via their subject matching the agent check.
                if matches!(applied.resource_new.get_subject(), Subject::Did { .. }) {
                    let is_agent = applied
                        .resource_new
                        .get(urls::IS_A)
                        .ok()
                        .and_then(|v| v.to_subjects(None).ok())
                        .unwrap_or_default()
                        .iter()
                        .any(|c| c == urls::AGENT);
                    if !is_agent {
                        let mut writers: Vec<String> = applied
                            .resource_new
                            .get(urls::WRITE)
                            .ok()
                            .and_then(|v| v.to_subjects(None).ok())
                            .unwrap_or_default();
                        if !writers.contains(&signer_str) {
                            writers.push(signer_str.clone());
                            applied
                                .resource_new
                                .set_unsafe(urls::WRITE.into(), writers.into())?;
                        }
                    }
                }
            } else {
                // This should use the _old_ resource, not the new one, as the new one might maliciously give itself write rights.
                crate::hierarchy::check_write(store, &resource_old, &validate_for.into()).await?;
            }

            if commit.destroy.unwrap_or(false) && !is_new {
                commit.reject_destroy_older_than_genesis(&resource_old)?;
            }

            // `drive` is a rights shortcut: `check_rights` consults it *before* it
            // walks the parent chain. It must therefore always agree with the
            // current parent, and must be derived here rather than trusted from
            // the client. Re-derive it at genesis and on any commit that moves the
            // resource — otherwise a resource moved out of a publicly readable
            // drive keeps that drive's grants and stays publicly readable from its
            // new, private home.
            //
            // Deriving it also covers creation paths that never stamped it — a
            // guest replying in a drive shared with them — which the commit fan-out
            // needs in order to route to the owning drive's subscribers. See
            // planning/commit-fanout-drive-isolation.md.
            let parent_changed = applied.changed_props.iter().any(|p| p == urls::PARENT);

            if is_new || parent_changed {
                if let Ok(parent_val) = applied.resource_new.get(urls::PARENT) {
                    let parent_subject = crate::Subject::from(parent_val.to_string());

                    // If the parent isn't materialized here we cannot derive the
                    // drive. Leave whatever was stamped rather than clearing it.
                    if let Ok(parent_res) = store.get_resource(&parent_subject).await {
                        let drive = match parent_res.get(urls::DRIVE_PROP) {
                            Ok(d) => d.to_string(),
                            Err(_) => parent_subject.to_string(),
                        };
                        applied.resource_new.set_unsafe(
                            urls::DRIVE_PROP.into(),
                            crate::values::Value::AtomicUrl(drive.into()),
                        )?;
                    }
                }
            }

            // Managed admission gate. No-op under the default OpenPolicy, so
            // self-hosted / FOSS is unaffected. On a managed node, the drive this
            // commit belongs to must be enrolled (allowlist + quota), with a
            // bootstrap grace so a freshly-created drive can sync while its
            // enrollment propagates. Agents (`did:ad:agent:…`) are exempt — they
            // are outside the enrollment model, which is exactly what a naïve
            // drive check got wrong before.
            //
            // The exemption MUST be keyed on the commit's own subject structure
            // (`is_agent_did`), never on a claimed `IS_A` value: `IS_A` is an
            // ordinary, fully client-controlled property with no required-props
            // gate on the `Agent` class, so checking it here would let any client
            // skip the gate for arbitrary data by tagging it `IS_A: [Agent]`.
            {
                let res = &applied.resource_new;
                let is_agent = commit.subject.is_agent_did();
                if !is_agent {
                    // The drive this resource belongs to: its `drive` stamp, or
                    // (a drive root / top-level resource) its own subject.
                    let drive_subject = res
                        .get(urls::DRIVE_PROP)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|_| res.get_subject().to_string());
                    match store.sync_policy().admit_decision(&drive_subject) {
                        crate::sync::policy::AdmitDecision::Admitted => {}
                        crate::sync::policy::AdmitDecision::NotEnrolled => {
                            // A drive nobody here has seen is either its owner
                            // setting one up or a stranger helping themselves to
                            // the disk. Only the policy can tell those apart, so
                            // ask it — and only for a drive being created, never
                            // as a way back in for one already refused.
                            //
                            // Whose signature this is has been checked by now
                            // (`validate_signature`, far above). When that check
                            // was skipped the commit did not come off the wire at
                            // all — it is initialization, a migration, or an
                            // import — so the writer is this node itself.
                            let writer = if opts.validate_signature {
                                crate::agents::ForAgent::AgentSubject(commit.signer.clone())
                            } else {
                                crate::agents::ForAgent::Sudo
                            };

                            let policy = store.sync_policy();

                            if is_new && policy.may_enroll_drive(&drive_subject, &writer) {
                                tracing::info!(
                                    "Enrolling new drive {} for {}",
                                    drive_subject,
                                    writer
                                );
                                policy.enroll_drive(&drive_subject);
                            } else {
                                return Err(policy.not_enrolled_message(&drive_subject).into());
                            }
                        }
                        crate::sync::policy::AdmitDecision::OverQuota => {
                            return Err(format!(
                                "Drive {drive_subject} has reached its storage quota on this node."
                            )
                            .into());
                        }
                    }
                }
            }
        };
        // Check if all required props are there
        if opts.validate_schema {
            applied.resource_new.check_required_props(store).await?;
        }

        let commit_resource: Resource = commit.into_resource(store).await?;

        // Stamp `lastCommit` with this envelope's id. The id is a receipt,
        // not a refetchable resource — ordinary content commits are not stored.
        applied
            .resource_new
            .set(
                urls::LAST_COMMIT.to_string(),
                Value::AtomicUrl(commit_resource.get_subject().clone()),
                store,
            )
            .await?;

        let destroyed = commit.destroy.unwrap_or(false);

        Ok(CommitResponse {
            commit,
            add_atoms: applied.add_atoms,
            remove_atoms: applied.remove_atoms,
            commit_resource,
            resource_new: if destroyed {
                None
            } else {
                Some(applied.resource_new)
            },
            resource_old: if is_new {
                None
            } else {
                Some(applied.resource_old)
            },
            changed_props: applied.changed_props,
            source_id: opts.source_id.clone(),
        })
    }

    /// A signed destroy is a durable artifact: it sits on the tombstone,
    /// travels in `SYNC_DIFF.removeCommits`, and is re-sent to replicas that
    /// were offline. That is what makes it replayable against a subject
    /// that was legitimately recreated after the destroy. A destroy that
    /// predates the genesis of the resource it names cannot be about this
    /// resource. (`Db::apply_commit` separately refuses a destroy commit it
    /// has already stored.)
    fn reject_destroy_older_than_genesis(&self, resource_old: &Resource) -> AtomicResult<()> {
        if let Ok(genesis_at) = resource_old.get(urls::CREATED_AT).and_then(|v| v.to_int()) {
            if self.created_at + ACCEPTABLE_TIME_DIFFERENCE < genesis_at {
                return Err(format!(
                    "Destroy commit for {} (created {}) predates the resource's genesis ({}); refusing replay",
                    self.subject, self.created_at, genesis_at
                )
                .into());
            }
        }
        Ok(())
    }

    /// Checks if the Commit has been created in the future or if it is expired.
    #[tracing::instrument(skip_all)]
    pub fn validate_timestamp(&self) -> AtomicResult<()> {
        crate::utils::check_timestamp_in_past(self.created_at, ACCEPTABLE_TIME_DIFFERENCE)
    }

    /// Applies the Loro CRDT update and/or destroy to the Resource.
    /// Returns the diff as atoms for index updates, plus the set of changed property URLs.
    #[tracing::instrument(skip_all)]
    pub async fn apply_changes(&self, mut resource: Resource) -> AtomicResult<CommitApplied> {
        let resource_unedited = resource.clone();

        let mut remove_atoms: Vec<Atom> = Vec::new();
        let mut add_atoms: Vec<Atom> = Vec::new();
        let mut changed_props: HashSet<String> = HashSet::new();
        let mut imported_new_ops = false;

        if let Some(loro_update_bytes) = &self.loro_update {
            // Seed from the current resource state when no snapshot exists yet so
            // older resources can still apply snapshot/delta updates correctly.
            let loro_doc = resource.build_state_doc()?;

            // Whether the import actually advances the oplog tells idempotent
            // replay (every op already present → VV unchanged) apart from a
            // genuine new write. See the causality guard in `apply_commit`.
            let vv_before = loro_doc.oplog_vv_map();

            // Import the update and compute the property-level diff for indexing
            let diff = loro_doc
                .import_update_with_diff(loro_update_bytes, &resource.get_subject().to_string())?;
            imported_new_ops = loro_doc.oplog_vv_map() != vv_before;

            // Track which properties changed
            for atom in &diff.add_atoms {
                changed_props.insert(atom.property.clone());
            }
            for atom in &diff.remove_atoms {
                changed_props.insert(atom.property.clone());
            }

            add_atoms.extend(diff.add_atoms);
            remove_atoms.extend(diff.remove_atoms);

            // Rebuild the materialized resource state from the merged Loro doc so
            // deleted properties disappear from propvals as well.
            resource.apply_state_doc(loro_doc)?;
        }

        // Remove all atoms from index if destroy
        if let Some(destroy) = self.destroy {
            if destroy {
                for atom in resource.to_atoms().into_iter() {
                    remove_atoms.push(atom);
                }
            }
        }

        Ok(CommitApplied {
            resource_old: resource_unedited,
            resource_new: resource,
            add_atoms,
            remove_atoms,
            changed_props,
            imported_new_ops,
        })
    }

    /// Converts a Resource of a Commit into a Commit
    pub fn from_resource(resource: Resource) -> AtomicResult<Commit> {
        let subject = resource.get(urls::SUBJECT)?.to_string();
        let created_at = resource.get(urls::CREATED_AT)?.to_int()?;
        let signer = resource.get(SIGNER)?.to_string();
        let loro_update = match resource.get(urls::LORO_UPDATE) {
            Ok(Value::LoroDoc(bin)) => Some(bin.clone()),
            _ => None,
        };
        let destroy = match resource.get(urls::DESTROY) {
            Ok(found) => Some(found.to_bool()?),
            Err(_) => None,
        };
        let previous_commit = match resource.get(urls::PREVIOUS_COMMIT) {
            Ok(found) => Some(found.to_string()),
            Err(_) => None,
        };
        let is_genesis = match resource.get(urls::IS_GENESIS) {
            Ok(found) => Some(found.to_bool()?),
            Err(_) => None,
        };
        let signature = resource.get(urls::SIGNATURE)?.to_string();
        let url = Some(resource.get_subject().to_string());

        Ok(Commit {
            subject: subject.into(),
            created_at,
            signer: signer.into(),
            loro_update,
            destroy,
            previous_commit,
            is_genesis,
            signature: Some(signature),
            url,
        })
    }

    /// Converts the Commit into a Resource with Atomic Values.
    /// Creates an identifier using the server_url
    /// Works for both Signed and Unsigned Commits
    #[tracing::instrument(skip_all)]
    pub async fn into_resource(&self, store: &impl Storelike) -> AtomicResult<Resource> {
        let commit_subject = match self.signature.as_ref() {
            Some(sig) => format!("did:ad:commit:{}", sig),
            None => {
                let now = crate::utils::now();
                format!("internal:/commitsUnsigned/{}", now)
            }
        };
        // `new_instance(COMMIT, …)` already set `isA: Commit`, so the
        // resource is `is_native()` from here on: every `set_unsafe`
        // below takes the propval-only branch and never materializes a Loro
        // state doc. That is exactly what keeps the commit's `loroUpdate`
        // (its signed payload) from being re-derived as a doc snapshot.
        let mut resource = Resource::new_instance(urls::COMMIT, store).await?;
        resource.set_subject(commit_subject);
        resource.set_unsafe(
            urls::SUBJECT.into(),
            Value::new(self.subject.as_str(), &DataType::AtomicUrl)?,
        )?;
        let classes = vec![urls::COMMIT.to_string()];
        resource.set_unsafe(urls::IS_A.into(), classes.into())?;
        resource.set_unsafe(
            urls::CREATED_AT.into(),
            Value::new(&self.created_at.to_string(), &DataType::Timestamp)?,
        )?;
        resource.set_unsafe(
            SIGNER.into(),
            Value::new(self.signer.as_str(), &DataType::AtomicUrl)?,
        )?;
        if let Some(destroy) = self.destroy {
            if destroy {
                resource.set_unsafe(urls::DESTROY.into(), true.into())?;
            }
        }
        if let Some(previous_commit) = &self.previous_commit {
            resource.set_unsafe(
                urls::PREVIOUS_COMMIT.into(),
                Value::AtomicUrl(previous_commit.clone().into()),
            )?;
        }
        if let Some(is_genesis) = self.is_genesis {
            resource.set_unsafe(urls::IS_GENESIS.into(), is_genesis.into())?;
        }
        if let Some(loro_update) = &self.loro_update {
            if !loro_update.is_empty() {
                resource.set_unsafe(
                    urls::LORO_UPDATE.into(),
                    Value::LoroDoc(loro_update.clone()),
                )?;
            }
        }
        resource.set_unsafe(
            SIGNER.into(),
            Value::new(self.signer.as_str(), &DataType::AtomicUrl)?,
        )?;
        if let Some(signature) = &self.signature {
            resource.set_unsafe(urls::SIGNATURE.into(), signature.clone().into())?;
        }
        Ok(resource)
    }

    pub fn get_subject(&self) -> &Subject {
        &self.subject
    }

    /// Generates a deterministic serialized JSON-AD representation of the Commit.
    /// Removes the signature from the object before serializing, since this function is used to check if the signature is correct.
    #[tracing::instrument(skip_all)]
    pub async fn serialize_deterministically_json_ad(
        &self,
        store: &impl Storelike,
    ) -> AtomicResult<String> {
        let mut commit_resource = self.into_resource(store).await?;
        // A deterministic serialization should not contain the hash (signature), since that would influence the hash.
        commit_resource.remove_propval(urls::SIGNATURE)?;

        let is_genesis_flag = self.is_genesis == Some(true);
        let has_previous = self.previous_commit.is_some();

        // The is_genesis flag is what distinguishes signing conventions
        // (genesis signs without `subject`; non-genesis signs with it),
        // so the two states must be internally consistent — but
        // `previous_commit` is no longer treated as a validation gate;
        // it's recorded as a propval for audit/history only.
        if is_genesis_flag && has_previous {
            return Err(format!(
                "Commit has is_genesis=true but also has a previous_commit ({}). A genesis commit cannot have a predecessor.",
                self.previous_commit.as_ref().unwrap()
            ).into());
        }

        // For genesis commits the subject is derived from the signature, so it
        // must not be part of the signed bytes (circular dependency).
        // is_genesis stays in the bytes so both sides sign/verify the same content.
        if is_genesis_flag {
            commit_resource.remove_propval(urls::SUBJECT)?;
        }
        let json_obj = crate::serialize::propvals_to_json_ad_map(
            commit_resource.get_propvals(),
            None,
            &store
                .get_base_domain()
                .unwrap_or_else(|| "internal".to_string()),
            false,
        )?;
        let json = serde_jcs::to_string(&json_obj)
            .map_err(|e| format!("Failed to serialize Commit: {}", e))?;
        Ok(json)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBuilderJSON {
    pub subject: String,
    pub loro_update: Option<String>,
    pub destroy: bool,
    pub previous_commit: Option<String>,
}

/// Use this for creating Commits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitBuilder {
    /// The subject URL that is to be modified by this Delta.
    pub subject: Subject,
    /// Property changes accumulated on the server side.
    /// These get converted to a Loro update at sign time.
    set: std::collections::HashMap<String, Value>,
    /// Properties to remove. Converted to Loro operations at sign time.
    remove: HashSet<String>,
    /// A Loro CRDT binary update (from client). Takes precedence over set/remove.
    loro_update: Option<Vec<u8>>,
    /// If set to true, deletes the entire resource
    destroy: bool,
    /// Optional audit pointer at an earlier envelope. Not a causal gate.
    previous_commit: Option<String>,
    /// Whether this is a genesis commit (the first commit for a DID resource).
    pub is_genesis: bool,
}

impl CommitBuilder {
    /// Start constructing a Commit.
    pub fn new(subject: Subject) -> Self {
        CommitBuilder {
            subject,
            set: HashMap::new(),
            remove: HashSet::new(),
            loro_update: None,
            destroy: false,
            previous_commit: None,
            is_genesis: false,
        }
    }

    pub fn from_commit_builder_json(commit_builder_json: CommitBuilderJSON) -> AtomicResult<Self> {
        let mut commit_builder = CommitBuilder::new(commit_builder_json.subject.into());

        commit_builder.destroy(commit_builder_json.destroy);

        if let Some(loro_b64) = commit_builder_json.loro_update {
            let bin = crate::agents::decode_base64(&loro_b64)
                .map_err(|e| format!("Invalid base64 in loro_update: {e}"))?;
            commit_builder.set_loro_update(bin);
        }

        Ok(commit_builder)
    }

    /// Returns true if this builder has any pending change that would
    /// produce a non-empty commit. Used by callers (`Resource::save`,
    /// `Resource::save_locally`) to skip a sign+apply round-trip when
    /// the caller asked to "save" a resource that hasn't been touched —
    /// `apply_commit` would otherwise reject the resulting empty commit
    /// with "no `loroUpdate` and is not a destroy", which surfaces as a
    /// hard error from idiomatic test code like
    /// `Resource::new_generate_subject(&store).save_locally(&store)`.
    pub fn has_changes(&self) -> bool {
        !self.set.is_empty()
            || !self.remove.is_empty()
            || self.loro_update.is_some()
            || self.destroy
    }

    /// Creates the Commit and signs it using a signature.
    /// Does not send it - see [atomic_lib::client::post_commit].
    /// Private key is the base64 encoded pkcs8 for the signer.
    pub async fn sign(
        mut self,
        agent: &crate::agents::Agent,
        store: &impl Storelike,
        resource: &Resource,
    ) -> AtomicResult<Commit> {
        // previousCommit is optional audit metadata. Callers that want a
        // chain put it on the builder; Loro is the causal authority.

        // If the resource has a live Loro doc but no snapshot was eagerly
        // exported to the commit builder, export it now (single export).
        // Skip when `set`/`remove` are pending — sign_at must merge those onto
        // `existing_loro_snapshot`. Exporting the live doc here would freeze a
        // stale snapshot and ignore commitbuilder.set (e.g. gallery folderId).
        if self.loro_update.is_none() && self.set.is_empty() && self.remove.is_empty() {
            if let Some(snapshot) = resource.export_open_state() {
                self.loro_update = Some(snapshot);
            }
        }

        // Pass the resource's existing Loro snapshot so sign_at can build
        // incremental updates on top of it instead of creating a detached doc.
        //
        // Prefer the in-memory Loro doc over the persisted `loroUpdate` propval.
        // `push_list_item` (strokes) updates the live doc but not the propval
        // until after save. Using the propval here drops stroke edits when
        // `touch_date_edited` also dirtied the commit builder via `set_unsafe`.
        //
        // Fall back to propvals / build_state_doc for resources without a live doc.
        let existing_snapshot: Option<Vec<u8>> =
            resource
                .export_open_state()
                .or_else(|| match resource.get(urls::LORO_UPDATE) {
                    Ok(Value::LoroDoc(snapshot)) => Some(snapshot.clone()),
                    _ => resource
                        .build_state_doc()
                        .ok()
                        .map(|doc| doc.export_snapshot()),
                });

        let now = crate::utils::now();
        sign_at(self, agent, now, store, existing_snapshot.as_deref()).await
    }

    /// Set a property value. On sign, this gets converted to a Loro update.
    pub fn set(&mut self, prop: String, val: Value) {
        self.set.insert(prop, val);
    }

    /// Mark a property for removal. On sign, this gets converted to a Loro update.
    pub fn remove(&mut self, prop: String) {
        self.remove.insert(prop);
    }

    /// Appends a URL or nested Resource to a ResourceArray.
    pub fn push_propval(&mut self, property: &str, value: SubResource) -> AtomicResult<()> {
        let mut vec = match self.set.get(property) {
            Some(Value::ResourceArray(resources)) => resources.to_owned(),
            _ => Vec::new(),
        };
        vec.push(value);
        self.set.insert(property.into(), Value::ResourceArray(vec));
        Ok(())
    }

    /// Set a new subject for this Commit
    pub fn set_subject(&mut self, subject: Subject) {
        self.subject = subject;
    }

    /// Set a Loro CRDT binary update for this commit.
    pub fn set_loro_update(&mut self, update: Vec<u8>) {
        self.loro_update = Some(update);
    }

    /// Set an optional audit pointer at an earlier envelope. Not a causal gate.
    pub fn set_previous_commit(&mut self, previous_commit: String) {
        self.previous_commit = Some(previous_commit);
    }

    /// Whether the resource needs to be removed fully
    pub fn destroy(&mut self, destroy: bool) {
        self.destroy = destroy
    }
}

/// Signs a CommitBuilder at a specific unix timestamp.
/// `existing_loro_snapshot` is the resource's current Loro state, if any.
/// When provided, the set/remove operations are applied on top of it and
/// an incremental update is exported. Without it, a full snapshot is created
/// (appropriate for genesis commits or when no prior state exists).
#[tracing::instrument(skip_all)]
async fn sign_at(
    commitbuilder: CommitBuilder,
    agent: &crate::agents::Agent,
    sign_date: i64,
    store: &impl Storelike,
    existing_loro_snapshot: Option<&[u8]>,
) -> AtomicResult<Commit> {
    // Build the Loro payload: merge set/remove onto existing state when present.
    // If both `loro_update` and set/remove are set, apply set/remove on top of the
    // builder update (import as snapshot or incremental — prefer full snapshot from
    // existing_loro_snapshot + set/remove when set/remove exist).
    let loro_update = if !commitbuilder.set.is_empty() || !commitbuilder.remove.is_empty() {
        let doc = if let Some(snapshot) = existing_loro_snapshot {
            crate::loro::AtomicLoroDoc::from_snapshot(snapshot)?
        } else if let Some(update) = &commitbuilder.loro_update {
            crate::loro::AtomicLoroDoc::from_snapshot(update)?
        } else {
            crate::loro::AtomicLoroDoc::new()
        };
        // Incremental loro_update from `sync_loro_changes_to_commit_builder`
        // (stroke appends) must be merged before applying commitbuilder.set.
        if let Some(update) = &commitbuilder.loro_update {
            let _ = doc.import_update(update);
        }
        for (prop, val) in &commitbuilder.set {
            doc.set_property(prop, val)?;
        }
        for prop in &commitbuilder.remove {
            doc.remove_property(prop)?;
        }
        // One tokened change per commit, like the browser: history buckets
        // versions by it and the envelope is attributed to it.
        doc.commit_with_message(&format!(
            "c-{:x}-{}",
            crate::utils::now(),
            crate::utils::random_string(6)
        ));
        Some(doc.export_snapshot())
    } else {
        commitbuilder.loro_update
    };

    let mut commit = Commit {
        subject: commitbuilder.subject,
        signer: agent.subject.clone(),
        loro_update,
        destroy: Some(commitbuilder.destroy),
        created_at: sign_date,
        previous_commit: commitbuilder.previous_commit,
        is_genesis: if commitbuilder.is_genesis {
            Some(true)
        } else {
            None
        },
        signature: None,
        url: None,
    };
    let stringified = commit
        .serialize_deterministically_json_ad(store)
        .await
        .map_err(|e| format!("Failed serializing commit: {}", e))?;
    let private_key = agent.private_key.clone().ok_or("No private key in agent")?;
    let signature = sign_message(&stringified, &private_key, &agent.public_key).map_err(|e| {
        format!(
            "Failed to sign message for resource {} with agent {}: {}",
            commit.subject, agent.subject, e
        )
    })?;
    commit.signature = Some(signature);
    Ok(commit)
}

/// Signs a string using a base64 encoded ed25519 private key. Outputs a base64 encoded ed25519 signature.
#[tracing::instrument(skip_all)]
pub fn sign_message(message: &str, private_key: &str, public_key: &str) -> AtomicResult<String> {
    let private_key_bytes = decode_base64(private_key)
        .map_err(|e| format!("Failed decoding private key {}: {}", private_key, e))?;
    let public_key_bytes = decode_base64(public_key)
        .map_err(|e| format!("Failed decoding public key {}: {}", public_key, e))?;
    let seed: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| "Ed25519 private key must be 32 bytes")?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    // Verify the public key matches
    let derived_public = signing_key.verifying_key();
    if derived_public.as_bytes() != public_key_bytes.as_slice() {
        return Err("Public key does not match private key".into());
    }
    use ed25519_dalek::Signer;
    let message_bytes = message.as_bytes();
    let signature = signing_key.sign(message_bytes);
    Ok(encode_base64(&signature.to_bytes()))
}

/// The amount of milliseconds that a Commit signature is valid for.
const ACCEPTABLE_TIME_DIFFERENCE: i64 = 10000;

#[cfg(test)]
mod test {
    lazy_static::lazy_static! {
        pub static ref OPTS: CommitOpts = CommitOpts {
            validate_schema: true,
            validate_signature: true,
            validate_timestamp: true,
            validate_loro_causality: true,
            validate_rights: false,
            validate_for_agent: None,
            update_index: true,
            source_id: None,
        };
    }

    use super::*;
    use crate::{agents::Agent, Store, Storelike};

    #[tokio::test]
    async fn agent_and_commit() {
        let store = Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        let agent = store.create_agent(Some("test_actor")).await.unwrap();
        let subject = "https://localhost/new_thing";
        let resource = Resource::new(subject.into());
        let mut commitbuiler = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = Value::new("Some value", &DataType::Markdown).unwrap();
        commitbuiler.set(property1.into(), value1.clone());
        let property2 = crate::urls::SHORTNAME;
        let value2 = Value::new("someval", &DataType::Slug).unwrap();
        commitbuiler.set(property2.into(), value2);
        let commit = commitbuiler.sign(&agent, &store, &resource).await.unwrap();
        let _created_resource = store.apply_commit(commit, &OPTS).await.unwrap();

        let resource = store.get_resource(&subject.into()).await.unwrap();
        assert!(resource.get(property1).unwrap().to_string() == value1.to_string());
    }

    #[tokio::test]
    async fn serialize_commit() {
        let store = Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        // Build a Loro update with some properties
        let doc = crate::loro::AtomicLoroDoc::new();
        doc.set_property(urls::SHORTNAME, &Value::String("shortname".into()))
            .unwrap();
        doc.set_property(urls::DESCRIPTION, &Value::String("Some description".into()))
            .unwrap();
        let loro_update = doc.export_snapshot();

        let commit = Commit {
            subject: "https://localhost/test".into(),
            created_at: 1603638837,
            signer: "https://localhost/author".into(),
            loro_update: Some(loro_update),
            previous_commit: None,
            is_genesis: None,
            destroy: None,
            signature: None,
            url: None,
        };
        let serialized = commit
            .serialize_deterministically_json_ad(&store)
            .await
            .unwrap();
        // Verify deterministic: serialize twice, must match
        let serialized2 = commit
            .serialize_deterministically_json_ad(&store)
            .await
            .unwrap();
        assert_eq!(serialized, serialized2);
        // Must contain loroUpdate and core fields
        assert!(serialized.contains("loroUpdate"));
        assert!(serialized.contains("https://atomicdata.dev/properties/signer"));
    }

    /// Regression: `sign()` must not export a stale live Loro snapshot when the
    /// commit builder still has `set` entries (e.g. gallery `folderId` moves).
    #[tokio::test]
    async fn sign_merges_commit_set_onto_existing_loro_snapshot() {
        let store = Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        let agent = store.create_agent(Some("folder_signer")).await.unwrap();

        const FOLDER_PROP: &str = "https://atomicdata.dev/ontology/canvas/folderId";
        let mut resource = Resource::new("https://localhost/canvas-folder-sign-test".into());
        let doc = crate::loro::AtomicLoroDoc::new();
        doc.set_property(crate::urls::NAME, &Value::String("Test canvas".into()))
            .unwrap();
        let snapshot = doc.export_snapshot();
        resource
            .set_unsafe(crate::urls::LORO_UPDATE.into(), Value::LoroDoc(snapshot))
            .unwrap();
        resource.ensure_materialized().unwrap();

        resource
            .set_unsafe(
                FOLDER_PROP.into(),
                Value::String("did:ad:folder:test".into()),
            )
            .unwrap();

        let commit = resource
            .get_commit_builder()
            .clone()
            .sign(&agent, &store, &resource)
            .await
            .unwrap();
        let update = commit
            .loro_update
            .as_ref()
            .expect("commit should carry loroUpdate");
        let merged = crate::loro::AtomicLoroDoc::from_snapshot(update).unwrap();
        let props = merged.get_all_properties();
        assert!(
            props.contains_key(FOLDER_PROP),
            "signed commit must include folderId in Loro state, keys: {:?}",
            props.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn signature_matches() {
        let store = Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
        let agent = Agent::new_from_private_key(None, private_key).unwrap();
        assert_eq!(
            agent.subject,
            // base64url (URL_SAFE_NO_PAD): agent DIDs must be URL-safe.
            "did:ad:agent:7LsjMW5gOfDdJzK_atgjQ1t20J_rw8MjVg6xwqm-h8U"
        );
        store
            .add_resource(&agent.to_resource().unwrap())
            .await
            .unwrap();
        let subject = "https://localhost/new_thing";
        let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
        let property1 = crate::urls::DESCRIPTION;
        let value1 = Value::new("Some value", &DataType::String).unwrap();
        commitbuilder.set(property1.into(), value1);
        let property2 = crate::urls::SHORTNAME;
        let value2 = Value::new("someval", &DataType::String).unwrap();
        commitbuilder.set(property2.into(), value2);
        let commit = sign_at(commitbuilder, &agent, 0, &store, None)
            .await
            .unwrap();
        let serialized = commit
            .serialize_deterministically_json_ad(&store)
            .await
            .unwrap();

        // Commits now use loroUpdate instead of set
        assert!(
            serialized.contains("loroUpdate"),
            "Commit should contain loroUpdate, got: {}",
            serialized
        );
        assert!(
            !serialized.contains("\"set\""),
            "Commit should not contain legacy set field"
        );
        // Verify signature is valid
        commit.validate_signature(&store).await.unwrap();
    }

    #[test]
    fn signature_basics() {
        let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
        let public_key = "7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=";
        // base64url (URL_SAFE_NO_PAD) — `sign_message` emits this form.
        let signature_expected = "YtDR_xo0272LHNBQtDer4LekzdkfUANFTI0eHxZhITXnbC3j0LCqDWhr6itNvo4tFnep6DCbev5OKAHH89-TDA";
        let message = "val";
        let signature = sign_message(message, private_key, public_key).unwrap();
        assert_eq!(signature, signature_expected);
    }

    #[tokio::test]
    async fn invalid_subjects() {
        let store = Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        let agent = store.create_agent(Some("test_actor")).await.unwrap();
        let resource = Resource::new("https://localhost/test_resource".into());

        // Helper — commits now must carry a loro_update (enforced by
        // validate_and_build_response). Attach an empty-but-present Loro doc
        // so the test exercises subject validation, not Loro absence.
        let minimal_loro = || {
            let doc = crate::loro::AtomicLoroDoc::new();
            doc.export_snapshot()
        };

        // Note: "invalid URL" now parses as Subject::Internal, which is valid
        // in the in-memory Store. Subject validation is handled by the Subject type itself.
        {
            let subject = "https://localhost/?q=invalid";
            let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
            commitbuilder.set_loro_update(minimal_loro());
            let commit = commitbuilder.sign(&agent, &store, &resource).await.unwrap();
            store.apply_commit(commit, &OPTS).await.unwrap_err();
        }
        {
            let subject = "https://localhost/valid";
            let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
            commitbuilder.set_loro_update(minimal_loro());
            let commit = commitbuilder.sign(&agent, &store, &resource).await.unwrap();
            store.apply_commit(commit, &OPTS).await.unwrap();
        }
        {
            // A did:ad: subject with a subpath is structurally invalid.
            // sign() requires is_genesis=true for a new DID resource, so we
            // set that here. apply_commit then rejects the subpath as
            // "Invalid DID".
            let subject = "did:ad:cbXxQGm7UBBS5JPvl/NR/p9RJNbSMUjvA7lRYQt9lZvKZrU1FBo6Icl5uctr7i1AMZ/mElWZ3X1dApo5ifzmBg==/subpath";
            let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
            commitbuilder.is_genesis = true;
            commitbuilder.set_loro_update(minimal_loro());
            let commit = commitbuilder.sign(&agent, &store, &resource).await.unwrap();
            let err = store.apply_commit(commit, &OPTS).await.unwrap_err();
            assert!(
                err.to_string().contains("Invalid DID"),
                "Expected Invalid DID error, got: {}",
                err
            );
        }
    }

    // ── DID commit tests ────────────────────────────────────────────────────

    /// Helper: build a store with a known agent whose private key we control.
    async fn store_with_known_agent() -> (crate::Store, Agent) {
        let store = Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
        let agent = Agent::new_from_private_key(None, private_key).unwrap();
        store
            .add_resource(&agent.to_resource().unwrap())
            .await
            .unwrap();
        (store, agent)
    }

    /// Creating a new `did:ad:` resource via genesis commit should succeed and
    /// the resulting resource subject must start with `did:ad:`.
    #[tokio::test]
    async fn did_genesis_commit_creates_resource() {
        let (store, agent) = store_with_known_agent().await;
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::DESCRIPTION.into(),
            Value::new("hello", &DataType::Markdown).unwrap(),
        );
        let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
        assert!(
            commit.subject.is_did(),
            "genesis subject should be a DID, got {}",
            commit.subject
        );
        assert!(!commit.subject.is_agent_did());
        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            ..CommitOpts::no_validations_no_index()
        };
        let result = store.apply_commit(commit, &opts).await.unwrap();
        let new_subject = result
            .resource_new
            .as_ref()
            .map(|r| r.get_subject().to_string())
            .unwrap_or_default();
        assert!(
            new_subject.starts_with("did:ad:"),
            "created resource subject should be a did:ad: DID, got: {}",
            new_subject
        );

        // Verify the resource is actually retrievable from the store
        let stored = store
            .get_resource(&new_subject.as_str().into())
            .await
            .expect("DID resource should be retrievable after genesis commit");
        assert_eq!(
            stored.get(crate::urls::DESCRIPTION).unwrap().to_string(),
            "hello",
            "Stored resource should have the description from the commit"
        );
    }

    /// Two devices holding the same key mint the same personal-drive DID.
    /// Applying both geneses merges the Loro docs instead of rejecting the
    /// second as "already exists".
    #[tokio::test]
    async fn repeat_private_drive_genesis_merges() {
        let (store, agent) = store_with_known_agent().await;
        let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            validate_loro_causality: true,
            ..CommitOpts::no_validations_no_index()
        };

        let mut first = CommitBuilder::new("placeholder".into());
        first.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
        );
        first.set(
            crate::urls::NAME.into(),
            Value::String("Device A home".into()),
        );
        first.set(
            crate::urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        let commit_a = Commit::create_did_with_cert(first, &agent, &store, Some(cert.clone()))
            .await
            .unwrap();
        let subject = commit_a.subject.clone();
        assert_eq!(
            subject.to_string(),
            crate::genesis::GenesisCert::private_drive_subject(agent.private_key.as_ref().unwrap())
                .unwrap()
        );
        store.apply_commit(commit_a, &opts).await.unwrap();

        let mut second = CommitBuilder::new("placeholder".into());
        second.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
        );
        second.set(
            crate::urls::NAME.into(),
            Value::String("Device B home".into()),
        );
        second.set(
            crate::urls::DESCRIPTION.into(),
            Value::String("from the second device".into()),
        );
        second.set(
            crate::urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        let commit_b = Commit::create_did_with_cert(second, &agent, &store, Some(cert))
            .await
            .unwrap();
        assert_eq!(commit_b.subject, subject);
        store
            .apply_commit(commit_b, &opts)
            .await
            .expect("repeat genesis for the same personal-drive DID must merge");

        let merged = store.get_resource(&subject).await.unwrap();
        assert_eq!(
            merged.get(crate::urls::DESCRIPTION).unwrap().to_string(),
            "from the second device",
            "property only set on the second device must survive the merge"
        );
        assert!(merged.get(crate::urls::NAME).is_ok());
        assert_eq!(
            merged
                .get(crate::urls::IS_A)
                .unwrap()
                .to_subjects(None)
                .unwrap()[0],
            crate::urls::DRIVE
        );
    }

    /// A repeat genesis whose every value loses to the resource's current
    /// state must still be accepted.
    ///
    /// The device that created the drive keeps a stashed genesis commit. Rename
    /// the drive, and that stash now says `name = "My drive"` while the stored
    /// state says the chosen name. It contributes new ops but changes no atom,
    /// which is exactly the shape the causality guard rejects — so the client
    /// re-posted it every 30 seconds for as long as the app stayed open.
    #[tokio::test]
    async fn repeat_genesis_losing_every_value_is_accepted() {
        let (store, agent) = store_with_known_agent().await;
        let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            validate_loro_causality: true,
            ..CommitOpts::no_validations_no_index()
        };

        let mut genesis = CommitBuilder::new("placeholder".into());
        genesis.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
        );
        genesis.set(crate::urls::NAME.into(), Value::String("My drive".into()));
        genesis.set(
            crate::urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        let first = Commit::create_did_with_cert(genesis, &agent, &store, Some(cert.clone()))
            .await
            .unwrap();
        let subject = first.subject.clone();
        store.apply_commit(first, &opts).await.unwrap();

        // The user names their home drive.
        let stored = store.get_resource(&subject).await.unwrap();
        let mut rename = CommitBuilder::new(subject.clone());
        rename.set(
            crate::urls::NAME.into(),
            Value::String("Joeps drijf".into()),
        );
        let rename = rename.sign(&agent, &store, &stored).await.unwrap();
        store.apply_commit(rename, &opts).await.unwrap();

        // Another device mints the same cert — same DID, creation defaults.
        // Every propval it carries now loses to the rename.
        let mut stale = CommitBuilder::new("placeholder".into());
        stale.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
        );
        stale.set(crate::urls::NAME.into(), Value::String("My drive".into()));
        stale.set(
            crate::urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        let stale = Commit::create_did_with_cert(stale, &agent, &store, Some(cert))
            .await
            .unwrap();
        assert_eq!(stale.subject, subject);

        store
            .apply_commit(stale, &opts)
            .await
            .expect("a repeat genesis that changes nothing must be accepted, not retried forever");

        let merged = store.get_resource(&subject).await.unwrap();
        assert_eq!(
            merged.get(crate::urls::NAME).unwrap().to_string(),
            "Joeps drijf",
            "the chosen name must survive the repeat genesis"
        );
    }

    /// The same materialization, arriving WITHOUT the `is_genesis` flag, must
    /// merge too.
    ///
    /// Whether a second device's from-scratch doc drains as a genesis or as an
    /// ordinary commit is an accident of which client path exported it. Seen in
    /// the field as a 500 loop on the owner's own home drive, posted from their
    /// second browser: the commit carried the creation defaults, every one lost
    /// to stored state, and the causality guard read that as silent data loss.
    /// The cert is what decides — it verifies against this subject and names
    /// this signer, so it can only be the same author.
    #[tokio::test]
    async fn repeat_materialization_merges_even_when_not_flagged_genesis() {
        let (store, agent) = store_with_known_agent().await;
        let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            validate_loro_causality: true,
            ..CommitOpts::no_validations_no_index()
        };

        let defaults = |builder: &mut CommitBuilder| {
            builder.set(
                crate::urls::IS_A.into(),
                Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
            );
            builder.set(crate::urls::NAME.into(), Value::String("My drive".into()));
            builder.set(
                crate::urls::WRITE.into(),
                Value::ResourceArray(vec![agent.subject.to_string().into()]),
            );
        };

        let mut genesis = CommitBuilder::new("placeholder".into());
        defaults(&mut genesis);
        let first = Commit::create_did_with_cert(genesis, &agent, &store, Some(cert.clone()))
            .await
            .unwrap();
        let subject = first.subject.clone();
        store.apply_commit(first, &opts).await.unwrap();

        let stored = store.get_resource(&subject).await.unwrap();
        let mut rename = CommitBuilder::new(subject.clone());
        rename.set(crate::urls::NAME.into(), Value::String("Home".into()));
        let rename = rename.sign(&agent, &store, &stored).await.unwrap();
        store.apply_commit(rename, &opts).await.unwrap();

        // Second device: same cert, same defaults — but drained as an ordinary
        // commit, so `is_genesis` never gets set.
        let mut second = CommitBuilder::new("placeholder".into());
        defaults(&mut second);
        let mut second = Commit::create_did_with_cert(second, &agent, &store, Some(cert))
            .await
            .unwrap();
        assert_eq!(second.subject, subject);
        second.is_genesis = None;
        // Re-sign: the flag is part of the signed payload.
        let stringified = second
            .serialize_deterministically_json_ad(&store)
            .await
            .unwrap();
        second.signature = Some(
            sign_message(
                &stringified,
                &agent.private_key.clone().unwrap(),
                &agent.public_key,
            )
            .unwrap(),
        );

        store.apply_commit(second, &opts).await.expect(
            "a repeat materialization is the same author by construction — merge it, do not \
             refuse it as silent data loss",
        );

        let merged = store.get_resource(&subject).await.unwrap();
        assert_eq!(
            merged.get(crate::urls::NAME).unwrap().to_string(),
            "Home",
            "the chosen name must survive the second device's defaults"
        );
    }

    /// A genesis retry without a verifiable cert still fails — only a
    /// same-signer, same-subject cert is treated as a merge.
    #[tokio::test]
    async fn repeat_genesis_without_cert_is_still_rejected() {
        let (store, agent) = store_with_known_agent().await;
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(crate::urls::NAME.into(), Value::String("once".into()));
        let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
        let subject = genesis.subject.clone();
        let opts = CommitOpts {
            validate_signature: false,
            validate_timestamp: false,
            validate_rights: false,
            ..CommitOpts::no_validations_no_index()
        };
        store.apply_commit(genesis, &opts).await.unwrap();

        let loro_doc = crate::loro::AtomicLoroDoc::new();
        loro_doc
            .set_property(crate::urls::NAME, &Value::String("twice".into()))
            .unwrap();
        let retry = Commit {
            subject: subject.clone(),
            signer: agent.subject.clone(),
            loro_update: Some(loro_doc.export_snapshot()),
            destroy: Some(false),
            created_at: crate::utils::now(),
            previous_commit: None,
            is_genesis: Some(true),
            signature: Some("not-checked".into()),
            url: None,
        };
        let err = store.apply_commit(retry, &opts).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("is_genesis: true, but the resource already exists"),
            "expected the old reject, got: {err}"
        );
    }

    /// Loro-only genesis commit (empty set map, only loroUpdate) — mimics browser behavior.
    /// The resource should be stored and retrievable with materialized properties.
    #[tokio::test]
    async fn did_loro_only_genesis_commit_stores_resource() {
        let (store, agent) = store_with_known_agent().await;

        // Build a Loro doc with properties (mimics browser-side Loro)
        let loro_doc = crate::loro::AtomicLoroDoc::new();
        loro_doc
            .set_property(crate::urls::NAME, &Value::String("My Table".into()))
            .unwrap();
        loro_doc
            .set_property(
                crate::urls::DESCRIPTION,
                &Value::String("A test table".into()),
            )
            .unwrap();
        loro_doc
            .set_property(
                crate::urls::PUBLIC_KEY,
                &Value::String(agent.public_key.clone()),
            )
            .unwrap();

        // Export as snapshot (this is what the browser sends for genesis)
        let snapshot = loro_doc.export_snapshot();

        // Create a CommitBuilder with ONLY loroUpdate (no set map)
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set_loro_update(snapshot);

        let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
        let did_subject = commit.subject.clone();

        assert!(
            commit.loro_update.is_some(),
            "commit should have loroUpdate"
        );

        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };

        let result = store.apply_commit(commit, &opts).await.unwrap();
        assert!(result.resource_new.is_some(), "should have resource_new");

        // THE KEY TEST: verify the resource is retrievable from the store
        let stored = store
            .get_resource(&did_subject.as_str().into())
            .await
            .expect("Loro-only DID resource should be retrievable after commit");

        assert_eq!(
            stored.get(crate::urls::NAME).unwrap().to_string(),
            "My Table",
            "Name should be materialized from Loro"
        );
        assert_eq!(
            stored.get(crate::urls::DESCRIPTION).unwrap().to_string(),
            "A test table",
            "Description should be materialized from Loro"
        );
    }

    /// A follow-up commit to a `did:ad:` resource (after genesis) should
    /// succeed when signed by the same agent.
    #[tokio::test]
    async fn did_followup_commit_succeeds() {
        let (store, agent) = store_with_known_agent().await;
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::DESCRIPTION.into(),
            Value::new("v1", &DataType::Markdown).unwrap(),
        );
        let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
        let did_subject = genesis.subject.clone();
        let _genesis_url = genesis.url.clone();
        let opts_no_rights = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            ..CommitOpts::no_validations_no_index()
        };
        store.apply_commit(genesis, &opts_no_rights).await.unwrap();

        // Load the existing resource and edit on top of its Loro state
        let mut resource = store
            .get_resource(&did_subject.as_str().into())
            .await
            .unwrap();
        resource
            .set_unsafe(
                crate::urls::DESCRIPTION.into(),
                Value::new("v2", &DataType::Markdown).unwrap(),
            )
            .unwrap();
        let update = resource
            .get_commit_builder()
            .clone()
            .sign(&agent, &store, &resource)
            .await
            .unwrap();
        store.apply_commit(update, &opts_no_rights).await.unwrap();

        let updated = store
            .get_resource(&did_subject.as_str().into())
            .await
            .unwrap();
        assert_eq!(
            updated.get(crate::urls::DESCRIPTION).unwrap().to_string(),
            "v2"
        );
    }

    /// Agent DID genesis commit should succeed even though get_resource()
    /// returns a synthetic "just-in-time" agent. The Loro snapshot must be
    /// persisted so follow-up commits can merge deltas correctly.
    #[tokio::test]
    async fn agent_did_genesis_and_followup_persists_loro() {
        let (store, agent) = store_with_known_agent().await;

        let agent_subject: Subject = format!("did:ad:agent:{}", agent.public_key).into();

        // Build a genesis Loro doc (mimics browser's handleNew)
        let loro_doc = crate::loro::AtomicLoroDoc::new();
        loro_doc
            .set_property(urls::PUBLIC_KEY, &Value::String(agent.public_key.clone()))
            .unwrap();
        loro_doc
            .set_property(urls::IS_A, &Value::ResourceArray(vec![urls::AGENT.into()]))
            .unwrap();
        let genesis_snapshot = loro_doc.export_snapshot();
        let genesis_version = loro_doc.oplog_vv();

        // Create the genesis commit via CommitBuilder (agent DIDs have a known subject)
        let mut builder = CommitBuilder::new(agent_subject.clone());
        builder.set_loro_update(genesis_snapshot);
        builder.is_genesis = true;
        let empty_resource = Resource::new(agent_subject.to_string());
        let genesis = builder.sign(&agent, &store, &empty_resource).await.unwrap();

        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };

        let result = store.apply_commit(genesis, &opts).await.unwrap();
        let genesis_commit_url = result.commit_resource.get_subject().to_string();
        assert!(
            result.resource_new.is_some(),
            "genesis should produce resource_new"
        );

        // Verify the stored resource has a loroUpdate
        let stored = store.get_resource(&agent_subject).await.unwrap();
        assert!(
            stored.get(urls::LORO_UPDATE).is_ok(),
            "Agent resource should have loroUpdate after genesis"
        );
        assert_eq!(
            stored.get(urls::PUBLIC_KEY).unwrap().to_string(),
            agent.public_key,
        );

        // Now create a follow-up commit that adds properties (mimics persistAgentAfterInvite)
        let loro_doc2 = crate::loro::AtomicLoroDoc::new();
        loro_doc2
            .import_update(&loro_doc.export_snapshot())
            .unwrap();
        loro_doc2
            .set_property(urls::NAME, &Value::String("Test Agent".into()))
            .unwrap();
        loro_doc2
            .set_property(urls::DESCRIPTION, &Value::String("My private drive".into()))
            .unwrap();
        let delta = loro_doc2.export_updates_since(&genesis_version);

        let mut builder2 = CommitBuilder::new(agent_subject.clone());
        builder2.set_loro_update(delta);
        builder2.previous_commit = Some(genesis_commit_url);
        let followup = builder2.sign(&agent, &store, &stored).await.unwrap();

        let result2 = store.apply_commit(followup, &opts).await.unwrap();
        assert!(result2.resource_new.is_some());

        // THE KEY ASSERTION: the follow-up properties must be materialized
        let stored2 = store.get_resource(&agent_subject).await.unwrap();
        assert_eq!(
            stored2.get(urls::NAME).unwrap().to_string(),
            "Test Agent",
            "Name from follow-up commit should be persisted"
        );
        assert_eq!(
            stored2.get(urls::DESCRIPTION).unwrap().to_string(),
            "My private drive",
            "Description from follow-up commit should be persisted"
        );
        assert_eq!(
            stored2.get(urls::PUBLIC_KEY).unwrap().to_string(),
            agent.public_key,
            "publicKey from genesis should still be present"
        );
    }

    #[tokio::test]
    async fn loro_update_without_stored_snapshot_seeds_from_propvals_and_removes_deleted_props() {
        let (store, agent) = store_with_known_agent().await;
        let subject = "https://localhost/loro_seeded_resource";

        let mut existing = Resource::new(subject.into());
        existing
            .set_unsafe(
                crate::urls::NAME.into(),
                Value::String("Before delete".into()),
            )
            .unwrap();
        existing
            .set_unsafe(
                crate::urls::DESCRIPTION.into(),
                Value::String("Delete me".into()),
            )
            .unwrap();

        let base_doc = crate::loro::AtomicLoroDoc::new();
        base_doc
            .set_property(crate::urls::NAME, &Value::String("Before delete".into()))
            .unwrap();
        base_doc
            .set_property(crate::urls::DESCRIPTION, &Value::String("Delete me".into()))
            .unwrap();

        let client_doc =
            crate::loro::AtomicLoroDoc::from_snapshot(&base_doc.export_snapshot()).unwrap();
        client_doc
            .remove_property(crate::urls::DESCRIPTION)
            .unwrap();
        client_doc
            .set_property(crate::urls::NAME, &Value::String("After delete".into()))
            .unwrap();

        let mut builder = CommitBuilder::new(subject.into());
        builder.set_loro_update(client_doc.export_snapshot());
        let commit = builder.sign(&agent, &store, &existing).await.unwrap();

        let applied = commit.apply_changes(existing).await.unwrap();
        let updated = applied.resource_new;

        assert_eq!(
            updated.get(crate::urls::NAME).unwrap().to_string(),
            "After delete"
        );
        assert!(
            updated.get(crate::urls::DESCRIPTION).is_err(),
            "deleted properties should be removed from materialized propvals"
        );
        assert!(
            matches!(
                updated.get(crate::urls::LORO_UPDATE),
                Ok(Value::LoroDoc(snapshot)) if !snapshot.is_empty()
            ),
            "updated resource should keep a persisted Loro snapshot"
        );
    }

    #[tokio::test]
    async fn did_child_keeps_parent_and_can_be_edited_with_inherited_write_rights() {
        let (store, agent) = store_with_known_agent().await;

        let drive_subject = "did:ad:test-drive";
        let mut drive = Resource::new(drive_subject.into());
        drive
            .set_unsafe(
                crate::urls::IS_A.into(),
                Value::ResourceArray(vec![crate::urls::DRIVE.to_string().into()]),
            )
            .unwrap();
        drive
            .set_unsafe(
                crate::urls::WRITE.into(),
                Value::ResourceArray(vec![agent.subject.to_string().into()]),
            )
            .unwrap();
        store.add_resource(&drive).await.unwrap();

        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::PARENT.into(),
            Value::AtomicUrl(drive_subject.into()),
        );
        builder.set(
            crate::urls::NAME.into(),
            Value::String("First version".into()),
        );

        let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
        let did_subject = genesis.subject.clone();

        let opts_with_rights = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: true,
            validate_for_agent: Some(agent.subject.to_string()),
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };

        store
            .apply_commit(genesis, &opts_with_rights)
            .await
            .unwrap();

        let created = store.get_resource(&did_subject).await.unwrap();
        assert_eq!(
            created.get(crate::urls::PARENT).unwrap().to_string(),
            drive_subject
        );

        let mut updated_resource = created.clone();
        updated_resource
            .set_unsafe(
                crate::urls::DESCRIPTION.into(),
                Value::String("Second version".into()),
            )
            .unwrap();
        let update = updated_resource
            .get_commit_builder()
            .clone()
            .sign(&agent, &store, &updated_resource)
            .await
            .unwrap();

        store.apply_commit(update, &opts_with_rights).await.unwrap();

        let updated = store.get_resource(&did_subject).await.unwrap();
        assert_eq!(
            updated.get(crate::urls::PARENT).unwrap().to_string(),
            drive_subject
        );
        assert_eq!(
            updated.get(crate::urls::DESCRIPTION).unwrap().to_string(),
            "Second version"
        );
    }

    /// Regression test for a real vulnerability: the admission-gate's agent
    /// exemption must key off the commit's actual subject structure
    /// (`is_agent_did`), never off a claimed `IS_A` propval. `IS_A` is an
    /// ordinary, fully client-controlled property (the `Agent` class has no
    /// required props gating it), so a version of the gate that trusted `IS_A`
    /// let any client skip drive-enrollment/quota checks entirely by tagging
    /// arbitrary data `IS_A: [Agent]`.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn admission_gate_rejects_spoofed_agent_tag_on_unenrolled_drive() {
        use crate::sync::policy::AllowlistPolicy;
        use std::sync::Arc;
        use std::time::Duration;

        let db = crate::Db::init_temp("gate_spoof_test").await.unwrap();
        let (agent, drive_subject) = db.setup("Alice").await.unwrap();

        // Managed node with an empty allowlist and no bootstrap grace: nothing
        // is enrolled, so any non-agent drive write must be rejected outright.
        let policy = Arc::new(AllowlistPolicy::new());
        policy.set_grace(Duration::ZERO);
        db.set_sync_policy(policy);

        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::PARENT.into(),
            Value::AtomicUrl(drive_subject.clone().into()),
        );
        // The spoof: claim to be an Agent so a naive check would exempt this
        // commit from the gate, even though the subject is an ordinary
        // resource under `drive_subject`, not an agent DID.
        builder.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::AGENT.to_string().into()]),
        );
        let commit = Commit::create_did(builder, &agent, &db).await.unwrap();

        let opts_with_rights = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: true,
            validate_for_agent: Some(agent.subject.to_string()),
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };

        let result = db.apply_commit(commit, &opts_with_rights).await;
        assert!(
            result.is_err(),
            "a spoofed IS_A: [Agent] tag must not bypass the drive-enrollment gate"
        );
    }

    /// Companion to the spoof-rejection test above: a genuine agent DID commit
    /// (the commit's own subject is `did:ad:agent:…`) must still be admitted
    /// even when its "drive" isn't enrolled — agents are legitimately outside
    /// the enrollment model.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn admission_gate_admits_real_agent_did_on_unenrolled_node() {
        use crate::sync::policy::AllowlistPolicy;
        use std::sync::Arc;
        use std::time::Duration;

        let db = crate::Db::init_temp("gate_real_agent_test").await.unwrap();
        let (agent, _drive_subject) = db.setup("Alice").await.unwrap();

        let policy = Arc::new(AllowlistPolicy::new());
        policy.set_grace(Duration::ZERO);
        db.set_sync_policy(policy);

        // The agent updates its own DID resource — a legitimate agent write,
        // unrelated to any enrolled drive.
        let mut agent_resource = db.get_resource(&agent.subject).await.unwrap();
        agent_resource
            .set_unsafe(crate::urls::NAME.into(), Value::String("Alice R.".into()))
            .unwrap();
        let commit = agent_resource
            .get_commit_builder()
            .clone()
            .sign(&agent, &db, &agent_resource)
            .await
            .unwrap();

        let opts_with_rights = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: true,
            validate_for_agent: Some(agent.subject.to_string()),
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };

        db.apply_commit(commit, &opts_with_rights)
            .await
            .expect("a real agent DID commit must be exempt from the drive-enrollment gate");
    }

    /// F11 (planning/unified-sync.md): a rights-checked genesis commit for a
    /// subject that was previously destroyed (and thus tombstoned, to stop
    /// bulk-sync from resurrecting it) must clear that tombstone — otherwise
    /// the legitimate re-create is invisible to future `SYNC_PUSH`/`SYNC_VV`
    /// bulk-sync with other replicas forever, since `is_tombstoned` keeps
    /// skipping it there.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn genesis_commit_clears_stale_tombstone_on_own_subject() {
        let db = crate::Db::init_temp("f11_clear_tombstone_test")
            .await
            .unwrap();
        let (agent, drive_subject) = db.setup("Alice").await.unwrap();

        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::PARENT.into(),
            Value::AtomicUrl(drive_subject.into()),
        );
        builder.set(crate::urls::NAME.into(), Value::String("Reborn".into()));
        let genesis = Commit::create_did(builder, &agent, &db).await.unwrap();
        let subject = genesis.subject.clone();

        // Simulate a prior local deletion of this exact subject.
        crate::sync::tombstones::record_tombstone(&db, subject.as_str());
        assert!(crate::sync::tombstones::is_tombstoned(
            &db,
            subject.as_str()
        ));

        let opts_with_rights = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: true,
            validate_for_agent: Some(agent.subject.to_string()),
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        };
        db.apply_commit(genesis, &opts_with_rights).await.unwrap();

        assert!(
            !crate::sync::tombstones::is_tombstoned(&db, subject.as_str()),
            "F11: a rights-checked genesis re-create must clear a stale tombstone on its own subject"
        );
    }

    /// Tampering with the signature of an otherwise valid commit must be
    /// rejected when signature validation is enabled.
    #[tokio::test]
    async fn tampered_signature_is_rejected() {
        let (store, agent) = store_with_known_agent().await;
        let subject = "https://localhost/tamper_target";
        let resource = Resource::new(subject.into());
        let mut builder = CommitBuilder::new(subject.into());
        builder.set(
            crate::urls::DESCRIPTION.into(),
            Value::new("legit", &DataType::Markdown).unwrap(),
        );
        let mut commit = builder.sign(&agent, &store, &resource).await.unwrap();
        // Flip the first character of the signature to invalidate it.
        commit.signature = Some(format!("XXXX{}", &commit.signature.unwrap()[4..]));

        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            ..CommitOpts::no_validations_no_index()
        };
        let err = store.apply_commit(commit, &opts).await.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("signature"),
            "expected a signature error, got: {}",
            err
        );
    }

    /// Signing a commit with agent B but writing to a resource that agent A
    /// created (and owns) must fail signature validation.
    #[tokio::test]
    async fn wrong_agent_signature_is_rejected() {
        let (store, agent_a) = store_with_known_agent().await;
        let agent_b = store.create_agent(Some("agent_b")).await.unwrap();

        let subject = "https://localhost/agent_a_resource";
        let resource = Resource::new(subject.into());
        let mut builder = CommitBuilder::new(subject.into());
        builder.set(
            crate::urls::DESCRIPTION.into(),
            Value::new("by agent_a", &DataType::Markdown).unwrap(),
        );
        // Sign with agent_b but claim agent_a signed it by manually overriding the signer.
        let mut commit = builder.sign(&agent_b, &store, &resource).await.unwrap();
        commit.signer = agent_a.subject.clone();

        let opts = CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            ..CommitOpts::no_validations_no_index()
        };
        let err = store.apply_commit(commit, &opts).await.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("signature"),
            "expected a signature error, got: {}",
            err
        );
    }

    /// A genesis commit's deterministic serialization must NOT include `@id`,
    /// so that the subject (= the signature) is not part of the signed bytes.
    #[tokio::test]
    async fn genesis_deterministic_serialization_excludes_id() {
        let (store, agent) = store_with_known_agent().await;
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::DESCRIPTION.into(),
            Value::new("test", &DataType::Markdown).unwrap(),
        );
        let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
        let serialized = commit
            .serialize_deterministically_json_ad(&store)
            .await
            .unwrap();
        assert!(
            !serialized.contains("@id"),
            "deterministic serialization must not contain @id, got: {}",
            serialized
        );
    }

    /// Regression: renaming a resource with two sequential commits should
    /// persist the SECOND name. Previously observed symptom: the client types
    /// "New Drive" one character at a time, each keystroke sends a commit,
    /// but only the first one sticks — the stored name remains "N".
    ///
    /// This exercises the real `store.apply_commit` path (not just
    /// `apply_changes`) so persistence + rehydration are part of the test.
    #[tokio::test]
    async fn two_sequential_commits_both_land() {
        let (store, agent) = store_with_known_agent().await;
        let subject = "https://localhost/rename_target";

        // Commit 1: create resource with name="N"
        let client_doc = crate::loro::AtomicLoroDoc::new();
        client_doc
            .set_property(crate::urls::NAME, &Value::String("N".into()))
            .unwrap();
        client_doc
            .set_property(
                crate::urls::IS_A,
                &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
            )
            .unwrap();
        client_doc
            .set_property(crate::urls::SHORTNAME, &Value::String("n".into()))
            .unwrap();
        client_doc
            .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
            .unwrap();

        let empty = Resource::new(subject.into());
        let mut builder = CommitBuilder::new(subject.into());
        builder.set_loro_update(client_doc.export_snapshot());
        let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
        store.apply_commit(commit1, &OPTS).await.unwrap();

        let after_first = store.get_resource(&subject.into()).await.unwrap();
        assert_eq!(
            after_first.get(crate::urls::NAME).unwrap().to_string(),
            "N",
            "commit 1 should set name to N"
        );

        // Commit 2: rename to "Ne" — same Loro doc (incremental), so the
        // exported snapshot represents one op of the same peer ID.
        client_doc
            .set_property(crate::urls::NAME, &Value::String("Ne".into()))
            .unwrap();
        let mut builder2 = CommitBuilder::new(subject.into());
        builder2.set_loro_update(client_doc.export_snapshot());
        // previousCommit is optional audit metadata; the TS client still
        // sets it, but sign() does not auto-fill a causal chain.
        let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
        store.apply_commit(commit2, &OPTS).await.unwrap();

        let after_second = store.get_resource(&subject.into()).await.unwrap();
        assert_eq!(
            after_second.get(crate::urls::NAME).unwrap().to_string(),
            "Ne",
            "commit 2 should rename name to Ne — if this fails, sequential commits aren't merging properly"
        );
    }

    /// Re-applying a commit the server has already applied must be accepted
    /// as an idempotent replay — NOT rejected as a silent LWW loss. The
    /// browser outbox relies on this when it retransmits a commit. The
    /// causality guard distinguishes "ops already in the oplog" (accept)
    /// from "new ops that lost LWW" (reject).
    #[tokio::test]
    async fn idempotent_commit_replay_is_accepted() {
        let (store, agent) = store_with_known_agent().await;
        let subject = "https://localhost/idempotent_replay_target";

        // Causality guard ON, previous-commit check OFF — matches the real
        // `/commit` apply path (a replay legitimately carries a stale
        // `previousCommit`, so that check is not the gate under test).
        let opts = CommitOpts {
            validate_schema: true,
            validate_signature: true,
            validate_timestamp: false,
            validate_loro_causality: true,
            validate_rights: false,
            validate_for_agent: None,
            update_index: true,
            source_id: None,
        };

        // Commit 1: create the resource.
        let client_doc = crate::loro::AtomicLoroDoc::new();
        client_doc
            .set_property(crate::urls::NAME, &Value::String("Original".into()))
            .unwrap();
        client_doc
            .set_property(
                crate::urls::IS_A,
                &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
            )
            .unwrap();
        client_doc
            .set_property(crate::urls::SHORTNAME, &Value::String("orig".into()))
            .unwrap();
        client_doc
            .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
            .unwrap();
        let empty = Resource::new(subject.into());
        let mut builder = CommitBuilder::new(subject.into());
        builder.set_loro_update(client_doc.export_snapshot());
        let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
        store.apply_commit(commit1, &opts).await.unwrap();

        // Commit 2: a rename.
        let after_first = store.get_resource(&subject.into()).await.unwrap();
        client_doc
            .set_property(crate::urls::NAME, &Value::String("Renamed".into()))
            .unwrap();
        let mut builder2 = CommitBuilder::new(subject.into());
        builder2.set_loro_update(client_doc.export_snapshot());
        let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();

        // Apply commit 2, then RE-APPLY the identical commit. Its ops are
        // already in the resource's oplog, so the second apply must be
        // accepted (idempotent replay), not rejected.
        store.apply_commit(commit2.clone(), &opts).await.unwrap();
        store
            .apply_commit(commit2, &opts)
            .await
            .expect("idempotent replay of an already-applied commit must be accepted");

        let after = store.get_resource(&subject.into()).await.unwrap();
        assert_eq!(
            after.get(crate::urls::NAME).unwrap().to_string(),
            "Renamed",
            "state must be unchanged by the idempotent replay",
        );
    }

    /// Same as above but each commit comes from a FRESH Loro doc seeded from
    /// the server's previous snapshot — simulates a client that rebuilds its
    /// Loro state between commits (or a peer that joins mid-session).
    #[tokio::test]
    async fn two_commits_with_fresh_doc_per_commit_both_land() {
        let (store, agent) = store_with_known_agent().await;
        let subject = "https://localhost/rename_fresh_doc";

        // Commit 1: name="N" from a fresh doc.
        let doc1 = crate::loro::AtomicLoroDoc::new();
        doc1.set_property(crate::urls::NAME, &Value::String("N".into()))
            .unwrap();
        doc1.set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
        doc1.set_property(crate::urls::SHORTNAME, &Value::String("n".into()))
            .unwrap();
        doc1.set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
            .unwrap();

        let empty = Resource::new(subject.into());
        let mut builder = CommitBuilder::new(subject.into());
        builder.set_loro_update(doc1.export_snapshot());
        let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
        store.apply_commit(commit1, &OPTS).await.unwrap();

        let after_first = store.get_resource(&subject.into()).await.unwrap();
        assert_eq!(after_first.get(crate::urls::NAME).unwrap().to_string(), "N");

        // Commit 2: client rebuilds Loro doc from the server's stored state,
        // then mutates. This models "fresh doc per commit" client behaviour.
        let stored_snapshot = match after_first.get(crate::urls::LORO_UPDATE).unwrap() {
            Value::LoroDoc(b) => b.clone(),
            other => panic!("expected LoroDoc, got {:?}", other),
        };
        let doc2 = crate::loro::AtomicLoroDoc::from_snapshot(&stored_snapshot).unwrap();
        doc2.set_property(crate::urls::NAME, &Value::String("Ne".into()))
            .unwrap();

        let mut builder2 = CommitBuilder::new(subject.into());
        builder2.set_loro_update(doc2.export_snapshot());
        let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
        store.apply_commit(commit2, &OPTS).await.unwrap();

        let after_second = store.get_resource(&subject.into()).await.unwrap();
        assert_eq!(
            after_second.get(crate::urls::NAME).unwrap().to_string(),
            "Ne",
            "fresh-doc-per-commit should still land the second rename"
        );
    }

    /// Two commits where each commit comes from a FRESH Loro doc with a
    /// different peer ID, NOT seeded from the server's state. Writes to the
    /// same key are concurrent — Loro's LWW tiebreak by peer ID decides which
    /// one wins. We pin the peer IDs so docA always wins LWW: docB's writes
    /// are guaranteed to be silently dropped against the merged state, which
    /// is exactly the case the causality guard exists to catch.
    #[tokio::test]
    async fn two_commits_with_independent_docs_both_peers_same_key() {
        let (store, agent) = store_with_known_agent().await;
        let subject = "https://localhost/concurrent_peers";

        // Commit 1: docA → name="A". Pin peer ID high so this peer wins LWW
        // tiebreaks against docB.
        let doc_a = crate::loro::AtomicLoroDoc::new();
        doc_a.set_peer_id(u64::MAX - 1).unwrap();
        doc_a
            .set_property(crate::urls::NAME, &Value::String("A".into()))
            .unwrap();
        doc_a
            .set_property(
                crate::urls::IS_A,
                &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
            )
            .unwrap();
        doc_a
            .set_property(crate::urls::SHORTNAME, &Value::String("a".into()))
            .unwrap();
        doc_a
            .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
            .unwrap();

        let empty = Resource::new(subject.into());
        let mut builder = CommitBuilder::new(subject.into());
        builder.set_loro_update(doc_a.export_snapshot());
        let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
        store.apply_commit(commit1, &OPTS).await.unwrap();

        // Commit 2: docB = FRESH, NOT seeded from server. Pin peer ID low so
        // this peer always loses LWW tiebreaks against docA.
        let doc_b = crate::loro::AtomicLoroDoc::new();
        doc_b.set_peer_id(1).unwrap();
        doc_b
            .set_property(crate::urls::NAME, &Value::String("B".into()))
            .unwrap();
        doc_b
            .set_property(
                crate::urls::IS_A,
                &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
            )
            .unwrap();
        doc_b
            .set_property(crate::urls::SHORTNAME, &Value::String("b".into()))
            .unwrap();
        doc_b
            .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
            .unwrap();

        let after_first = store.get_resource(&subject.into()).await.unwrap();
        let mut builder2 = CommitBuilder::new(subject.into());
        builder2.set_loro_update(doc_b.export_snapshot());
        let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
        let err = store.apply_commit(commit2, &OPTS).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("silently dropped"),
            "expected silent-drop error from causality guard, got: {msg}"
        );

        // Stored state is unchanged; commit 2 was rejected.
        let after_second = store.get_resource(&subject.into()).await.unwrap();
        assert_eq!(
            after_second.get(crate::urls::NAME).unwrap().to_string(),
            "A",
            "stored name should still be `A` since commit 2 was rejected"
        );
    }

    #[tokio::test]
    async fn deserialize_from_json() {
        let json = r#"
        {
            "subject": "https://localhost/test",
            "loro_update": "bG9ybw==",
            "destroy": false
        }
        "#;

        let commit_builder_json: CommitBuilderJSON = serde_json::from_str(json).unwrap();
        let commit_builder = CommitBuilder::from_commit_builder_json(commit_builder_json).unwrap();

        assert_eq!(commit_builder.subject, "https://localhost/test");
        assert!(commit_builder.loro_update.is_some());
        assert!(!commit_builder.destroy);
    }
}

/// Owner mode: only the node's owner may put a *new* drive here.
///
/// The managed-node tests above cover an allowlist a control plane populates.
/// These cover the self-hosted gate, where the answer turns on *who is signing*
/// rather than on what some other system already enrolled.
#[cfg(all(test, feature = "db"))]
mod owner_mode_tests {
    use super::*;
    use crate::sync::policy::OwnerPolicy;
    use crate::Value;
    use std::sync::Arc;

    fn signed_opts(agent: &crate::agents::Agent) -> CommitOpts {
        CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: true,
            validate_for_agent: Some(agent.subject.to_string()),
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        }
    }

    /// A commit that brings a new drive into being, signed by `agent`.
    async fn new_drive_commit(db: &crate::Db, agent: &crate::agents::Agent) -> Commit {
        let mut builder = CommitBuilder::new("placeholder".into());
        builder.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.to_string().into()]),
        );
        builder.set(crate::urls::NAME.into(), Value::String("A Drive".into()));
        Commit::create_did(builder, agent, db).await.unwrap()
    }

    #[tokio::test]
    async fn a_stranger_cannot_create_a_drive_on_someone_elses_node() {
        let db = crate::Db::init_temp("owner_gate_stranger").await.unwrap();
        let (owner, _) = db.setup("Owner").await.unwrap();
        let stranger = db.create_agent(Some("Stranger")).await.unwrap();

        db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

        let commit = new_drive_commit(&db, &stranger).await;
        let err = db
            .apply_commit(commit, &signed_opts(&stranger))
            .await
            .expect_err("a stranger must not be able to genesis a drive on a gated node")
            .to_string();

        // The person reading this clicked a button; the message has to be about
        // them, not about enrollment bookkeeping.
        assert!(err.contains("does not host new Drives"), "{err}");
    }

    #[tokio::test]
    async fn the_owner_can_still_create_drives() {
        let db = crate::Db::init_temp("owner_gate_owner").await.unwrap();
        let (owner, _) = db.setup("Owner").await.unwrap();

        db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

        let commit = new_drive_commit(&db, &owner).await;
        let subject = commit.subject.to_string();

        db.apply_commit(commit, &signed_opts(&owner))
            .await
            .expect("the owner must be able to create a drive on their own node");

        // And it was enrolled, so the *next* write to it is admitted without
        // re-deciding who may enroll.
        assert!(
            db.sync_policy().admit_drive_write(&subject),
            "creating a drive must enroll it"
        );
    }

    #[tokio::test]
    async fn drives_that_predate_the_gate_keep_working() {
        // The switch from open to owner must never revoke access to data
        // already on the disk — including a guest's drive from before.
        let db = crate::Db::init_temp("owner_gate_snapshot").await.unwrap();
        let (owner, _) = db.setup("Owner").await.unwrap();
        let guest = db.create_agent(Some("Guest")).await.unwrap();

        let commit = new_drive_commit(&db, &guest).await;
        let guest_drive = commit.subject.to_string();
        db.apply_commit(commit, &signed_opts(&guest))
            .await
            .expect("open node accepts the guest drive");

        // Now the operator names an owner and restarts.
        let policy = OwnerPolicy::new(owner.subject.to_string());
        policy.enroll_existing(db.drive_subjects().await);
        db.set_sync_policy(Arc::new(policy));

        assert!(
            db.sync_policy().admit_drive_write(&guest_drive),
            "a drive created before the gate went up must stay writable"
        );
    }

    #[tokio::test]
    async fn an_open_node_still_takes_a_drive_from_anyone() {
        // The default path, and the one every existing deployment is on.
        let db = crate::Db::init_temp("owner_gate_open").await.unwrap();
        let (_owner, _) = db.setup("Owner").await.unwrap();
        let stranger = db.create_agent(Some("Stranger")).await.unwrap();

        let commit = new_drive_commit(&db, &stranger).await;
        db.apply_commit(commit, &signed_opts(&stranger))
            .await
            .expect("an open node must behave exactly as it did before host mode existed");
    }
}
