use super::*;

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
                crate::genesis::GenesisCert::new_v2(signer_pubkey, now, nonce, None, parent, drive)
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
    ///
    /// Every failure is an authentication failure (a server answers 401):
    /// there is no signature, the signer is unknown here, its key is not a
    /// key, or the signature does not verify.
    pub async fn validate_signature(&self, store: &impl Storelike) -> AtomicResult<()> {
        self.check_signature(store)
            .await
            .map_err(crate::errors::AtomicError::into_unauthorized)
    }

    async fn check_signature(&self, store: &impl Storelike) -> AtomicResult<()> {
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
                .agent_public_key()
                .ok_or("Invalid atomic:agent / did:ad:agent signer")?
                .to_string()
        } else if let Some(path_key) = crate::agents::legacy_agent_pubkey(commit.signer.as_str()) {
            // Legacy HTTP agents (`https://host/agents/{pubkey}`): rights
            // checks treat this signer as `did:ad:agent:{pubkey}`, so the key
            // in the path is the identity being claimed and is what the
            // signature must verify against. A resource stored (or fetched)
            // at that URL must not override it: anyone can publish a resource
            // at `https://theirs/agents/<victim key>` carrying their own key.
            path_key
        } else if signer_subject.is_local() {
            match store.get_resource(&signer_subject).await {
                Ok(resource) => resource.get(urls::PUBLIC_KEY)?.to_string(),
                Err(_) => return Err(format!("Signer {} not found in store", commit.signer).into()),
            }
        } else {
            // Never fetch a signer over the network to learn its key: the
            // fetch is unauthenticated SSRF and the body would be stored as
            // a trusted resource.
            return Err(format!(
                "Signer {} is hosted elsewhere; only did:ad:agent signers or agents known to this store can sign commits here",
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
            // A Property ID names no signature and has no cert: its hash must
            // match the namespace, shortname and datatype in the doc.
            if is_content_addressed_id(commit.subject.as_str()) {
                let propvals = commit
                    .loro_update
                    .as_ref()
                    .and_then(|u| crate::Resource::propvals_from_loro_update(u))
                    .ok_or("A property or lens genesis commit must carry its fields")?;
                return verify_content_addressed_genesis(commit.subject.as_str(), &propvals);
            }
            let subject_val = crate::identifiers::identifier_body(commit.subject.as_str())
                .filter(|body| !body.contains(':'))
                .ok_or("Invalid atomic: / did:ad: resource subject")?;

            let doc_propvals = commit
                .loro_update
                .as_ref()
                .and_then(|u| crate::Resource::propvals_from_loro_update(u));
            let cert_b64 = doc_propvals
                .as_ref()
                .and_then(|p| p.get(urls::GENESIS).map(|v| v.to_string()));

            if let Some(cert_b64) = cert_b64 {
                // Path 1: self-verifying genesis certificate.
                let cert_bytes = decode_base64(&cert_b64)?;
                let cert = crate::genesis::GenesisCert::decode(&cert_bytes)?;
                cert.verify_signed_bytes(&cert_bytes, subject_val)?;
                if cert.signer_pubkey != pubkey_bytes {
                    return Err(
                        "Genesis certificate signer does not match the commit signer".into(),
                    );
                }
                // The cert binds the original `parent` and `drive`; the doc
                // carries the (mutable) propvals. At genesis they must agree,
                // or a doc could place the resource somewhere the cert's
                // signer never put it while the DID still verifies.
                if let Some(propvals) = &doc_propvals {
                    for (name, cert_val, prop) in [
                        ("parent", cert.parent.as_str(), urls::PARENT),
                        ("drive", cert.drive.as_str(), urls::DRIVE_PROP),
                    ] {
                        if cert_val.is_empty() {
                            continue;
                        }
                        if let Some(doc_val) = propvals.get(prop) {
                            // A v1 cert carries the string as it was signed
                            // (`did:ad:` for every pre-rename resource) while
                            // the materialized doc is canonical (`atomic:`).
                            // Both name the same resource; compare on one
                            // spelling or every old client's genesis fails.
                            let doc_str = doc_val.to_string();
                            if crate::identifiers::canonicalize_scheme(&doc_str)
                                != crate::identifiers::canonicalize_scheme(cert_val)
                            {
                                return Err(format!(
                                    "Genesis certificate {name} ({cert_val}) does not match the resource's {name} ({doc_val})"
                                )
                                .into());
                            }
                        }
                    }
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
    pub(super) fn repeat_genesis_is_mergeable(&self) -> AtomicResult<bool> {
        if !self.subject.is_did() || self.subject.is_agent_did() {
            return Ok(false);
        }
        if is_content_addressed_id(self.subject.as_str()) {
            // Two devices mint the same Property or Lens ID independently. No
            // cert: the hash of the incoming doc's fields is the proof.
            return Ok(self
                .loro_update
                .as_ref()
                .and_then(|u| crate::Resource::propvals_from_loro_update(u))
                .is_some_and(|p| {
                    verify_content_addressed_genesis(self.subject.as_str(), &p).is_ok()
                }));
        }
        let subject_val = crate::identifiers::identifier_body(self.subject.as_str())
            .filter(|body| !body.contains(':'))
            .ok_or("Invalid atomic: / did:ad: resource subject")?;
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
            .agent_public_key()
            .ok_or("Repeat genesis requires an atomic:agent / did:ad:agent signer")?;
        let signer_bytes: [u8; 32] = decode_base64(signer_key)?
            .try_into()
            .map_err(|_| "Agent public key must be 32 bytes")?;
        if cert.signer_pubkey != signer_bytes {
            return Ok(false);
        }
        Ok(true)
    }
}
