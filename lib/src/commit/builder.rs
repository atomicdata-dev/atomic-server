use super::*;

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
        //
        // The delta base is derived from the resource's *persisted* state
        // (`loroUpdate` propval), not the live doc: the live doc already holds
        // this commit's pending edits, so its own version would yield an empty
        // delta. See `AtomicLoroDoc::tokened_base_vv` for why not its full vv.
        let persisted_base: Option<Vec<u8>> = match resource.get(urls::LORO_UPDATE) {
            Ok(Value::LoroDoc(snapshot)) if !snapshot.is_empty() => Some(snapshot.clone()),
            _ => None,
        };
        let base_vv = persisted_base
            .as_deref()
            .and_then(|s| crate::loro::AtomicLoroDoc::from_snapshot(s).ok())
            .and_then(|d| d.tokened_base_vv());
        if self.loro_update.is_none() && self.set.is_empty() && self.remove.is_empty() {
            let delta = base_vv
                .as_ref()
                .and_then(|vv| resource.export_open_delta(vv));
            if let Some(update) = delta.or_else(|| resource.export_open_state()) {
                self.loro_update = Some(update);
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
        sign_at(
            self,
            agent,
            now,
            store,
            existing_snapshot.as_deref(),
            base_vv,
        )
        .await
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
/// When provided, the set/remove operations are applied on top of it.
/// `base_vv` is what the receiver is
/// assumed to hold (`AtomicLoroDoc::tokened_base_vv` of the persisted state;
/// `existing_loro_snapshot` may extend that with pending live edits): when
/// given, the signed payload is the delta since it. Without it, a full snapshot
/// is created (appropriate for genesis commits or when no prior state exists).
#[tracing::instrument(skip_all)]
pub(super) async fn sign_at(
    commitbuilder: CommitBuilder,
    agent: &crate::agents::Agent,
    sign_date: i64,
    store: &impl Storelike,
    existing_loro_snapshot: Option<&[u8]>,
    base_vv: Option<::loro::VersionVector>,
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
        match base_vv {
            // Existing state: ship only what this commit added, so the
            // envelope does not grow with the document.
            Some(vv) => Some(doc.export_updates_since(&vv)),
            // Genesis / no prior state: the snapshot is the whole history.
            None => Some(doc.export_snapshot()),
        }
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
