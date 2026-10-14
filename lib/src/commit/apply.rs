use super::*;

impl Commit {
    /// Applies the Loro CRDT update and/or destroy to the Resource.
    /// Returns the diff as atoms for index updates, plus the set of changed property URLs.
    #[tracing::instrument(skip_all)]
    pub async fn apply_changes(&self, mut resource: Resource) -> AtomicResult<CommitApplied> {
        let resource_unedited = resource.clone();

        let mut remove_atoms: Vec<Atom> = Vec::new();
        let mut add_atoms: Vec<Atom> = Vec::new();
        let mut changed_props: HashSet<String> = HashSet::new();
        let mut imported_new_ops = false;
        let mut vv_before: Option<loro::VersionVector> = None;
        let mut imported_pending_ops = false;
        let mut changed_property_keys: Vec<String> = Vec::new();
        let mut datatypes_changed = false;
        let mut entry_changes: Vec<crate::chat_log::EntryChange> = Vec::new();

        if let Some(loro_update_bytes) = &self.loro_update {
            // Seed from the current resource state when no snapshot exists yet so
            // older resources can still apply snapshot/delta updates correctly.
            let loro_doc = resource.build_state_doc()?;

            // Whether the import actually advances the oplog tells idempotent
            // replay (every op already present → VV unchanged) apart from a
            // genuine new write. See the causality guard in `apply_commit`.
            let vv_map_before = loro_doc.oplog_vv_map();
            vv_before = Some(loro_doc.oplog_vv());

            // Import the update and compute the property-level diff for indexing
            let diff = loro_doc
                .import_update_with_diff(loro_update_bytes, &resource.get_subject().to_string())?;
            imported_new_ops = loro_doc.oplog_vv_map() != vv_map_before;
            imported_pending_ops = diff.imported_pending_ops;
            changed_property_keys = diff.changed_property_keys;
            datatypes_changed = diff.datatypes_changed;
            entry_changes = diff.entry_changes;

            // Validate the author's state as well as the merged state. Concurrent
            // LWW decisions may retain our baseline while accepting a stale value.
            // Reconstruct the incoming causal frontier so that losing metadata
            // cannot turn an import into an unchecked ordinary edit.
            if imported_new_ops
                && (resource_unedited.get(urls::IMPORT_BASELINE).is_ok()
                    || resource_unedited.get(urls::IMPORT_REFERENCE_REVIEW).is_ok()
                    || diff
                        .add_atoms
                        .iter()
                        .any(|atom| atom.property == urls::IMPORT_REFERENCE_REVIEW))
            {
                let meta = loro::LoroDoc::decode_import_blob_meta(loro_update_bytes, true)
                    .map_err(|e| format!("Invalid import update metadata: {e}"))?;
                let mut ends = loro::Frontiers::new();
                for (peer, counter) in meta.partial_end_vv.iter() {
                    if *counter > 0 {
                        ends.push(loro::ID::new(*peer, *counter - 1));
                    }
                }
                if !ends.is_empty() {
                    let intended_doc =
                        loro_doc.fork_at(&crate::loro::VersionID::from_frontiers(&ends))?;
                    let mut intended = resource_unedited.clone();
                    intended.apply_state_doc(intended_doc)?;
                    crate::import_identity::validate_baseline(Some(&resource_unedited), &intended)?;
                    crate::import_identity::validate_reference_review(
                        Some(&resource_unedited),
                        &intended,
                    )?;
                }
            }

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
            vv_before,
            imported_pending_ops,
            changed_property_keys,
            datatypes_changed,
            entry_changes,
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
            Some(sig) => crate::identifiers::commit_subject(sig),
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
