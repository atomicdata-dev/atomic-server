//! Persisting replicated resources into [`Db`].

use super::*;

impl Db {
    /// Persist already-admitted replica state, including independently created
    /// duplicate import identities. Keep both subjects available for review;
    /// authoring paths must still enforce identity uniqueness.
    pub async fn persist_replicated_resource(&self, resource: &Resource) -> AtomicResult<()> {
        self.persist_replicated(resource, None).await
    }

    /// [`Self::persist_replicated_resource`] with the CRDT snapshot the caller
    /// already holds. The row, its snapshot and its index entries land in one
    /// transaction, and the stored snapshot keeps the caller's history instead
    /// of a doc re-seeded from the propvals (which would carry a fresh peer id
    /// and merge badly with the real one).
    pub async fn persist_replicated_resource_with_snapshot(
        &self,
        resource: &Resource,
        snapshot: Vec<u8>,
    ) -> AtomicResult<()> {
        self.persist_replicated(resource, Some(snapshot)).await
    }

    /// [`Self::persist_replicated_resource_with_snapshot`] for many resources in
    /// one write. Each resource costs the same index entries as on its own, but
    /// they share one commit, so a page the batch touches repeatedly (a
    /// parent's member list, the name index) is written once instead of once
    /// per resource. A large first sync is bound by that cost.
    ///
    /// A resource named twice keeps its last entry. One with an import
    /// identity goes through the single-resource path, which serialises on the
    /// identity lock and flushes.
    pub async fn persist_replicated_resources(
        &self,
        entries: Vec<(Resource, Option<Vec<u8>>)>,
    ) -> AtomicResult<()> {
        self.persist_replicated_resources_opts(entries, false).await
    }

    /// [`Self::persist_replicated_resources`] for a bulk pull: with
    /// `defer_search` the full-text entries (most of the index writes) are left
    /// out and each resource is filed for [`crate::search::index_pending`].
    pub async fn persist_replicated_resources_opts(
        &self,
        entries: Vec<(Resource, Option<Vec<u8>>)>,
        defer_search: bool,
    ) -> AtomicResult<()> {
        let mut last: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, (resource, _)) in entries.iter().enumerate() {
            last.insert(self.normalize_subject(resource.get_subject()).pure_id(), i);
        }
        let mut transaction = Transaction::new();
        let mut batched: Vec<&Resource> = Vec::new();
        for (i, (resource, snapshot)) in entries.iter().enumerate() {
            let key = self.normalize_subject(resource.get_subject()).pure_id();
            if last.get(&key) != Some(&i) {
                continue;
            }
            if crate::import_identity::identity(resource).is_some() {
                self.persist_replicated(resource, snapshot.clone()).await?;
                continue;
            }
            let before = transaction.len();
            self.build_projection_tx(
                resource,
                false,
                true,
                true,
                snapshot.clone(),
                &mut transaction,
            )
            .await?;
            if defer_search {
                let mut added = transaction.split_off(before);
                added.retain(|op| !crate::search::is_search_op(op));
                transaction.extend(added);
                transaction.push(crate::search::pending_marker(&key));
            }
            batched.push(resource);
        }
        if batched.is_empty() {
            return Ok(());
        }
        self.apply_transaction(&mut transaction)?;
        for resource in batched {
            self.note_lens_related(resource).await;
            let _ = self.db_events.send(DbEvent::Changed {
                subject: resource.get_subject().without_params(),
                delta: None,
                source_id: crate::sync::ws_apply::current_import_source(),
                is_new: false,
                from_commit: false,
            });
        }
        Ok(())
    }

    pub(super) async fn persist_replicated(
        &self,
        resource: &Resource,
        snapshot: Option<Vec<u8>>,
    ) -> AtomicResult<()> {
        // Review validation holds this same identity lock while reading all
        // copies. Replica changes must not land halfway through that review.
        let _identity_guard = if let Some((parent, id)) = crate::import_identity::identity(resource)
        {
            Some(
                self.subject_locks
                    .lock(&format!(
                        "import-identity:{}",
                        serde_json::to_string(&(parent.pure_id(), &id))?
                    ))
                    .await,
            )
        } else {
            None
        };
        self.persist_resource_projection(resource, false, true, true, snapshot)
            .await
    }

    pub(super) async fn persist_resource_projection(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
        snapshot: Option<Vec<u8>>,
    ) -> AtomicResult<()> {
        let mut transaction = Transaction::new();
        self.build_projection_tx(
            resource,
            check_required_props,
            update_index,
            overwrite_existing,
            snapshot,
            &mut transaction,
        )
        .await?;
        self.apply_transaction(&mut transaction)?;
        if crate::import_identity::identity(resource).is_some() {
            self.flush()?;
        }
        self.note_lens_related(resource).await;
        let _ = self.db_events.send(DbEvent::Changed {
            subject: resource.get_subject().without_params(),
            delta: None,
            // Attributed here, while the importing write is still on the stack:
            // the live push loop uses it to avoid sending an update straight
            // back to the peer it came from.
            source_id: crate::sync::ws_apply::current_import_source(),
            is_new: false,
            from_commit: false,
        });
        Ok(())
    }

    /// Everything [`Self::persist_resource_projection`] writes for one
    /// resource, appended to `transaction` instead of applied: the index
    /// entries, the Loro snapshot and the row.
    pub(super) async fn build_projection_tx(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
        snapshot: Option<Vec<u8>>,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        // This only works if no external functions rely on using add_resource for atom-like operations!
        // However, add_atom uses set_propvals, which skips the validation.
        let subject = self.normalize_subject(resource.get_subject());
        let subject_str = subject.pure_id();
        // Lenses derive values the doc does not hold; the stored row and the
        // indexes carry them like real ones. Only a resource that holds a lens
        // property is copied.
        let lenses = self.lenses();
        let derived_resource;
        let resource = if !lenses.is_empty()
            && resource
                .get_propvals()
                .keys()
                .any(|prop| lenses.touches(prop))
        {
            let mut copy = resource.clone();
            copy.apply_lenses(&lenses);
            derived_resource = copy;
            &derived_resource
        } else {
            resource
        };
        let existing = self
            .get_propvals_canonical(&subject_str)
            .ok()
            .map(|(_, pv)| pv);
        if !overwrite_existing && existing.is_some() {
            return Err(format!(
                "Failed to add: '{}', already exists, should not be overwritten.",
                resource.get_subject()
            )
            .into());
        }
        if check_required_props {
            resource.check_required_props(self).await?;
        }
        if update_index {
            // Every atom is removed and filed again, not only the changed
            // ones. Identical re-puts from a tab are already skipped before
            // they reach here (`Store.persistState`).
            //
            // Evict against the state that is going away, not the one
            // replacing it. Whether an entry belongs in a watched query's
            // member list, and under which sort key it was filed, are facts
            // about the old values: asking the new resource instead makes a
            // row edited out of a filtered view skip the one delete it needs.
            if let Some(pv) = existing {
                let old = Resource::from_propvals(pv, resource.get_subject().clone());
                for atom in old.to_atoms() {
                    self.remove_atom_from_index(&atom, &old, transaction)
                        .map_err(|e| format!("Failed to remove atom from index {}. {}", atom, e))?;
                }
            }
            for atom in resource.to_atoms() {
                self.add_atom_to_index(&atom, resource, transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", atom, e))?;
            }
            crate::search::index_resource(self, resource, transaction)?;
        }
        // The snapshot in `Tree::LoroSnapshots` is the authoritative CRDT
        // state. Store it for every CRDT resource in the same transaction as
        // the `Tree::Resources` row, so every row is paired with a current
        // snapshot. Commits are native (immutable, not CRDT): they get no
        // snapshot and keep their `loroUpdate` payload in the row.
        if !subject.is_commit_did() {
            let snapshot = match snapshot {
                Some(snapshot) => snapshot,
                None => resource.build_state_doc()?.export_snapshot(),
            };
            transaction.push(Operation {
                tree: Tree::LoroSnapshots,
                method: Method::Insert,
                key: subject_str.as_bytes().to_vec(),
                val: Some(snapshot),
            });
        }
        // The row (a projection without `loroUpdate`), its DID routing hint
        // and the removal of other identifier spellings: the same write a
        // commit makes.
        self.add_resource_tx(resource, transaction)?;
        Ok(())
    }
}
