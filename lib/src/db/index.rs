//! Atom indexing and search for [`Db`].

use super::*;

impl Db {
    #[instrument(level = "trace", skip_all)]
    pub(super) fn add_atom_to_index(
        &self,
        atom: &Atom,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        for mut index_atom in atom.to_indexable_atoms() {
            // Index by resource identity, even when an older peer sent the
            // same subject using the legacy identifier scheme.
            index_atom.subject = index_atom.subject.pure_id().into();
            add_atom_to_valpropsub_index(&index_atom, transaction)?;
            add_atom_to_prop_val_sub_index(&index_atom, transaction)?;
            // Also update the query index to keep collections performant
            check_if_atom_matches_watched_query_filters(
                self,
                &index_atom,
                atom,
                false,
                resource,
                transaction,
            )
            .map_err(|e| format!("Failed to check_if_atom_matches_watched_collections. {}", e))?;
        }
        Ok(())
    }

    /// Index the propvals the server derives for a resource rather than
    /// reading them off the commit.
    ///
    /// `createdAt` / `createdBy` / `parent` / `drive` can all reach a resource
    /// without ever being atoms of its commit: `validate_and_build_response`
    /// stamps `drive` from the parent via `set_unsafe`, and
    /// `materialize_genesis_metadata` fills the rest in from the inline
    /// certificate. Both mutate `resource_new` — which is what gets stored —
    /// but neither touches `add_atoms`, and `apply_commit` indexes `add_atoms`.
    /// So these landed in the resource projection and never in the index.
    ///
    /// `drive` is the one that bites, because nothing else ever sets it: its
    /// index held only the rare resource whose commit named it explicitly. A
    /// drive-scoped filtered query then estimates that constraint as the
    /// cheapest candidate source (one entry), verifies just that one resource,
    /// and files an empty member list — which `query_complex` then caches for
    /// good, since it rebuilds only for filters that are not yet watched.
    ///
    /// Runs on every commit, not just the creating one: the values are
    /// immutable, so re-indexing is idempotent, and it lets a resource written
    /// before this existed heal on its next edit instead of waiting for a full
    /// index rebuild.
    pub(super) fn index_genesis_derived_atoms(
        &self,
        commit_atoms: &[Atom],
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        const DERIVED_PROPS: [&str; 4] = [
            urls::CREATED_AT,
            urls::CREATED_BY,
            urls::PARENT,
            urls::DRIVE_PROP,
        ];

        for property in DERIVED_PROPS {
            // The commit set it itself — already indexed above.
            if commit_atoms.iter().any(|atom| atom.property == property) {
                continue;
            }

            let Ok(value) = resource.get(property) else {
                continue;
            };

            let atom = Atom::new(
                resource.get_subject().clone(),
                property.into(),
                value.clone(),
            );
            self.add_atom_to_index(&atom, resource, transaction)?;
        }

        Ok(())
    }

    pub(super) fn add_resource_tx(
        &self,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        let subject = self.normalize_subject(resource.get_subject());
        let subject_str = subject.pure_id();
        let mut propvals = resource.get_propvals().clone();
        canonical_scheme::canonicalize_propvals(&mut propvals);

        // Persist DID routing hint if available
        if let Subject::Did {
            drive_hint: Some(hint),
            ..
        } = &subject
        {
            transaction.push(Operation {
                tree: Tree::DidMapping,
                method: Method::Insert,
                key: subject_str.as_bytes().to_vec(),
                val: Some(hint.as_bytes().to_vec()),
            });
        }

        // The `loroUpdate` propval is the resource's CRDT snapshot — it
        // belongs in `Tree::LoroSnapshots`, not
        // duplicated inside the resource blob, which is now a pure derived
        // projection. Commit resources are the exception: a commit's
        // `loroUpdate` is its signed payload and must stay in the blob.
        let resource_bin = if subject.is_commit_did() {
            encode_propvals(&propvals)?
        } else {
            let mut projection = propvals.clone();
            projection.remove(crate::urls::LORO_UPDATE);
            encode_propvals(&projection)?
        };

        transaction.push(Operation {
            tree: Tree::Resources,
            method: Method::Insert,
            key: subject_str.as_bytes().to_vec(),
            val: Some(resource_bin),
        });
        Ok(())
    }

    #[instrument(skip_all)]
    pub(super) fn all_index_atoms(&self, include_external: bool) -> IndexIterator {
        Box::new(
            self.all_resources(include_external)
                .flat_map(|resource| {
                    let index_atoms: Vec<IndexAtom> = resource
                        .to_atoms()
                        .iter()
                        .flat_map(|atom| atom.to_indexable_atoms())
                        .collect();
                    index_atoms
                })
                .map(Ok),
        )
    }

    /// Constructs the value index from all resources in the store. Could take a while.
    pub fn build_index(&self, include_external: bool) -> AtomicResult<()> {
        tracing::info!("Building index (this could take a few minutes for larger databases)");
        for (count, r) in self.all_resources(include_external).enumerate() {
            let mut transaction = Transaction::new();
            for atom in r.to_atoms_iter() {
                self.add_atom_to_index(&atom, &r, &mut transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", atom, e))?;
            }
            crate::search::index_resource(self, &r, &mut transaction)?;
            self.apply_transaction(&mut transaction)
                .map_err(|e| format!("Failed to commit transaction. {}", e))?;

            if count % 1000 == 0 {
                tracing::info!("Building index, applied transaction: {}", count);
            }

            if count % 10000 == 0 {
                tracing::info!("Building index, flushing to disk");
                self.kv.flush()?;
            }
        }

        tracing::info!("Building index finished!");
        Ok(())
    }

    /// Ranked full-text search over the local KV index.
    pub fn search_hits(
        &self,
        query: &str,
        opts: &crate::client::search::SearchOpts,
    ) -> AtomicResult<Vec<crate::search::SearchHit>> {
        crate::search::query(self, query, opts)
    }

    /// Removes all values from the indexes.
    pub fn clear_index(&self) -> AtomicResult<()> {
        self.kv.clear_tree(Tree::ValPropSub)?;
        self.kv.clear_tree(Tree::PropValSub)?;
        self.kv.clear_tree(Tree::QueryMembers)?;
        self.kv.clear_tree(Tree::WatchedQueries)?;
        Ok(())
    }

    /// Reset the watched-query registry (`Tree::WatchedQueries` + the
    /// in-memory `watched_queries_by_drive` map). Called on server
    /// startup: every restart drops every WS connection, so any
    /// previously-registered filter is now an orphan with no live
    /// subscriber. Without this, e2e suites leak filters across runs
    /// (each test's drive is unique, so each filter is unique), and
    /// `check_if_atom_matches_watched_query_filters` iterates a growing
    /// pile of dead entries on every commit — observed to reach 13k+
    /// filters, slowing rapid-save tests past their timeout. Active
    /// subscribers re-register their filters on reconnect, so the
    /// map repopulates organically without surprising anyone.
    pub fn clear_watched_queries(&self) -> AtomicResult<()> {
        self.kv.clear_tree(Tree::WatchedQueries)?;
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            map.clear();
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub(super) fn remove_atom_from_index(
        &self,
        atom: &Atom,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        for mut index_atom in atom.to_stored_index_atoms() {
            index_atom.subject = index_atom.subject.pure_id().into();
            for op in Operation::remove_atom_from_legacy_indexes(&index_atom) {
                transaction.push(op);
            }
            if atom.property == urls::GENESIS {
                continue;
            }
            transaction.push(Operation::remove_atom_from_reference_index(&index_atom));
            transaction.push(Operation::remove_atom_from_prop_val_sub_index(&index_atom));

            check_if_atom_matches_watched_query_filters(
                self,
                &index_atom,
                atom,
                true,
                resource,
                transaction,
            )
            .map_err(|e| format!("Checking atom went wrong: {}", e))?;
        }
        Ok(())
    }
}
