//! Core storage access, events, transactions and removal for [`Db`].

use super::*;

impl Db {
    /// Cheap local-presence check (no network fetch): is this subject's resource
    /// already stored locally? Used by managed-node replication to skip drives it
    /// already hosts before resolving/pulling them from a peer.
    pub fn has_resource_locally(&self, subject: &str) -> bool {
        let key = crate::identifiers::canonicalize_scheme(subject);
        self.kv
            .contains_key(Tree::Resources, key.as_bytes())
            .unwrap_or(false)
    }

    /// The stored Loro snapshot of `subject`, under whichever spelling the
    /// caller used: normalized to the `pure_id` key writers store it under.
    pub fn get_loro_snapshot(&self, subject: &Subject) -> Option<Vec<u8>> {
        self.get_loro_snapshot_bytes(&self.normalize_subject(subject).pure_id())
    }

    pub(crate) fn get_loro_snapshot_bytes(&self, subject: &str) -> Option<Vec<u8>> {
        let key = crate::identifiers::canonicalize_scheme(subject);
        self.kv
            .get(Tree::LoroSnapshots, key.as_bytes())
            .ok()
            .flatten()
    }

    /// Sets a function that is called whenever a [Commit::apply] is called.
    /// This can be used to listen to events.
    pub fn set_handle_commit(&mut self, on_commit: HandleCommit) {
        self.on_commit = Some(Arc::new(on_commit));
    }

    /// Removes `subject` and its children in one transaction and tombstones
    /// them, returning what was removed so the caller can announce it once it
    /// has decided how: `remove_resource` sends a plain `DbEvent::Destroyed`
    /// for each, `apply_commit` wraps the destroyed subject in its signed
    /// destroy commit and announces only the children this way.
    pub(super) async fn remove_applied(
        &self,
        subject: &Subject,
    ) -> AtomicResult<Vec<RemovedSubject>> {
        let mut transaction = Transaction::new();
        let mut removed = Vec::new();
        self.recursive_remove(subject, &mut transaction, &mut removed, None)
            .await?;
        self.apply_transaction(&mut transaction)?;
        // Tombstone every removed subject so bulk sync (Iroh / WS `SYNC`)
        // does not resurrect them from a peer that still holds a stale copy.
        // Only after the apply succeeded: a tombstone for a resource that is
        // still present would suppress it forever.
        for r in &removed {
            crate::sync::tombstones::record_tombstone(self, &r.subject.pure_id());
        }
        Ok(removed)
    }

    /// Subscribe to all DB events (changes, deletions).
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<DbEvent> {
        self.db_events.subscribe()
    }

    /// Presence arriving from peers. See [`EphemeralEvent`].
    pub fn subscribe_ephemeral(&self) -> tokio::sync::broadcast::Receiver<EphemeralEvent> {
        self.ephemeral_events.subscribe()
    }

    /// Publish presence received from a peer. Send failure means nobody is
    /// listening (no websocket clients on this node) — expected, not an error.
    pub fn publish_ephemeral(&self, event: EphemeralEvent) {
        let _ = self.ephemeral_events.send(event);
    }

    /// Finds resource by Subject, return PropVals HashMap
    #[instrument(skip_all)]
    pub(crate) fn get_propvals(&self, subject: &str) -> AtomicResult<PropVals> {
        match self.kv.get(Tree::Resources, subject.as_bytes())? {
            Some(binpropval) => {
                let propval: PropVals = decode_propvals(&binpropval)?;
                Ok(propval)
            }
            None => Err(AtomicError::not_found(format!(
                "Resource {} not found",
                subject
            ))),
        }
    }

    /// The stored row of `subject`, and the key it is stored under: the
    /// `atomic:` spelling. Opening a store rewrites every `did:ad:` key
    /// (`canonical_scheme::migrate_if_needed`) and every write keys by
    /// [`Subject::pure_id`], so a legacy spelling only needs normalizing.
    pub(super) fn get_propvals_canonical(&self, subject: &str) -> AtomicResult<(String, PropVals)> {
        let key = crate::identifiers::canonicalize_scheme(subject);
        let propvals = self.get_propvals(&key)?;
        Ok((key, propvals))
    }

    /// A resource built only from its last-committed materialized propvals,
    /// **skipping the Loro snapshot re-decode** that [`Storelike::get_resource`]
    /// performs. That decode decompresses a resource's full CRDT history and can
    /// cost tens of milliseconds each — fine for a single fetch, ruinous when a
    /// directory listing reads hundreds of resources just to project their names
    /// and sizes. The propvals are the materialized state after the last commit,
    /// which is exactly what a read-only listing needs; do not use this where
    /// CRDT-authoritative state matters. Subject normalization (incl. the DID
    /// drive hint) matches `get_resource`, so ids/subjects stay consistent.
    pub fn get_resource_shallow(&self, subject: &Subject) -> AtomicResult<Resource> {
        self.fetch_counters
            .get_resource_shallow
            .fetch_add(1, Ordering::Relaxed);
        let normalized = self.normalize_subject(subject);
        let (subject_str, propvals) = self.get_propvals_canonical(&normalized.pure_id())?;

        let mut res_subject = normalized.clone();
        if let Subject::Did {
            drive_hint: None, ..
        } = &res_subject
        {
            if let Some(hint) = self.get_did_mapping_hint(&subject_str) {
                res_subject = res_subject.set_drive_hint(hint);
            }
        }

        Ok(Resource::from_propvals(propvals, res_subject))
    }

    /// Zero the fetch counters. Tests call this after fixture setup so the
    /// subsequent query's counts aren't mixed with bootstrap / save traffic.
    pub fn reset_fetch_counters(&self) {
        self.fetch_counters.get_resource.store(0, Ordering::Relaxed);
        self.fetch_counters
            .get_resource_shallow
            .store(0, Ordering::Relaxed);
    }

    /// Full-decode [`Storelike::get_resource`] calls since the last reset.
    pub fn get_resource_call_count(&self) -> usize {
        self.fetch_counters.get_resource.load(Ordering::Relaxed)
    }

    /// Propvals-only [`Db::get_resource_shallow`] calls since the last reset.
    pub fn get_resource_shallow_call_count(&self) -> usize {
        self.fetch_counters
            .get_resource_shallow
            .load(Ordering::Relaxed)
    }

    /// Flushes the current state to disk.
    pub fn flush(&self) -> AtomicResult<()> {
        self.kv.flush()
    }

    /// Removes the DB and all content from disk.
    /// WARNING: This is irreversible.
    #[cfg(feature = "db-sled")]
    pub fn clear_all_danger(self) -> AtomicResult<()> {
        let path = self.path.clone();
        drop(self);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    pub(super) fn map_kv_item_to_resource(
        subject_bytes: &[u8],
        resource_bin: &[u8],
        include_external: bool,
        base_domain: Option<&str>,
    ) -> Option<Resource> {
        let subject: String = String::from_utf8_lossy(subject_bytes).to_string();

        let subject_obj = Subject::from_raw(&subject, base_domain);

        if !include_external && !subject_obj.is_local() {
            return None;
        }

        let propvals: PropVals = decode_propvals(resource_bin)
            .unwrap_or_else(|e| panic!("{}. {}", corrupt_db_message(&subject), e));

        Some(Resource::from_propvals(propvals, subject_obj))
    }

    /// Apply made changes to the store.
    /// After a successful KV apply, scans the transaction for writes to
    /// `Tree::QueryMembers` and broadcasts a `DbEvent::QueryMembershipChanged`
    /// for each one. Subscribers (e.g. `CommitMonitor`'s listener task) use
    /// these to push live `QUERY_UPDATE` notifications without re-deriving
    /// membership from the raw atom stream.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn apply_transaction(&self, transaction: &mut Transaction) -> AtomicResult<()> {
        self.apply_transaction_with_source(transaction, None)
    }

    pub(super) fn apply_transaction_with_source(
        &self,
        transaction: &mut Transaction,
        source_id: Option<&str>,
    ) -> AtomicResult<()> {
        // Persist delivery before publishing the wake-up. A crashed or lagging
        // subscriber can replay the queue; it is never the owner of the event.
        // A sorted member moving positions has a delete and insert in this
        // batch, which is not a membership edge.
        let mut edges = std::collections::BTreeMap::new();
        for op in transaction
            .iter()
            .filter(|op| op.tree == Tree::QueryMembers)
        {
            if let Some((query, subject)) = query_index::parse_members_key_id_subject(&op.key) {
                let delta = edges.entry((query, subject)).or_insert(0i32);
                *delta += if matches!(op.method, Method::Insert) {
                    1
                } else {
                    -1
                };
            }
        }
        for ((query, subject), delta) in edges {
            if delta == 0 {
                continue;
            }
            let edge = plugin_trigger::Edge::of(delta > 0);
            for (key, trigger) in self.plugin_triggers_for_query(&query)? {
                if !trigger.wants(edge) {
                    continue;
                }
                let event = plugin_trigger::QueuedEvent {
                    id: format!(
                        "{:020}-{}",
                        crate::utils::now(),
                        crate::utils::random_string(24)
                    ),
                    key,
                    subject: subject.clone(),
                    edge,
                    at: crate::utils::now(),
                    verdict: None,
                    waiting_for_review: false,
                    authorization: None,
                };
                transaction.push(Operation {
                    tree: Tree::PluginMeta,
                    method: Method::Insert,
                    key: format!("plugin-event/v1/{}", event.id).into_bytes(),
                    val: Some(serde_json::to_vec(&event)?),
                });
            }
        }
        self.kv.apply_batch(transaction)?;

        for op in transaction.iter() {
            if op.tree != Tree::QueryMembers {
                continue;
            }
            // Op key layout: `query_id(16B) || sort_key || 0x00 0x00 || subject`.
            let Some((query_id, subject)) = query_index::parse_members_key_id_subject(&op.key)
            else {
                continue;
            };
            let added = matches!(op.method, crate::db::trees::Method::Insert);
            let _ = self.db_events.send(DbEvent::QueryMembershipChanged {
                query_id,
                subject,
                added,
                source_id: source_id.map(str::to_string),
            });
        }
        Ok(())
    }

    /// Recursively removes a resource and its children from the database.
    /// `removed` collects every deleted subject so the caller can tombstone
    /// and announce them after the transaction is applied — nothing is sent on
    /// `db_events` from here, since the removal has not happened yet.
    /// `inherited_drive` is the drive of the resource whose cascade brought us
    /// here. A child that carries no `drive` of its own — anything created
    /// before the server stamped it — is still in its parent's drive, and the
    /// removal has to name one or it reaches no subscriber.
    pub(super) async fn recursive_remove(
        &self,
        subject: &Subject,
        transaction: &mut Transaction,
        removed: &mut Vec<RemovedSubject>,
        inherited_drive: Option<Subject>,
    ) -> AtomicResult<()> {
        // Key by `pure_id()` — that is how resources and Loro snapshots are
        // stored (`add_resource_tx`, `apply_commit`). Looking up by the raw
        // `to_string()` (which may carry `?drive=` params) would miss the
        // row entirely for DID subjects with a drive hint.
        let subject_str = subject.pure_id();
        if let Ok((found_key, found)) = self.get_propvals_canonical(&subject_str) {
            let resource = Resource::from_propvals(found, subject.clone());
            transaction.push(Operation::remove_resource(&found_key));
            transaction.push(Operation::remove_loro_snapshot(&found_key));
            // Read the drive now, while the resource still exists: a listener
            // reacting to the removal cannot look it up any more.
            let drive = resource.get_drive().or(inherited_drive);
            removed.push(RemovedSubject {
                subject: subject.without_params(),
                drive: drive.clone(),
            });
            let mut children = resource.get_children(self).await?;
            for child in children.iter_mut() {
                // Because the function is async we need to box it to use recursion.
                Box::pin(self.recursive_remove(
                    child.get_subject(),
                    transaction,
                    removed,
                    drive.clone(),
                ))
                .await?;
            }
            for (prop, val) in resource.get_propvals() {
                let remove_atom = crate::Atom::new(subject.clone(), prop.clone(), val.clone());
                self.remove_atom_from_index(&remove_atom, &resource, transaction)?;
            }
            crate::search::unindex_subject(self, &subject_str, transaction)?;
            crate::search::unindex_subject(self, &found_key, transaction)?;
        } else {
            return Err(format!(
                "Resource {} could not be deleted, because it was not found in the store.",
                subject
            )
            .into());
        }
        Ok(())
    }

    /// Announces subjects `recursive_remove` collected, once the transaction
    /// holding their removal has been applied. Any earlier and a listener
    /// (the WS fan-out in `atomic-server`'s `CommitMonitor`, a peer
    /// transport) would tell clients about a deletion that can still fail or
    /// roll back, and hear of a child before the parent whose destroy caused
    /// it. Removals no commit authorises carry no `commit_json`, so they are
    /// not propagated live to peers; see [`DbEvent::Destroyed`].
    pub(super) fn emit_destroyed<'a>(&self, removed: impl IntoIterator<Item = &'a RemovedSubject>) {
        for r in removed {
            let _ = self.db_events.send(DbEvent::Destroyed {
                subject: r.subject.clone(),
                drive: r.drive.clone(),
                source_id: None,
                from_commit: false,
                commit_json: None,
            });
        }
    }
}
