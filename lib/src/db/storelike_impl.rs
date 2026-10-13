//! The [`Storelike`] implementation for [`Db`].

use super::*;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Storelike for Db {
    fn normalize_subject(&self, subject: &Subject) -> Subject {
        Subject::from_raw(subject.as_str(), self.get_base_domain().as_deref())
    }

    fn sync_policy(&self) -> Arc<dyn crate::sync::policy::SyncPolicy> {
        // The installed policy (managed) or the permissive default. Reads the
        // field directly to avoid resolving against the inherent method of the
        // same name.
        self.sync_policy
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| Arc::new(crate::sync::policy::OpenPolicy))
    }

    fn get_active_drive(&self) -> Option<String> {
        self.get_active_drive()
    }

    fn set_active_drive(&self, drive: &str) -> AtomicResult<()> {
        self.set_active_drive(drive)
    }

    fn clear_tombstone(&self, subject: &str) {
        crate::sync::tombstones::clear_tombstone(self, subject)
    }

    fn clear_default_agent(&self) {
        self.clear_default_agent()
    }

    /// Adds Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    /// Validates datatypes and required props presence.
    #[instrument(skip_all)]
    async fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        // Start with a nested HashMap, containing only strings.
        let mut map: HashMap<Subject, Resource> = HashMap::new();
        for atom in atoms {
            match map.get_mut(&atom.subject) {
                // Resource exists in map
                Some(resource) => {
                    resource
                        .set_string(atom.property.clone(), &atom.value.to_string(), self)
                        .await
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.to_string());
                    resource
                        .set_string(atom.property.clone(), &atom.value.to_string(), self)
                        .await
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                    map.insert(atom.subject, resource);
                }
            }
        }
        for resource in map.values() {
            self.add_resource(resource).await?
        }
        self.kv.flush()?;
        Ok(())
    }

    /// Maps a host (domain/subdomain) to a Drive DID.
    fn add_drive_mapping(&self, host: &str, drive_did: &Value) -> AtomicResult<()> {
        self.add_drive_mapping(host, drive_did)
    }

    /// Removes the drive mapping for a given host.
    fn remove_drive_mapping(&self, host: &str) -> AtomicResult<()> {
        self.remove_drive_mapping(host)
    }

    /// Returns the base domain of the store, e.g. "https://atomicdata.dev".
    fn get_base_domain(&self) -> Option<String> {
        self.base_domain.clone()
    }

    fn set_base_url(&self, _url: &str) {
        // Since Db is mostly immutable and cloned per-request in multi-tenant mode,
        // setting base_url on the original instance might not be what's intended
        // in all cases, but for CLI usage it is.
        // However, we don't have a Mutex for base_domain in Db.
        // Let's just say it's not supported for Db yet if it's not a clone.
        // Actually, for CLI it's usually just initialized once.
        tracing::warn!(
            "set_base_url called on Db, but it is not supported to change it after initialization. Use clone_with_url instead."
        );
    }

    #[instrument(skip_all)]
    async fn add_resource_opts(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
    ) -> AtomicResult<()> {
        let _import_guard = if let Some((parent, id)) = crate::import_identity::identity(resource) {
            let guard = self
                .subject_locks
                .lock(&format!(
                    "import-identity:{}",
                    serde_json::to_string(&(parent.pure_id(), &id))?
                ))
                .await;
            if let Some(found) = crate::import_identity::find_existing(self, &parent, &id).await? {
                if Subject::from(found).pure_id() != resource.get_subject().pure_id() {
                    return Err("Import identity already exists; preview again instead of creating a duplicate".into());
                }
            }
            Some(guard)
        } else {
            None
        };
        self.persist_resource_projection(
            resource,
            check_required_props,
            update_index,
            overwrite_existing,
            None,
        )
        .await
    }

    /// Apply a single signed Commit to the Db.
    /// Creates, edits or destroys a resource.
    /// Allows for control over which validations should be performed.
    /// Returns the generated Commit, the old Resource and the new Resource.
    #[tracing::instrument(skip_all)]
    async fn apply_commit(
        &self,
        commit: Commit,
        opts: &CommitOpts,
    ) -> AtomicResult<CommitResponse> {
        let store = self;

        // Persisting a commit is a read-modify-write: `validate_and_build_response`
        // reads the resource's stored Loro snapshot, applies this commit's ops to
        // it, and the transaction below writes the result back as a *replace*. A
        // peer update landing in that window would be overwritten and lost, so the
        // whole span is exclusive per subject. See `subject_lock` for why this is
        // a lock rather than a merge, and for the no-reentrancy invariant.
        let subject_guard = store.subject_locks.lock(&commit.subject.pure_id()).await;

        // A signed destroy is durable (tombstone envelope, re-sent by bulk
        // sync). If this exact commit is already stored here and the subject
        // exists again, the subject was recreated after the destroy and this
        // is a replay, not a delete. Local presence only — a commit DID must
        // never be resolved over the network.
        if commit.destroy.unwrap_or(false) && opts.validate_rights {
            if let Some(sig) = commit.signature.as_ref() {
                let commit_id = crate::identifiers::commit_subject(sig);
                if store.has_resource_locally(&commit_id)
                    && store.has_resource_locally(&commit.subject.pure_id())
                {
                    return Err(format!(
                        "Destroy commit for {} was already applied here; refusing replay",
                        commit.subject
                    )
                    .into());
                }
            }
        }

        let commit_response = commit.validate_and_build_response(opts, store).await?;

        if let Some(old) = &commit_response.resource_old {
            if old.get(crate::urls::IMPORT_RESOLUTION).is_ok() {
                let same_identity = commit_response.resource_new.as_ref().is_some_and(|new| {
                    crate::import_identity::identity(old) == crate::import_identity::identity(new)
                });
                if !same_identity {
                    return Err(
                        "A reviewed primary record must retain its identity and history".into(),
                    );
                }
            }
        }
        let import_guard = if let Some(new) = &commit_response.resource_new {
            crate::import_identity::validate_baseline(commit_response.resource_old.as_ref(), new)?;
            crate::import_identity::validate_reference_review(
                commit_response.resource_old.as_ref(),
                new,
            )?;
            if let Some((parent, id)) = crate::import_identity::identity(new) {
                let guard = self
                    .subject_locks
                    .lock(&format!(
                        "import-identity:{}",
                        serde_json::to_string(&(parent.pure_id(), &id))?
                    ))
                    .await;
                if let Some(found) = crate::import_identity::validate_candidate(
                    self,
                    commit_response.resource_old.as_ref(),
                    new,
                )
                .await?
                {
                    if Subject::from(found).pure_id() != new.get_subject().pure_id() {
                        return Err("Import identity already exists; preview again instead of creating a duplicate".into());
                    }
                }
                Some(guard)
            } else {
                None
            }
        } else {
            None
        };
        let mut transaction = Transaction::new();

        let mut root_subject: Option<String> = None;

        // BEFORE APPLY COMMIT HANDLERS
        let resource_before = commit_response
            .resource_new
            .as_ref()
            .or(commit_response.resource_old.as_ref());

        if let Some(resource) = resource_before {
            let extenders = self
                .class_extenders
                .read()
                .map_err(|e| format!("Failed to read class extenders: {}", e))?
                .clone();
            for extender in extenders.iter() {
                if extender.resource_has_extender(resource)? {
                    if !extender.can_extend(resource) {
                        // A plugin may not extend a plugin. Silently skipping
                        // read as "the hook did not run" with no way to tell
                        // this apart from a class mismatch.
                        tracing::debug!(
                            resource = %resource.get_subject(),
                            "class extender skipped: a plugin cannot extend another plugin"
                        );
                        continue;
                    }

                    let (is_in_scope, cached_root) =
                        extender.check_scope(resource, self, root_subject).await?;

                    root_subject = cached_root;

                    if !is_in_scope {
                        continue;
                    }

                    let Some(handler) = extender.before_commit.as_ref() else {
                        continue;
                    };

                    let fut = (handler)(CommitExtenderContext {
                        store,
                        commit: &commit_response.commit,
                        resource,
                        is_new: commit_response.resource_old.is_none(),
                        changed_props: &commit_response.changed_props,
                    });
                    fut.await?;
                }
            }
        }

        // Commits are signed envelopes, not a queryable class. Keep genesis
        // and rights/parent/destroy; drop ordinary content certificates.
        if commit_response.auth_impact().is_critical() {
            store.add_resource_tx(&commit_response.commit_resource, &mut transaction)?;
            // A creation's commit is found by its id (it names the resource),
            // so its atoms stay out of the indexes: five rows and about
            // 0.5 KB for every new resource that no query asks for. Later
            // critical commits (rights, parent, destroy) stay queryable by
            // the subject they are about.
            if !commit_response.creates_resource() {
                for atom in commit_response.commit_resource.to_atoms() {
                    store.add_atom_to_index(
                        &atom,
                        &commit_response.commit_resource,
                        &mut transaction,
                    )?;
                }
            }
        }

        // The signed envelope itself lives in `Tree::Envelopes`, keyed by the
        // resource it is about, in the same transaction as the state it
        // signs. This is what lets any node that holds the resource say who
        // signed it, independent of the commit rows above.
        crate::envelopes::record_ops(store, &commit_response, &mut transaction)?;

        // Every subject a destroy removes below (the resource and its
        // cascade-deleted children). Tombstoned and announced once the
        // transaction has landed; empty for anything but a destroy.
        let mut removed: Vec<RemovedSubject> = Vec::new();

        match (&commit_response.resource_old, &commit_response.resource_new) {
            (None, None) if !commit_response.commit.destroy.unwrap_or(false) => {
                return Err("Neither an old nor a new resource is returned from the commit - something went wrong.".into());
            }
            (None, None) => {}
            (Some(old), None) => {
                let normalized_commit_subject =
                    self.normalize_subject(&commit_response.commit.subject);
                if old.get_subject().as_str() != normalized_commit_subject.as_str() {
                    return Err(format!(
                        "Commit for {} removed a different resource ({}) - refusing to apply.",
                        normalized_commit_subject,
                        old.get_subject()
                    )
                    .into());
                }
                if !commit_response.commit.destroy.unwrap_or(false) {
                    return Err(format!(
                        "Resource {} was removed but `commit.destroy` was not set.",
                        normalized_commit_subject
                    )
                    .into());
                }
                let subject: Subject = commit_response.commit.subject.clone();
                // Queue the removal (resource, Loro snapshot, index and search
                // rows, cascaded children) into the same transaction as the
                // envelope row `record_ops` queued above, so the signed
                // destroy — what `SYNC_DIFF.removeCommits` carries — lands
                // with the deletion it signs, or not at all. Tombstones and
                // the children's `Destroyed` events follow the apply below.
                self.recursive_remove(&subject, &mut transaction, &mut removed, None)
                    .await?;
            }
            _ => {}
        };

        if let Some(new) = &commit_response.resource_new {
            self.add_resource_tx(new, &mut transaction)?;

            // Persist the Loro snapshot so VV-based sync can find it.
            // Use pure_id() (strips query params/drive hints) for a canonical key.
            if let Some(snapshot) = new.materialized_state() {
                transaction.push(trees::Operation {
                    tree: trees::Tree::LoroSnapshots,
                    method: trees::Method::Insert,
                    key: new.get_subject().pure_id().as_bytes().to_vec(),
                    val: Some(snapshot),
                });
            }
        }

        // A destroy's `recursive_remove` above already queued the index and
        // search removals for every stored atom of the subject (and its
        // children); queuing them again here would only duplicate the same
        // deletes and re-run the watched-query checks.
        let removal_queued = !removed.is_empty();

        if opts.update_index {
            if let Some(old) = &commit_response.resource_old {
                if !removal_queued {
                    for atom in &commit_response.remove_atoms {
                        store
                            .remove_atom_from_index(atom, old, &mut transaction)
                            .map_err(|e| {
                                format!("Error removing atom from index: {e}  Atom: {e}")
                            })?
                    }
                }
            }
            if let Some(new) = &commit_response.resource_new {
                for atom in &commit_response.add_atoms {
                    store
                        .add_atom_to_index(atom, new, &mut transaction)
                        .map_err(|e| format!("Error adding atom to index: {e}  Atom: {e}"))?
                }

                store.index_genesis_derived_atoms(
                    &commit_response.add_atoms,
                    new,
                    &mut transaction,
                )?;
                if let Some(old) = &commit_response.resource_old {
                    if !removal_queued {
                        query_index::refile_sort_order_entries(store, old, new, &mut transaction)?;
                    }
                }
                crate::search::index_resource(store, new, &mut transaction)?;
            }
            if commit_response.resource_new.is_none() && !removal_queued {
                if let Some(old) = &commit_response.resource_old {
                    crate::search::unindex_subject(
                        store,
                        &old.get_subject().pure_id(),
                        &mut transaction,
                    )?;
                }
            }
        }

        store.apply_transaction_with_source(
            &mut transaction,
            commit_response.source_id.as_deref(),
        )?;

        // An import receipt may be the only evidence available when retrying
        // after a process kill. Persist identity, snapshot and index before ACK.
        if [&commit_response.resource_new, &commit_response.resource_old]
            .into_iter()
            .filter_map(|r| r.as_ref())
            .any(|r| {
                crate::import_identity::identity(r).is_some()
                    || r.get(crate::urls::IMPORT_REFERENCE_REVIEW).is_ok()
            })
        {
            store.flush()?;
        }

        // Tombstone every subject the destroy removed, so bulk sync (Iroh /
        // WS `SYNC`) does not resurrect them from a peer that still holds a
        // stale copy. Only after the transaction above succeeded: a tombstone
        // for a resource that is still present would suppress it forever.
        for r in &removed {
            crate::sync::tombstones::record_tombstone(store, &r.subject.pure_id());
        }

        // Announce the cascade-deleted children now that the removal has
        // landed. The destroyed subject itself is announced below, wrapped in
        // the signed destroy commit, so it is left out here.
        let top_level = commit_response.commit.subject.pure_id();
        store.emit_destroyed(removed.iter().filter(|r| r.subject.pure_id() != top_level));

        // Notify subscribers
        let subject = commit_response.commit.subject.without_params();
        let is_destroy = commit_response.commit.destroy.unwrap_or(false);
        let event = if is_destroy {
            // The signed destroy itself, so a peer transport can forward it
            // as a `COMMIT` frame. Serialisation failure is not fatal for the
            // local apply; the event just carries no commit and the destroy
            // reaches peers on the next bulk reconcile instead.
            let commit_json = commit_response.commit_resource.to_json_ad(None).ok();
            DbEvent::Destroyed {
                subject,
                drive: commit_response
                    .resource_old
                    .as_ref()
                    .and_then(|old| old.get_drive()),
                source_id: commit_response.source_id.clone(),
                from_commit: true,
                commit_json,
            }
        } else {
            DbEvent::Changed {
                subject,
                delta: commit_response.fanout_delta().map(<[u8]>::to_vec),
                source_id: commit_response.source_id.clone(),
                is_new: commit_response.resource_old.is_none(),
                from_commit: true,
            }
        };
        let _ = store.db_events.send(event);

        store.handle_commit(&commit_response);

        // The read-modify-write this lock protects (read snapshot, apply ops,
        // write back the transaction above) is done. Release it before running
        // AFTER APPLY COMMIT HANDLERS: an `after_commit` extender is allowed to
        // issue its own follow-up commit to the same subject (see
        // `atomic_plugin::commit` / `server/src/plugins/wasm.rs`'s `commit`
        // host function), which re-enters `apply_commit` and tries to lock the
        // same subject again. Holding the guard across that call would be the
        // exact self-reentrancy `subject_lock` warns against and deadlocks the
        // request forever, since nothing else can ever release a lock this
        // task already holds.
        drop(import_guard);
        drop(subject_guard);

        // A Lens starts (or, destroyed, stops) applying. Not part of the
        // commit: it cannot fail it.
        if is_destroy {
            if crate::identifiers::is_lens_id(&top_level) {
                store.unregister_lens(&top_level);
            }
        } else if let Some(new) = &commit_response.resource_new {
            store.note_lens_related(new).await;
        }

        // AFTER APPLY COMMIT HANDLERS
        // Commit has been checked and saved.
        // Here you can add side-effects, such as creating new Commits.
        //
        // Nothing below may fail the commit: it is already persisted, so an
        // error here would tell the client a saved change failed, and it would
        // retry or show an error for data that did change (#1848). Each
        // extender's failure is logged and the next extender still runs.
        let resource_after = commit_response
            .resource_new
            .as_ref()
            .or(commit_response.resource_old.as_ref());

        if let Some(resource) = resource_after {
            // A poisoned lock still holds a usable list; a panic elsewhere is
            // no reason to skip every after-commit side effect.
            let extenders = match self.class_extenders.read() {
                Ok(extenders) => extenders.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            for extender in extenders.iter() {
                let result = self
                    .run_after_commit_extender(
                        extender,
                        resource,
                        &commit_response,
                        &mut root_subject,
                    )
                    .await;
                if let Err(e) = result {
                    tracing::error!(
                        extender = extender.id.as_deref().unwrap_or("<anonymous>"),
                        plugin = extender.subject.as_deref(),
                        subject = %commit_response.commit.subject,
                        commit = %commit_response.commit_resource.get_subject(),
                        error = %e,
                        "after_commit extender failed; the commit is saved and still succeeds"
                    );
                }
            }
        }
        Ok(commit_response)
    }

    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        match self.default_agent.lock().unwrap().to_owned() {
            Some(agent) => Ok(agent),
            None => {
                Err("No agent set. Call db.setup() or db.load_agent_from_secret() first.".into())
            }
        }
    }

    #[instrument(skip_all)]
    async fn get_value(&self, subject: &str, property: &str) -> AtomicResult<Value> {
        self.get_resource(&subject.into())
            .await
            .and_then(|r| r.get(property).cloned())
    }

    #[instrument(skip_all)]
    async fn get_resource(&self, subject: &Subject) -> AtomicResult<Resource> {
        self.fetch_counters
            .get_resource
            .fetch_add(1, Ordering::Relaxed);
        let normalized = self.normalize_subject(subject);
        let subject_str = normalized.pure_id();
        if let Ok((subject_str, propvals)) = self.get_propvals_canonical(&subject_str) {
            let mut res_subject = normalized.clone();

            // If it's a DID and we don't have a hint in the requested subject,
            // check if we have one persisted in the did_mapping tree.
            if let Subject::Did {
                drive_hint: None, ..
            } = &res_subject
            {
                if let Some(hint) = self.get_did_mapping_hint(&subject_str) {
                    res_subject = res_subject.set_drive_hint(hint);
                }
            }

            let mut resource = Resource::from_propvals(propvals, res_subject);
            // Authoritative merged CRDT state (full oplog) lives in LoroSnapshots.
            // Propvals may carry a smaller incremental `loroUpdate` from the last commit.
            if let Some(snapshot) = self.get_loro_snapshot_bytes(&subject_str) {
                // A snapshot that cannot be read or applied is not fatal: the
                // read falls back to the (possibly stale) propval projection
                // stored beside it. It is still worth a warning, because a
                // silent fallback would hide corruption behind stale data.
                match crate::loro::AtomicLoroDoc::from_snapshot(&snapshot) {
                    // We already hold the exact bytes `doc` was just imported
                    // from — reuse them instead of having `apply_state_doc`
                    // re-export an equivalent snapshot. This is the hot path
                    // for every resource read (including once per member of
                    // a collection query), so the saved export is per-read,
                    // not one-off.
                    Ok(doc) => {
                        let lenses = self.lenses();
                        let lenses = (!lenses.is_empty()).then_some(&*lenses);
                        if let Err(e) = resource.apply_state_doc_with_lenses(doc, snapshot, lenses)
                        {
                            tracing::warn!(
                                subject = %subject_str,
                                error = %e,
                                "Failed to apply stored Loro snapshot; serving the stored propvals instead"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(
                        subject = %subject_str,
                        error = %e,
                        "Failed to read stored Loro snapshot; serving the stored propvals instead"
                    ),
                }
            }
            Ok(resource)
        } else {
            // Resolve the subject to a full URL for network operations
            let origin = self
                .get_base_domain()
                .unwrap_or_else(|| "http://localhost".to_string());
            let resolved_url = normalized.resolve(&origin);

            // If the resource is not found, it might be an endpoint.
            // This is checking if the subject matches one of the endpoints
            if let Ok(url) = url::Url::parse(&resolved_url) {
                if self.is_endpoint(&url) {
                    let agent_opt = self.get_default_agent().ok();
                    let for_agent = if let Some(agent) = &agent_opt {
                        ForAgent::from(agent)
                    } else {
                        ForAgent::Public
                    };
                    return Ok(self
                        .call_endpoint(&resolved_url, &for_agent)
                        .await?
                        .to_single());
                }
            }
            let resolved_url = normalized.resolve(&origin);
            let path = normalized.path();

            if normalized.is_did() || crate::identifiers::is_identifier_resolution_path(&path) {
                // If it's an agent identifier and not found locally, return a minimal resource
                // instead of an error. This is important for "just-in-time" agent registration.
                if normalized.is_agent_did()
                    || crate::identifiers::is_agent_id(path.trim_start_matches('/'))
                {
                    let lookup = path.strip_prefix('/').unwrap_or(&path);
                    if let Some(pubkey) = crate::identifiers::agent_public_key(lookup) {
                        // The same key has been spelled padded, unpadded,
                        // standard and URL-safe. A profile stored under another
                        // spelling is this agent: serve it, rather than
                        // synthesizing an empty twin beside it.
                        for spelling in crate::identifiers::agent_pubkey_spellings(pubkey)
                            .into_iter()
                            .skip(1)
                        {
                            let alias = Subject::from_raw(
                                &crate::identifiers::agent_subject(&spelling),
                                self.get_base_domain().as_deref(),
                            );
                            if self.has_stored_resource(&alias) {
                                let mut found = self.get_resource(&alias).await?;
                                found.set_subject(normalized.to_string());
                                return Ok(found);
                            }
                            let legacy_did = Subject::from_raw(
                                &format!("{}{}", crate::identifiers::DID_AD_AGENT_PREFIX, spelling),
                                self.get_base_domain().as_deref(),
                            );
                            if self.has_stored_resource(&legacy_did) {
                                let mut found = self.get_resource(&legacy_did).await?;
                                found.set_subject(normalized.to_string());
                                return Ok(found);
                            }
                        }
                        if let Ok(agent) = crate::agents::Agent::new_from_public_key(pubkey) {
                            if let Ok(mut resource) = agent.to_resource() {
                                // A lookup is not creation of an agent. There is
                                // no known creation date or signed history yet.
                                // Seed the same fallback ops on every read and
                                // device, otherwise a refresh replaces the cached
                                // profile with new ops and grows its vault backup.
                                resource.remove_propval(crate::urls::CREATED_AT)?;
                                let doc = crate::loro::AtomicLoroDoc::new();
                                doc.set_peer_id(0)?;
                                let ordered: std::collections::BTreeMap<_, _> =
                                    resource.get_propvals().iter().collect();
                                for (property, value) in ordered {
                                    doc.set_property(property, value)?;
                                }
                                doc.doc()
                                    .commit_with(loro::CommitOptions::new().timestamp(0));
                                resource.apply_state_doc(doc)?;
                                return Ok(resource);
                            }
                        }
                    }
                }

                if normalized.is_did()
                    || crate::identifiers::is_identifier_path_form(&resolved_url)
                    || crate::identifiers::is_atomic_identifier(&resolved_url)
                {
                    return Err(AtomicError::not_found(format!(
                        "DID Resource {} not found locally",
                        resolved_url
                    )));
                }

                return self
                    .handle_not_found(
                        &resolved_url,
                        format!("Resource {} not found locally", resolved_url).into(),
                        self.get_default_agent().ok().as_ref(),
                    )
                    .await;
            }

            // Only attempt a network fetch for external subjects.
            // Fetching a local URL would cause the server to request itself,
            // creating an infinite loop.
            //
            // `is_local()` alone is not enough: the canonical atomicdata.dev
            // vocabulary is deliberately kept `External` even on its own host
            // (see `Subject::CANONICAL_VOCABULARY_PREFIXES`), so on
            // atomicdata.dev a miss for `/properties/*` would fall through to a
            // network fetch of this very server. Anything served from our own
            // authority is ours whether or not it is `Internal`, so compare
            // authorities too — and ignore the scheme, since a store migrated
            // as `https://` must not self-fetch when served over `http://`.
            let base_domain = self.get_base_domain();
            let resolved_subject_obj = Subject::from_raw(&resolved_url, base_domain.as_deref());
            let is_own_authority = base_domain
                .as_deref()
                .map(|base| {
                    let strip = |s: &str| {
                        s.trim_start_matches("https://")
                            .trim_start_matches("http://")
                            .trim_end_matches('/')
                            .to_string()
                    };
                    let base_authority = strip(base);
                    let resolved = strip(&resolved_url);
                    resolved == base_authority
                        || resolved.starts_with(&format!("{}/", base_authority))
                })
                .unwrap_or(false);

            if resolved_subject_obj.is_local() || is_own_authority {
                return self
                    .handle_not_found(
                        &resolved_url,
                        "Not found in DB".into(),
                        self.get_default_agent().ok().as_ref(),
                    )
                    .await;
            }

            if self.is_remote_not_found(&resolved_url) {
                return Err(AtomicError::not_found(format!(
                    "{} was not found on its server earlier this session",
                    resolved_url
                )));
            }

            match self
                .fetch_resource(&resolved_url, self.get_default_agent().ok().as_ref())
                .await
            {
                Ok(resource) => {
                    // If the resource is external, it's not present in the store.
                    // However, we did fetch it (because the user probably requested it).
                    // So we should add it to the store.
                    // Note that this logic is also in `Store`'s `get_resource`, but it's slightly different there.
                    // We should probably unify this.
                    // Also, this might cause issues if we want to get a resource but NOT save it.
                    self.add_resource_opts(&resource, false, false, true)
                        .await?;
                    Ok(resource)
                }
                Err(e) => {
                    // The failed fetch is the answer. The default
                    // `handle_not_found` would fetch the same URL a second time.
                    if e.error_type == AtomicErrorType::NotFoundError {
                        self.remember_remote_not_found(&resolved_url);
                    }
                    Err(e)
                }
            }
        }
    }

    async fn get_resource_shallow(&self, subject: &Subject) -> AtomicResult<Resource> {
        Db::get_resource_shallow(self, subject)
    }

    fn has_stored_resource(&self, subject: &Subject) -> bool {
        let normalized = self.normalize_subject(subject);
        self.get_propvals(&normalized.pure_id()).is_ok()
    }

    fn lens_index(&self) -> Option<Arc<crate::lens::LensIndex>> {
        let lenses = self.lenses();
        (!lenses.is_empty()).then_some(lenses)
    }

    fn get_defaults_fingerprint(&self) -> AtomicResult<Option<String>> {
        Ok(self
            .kv
            .get(Tree::PluginMeta, DEFAULTS_FINGERPRINT_KEY)?
            .and_then(|v| String::from_utf8(v).ok()))
    }

    fn set_defaults_fingerprint(&self, fingerprint: &str) -> AtomicResult<()> {
        // Folds into the open bootstrap batch, so the fingerprint is only
        // persisted together with the seed it describes.
        self.kv.insert(
            Tree::PluginMeta,
            DEFAULTS_FINGERPRINT_KEY,
            fingerprint.as_bytes(),
        )
    }

    #[instrument(skip_all)]
    async fn get_resource_extended(
        &self,
        subject: &Subject,
        skip_dynamic: bool,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        let subject_without_params = subject.without_params();

        // Get the inner URL for endpoint checking and extender context
        let inner_url = match subject {
            Subject::Internal { url, .. } => url,
            Subject::External(u) => u,
            Subject::Did { url, .. } => url,
        };

        // Check if the subject matches one of the endpoints, if so, call the endpoint.
        let is_endpoint = self.is_endpoint(inner_url);

        if is_endpoint {
            return self.call_endpoint(subject.as_str(), for_agent).await;
        }

        async move {
            let mut resource = self.get_resource(&subject_without_params).await?;

            let _explanation = crate::hierarchy::check_read(self, &resource, for_agent).await?;

            let mut root_subject: Option<String> = None;

            // Response shaping below (`incomplete`, class extenders) writes
            // dynamic propvals through `Resource::set`, which also records each
            // write as a Loro op on the doc `get_resource` decoded from the
            // stored snapshot; serialization would then re-export that doc as
            // the served `loroUpdate`. Those ops are never persisted, so a
            // client that seeds its doc from the response builds every later
            // delta on ops this store does not have, and `apply_commit` parks
            // them as pending ("Commit's Loro update depends on ops the server
            // does not have"). Observed as the form builder's Publish never
            // reaching visitors: the Form extender's `form-submission-summary`
            // op poisoned every doc hydrated from an HTTP GET. Whatever the
            // extender does to the doc, the response carries the persisted
            // snapshot.
            let persisted_snapshot = match resource.get(crate::urls::LORO_UPDATE) {
                Ok(crate::Value::LoroDoc(bytes)) => Some(bytes.clone()),
                _ => None,
            };
            let served_id = resource.get_subject().pure_id();
            let serve_persisted = |shaped: &mut Resource| {
                if let Some(snapshot) = &persisted_snapshot {
                    if shaped.get_subject().pure_id() == served_id {
                        shaped.restore_persisted_state(snapshot.clone());
                    }
                }
            };

            let extenders = self
                .class_extenders
                .read()
                .map_err(|e| format!("Failed to read class extenders: {}", e))?
                .clone();
            for extender in extenders.iter() {
                if !extender.can_extend(&resource) {
                    continue;
                }

                if extender.resource_has_extender(&resource)? {
                    let (is_in_scope, cached_root) =
                        extender.check_scope(&resource, self, root_subject).await?;

                    root_subject = cached_root;

                    if !is_in_scope {
                        continue;
                    }

                    if skip_dynamic {
                        // This lets clients know that the resource may have dynamic properties that are currently not included
                        resource
                            .set(
                                crate::urls::INCOMPLETE.into(),
                                crate::Value::Boolean(true),
                                self,
                            )
                            .await?;
                        serve_persisted(&mut resource);

                        return Ok(resource.into());
                    }

                    if let Some(handler) = extender.on_resource_get.as_ref() {
                        let fut = (handler)(GetExtenderContext {
                            store: self,
                            url: inner_url,
                            db_resource: &mut resource,
                            for_agent,
                        });
                        let resource_response = fut.await?;

                        // TODO: Check if we actually need this
                        // make sure the actual subject matches the one requested - It should not be changed in the logic above
                        match resource_response {
                            ResourceResponse::Resource(mut resource) => {
                                serve_persisted(&mut resource);
                                resource.set_subject(subject.to_string());
                                return Ok(resource.into());
                            }
                            ResourceResponse::ResourceWithReferenced(mut resource, referenced) => {
                                serve_persisted(&mut resource);
                                resource.set_subject(subject.to_string());

                                return Ok(ResourceResponse::ResourceWithReferenced(
                                    resource, referenced,
                                ));
                            }
                            ResourceResponse::Redirect(target) => {
                                return Ok(ResourceResponse::Redirect(target));
                            }
                        }
                    }
                }
            }

            resource.set_subject(subject.to_string());

            Ok(resource.into())
        }
        .await
    }

    fn handle_commit(&self, commit_response: &CommitResponse) {
        if let Some(fun) = &self.on_commit {
            fun(commit_response);
        }
    }

    /// Search the Store, returns the matching subjects.
    /// The second returned vector should be filled if query.include_resources is true.
    /// Tries `query_cache`, which you should implement yourself.
    #[instrument(skip_all)]
    async fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        // A constraint on a computed value can't come from the index, so it is
        // applied to the set the index narrows to — which means paging has to
        // happen after it, not in it.
        let mut result = if !q.expression_filters.is_empty() {
            self.query_with_expression_filters(q).await?
        } else if requires_query_index(q) {
            self.query_complex(q).await?
        } else {
            self.query_basic(q).await?
        };

        // Aggregates run over the whole matching set, so they need their own
        // pass — the one above is limited to the requested page. Only when
        // asked: a query without aggregates pays nothing for this.
        if let Some(aggregation) = &q.aggregation {
            if !aggregation.is_empty() {
                result.aggregates = self.compute_aggregation(q, aggregation).await?;
            }
        }

        Ok(result)
    }

    async fn search(
        &self,
        query_str: &str,
        opts: crate::client::search::SearchOpts,
    ) -> AtomicResult<Vec<Resource>> {
        let hits = crate::search::query(self, query_str, &opts)?;
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
            match self.get_resource(&hit.subject).await {
                Ok(r) => out.push(r),
                Err(_) => out.push(Resource::new(hit.subject.to_string())),
            }
        }
        Ok(out)
    }

    #[instrument(skip_all)]
    fn all_resources(
        &self,
        include_external: bool,
    ) -> Box<dyn std::iter::Iterator<Item = Resource> + Send> {
        let base_domain = self.base_domain.clone();
        let result = self.kv.iter_tree(Tree::Resources).filter_map(move |item| {
            let (subject_bytes, resource_bin) = item.expect(DB_CORRUPT_MSG);
            Db::map_kv_item_to_resource(
                &subject_bytes,
                &resource_bin,
                include_external,
                base_domain.as_deref(),
            )
        });

        Box::new(result)
    }

    async fn post_resource(
        &self,
        subject: &str,
        body: Vec<u8>,
        for_agent: &ForAgent,
    ) -> AtomicResult<Resource> {
        let endpoints = self.endpoints.iter().filter(|e| e.handle_post.is_some());
        let subj_url = url::Url::try_from(subject)?;
        for e in endpoints {
            if let Some(fun) = &e.handle_post {
                if subj_url.path() == e.path {
                    let handle_post_context = crate::endpoints::HandlePostContext {
                        store: self,
                        body: body.clone(),
                        for_agent,
                        subject: subj_url.clone(),
                    };
                    let mut resource = fun(handle_post_context).await?.to_single();
                    resource.set_subject(subject.into());

                    return Ok(resource);
                }
            }
        }
        // If we get Class Handlers with POST, this is where the code goes
        // let mut r = self.get_resource(subject)?;
        // for class in r.get_classes(self)? {
        //     match class.subject.as_str() {
        //         urls::IMPORTER => {
        //             let query_params = url::Url::try_from(subject)?;
        //             return crate::plugins::importer::construct_importer(
        //                 self,
        //                 query_params.query_pairs(),
        //                 &mut r,
        //                 for_agent,
        //                 Some(body),
        //             );
        //         }
        //         _ => {}
        //     }
        // }
        Err(
            AtomicError::method_not_allowed("Cannot post here - no Endpoint Post handler found")
                .set_subject(subject),
        )
    }

    async fn populate(&self) -> AtomicResult<()> {
        crate::populate::bootstrap(self).await.map(|_| ())
    }

    #[instrument(skip_all)]
    async fn remove_resource(&self, subject: &Subject) -> AtomicResult<()> {
        let removed = self.remove_applied(subject).await?;
        // Only now, with the removal on disk: a listener that hears of it
        // earlier evicts a resource the store may still hold.
        self.emit_destroyed(&removed);
        // TODO: deletion sync — should create a signed destroy commit
        // and push it through the normal commit pipeline, not a raw DESTROY frame.
        Ok(())
    }

    fn set_default_agent(&self, agent: crate::agents::Agent) {
        self.default_agent.lock().unwrap().replace(agent);
    }

    fn begin_batch(&self) {
        self.kv.begin_batch();
    }

    fn commit_batch(&self) -> AtomicResult<()> {
        self.kv.commit_batch()
    }
}
