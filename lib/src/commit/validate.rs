use super::*;

impl Commit {
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

        if subject.is_did() && crate::identifiers::is_atomic_identifier(subject.as_str()) {
            let pure_id = subject.pure_id();
            if crate::identifiers::is_prop_id(&pure_id) {
                if !crate::property_identity::is_property_id(&pure_id) {
                    return Err("Invalid property ID: expected 64 lowercase hex characters".into());
                }
            } else if crate::identifiers::is_lens_id(&pure_id) {
                if !crate::lens::is_lens_id(&pure_id) {
                    return Err("Invalid lens ID: expected 64 lowercase hex characters".into());
                }
            } else {
                let b64_part = if subject.is_agent_did() {
                    crate::identifiers::agent_public_key(&pure_id)
                } else if subject.is_commit_did() {
                    crate::identifiers::commit_signature(&pure_id)
                } else {
                    crate::identifiers::identifier_body(&pure_id)
                }
                .ok_or("Invalid Atomic identifier format")?;

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

        // Nothing to destroy: a client that deletes a placeholder it never saved
        // (`_new:…`), or replays a delete that already landed, names a resource
        // this node does not hold. That is not a drive being created or a write
        // to a foreign domain, so say what happened before rights and admission
        // read it as one. Clients treat this message as settled.
        if is_new && commit.destroy.unwrap_or(false) && opts.validate_rights {
            return Err(format!(
                "Destroy commit for {} has no such resource to destroy on this node",
                commit.subject
            )
            .into());
        }

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

        if is_content_addressed_id(commit.subject.as_str()) && !is_destroy {
            if is_new {
                verify_content_addressed_genesis(
                    commit.subject.as_str(),
                    applied.resource_new.get_propvals(),
                )?;
            } else if crate::identifiers::is_lens_id(commit.subject.as_str()) {
                crate::lens::check_lens_identity_unchanged(
                    &applied.resource_old,
                    &applied.resource_new,
                )?;
            } else {
                check_property_identity_unchanged(&applied.resource_old, &applied.resource_new)?;
            }
        }

        // NOTE: `createdAt` / `createdBy` are server-managed creation metadata
        // (materialized from the genesis oplog change). We do NOT reject commits
        // that carry them: the materialized values round-trip back to clients in
        // JSON-AD, so a later edit legitimately re-sends them (e.g. saving an
        // agent's name). Rejecting broke those saves. Forge-resistance is the
        // job of the genesis certificate (`planning/genesis-self-verifying.md`),
        // where identity metadata is signed into the DID, not a settable propval.

        // Pending-import guard: the commit's loroUpdate contained ops whose
        // causal dependencies are missing from the stored doc (e.g. the
        // client's earlier commit never arrived, or the server's state was
        // rolled back). Loro parks those ops as "pending": the version
        // vector doesn't advance and the diff is empty, which makes the
        // commit look exactly like an idempotent replay below — silently
        // ACKing the client while its writes go nowhere, and every later
        // delta from that client inherits the same fate. Reject instead so
        // the client keeps its save cursor, refetches, and re-sends the
        // full range.
        if opts.validate_loro_causality && applied.imported_pending_ops {
            tracing::warn!(
                subject = %commit.subject,
                loro_bytes = commit.loro_update.as_ref().map(|b| b.len()).unwrap_or(0),
                "[causality-guard] rejecting commit whose Loro update depends on ops missing from the stored doc (import left ops pending)"
            );

            return Err(format!(
                "Commit's Loro update depends on ops the server does not have — the update \
                 was parked as pending and none of its changes could be applied. An earlier \
                 commit from this client likely never arrived. Refetch the resource and \
                 re-send the missing changes. subject={}",
                commit.subject,
            )
            .into());
        }

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
        //     REJECT so the silent data loss surfaces — but only when the
        //     doc really was unseeded, which its version vector says and
        //     the values do not: a client that holds the stored history and
        //     lost to a newer peer is LWW working as designed, and refusing
        //     it only teaches the client to send the same bytes again.
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
                // Atom diffs only cover properties. A document or canvas
                // merge can change another root while historical property
                // writes lose LWW. Count that visible change as well, just as
                // we already accept commits that change at least one atom.
                let body_state = |doc: &crate::loro::AtomicLoroDoc| {
                    let loro::LoroValue::Map(roots) = doc.doc().get_deep_value() else {
                        return std::collections::BTreeMap::new();
                    };
                    roots
                        .iter()
                        .filter(|(key, _)| !matches!(key.as_str(), "properties" | "datatypes"))
                        .map(|(key, value)| (key.to_string(), value.clone()))
                        .collect::<std::collections::BTreeMap<_, _>>()
                };
                let stored_doc = applied.resource_old.build_state_doc()?;
                let body_changed = body_state(&stored_doc) != body_state(&merged_doc);
                // The writes that did not survive the merge, each with what the
                // commit sent and what the store kept. Empty means nothing was
                // dropped. Collecting the losers rather than answering
                // yes-or-no is what lets the rejection name them: a key list
                // alone leaves the one question the reader has ("which write
                // lost, and to what?") to be guessed from the server's own
                // logs, which whoever reads the error usually cannot see.
                let dropped: Vec<String> = if body_changed || incoming_intent.is_empty() {
                    Vec::new()
                } else {
                    incoming_intent
                        .iter()
                        .filter(|(key, _)| !server_managed.contains(&key.as_str()))
                        .filter_map(|(key, incoming_val)| {
                            let stored = merged_state.get(key);

                            if stored.is_some_and(|mv| mv == incoming_val) {
                                return None;
                            }

                            Some(format!("{key}: sent {incoming_val:?}, stored {stored:?}"))
                        })
                        .collect()
                };

                // Whether this client had ever seen the stored state. A doc
                // seeded from the server carries the server's peers in its own
                // version vector, however far behind it has since fallen; a doc
                // built from scratch carries only its own. That is the
                // difference this guard exists to catch — case 2 above says so
                // in as many words, "fresh peer ID" — and comparing values
                // cannot see it, because a write that never saw the server and
                // a write that merely lost a race to a newer peer both fail to
                // survive the merge. Losing a race is what LWW is for, so a
                // client that holds the history is told nothing; a client whose
                // writes vanished without it ever having read the resource
                // still is. `update_range` reads the version out of the blob
                // header, so this costs a parse and not a second doc build.
                let client_holds_stored_history = commit
                    .loro_update
                    .as_deref()
                    .and_then(|bytes| crate::loro::AtomicLoroDoc::update_range(bytes).ok())
                    .is_some_and(|(_, incoming_vv)| {
                        let stored_vv = stored_doc.oplog_vv();
                        incoming_vv.iter().any(|(peer, counter)| {
                            *counter > 0 && stored_vv.get(peer).copied().unwrap_or(0) > 0
                        })
                    });

                if dropped.is_empty() {
                    tracing::debug!(
                        subject = %commit.subject,
                        keys = ?incoming_intent.keys().collect::<Vec<_>>(),
                        empty_intent = incoming_intent.is_empty(),
                        "[causality-guard] accepting commit (propval intent is empty or matches stored state)"
                    );
                } else if client_holds_stored_history {
                    tracing::debug!(
                        subject = %commit.subject,
                        dropped = ?dropped,
                        "[causality-guard] accepting a concurrent loss (the client's doc carries the stored history, so LWW decided against it rather than it never having read the resource)"
                    );
                } else {
                    tracing::warn!(
                        subject = %commit.subject,
                        loro_bytes = commit.loro_update.as_ref().map(|b| b.len()).unwrap_or(0),
                        dropped = ?dropped,
                        incoming_intent = ?incoming_intent,
                        merged_state = ?merged_state,
                        "[causality-guard] rejecting commit with non-trivial loroUpdate that produced no state changes (silent LWW loss)"
                    );

                    return Err(format!(
                        "Commit's Loro update produced no state changes — its writes were \
                         silently dropped by LWW against stored state. The client's Loro doc \
                         wasn't seeded from the server's current state. Refetch the resource \
                         and retry the commit. subject={} dropped={:?}",
                        commit.subject, dropped,
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
            // A repeat genesis of a Property ID needs append rights on the
            // parent, like the first one: the earlier minter's write grant
            // does not extend to another agent.
            let repeat_property_genesis = !is_new
                && commit.is_genesis == Some(true)
                && is_content_addressed_id(commit.subject.as_str());
            if repeat_property_genesis {
                crate::hierarchy::check_append(store, &applied.resource_new, &validate_for.into())
                    .await?;
            } else if is_new {
                crate::hierarchy::check_append(store, &applied.resource_new, &validate_for.into())
                    .await?;

                // A chat log page: the creator gets no `write` (below), so
                // the page cannot be rewritten by whoever happened to create
                // it, and it may not hand itself or anyone else `write` at
                // genesis either unless the creator may write to the chat.
                // Every entry in it must be the creator's own.
                if crate::hierarchy::is_chat_log(&applied.resource_new) {
                    let for_agent: crate::agents::ForAgent = validate_for.into();
                    if applied.resource_new.get(urls::WRITE).is_ok() {
                        let parent = applied.resource_new.get_parent(store).await?;
                        crate::hierarchy::check_write(store, &parent, &for_agent)
                            .await
                            .map_err(|_| {
                                crate::errors::AtomicError::unauthorized(
                                    "Only a writer of the chat may set `write` on a chat log page"
                                        .to_string(),
                                )
                            })?;
                    }
                    crate::hierarchy::check_chat_log_member_commit(
                        store,
                        &for_agent,
                        &[],
                        false,
                        &applied.entry_changes,
                    )?;
                }

                // For new DID resources, grant the signer explicit write access so future
                // commits don't need drive-level rights. Agents are excluded because they
                // already have self-write via their subject matching the agent check.
                if matches!(applied.resource_new.get_subject(), Subject::Did { .. })
                    && !crate::hierarchy::is_chat_log(&applied.resource_new)
                {
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
                let write_check =
                    crate::hierarchy::check_write(store, &resource_old, &validate_for.into()).await;
                match write_check {
                    Ok(_) => {}
                    // A chat log page takes entry changes from anyone with
                    // `append` on it, as long as each is their own.
                    Err(write_err) if crate::hierarchy::is_chat_log(&resource_old) => {
                        let for_agent: crate::agents::ForAgent = validate_for.into();
                        if commit.destroy.unwrap_or(false) {
                            return Err(write_err);
                        }
                        crate::hierarchy::check_rights(
                            store,
                            &resource_old,
                            &for_agent,
                            crate::hierarchy::Right::Append,
                        )
                        .await?;
                        crate::hierarchy::check_chat_log_member_commit(
                            store,
                            &for_agent,
                            &applied.changed_property_keys,
                            applied.datatypes_changed,
                            &applied.entry_changes,
                        )?;
                    }
                    Err(e) => return Err(e),
                }
            }

            // Entries are client time; refuse ones from the far future.
            if !commit.destroy.unwrap_or(false)
                && (if is_new {
                    crate::hierarchy::is_chat_log(&applied.resource_new)
                } else {
                    crate::hierarchy::is_chat_log(&resource_old)
                })
            {
                crate::hierarchy::check_chat_log_entry_times(&applied.entry_changes)?;
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
        // Value constraints from the resource's classes, and the shape of a
        // Class's own `constraints` map. Reconcile writes snapshots straight
        // to the store and never gets here; peer commits opt out.
        if opts.validate_schema && opts.validate_constraints {
            crate::class_constraints::validate_constraints_prop(&applied.resource_new)?;
            crate::class_constraints::check_resource(store, &applied.resource_new).await?;
        }

        let commit_resource: Resource = commit.into_resource(store).await?;

        // Stamp `lastCommit` with this envelope's id. The id is a receipt,
        // not a refetchable resource — ordinary content commits are not stored.
        //
        // Not on later commits to a chat log page: the stamp is a ~100 byte
        // incompressible string written as its own Loro change per commit,
        // which would triple the cost of a chat message (planning/chat-log.md).
        // The page keeps its genesis value.
        if is_new || !crate::hierarchy::is_chat_log(&applied.resource_new) {
            applied
                .resource_new
                .set(
                    urls::LAST_COMMIT.to_string(),
                    Value::AtomicUrl(commit_resource.get_subject().clone()),
                    store,
                )
                .await?;
        }

        let destroyed = commit.destroy.unwrap_or(false);

        // Lenses derive values for the properties the doc does not really
        // hold. Done last: setting `lastCommit` above rebuilds the propvals
        // from the doc. The index follows the derived values like real ones.
        if !destroyed {
            if let Some(lenses) = store.lens_index() {
                reconcile_lens_atoms(
                    &lenses,
                    (!is_new).then_some(&applied.resource_old),
                    &mut applied.resource_new,
                    &mut applied.add_atoms,
                    &mut applied.remove_atoms,
                );
            }
        }

        // Export what the doc gained during this apply — the author's ops and
        // the stamp above — for the live fan-out (`CommitResponse::fanout_delta`).
        let broadcast_update = applied
            .vv_before
            .as_ref()
            .and_then(|vv| applied.resource_new.export_updates_since(vv));

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
            broadcast_update,
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
}
