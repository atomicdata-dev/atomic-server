//! Request routing: drive mappings, replication targets and DID fallbacks for [`Db`].

use super::*;

impl Db {
    pub(super) fn get_did_mapping_hint(&self, subject: &str) -> Option<String> {
        let key = crate::identifiers::canonicalize_scheme(subject);
        let bin = self.kv.get(Tree::DidMapping, key.as_bytes()).ok()??;
        std::str::from_utf8(&bin).ok().map(str::to_string)
    }

    pub async fn resolve_request_target(
        &self,
        subject: &Subject,
        host: &str,
        subject_string: &str,
        origin: &str,
    ) -> AtomicResult<ResolvedTarget> {
        let full_subject = format!("{}{}", origin.trim_end_matches('/'), subject_string);
        match self
            .map_request_subject(subject, host, subject_string)
            .await
        {
            Ok(mapped_subject) => {
                let alias_subject = if mapped_subject != *subject {
                    Some(full_subject)
                } else {
                    None
                };
                Ok(ResolvedTarget {
                    subject: mapped_subject,
                    alias_subject,
                })
            }
            Err(e) => {
                // Drive-routing failed (e.g. ULID subject not found via shortname traversal).
                // Fall back to a direct DB lookup for the full HTTP URL before giving up.
                let direct = Subject::from_raw(&full_subject, None);
                if self.get_resource(&direct).await.is_ok() {
                    Ok(ResolvedTarget {
                        subject: direct,
                        alias_subject: None,
                    })
                } else {
                    Err(e)
                }
            }
        }
    }

    pub(super) async fn map_request_subject(
        &self,
        subject: &Subject,
        host: &str,
        subject_string: &str,
    ) -> AtomicResult<Subject> {
        if Self::should_bypass_drive_routing(subject, subject_string) {
            return Ok(subject.clone());
        }

        let Some(drive_did) = self.get_drive_did(host).await? else {
            return Ok(subject.clone());
        };

        // A host bound to a Drive serves that Drive or nothing. Falling through
        // to the store root here is what let a vanity host whose Drive has not
        // synced yet — or was migrated to another node — quietly serve the
        // node's *own* root Drive under a customer's hostname. On a
        // multi-tenant node that is one tenant's domain answering with another
        // namespace's content, so it is a 404 instead.
        if self.get_resource(&drive_did).await.is_err() {
            return Err(AtomicError::not_found(format!(
                "Host '{host}' is bound to drive {drive_did}, which this server does not have."
            )));
        }

        if subject_string == "/" {
            return Ok(drive_did);
        }

        let resolved = self
            .get_resource_at_path(&drive_did, subject_string)
            .await
            .map_err(|e| {
                AtomicError::not_found(format!(
                    "Path '{}' not found in drive {}: {}",
                    subject_string, drive_did, e
                ))
            })?;

        Ok(resolved.set_drive_hint(drive_did.as_str().to_string()))
    }

    pub(super) fn should_bypass_drive_routing(subject: &Subject, subject_string: &str) -> bool {
        subject.is_did()
            || crate::identifiers::is_identifier_resolution_path(subject_string)
            || subject_string.starts_with("/bind-drive")
            || subject_string.starts_with("/search")
            || subject_string.starts_with("/upload")
            || subject_string.starts_with("/export")
            || subject_string.starts_with("/download")
            || subject_string.starts_with("/invites")
            || subject_string.starts_with("/commit")
            || subject_string.starts_with("/path")
            || subject_string.starts_with("/query")
    }

    /// Where a pre-DID server stored the Agent that `did:ad:agent:{pubkey}`
    /// now identifies. `None` for anything that isn't an Agent DID.
    ///
    /// The inverse of [crate::agents::migrate_legacy_agent_subject]. The
    /// pubkey is standard base64 and contains `/` and `+`, so the whole
    /// remainder is carried across untouched.
    pub(super) fn legacy_agent_subject(subject: &Subject) -> Option<Subject> {
        let pubkey = subject.agent_public_key()?;

        if pubkey.is_empty() {
            return None;
        }

        Some(Subject::new_local(&format!("/agents/{pubkey}"), None))
    }

    pub async fn fetch_resource_with_did_fallback(
        &self,
        subject: &Subject,
        origin: &str,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        if subject.is_blob_did() {
            if let Some(hash) = subject.blob_hash_hex() {
                let target = format!("{}/download/files/{}", origin.trim_end_matches('/'), hash);
                return Ok(ResourceResponse::Redirect(target));
            }
        }

        let store = self.clone_with_url(origin.to_string());

        // A user from before the DID migration signs in as
        // `did:ad:agent:{pubkey}`, but their Agent resource is still stored
        // where the old server put it — `internal:/agents/{pubkey}` (the
        // localized form of `https://server/agents/{pubkey}`). Nothing links
        // the two.
        //
        // Resolving an Agent DID does not fail when there is no stored
        // resource: it synthesizes a minimal Agent from the key. So the user
        // isn't met with an error — they're met with an account that looks
        // brand new. Their name is gone, and because the Agent carries
        // `drives`, so is every drive they own, which is what empties the
        // sidebar.
        //
        // Same key, same identity, so serve the stored resource under the DID
        // that asked for it. Gated on the DID having nothing of its own, which
        // makes it self-healing: it applies only to identities that predate the
        // migration, and stops the moment a real Agent exists at the DID.
        // Read-only — the legacy resource is left exactly as it is.
        if !self.has_stored_resource(subject) {
            if let Some(legacy) = Self::legacy_agent_subject(subject) {
                if self.has_stored_resource(&legacy) {
                    let mut response = store
                        .get_resource_extended(&legacy, false, for_agent)
                        .await?;
                    // Answer under the subject that was requested, so the
                    // client caches it against the DID rather than
                    // re-introducing the legacy spelling.
                    response.set_subject(subject.clone());

                    return Ok(response);
                }
            }
        }

        store.get_resource_extended(subject, false, for_agent).await
    }

    /// Maps a drive hint (short ID) to a full Drive DID.
    pub fn add_drive_mapping(&self, host: &str, drive_did: &Value) -> AtomicResult<()> {
        let did_str = match drive_did {
            Value::AtomicUrl(s) => s.to_string(),
            Value::ResourceArray(arr) => {
                if let Some(first) = arr.first() {
                    first.to_string()
                } else {
                    return Err("Drive DID array is empty".into());
                }
            }
            _ => drive_did.to_string(),
        };

        let key = drive_mapping_key(host);
        self.kv
            .insert(Tree::DriveMapping, key.as_bytes(), did_str.as_bytes())?;
        tracing::info!("Added drive mapping: {} -> {}", key, did_str);
        Ok(())
    }

    /// Removes the drive mapping for a given host.
    pub fn remove_drive_mapping(&self, host: &str) -> AtomicResult<()> {
        let key = drive_mapping_key(host);
        self.kv.remove(Tree::DriveMapping, key.as_bytes())?;
        tracing::info!("Removed drive mapping for host: {}", key);
        Ok(())
    }

    /// Every host → Drive mapping in this store, sorted by host.
    pub fn list_drive_mappings(&self) -> AtomicResult<Vec<(String, String)>> {
        let mut out = Vec::new();

        for (key, value) in self.kv.scan_prefix(Tree::DriveMapping, b"").flatten() {
            let (Ok(host), Ok(did)) = (std::str::from_utf8(&key), std::str::from_utf8(&value))
            else {
                continue;
            };
            // `RedbStore::flush` parks its sentinel in this tree, so any open
            // that ran a flush (the index-key migration does) holds one.
            if host == "__flush_sentinel__" {
                continue;
            }
            out.push((host.to_string(), did.to_string()));
        }

        out.sort();
        Ok(out)
    }

    /// The hosts [`Self::sync_drive_mappings`] installed on its last run.
    pub fn managed_alias_hosts(&self) -> AtomicResult<Vec<String>> {
        let Some(bytes) = self.kv.get(Tree::PluginMeta, MANAGED_ALIAS_HOSTS_KEY)? else {
            return Ok(Vec::new());
        };

        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Corrupt managed alias host list: {e}").into())
    }

    /// Reconciles the host → Drive mappings this server installs on behalf of a
    /// control plane against `desired`, reporting what changed.
    ///
    /// Idempotent, so a managed node can call it on every policy poll: a host
    /// already pointing at the right Drive is left untouched. Hosts a previous
    /// run installed that `desired` no longer names are removed, which is what
    /// makes a released vanity name stop resolving without anyone touching the
    /// box. Ownership is tracked in [`MANAGED_ALIAS_HOSTS_KEY`], so a mapping
    /// made by hand through `/bind-drive` is never removed by a reconcile that
    /// does not name it.
    ///
    /// A host the control plane *does* name is taken over even if something
    /// else bound it first: the control plane owns the namespace it hands out,
    /// and a stale local binding shadowing an issued name is the failure this
    /// is meant to correct.
    pub fn sync_drive_mappings(
        &self,
        desired: &[(String, String)],
    ) -> AtomicResult<DriveMappingSync> {
        let mut report = DriveMappingSync::default();
        let mut managed: Vec<String> = Vec::with_capacity(desired.len());

        for (host, drive_did) in desired {
            let key = drive_mapping_key(host);
            // An empty host would claim the zero-length key and match no
            // request; an empty DID would point a live hostname at nothing.
            // Either is a bug upstream, and neither is worth writing.
            if key.is_empty() || drive_did.trim().is_empty() {
                tracing::warn!("Skipping drive mapping with an empty host or drive: {key:?}");
                continue;
            }

            let current = self
                .kv
                .get(Tree::DriveMapping, key.as_bytes())?
                .and_then(|bytes| String::from_utf8(bytes).ok());

            match current {
                Some(current) if current == *drive_did => {}
                Some(_) => {
                    self.kv
                        .insert(Tree::DriveMapping, key.as_bytes(), drive_did.as_bytes())?;
                    report.updated.push(key.clone());
                }
                None => {
                    self.kv
                        .insert(Tree::DriveMapping, key.as_bytes(), drive_did.as_bytes())?;
                    report.added.push(key.clone());
                }
            }

            if !managed.contains(&key) {
                managed.push(key);
            }
        }

        for host in self.managed_alias_hosts()? {
            if managed.contains(&host) {
                continue;
            }
            if self.kv.get(Tree::DriveMapping, host.as_bytes())?.is_some() {
                self.kv.remove(Tree::DriveMapping, host.as_bytes())?;
                report.removed.push(host);
            }
        }

        managed.sort();
        let bytes = serde_json::to_vec(&managed)
            .map_err(|e| format!("Could not encode managed alias hosts: {e}"))?;
        self.kv
            .insert(Tree::PluginMeta, MANAGED_ALIAS_HOSTS_KEY, &bytes)?;

        if !report.is_empty() {
            tracing::info!(
                "Drive mappings reconciled: {} added, {} updated, {} removed",
                report.added.len(),
                report.updated.len(),
                report.removed.len()
            );
        }

        Ok(report)
    }

    /// Where a drive is replicated to, and who authorized it.
    ///
    /// This is **server-local config, and must stay out of the drive**. A
    /// drive's sync set is its root plus every child (`collect_drive_subjects`),
    /// so a target stored inside the drive would be pushed to the target itself
    /// — and the receiving server, running this same code, would read it and
    /// start replicating onward to hosts it was never meant to contact.
    pub fn get_replication_targets(&self, drive: &str) -> AtomicResult<Vec<ReplicationTarget>> {
        let Some(bytes) = self
            .kv
            .get(Tree::PluginMeta, replication_key(drive).as_bytes())?
        else {
            return Ok(vec![]);
        };

        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Corrupt replication targets for {drive}: {e}").into())
    }

    /// Record a replication target for a drive. Idempotent: re-adding the same
    /// target updates who authorized it rather than duplicating it.
    pub fn add_replication_target(
        &self,
        drive: &str,
        target: &ReplicationTarget,
    ) -> AtomicResult<()> {
        let mut targets = self.get_replication_targets(drive)?;
        targets.retain(|t| t.url != target.url);
        targets.push(target.clone());

        let bytes = serde_json::to_vec(&targets)
            .map_err(|e| format!("Could not encode replication targets: {e}"))?;
        self.kv
            .insert(Tree::PluginMeta, replication_key(drive).as_bytes(), &bytes)?;

        Ok(())
    }

    /// Every drive that has at least one replication target, for the boot-time
    /// reconcile.
    pub fn get_all_replication_targets(
        &self,
    ) -> AtomicResult<Vec<(String, Vec<ReplicationTarget>)>> {
        let mut out = Vec::new();

        for (key, value) in self
            .kv
            .scan_prefix(Tree::PluginMeta, REPLICATION_PREFIX.as_bytes())
            .flatten()
        {
            let Ok(key) = std::str::from_utf8(&key) else {
                continue;
            };
            let Some(drive) = key.strip_prefix(REPLICATION_PREFIX) else {
                continue;
            };
            if let Ok(targets) = serde_json::from_slice::<Vec<ReplicationTarget>>(&value) {
                out.push((drive.to_string(), targets));
            }
        }

        Ok(out)
    }

    /// Whether `host` (no port) has a Drive mapping in this store: bound by
    /// hand through `/bind-drive`, or installed by a control plane through
    /// [`Self::sync_drive_mappings`]. Either way the server answers for it.
    pub fn has_drive_mapping(&self, host: &str) -> bool {
        let key = drive_mapping_key(host);
        !key.is_empty() && matches!(self.kv.get(Tree::DriveMapping, key.as_bytes()), Ok(Some(_)))
    }

    /// Returns the full Drive DID for a given host (domain/subdomain).
    pub async fn get_drive_did(&self, host: &str) -> AtomicResult<Option<Subject>> {
        let key = drive_mapping_key(host);
        if let Some(did_bin) = self.kv.get(Tree::DriveMapping, key.as_bytes())? {
            let did_str = std::str::from_utf8(&did_bin)
                .map_err(|e| format!("Failed to parse DID from database: {}", e))?;
            return Ok(Some(Subject::from_raw(did_str, None)));
        }

        Ok(None)
    }

    /// Resolves a path (e.g. "/blog/my-post") relative to a Drive DID.
    /// 1. First, it tries to find a resource in the Drive that has this exact string in its `PATH` property.
    /// 2. If not found, it traverses the hierarchy recursively using the PARENT property and shortnames.
    pub async fn get_resource_at_path(
        &self,
        drive_did: &Subject,
        path: &str,
    ) -> AtomicResult<Subject> {
        if path == "/" || path.is_empty() {
            return Ok(drive_did.clone());
        }

        // Strategy 1: Direct PATH lookup (flat routing)
        // Find any resource where parent is the drive and path matches the full path string.
        let mut query_path = Query::new_prop_val(urls::PATH, path);
        query_path.limit = Some(1);
        if let Ok(result) = self.query(&query_path).await {
            for resource in result.resources {
                // Verify the resource belongs to this drive
                // (In a multi-tenant world, we want to make sure we don't return someone else's resource)
                if let Ok(parent) = resource.get(urls::PARENT) {
                    if parent.to_string() == *drive_did {
                        return Ok(resource.get_subject().clone());
                    }
                }
            }
        }

        // Strategy 2: Recursive SHORTNAME traversal (hierarchical routing)
        let mut current_subject = drive_did.clone();
        let segments = path.trim_start_matches('/').split('/');

        for segment in segments {
            if segment.is_empty() {
                continue;
            }

            let mut query = Query::new_prop_val(urls::PARENT, current_subject.as_str());
            query.limit = Some(1000); // Reasonable limit for children

            let result = self.query(&query).await?;
            let mut found = None;

            for resource in result.resources {
                if let Ok(sn) = resource.get(urls::SHORTNAME) {
                    if sn.to_string() == segment {
                        found = Some(resource.get_subject().clone());
                        break;
                    }
                }
            }

            current_subject = found.ok_or_else(|| {
                format!(
                    "Could not find segment '{}' in {} (path: {})",
                    segment, current_subject, path
                )
            })?;
        }

        Ok(current_subject)
    }
}
