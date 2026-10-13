//! Drive lifecycle, usage accounting and children for [`Db`].

use super::*;

impl Db {
    /// Get the active drive subject, if one is set.
    pub fn get_active_drive(&self) -> Option<String> {
        self.kv
            .get(trees::Tree::PluginMeta, b"active_drive")
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Set the active drive subject. Persisted in the database.
    pub fn set_active_drive(&self, drive: &str) -> AtomicResult<()> {
        self.kv
            .insert(trees::Tree::PluginMeta, b"active_drive", drive.as_bytes())?;
        // Durable now: with Durability::None a freshly adopted drive is rolled
        // back on the next app kill, and the auto-connect loop (which needs an
        // active drive) then has nothing to reconnect to. Rare write; cheap.
        let _ = self.flush();
        Ok(())
    }

    /// Clear the default agent.
    pub fn clear_default_agent(&self) {
        self.default_agent.lock().unwrap().take();
    }

    /// Create a new drive owned by the current agent.
    /// Signs a genesis commit to produce a `did:ad:` subject.
    /// Sets it as the active drive. Returns the drive DID.
    pub async fn create_drive(&self, name: &str) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;

        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::DRIVE.into()]),
        );
        builder.set(urls::NAME.into(), Value::String(name.into()));
        builder.set(
            urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        builder.set(
            urls::READ.into(),
            Value::ResourceArray(vec![urls::PUBLIC_AGENT.into()]),
        );

        let commit = crate::commit::Commit::create_did(builder, &agent, self).await?;
        let did = commit.subject.to_string();

        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        self.apply_commit(commit, &opts).await?;
        self.set_active_drive(&did)?;

        // Record the new drive on the private drive's `drives` list when
        // that home already exists. Otherwise keep writing to the Agent so
        // `create_drive` in tests / first-run does not mint a second drive.
        let listed = if let Ok(personal) = self.private_drive_subject() {
            self.get_resource(&personal.as_str().into())
                .await
                .ok()
                .map(|_| personal)
        } else {
            None
        };
        if let Some(personal) = listed {
            if personal != did {
                self.push_drive_to_list(&personal, &did).await?;
            }
        } else {
            let agent = self.get_default_agent()?;
            self.push_drive_to_list(&agent.subject.to_string(), &did)
                .await?;
        }

        Ok(did)
    }

    /// The agent's derived personal-drive DID. Same key → same subject.
    pub fn private_drive_subject(&self) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;
        let private_key = agent
            .private_key
            .as_ref()
            .ok_or("Cannot derive a private drive without a private key")?;
        crate::genesis::GenesisCert::private_drive_subject(private_key)
    }

    /// Materialize the derived private drive if it is not already stored.
    /// Repeat genesis for the same subject merges.
    pub async fn ensure_private_drive(&self) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;
        let did = self.private_drive_subject()?;
        if self.get_resource(&did.as_str().into()).await.is_ok() {
            return Ok(did);
        }

        let signer_pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)?
            .try_into()
            .map_err(|_| "Agent public key must be 32 bytes")?;
        let cert = crate::genesis::GenesisCert::for_private_drive(signer_pubkey);

        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::DRIVE.into()]),
        );
        builder.set(urls::NAME.into(), Value::String("My drive".into()));
        builder.set(
            urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        builder.set(
            urls::READ.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        builder.set(
            urls::DESCRIPTION.into(),
            Value::String("Your private drive.".into()),
        );

        let commit =
            crate::commit::Commit::create_did_with_cert(builder, &agent, self, Some(cert)).await?;
        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        self.apply_commit(commit, &opts).await?;
        Ok(did)
    }

    pub(super) async fn push_drive_to_list(
        &self,
        list_subject: &str,
        drive_did: &str,
    ) -> AtomicResult<()> {
        let mut resource = self.get_resource(&list_subject.into()).await?;
        let mut drives: Vec<crate::values::SubResource> = resource
            .get(urls::DRIVES)
            .ok()
            .and_then(|v| match v {
                Value::ResourceArray(arr) => Some(arr.clone()),
                _ => None,
            })
            .unwrap_or_default();
        if !drives.iter().any(|d| d.to_string() == drive_did) {
            drives.push(drive_did.to_string().into());
            resource.set_unsafe(urls::DRIVES.into(), Value::ResourceArray(drives))?;
            self.add_resource_opts(&resource, false, true, true).await?;
        }
        Ok(())
    }

    /// Create a new resource with a `did:ad:` subject via genesis commit.
    pub async fn create_resource(
        &self,
        class: &str,
        parent: &str,
        name: &str,
        props: Option<Vec<(&str, Value)>>,
    ) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;

        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(urls::IS_A.into(), Value::ResourceArray(vec![class.into()]));
        builder.set(urls::NAME.into(), Value::String(name.into()));
        builder.set(urls::PARENT.into(), Value::AtomicUrl(parent.into()));

        if let Some(extra) = props {
            for (prop, val) in extra {
                builder.set(prop.into(), val);
            }
        }

        let commit = crate::commit::Commit::create_did(builder, &agent, self).await?;
        let did = commit.subject.to_string();

        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        self.apply_commit(commit, &opts).await?;
        Ok(did)
    }

    /// Load an agent from a secret and set it as the default agent.
    /// Persists the agent resource so its `drives` property is queryable.
    /// If the secret contains a drive DID, sets it as the active drive.
    ///
    /// Returns `AgentLoadResult` which indicates whether the drive exists locally.
    /// If `drive_needs_sync` is true, the caller must sync with another device
    /// before the user can create resources — the drive's genesis commit is missing.
    pub async fn load_agent_from_secret(&self, secret: &str) -> AtomicResult<AgentLoadResult> {
        let agent = crate::agents::Agent::from_secret(secret)?;
        self.set_default_agent(agent.clone());

        // Persist so list_drives() can read the agent's `drives` property
        let agent_resource = agent.to_resource()?;
        self.add_resource_opts(&agent_resource, false, false, true)
            .await?;

        let mut drive_needs_sync = false;

        if let Some(drive) = &agent.initial_drive {
            let drive_str = drive.to_string();
            let _ = self.set_active_drive(&drive_str);

            // Check if the drive resource actually exists locally.
            // Without the genesis commit, the DID is just a string — the device
            // can't create resources under it.
            //
            // `has_stored_resource`, not `get_resource`: the latter falls back to
            // fetching the subject over the network, so asking whether a drive is
            // *here* would go looking for it *there* — a DID resolution that can
            // hang for half a minute while it holds up everything waiting on this
            // call. Signing in on a device that doesn't have the drive yet is the
            // normal case, not the exception.
            let drive_subject = Subject::from_raw(&drive_str, self.get_base_domain().as_deref());
            if !self.has_stored_resource(&drive_subject) {
                tracing::warn!(
                    "Drive {} from secret does not exist locally — needs sync from another device",
                    &drive_str[..drive_str.len().min(30)]
                );
                drive_needs_sync = true;
            }
        }

        Ok(AgentLoadResult {
            agent,
            drive_needs_sync,
        })
    }

    /// List drives belonging to the current agent.
    /// Falls back to the active drive if the agent resource has no `drives` property.
    pub async fn list_drives(&self) -> AtomicResult<Vec<DriveInfo>> {
        let agent = self.get_default_agent()?;
        let agent_resource = self.get_resource(&agent.subject).await?;

        // Keep legacy Agent.drives entries, then include the private home where
        // create_drive records new drives. Read both during the migration.
        let mut subjects = match agent_resource.get(urls::DRIVES) {
            Ok(Value::ResourceArray(arr)) => arr.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            _ => vec![],
        };
        if let Ok(personal) = self.private_drive_subject() {
            if let Ok(home) = self.get_resource(&personal.as_str().into()).await {
                if !subjects.contains(&personal) {
                    subjects.push(personal);
                }
                if let Ok(Value::ResourceArray(listed)) = home.get(urls::DRIVES) {
                    for subject in listed {
                        let subject = subject.to_string();
                        if !subjects.contains(&subject) {
                            subjects.push(subject);
                        }
                    }
                }
            }
        }
        if let Some(active) = self.get_active_drive() {
            if !subjects.contains(&active) {
                subjects.push(active);
            }
        }

        let mut drives = Vec::with_capacity(subjects.len());
        for subject in subjects {
            let name = match self.get_resource(&subject.as_str().into()).await {
                Ok(r) => r.get(urls::NAME).map(|v| v.to_string()).unwrap_or_default(),
                Err(_) => String::new(),
            };
            drives.push(DriveInfo { subject, name });
        }

        Ok(drives)
    }

    /// Every Drive this node stores.
    ///
    /// A full scan of the resource tree, deliberately. The query indexes would
    /// be faster, but an index that is stale or partial answers "fewer drives
    /// than you have" — and the caller (owner-mode enrollment) would then
    /// silently lock the owner out of their own data. Paying O(store) once at
    /// boot for a certain answer is the right trade; do not "optimize" this into
    /// a query without changing what a wrong answer costs.
    pub async fn drive_subjects(&self) -> Vec<String> {
        use crate::storelike::Storelike;

        self.all_resources(false)
            .filter(|resource| {
                matches!(
                    resource.get(crate::urls::IS_A),
                    Ok(Value::ResourceArray(classes))
                        if classes.iter().any(|class| class.to_string() == crate::urls::DRIVE)
                )
            })
            .map(|resource| resource.get_subject().to_string())
            .collect()
    }

    /// Per-drive storage usage (resource count, Loro snapshot bytes, blob
    /// bytes) for the given `drive_subjects` — the Sync page's usage display and
    /// a managed node's control-plane usage report. A managed node passes its
    /// allowlisted (hosted) drives — these belong to enrolled users, not the
    /// node's own agent.
    ///
    /// Cost is O(the drives' resources), not O(store): it resolves each drive's
    /// subjects and point-looks-up their propvals/snapshots. Blobs are
    /// content-addressed and counted once per drive. Each drive pays its own
    /// logical quota usage even when another owner's drive shares the same
    /// physical object. These counters must not be used as bucket-size totals.
    pub async fn per_drive_usage(
        &self,
        drive_subjects: &[String],
    ) -> AtomicResult<Vec<DriveUsage>> {
        use std::collections::{HashMap, HashSet};

        if drive_subjects.is_empty() {
            return Ok(vec![]);
        }

        // Map every resource subject (pure id) → its drive, and seed a row per drive.
        let mut subject_to_drive: HashMap<String, String> = HashMap::new();
        let mut usage: HashMap<String, DriveUsage> = HashMap::new();
        for drive_subject in drive_subjects {
            // Best-effort display name from the drive resource.
            let name = match self.get_resource(&drive_subject.as_str().into()).await {
                Ok(r) => r.get(urls::NAME).ok().map(|v| v.to_string()),
                Err(_) => None,
            };
            usage.insert(
                drive_subject.clone(),
                DriveUsage {
                    drive_subject: drive_subject.clone(),
                    name,
                    resource_count: 0,
                    blob_bytes: 0,
                    loro_bytes: 0,
                },
            );
            let ds: crate::Subject = drive_subject.as_str().into();
            // The drive root resource itself is part of the drive;
            // collect_drive_subjects only walks its children.
            subject_to_drive.insert(ds.pure_id(), drive_subject.clone());
            for subject in crate::sync::engine::collect_drive_subjects(self, &ds).await {
                subject_to_drive.insert(subject, drive_subject.clone());
            }
        }

        // Walk only the drives' own subjects, with point lookups. Scanning every
        // resource and every Loro snapshot in the store to filter down to one
        // drive makes this O(store) rather than O(drive) — measured at ~4s for a
        // 43-resource drive on a multi-GB store, and it is paid on every Sync
        // page load.
        let mut seen_blobs: HashSet<(&str, [u8; 32])> = HashSet::new();
        // Share metadata lookups, not quota attribution, across drives.
        let mut blob_sizes: HashMap<[u8; 32], Option<u64>> = HashMap::new();

        for (subject, drive) in &subject_to_drive {
            let Some(row) = usage.get_mut(drive) else {
                continue;
            };

            if let Some(snapshot) = self.get_loro_snapshot_bytes(subject) {
                row.loro_bytes += snapshot.len() as u64;
            }

            // Propvals only — the materialized state carries `blob`, and a Loro
            // decode per resource would put the cost right back.
            let Ok(propvals) = self.get_propvals(subject) else {
                continue;
            };

            row.resource_count += 1;

            let Some(blob_val) = propvals.get(urls::BLOB) else {
                continue;
            };
            let blob_did = blob_val.to_string();
            let blob_subject = crate::Subject::from_raw(&blob_did, None);
            let Some(hash_hex) = blob_subject.blob_hash_hex() else {
                continue;
            };
            let Ok(hash_bytes) = hex::decode(hash_hex) else {
                continue;
            };
            if hash_bytes.len() != 32 {
                continue;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            if !seen_blobs.insert((drive.as_str(), hash)) {
                continue;
            }
            let size = match blob_sizes.get(&hash) {
                Some(size) => *size,
                None => {
                    let size = self.blob_size(&hash).await?;
                    blob_sizes.insert(hash, size);
                    size
                }
            };
            if let Some(size) = size {
                row.blob_bytes += size;
            }
        }

        Ok(usage.into_values().collect())
    }

    /// Per-resource storage of one drive: Loro snapshot bytes (history) and the
    /// blob bytes of attached files. Same accounting as [`Db::per_drive_usage`],
    /// kept per resource so a client can draw a size map of the drive.
    pub async fn drive_usage_breakdown(
        &self,
        drive_subject: &str,
    ) -> AtomicResult<Vec<ResourceUsage>> {
        use std::collections::HashSet;

        let ds: crate::Subject = drive_subject.into();
        let mut subjects: Vec<String> = crate::sync::engine::collect_drive_subjects(self, &ds)
            .await
            .into_iter()
            .collect();
        subjects.sort();

        let mut seen_blobs: HashSet<[u8; 32]> = HashSet::new();
        let mut rows = Vec::new();

        for subject in subjects {
            let Ok(propvals) = self.get_propvals(&subject) else {
                continue;
            };
            let loro_bytes = self
                .get_loro_snapshot_bytes(&subject)
                .map(|s| s.len() as u64)
                .unwrap_or(0);

            let mut blob_bytes = 0;
            if let Some(blob_val) = propvals.get(urls::BLOB) {
                let blob_subject = crate::Subject::from_raw(&blob_val.to_string(), None);
                if let Some(hash_bytes) = blob_subject
                    .blob_hash_hex()
                    .and_then(|h| hex::decode(h).ok())
                    .filter(|b| b.len() == 32)
                {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&hash_bytes);
                    if seen_blobs.insert(hash) {
                        blob_bytes = self.blob_size(&hash).await?.unwrap_or(0);
                    }
                }
            }

            let text = |prop: &str| propvals.get(prop).map(|v| v.to_string());
            rows.push(ResourceUsage {
                name: text(urls::NAME).or_else(|| text(urls::FILENAME)),
                parent: text(urls::PARENT),
                is_a: text(urls::IS_A).and_then(|c| c.split(',').next().map(str::to_string)),
                subject,
                loro_bytes,
                blob_bytes,
            });
        }

        Ok(rows)
    }

    /// Get children of a resource, optionally filtered by class.
    pub async fn get_children(
        &self,
        parent: &str,
        class_filter: Option<&str>,
    ) -> AtomicResult<Vec<Resource>> {
        let mut result = Vec::new();

        for resource in self.all_resources(false) {
            if let Ok(p) = resource.get(urls::PARENT) {
                if crate::identifiers::canonicalize_scheme(&p.to_string())
                    != crate::identifiers::canonicalize_scheme(parent)
                {
                    continue;
                }
            } else {
                continue;
            }

            if let Some(class) = class_filter {
                if let Ok(is_a) = resource.get(urls::IS_A) {
                    if !is_a.to_string().contains(class) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            result.push(resource);
        }

        Ok(result)
    }

    /// Full onboarding: create an agent and a private drive in one call.
    /// The agent's secret will contain the drive DID for DHT discovery.
    /// Returns (agent, drive_subject).
    pub async fn setup(&self, agent_name: &str) -> AtomicResult<(crate::agents::Agent, String)> {
        let mut agent = self.create_agent(Some(agent_name)).await?;
        self.set_default_agent(agent.clone());
        let drive = self.ensure_private_drive().await?;
        // `create_drive` — which this used to call — set the active drive as
        // part of creating one. `ensure_private_drive` deliberately does not:
        // materializing a home is not the same act as switching to it. Setup IS
        // that act, so it records it here; without this every later call fails
        // with "No drive set. Call setup() first."
        self.set_active_drive(&drive)?;

        if let Ok(mut personal) = self.get_resource(&drive.as_str().into()).await {
            personal.set_unsafe(
                urls::NAME.into(),
                Value::String(format!("{}'s Drive", agent_name)),
            )?;
            self.add_resource_opts(&personal, false, true, true).await?;
        }

        // Set initial_drive so the secret contains the drive DID.
        // This lets other devices find this drive via DHT when restoring from secret.
        agent.initial_drive = Some(drive.as_str().into());
        self.set_default_agent(agent.clone());
        // Re-save the agent resource so `drives` and `personalDrive` are persisted.
        self.add_resource_opts(&agent.to_resource()?, false, true, true)
            .await?;

        Ok((agent, drive))
    }
    // ── High-level SDK helpers ─────────────────────────────────────────
}
