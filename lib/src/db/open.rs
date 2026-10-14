//! Constructors and opening a [`Db`] on its storage backends.

use super::*;

impl Db {
    pub(super) fn is_remote_not_found(&self, subject: &str) -> bool {
        let Ok(mut map) = self.remote_not_found.lock() else {
            return false;
        };
        match map.get(subject) {
            Some(expires) if web_time::Instant::now() < *expires => true,
            Some(_) => {
                map.remove(subject);
                false
            }
            None => false,
        }
    }

    pub(super) fn remember_remote_not_found(&self, subject: &str) {
        if let Ok(mut map) = self.remote_not_found.lock() {
            map.insert(
                subject.to_string(),
                web_time::Instant::now() + REMOTE_NOT_FOUND_TTL,
            );
        }
    }

    /// A `Db` over `kv` with every other field at its default. Not usable
    /// until [`Db::open`] has run.
    pub(super) fn from_kv(
        path: std::path::PathBuf,
        kv: Arc<dyn KvStore>,
        base_domain: Option<String>,
    ) -> Db {
        Db {
            path,
            blob_backend: None,
            kv: Arc::new(compressed_kv::CompressedKv::new(kv)),
            default_agent: Arc::new(Mutex::new(None)),
            node_key: Arc::new(std::sync::OnceLock::new()),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),
            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            filter_drive_roots: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            plugin_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
            fetch_counters: default_fetch_counters(),
            lenses: Default::default(),
            pending_lenses: Default::default(),
            remote_not_found: Default::default(),
        }
    }

    /// The steps every backend runs once its KV is ready.
    pub(super) async fn open(self) -> AtomicResult<Db> {
        self.add_class_extender(crate::collections::get_collection_class_extender())?;

        // Load persisted watched-queries (if any) into the in-memory map
        // before bootstrap, so any filter-matching commits during bootstrap
        // see the right state.
        self.migrate_canonical_scheme_if_needed()?;
        // The browser runs this in slices it can show progress for
        // (`ClientDb.migrateIndexKeysStep`); everywhere else it is done here.
        #[cfg(not(target_arch = "wasm32"))]
        self.migrate_index_keys()?;
        #[cfg(target_arch = "wasm32")]
        if self.kv.iter_tree(Tree::Resources).next().is_none() {
            self.migrate_index_keys_step(1)?;
        }
        self.populate_watched_queries_cache()?;

        // Runs on every open, but only writes when the embedded defaults
        // (`lib/defaults/*.json` + base models) changed since this store was
        // last seeded: `bootstrap` compares a fingerprint of them against the
        // one stored in `Tree::PluginMeta` and adds what is missing.
        crate::populate::bootstrap(&self)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        // Old chat messages become entries in chat log pages. The browser runs
        // this in slices it can show progress for
        // (`ClientDb.migrateMessagesStep`); everywhere else it is done here,
        // after the watched queries are loaded so the new pages are indexed.
        #[cfg(not(target_arch = "wasm32"))]
        self.migrate_messages().await?;
        #[cfg(not(target_arch = "wasm32"))]
        self.migrate_ai_chats().await?;
        crate::search::maybe_rebuild_search_index(&self)?;
        self.load_lenses().await;
        Ok(self)
    }

    /// Creates a new store at the specified path, or opens the store if it already exists.
    /// Uses sled as the storage backend.
    #[cfg(feature = "db-sled")]
    pub async fn init(path: &std::path::Path, base_domain: Option<String>) -> AtomicResult<Db> {
        tracing::info!("Opening database at {:?}", path);

        let sled_store = sled_store::SledStore::open(path)?;

        // Run migrations before wrapping in Arc (migrations need direct sled access)
        migrations::migrate_maybe(&sled_store, base_domain.as_deref())
            .map_err(|e| format!("Error during migration of database: {:?}", e))?;

        Db::from_kv(path.into(), Arc::new(sled_store), base_domain)
            .open()
            .await
    }

    /// Creates a Db backed by redb with an in-memory backend.
    /// Useful for WASM targets where redb provides proper B-tree indexing.
    /// Can be upgraded to OPFS persistence in the future.
    pub async fn init_redb(base_domain: Option<String>) -> AtomicResult<Db> {
        let redb_store = redb_store::RedbStore::new_memory()?;
        Db::from_kv(std::path::PathBuf::new(), Arc::new(redb_store), base_domain)
            .open()
            .await
    }

    /// Creates a Db backed by redb with file-based persistent storage.
    /// Works on all native targets (not WASM — use init_redb_opfs for that).
    ///
    /// Runs the default [`compaction::CompactionPolicy`] on the file before
    /// serving it; `init_redb_file_with_policy` takes another.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub async fn init_redb_file(
        path: &std::path::Path,
        base_domain: Option<String>,
        uploads_path: &std::path::Path,
    ) -> AtomicResult<Db> {
        Self::init_redb_file_with_policy(
            path,
            base_domain,
            uploads_path,
            &compaction::CompactionPolicy::default(),
        )
        .await
    }

    /// `init_redb_file` with an explicit startup compaction policy. The
    /// file's size and open duration are logged either way; with the policy
    /// enabled the reclaimable space is measured and, past both thresholds,
    /// compacted before any table is read. A compaction failure (including
    /// redb refusing because of a live transaction) is logged and the store
    /// opens as it was; it never fails startup.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub async fn init_redb_file_with_policy(
        path: &std::path::Path,
        base_domain: Option<String>,
        uploads_path: &std::path::Path,
        policy: &compaction::CompactionPolicy,
    ) -> AtomicResult<Db> {
        tracing::info!("Opening ReDB database at {:?}", path);

        std::fs::create_dir_all(path).map_err(|e| {
            format!(
                "Failed to create database directory {}: {e}",
                path.display()
            )
        })?;

        let redb_path = path.join("atomic.redb");

        // Migration logic: if a sled store exists but redb doesn't, migrate it.
        #[cfg(feature = "db-sled")]
        if !redb_path.exists() {
            let sled_path = path.join("sled");

            // Pre-redb servers stored the sled DB directly in the store dir
            // (`store/db`, `store/conf`), NOT in a `sled/` subdir. Detect that
            // legacy layout and relocate the sled files into `sled/` first.
            // Without this the auto-migration never fires on a real in-place
            // upgrade, and `migrate_from_sled`'s rename-to-`.bak` would try to
            // rename the whole store dir — clobbering the redb we just wrote.
            let legacy_root_sled =
                !sled_path.exists() && path.join("db").exists() && path.join("conf").exists();
            if legacy_root_sled {
                tracing::warn!(
                    "Detected a legacy sled store at the store root; relocating it into `sled/` before migration."
                );
                std::fs::create_dir_all(&sled_path)?;
                // Collect first, then move — don't mutate the dir mid-iteration.
                // Everything in the store dir is sled's (uploads live elsewhere);
                // skip the `sled/` dir we just created.
                let names: Vec<std::ffi::OsString> = std::fs::read_dir(path)?
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .filter(|name| name.as_os_str() != "sled")
                    .collect();
                for name in names {
                    std::fs::rename(path.join(&name), sled_path.join(&name))?;
                }
            }

            if sled_path.exists() {
                Self::migrate_from_sled(
                    &sled_path,
                    &redb_path,
                    uploads_path,
                    base_domain.as_deref(),
                )
                .await?;
            }
        } else {
            let _ = uploads_path;
        }

        #[cfg(not(feature = "db-sled"))]
        let _ = uploads_path;

        let (redb_store, compaction) =
            redb_store::RedbStore::new_file_with_policy(&redb_path, policy)?;

        let store = Db::from_kv(path.to_path_buf(), Arc::new(redb_store), base_domain);

        // Bookkeeping only: the compaction itself already happened, and
        // failing to note it must not refuse the start.
        if let Ok(record) = compaction {
            if let Err(e) = store.record_compaction(&record) {
                tracing::warn!("Could not record the startup compaction: {e}");
            }
        }

        let store = store.open().await?;
        store.spawn_durable_flush(DURABLE_FLUSH_INTERVAL);
        Ok(store)
    }

    #[cfg(all(feature = "db", feature = "db-sled", not(target_arch = "wasm32")))]
    pub(super) async fn migrate_from_sled(
        sled_path: &std::path::Path,
        redb_path: &std::path::Path,
        uploads_path: &std::path::Path,
        base_domain: Option<&str>,
    ) -> AtomicResult<()> {
        tracing::warn!("Migrating data from Sled to ReDB and files to CAS...");

        let sled_store = sled_store::SledStore::open(sled_path)?;

        // Bring the sled schema fully up to date BEFORE reading Tree::Resources.
        // A pre-v3 backup keeps its data in `resources_v2` (or `resources_v1`);
        // without this, the loop below reads the empty `resources_v3` tree and
        // silently migrates ZERO user resources — then renames the source dir to
        // `.bak`. `migrate_maybe` chains v0→v1→v2→v3 in place so the read sees
        // every resource. (Verified against a real v2 backup: 61,804 resources
        // were invisible without this call.)
        migrations::migrate_maybe(&sled_store, base_domain)?;

        let redb_store = redb_store::RedbStore::new_file(redb_path)?;

        let mut count_resources = 0;
        let mut count_snapshots = 0;
        let mut count_blobs = 0;

        // Migrate Resources
        for item in sled_store.iter_tree(Tree::Resources) {
            let (subject_bytes, propvals_bin) = item?;
            let subject_str = String::from_utf8_lossy(&subject_bytes).to_string();

            // Try to decode with various versions
            let mut propvals = if let Ok(pv) = rmp_serde::from_slice::<PropVals>(&propvals_bin) {
                pv
            } else if let Ok(pv_v2) = rmp_serde::from_slice::<v2_types::PropValsV2>(&propvals_bin) {
                v2_types::propvals_v2_to_v3(pv_v2, base_domain.unwrap_or("localhost"))
            } else if let Ok(pv_v1) = bincode1::deserialize::<v1_types::PropValsV1>(&propvals_bin) {
                v1_types::propvals_v1_to_v2(pv_v1)
            } else {
                tracing::error!("Failed to migrate resource: {}", subject_str);
                continue;
            };

            // Migrate File resources to CAS
            let is_file = propvals
                .get(urls::IS_A)
                .map(|v| v.to_string().contains(urls::FILE))
                .unwrap_or(false);

            if is_file && !propvals.contains_key(urls::BLOB) {
                if let Some(internal_id) = propvals.get(urls::INTERNAL_ID).map(|v| v.to_string()) {
                    let file_path = uploads_path.join(&internal_id);
                    if file_path.exists() {
                        if let Ok(bytes) = std::fs::read(&file_path) {
                            let hash = blake3::hash(&bytes);
                            let hash_hex = hash.to_hex().to_string();
                            let hash_bytes = hash.as_bytes();

                            redb_store.insert(Tree::Blobs, hash_bytes, &bytes)?;
                            propvals.insert(
                                urls::BLOB.to_string(),
                                Value::AtomicUrl(
                                    crate::identifiers::blob_subject(&hash_hex).into(),
                                ),
                            );
                            propvals.insert(urls::INTERNAL_ID.to_string(), Value::String(hash_hex));
                            count_blobs += 1;
                        }
                    }
                }
            }

            redb_store.insert(
                Tree::Resources,
                &subject_bytes,
                &rmp_serde::to_vec(&propvals).unwrap(),
            )?;
            count_resources += 1;
        }

        // Migrate LoroSnapshots
        for item in sled_store.iter_tree(Tree::LoroSnapshots) {
            let (key, val) = item?;
            redb_store.insert(Tree::LoroSnapshots, &key, &val)?;
            count_snapshots += 1;
        }

        // Migrate other metadata trees
        for tree in [Tree::PluginMeta, Tree::DriveMapping, Tree::DidMapping] {
            for item in sled_store.iter_tree(tree) {
                let (key, val) = item?;
                redb_store.insert(tree, &key, &val)?;
            }
        }

        tracing::info!(
            "Migration complete: {} resources, {} snapshots, {} blobs migrated.",
            count_resources,
            count_snapshots,
            count_blobs
        );

        // Optionally rename old sled dir
        let mut backup_path = sled_path.to_path_buf();
        backup_path.set_extension("bak");
        let _ = std::fs::rename(sled_path, backup_path);

        Ok(())
    }

    /// Creates a Db backed by redb with OPFS persistent storage.
    /// Only available in WASM Workers. Data survives page reloads.
    ///
    /// `encryption_key` (32 bytes) enables at-rest encryption of the OPFS
    /// file; the browser passes a per-agent key so one agent's cache is
    /// unreadable to other sessions on the same origin.
    #[cfg(all(feature = "db", target_arch = "wasm32"))]
    pub async fn init_redb_opfs(
        base_domain: Option<String>,
        filename: &str,
        encryption_key: Option<&[u8; 32]>,
    ) -> AtomicResult<Db> {
        let redb_store = redb_store::RedbStore::new_opfs(filename, encryption_key).await?;
        Db::from_kv(std::path::PathBuf::new(), Arc::new(redb_store), base_domain)
            .open()
            .await
    }

    /// Creates a clone of the store with a different base_domain.
    /// This is useful for multi-tenant applications.
    /// Cloning is very cheap, as it only clones Arc pointers.
    pub fn clone_with_url(&self, base_domain: String) -> Db {
        let mut clone = self.clone();
        clone.base_domain = Some(base_domain);
        clone
    }

    /// Create a temporary Db backed by ReDB. Useful for testing.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub async fn init_temp(id: &str) -> AtomicResult<Db> {
        let tmp_dir_path = format!(".temp/db/{}", id);
        let uploads_path = format!(".temp/db/{}/uploads", id);
        let _try_remove_existing = std::fs::remove_dir_all(&tmp_dir_path);
        std::fs::create_dir_all(&uploads_path)
            .map_err(|e| format!("Failed to create temp dir: {e}"))?;
        let store = Db::init_redb_file(
            std::path::Path::new(&tmp_dir_path),
            Some("https://localhost".into()),
            std::path::Path::new(&uploads_path),
        )
        .await?;
        let agent = store.create_agent(None).await?;
        store.set_default_agent(agent);
        store.populate().await?;
        Ok(store)
    }

    // ── High-level SDK helpers ──────────────────────────────────────────────────

    /// Rewrite `did:ad:` resource / snapshot / mapping keys to `atomic:` on
    /// open. Idempotent; see [`canonical_scheme::migrate_if_needed`].
    pub(super) fn migrate_canonical_scheme_if_needed(&self) -> AtomicResult<()> {
        canonical_scheme::migrate_if_needed(self)
    }
}
