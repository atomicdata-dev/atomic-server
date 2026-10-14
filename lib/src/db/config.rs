//! Runtime configuration, durable flush, compaction records and node-key secrets for [`Db`].

use super::*;

impl Db {
    /// Install a sync admission/quota policy (managed nodes). The default is
    /// [`crate::sync::policy::OpenPolicy`] (allow everything, no quotas).
    pub fn set_sync_policy(&self, policy: Arc<dyn crate::sync::policy::SyncPolicy>) {
        if let Ok(mut guard) = self.sync_policy.write() {
            *guard = policy;
        }
    }

    /// The currently-installed sync policy.
    /// Set how many signed envelopes are kept per resource. Takes effect on
    /// the next `apply_commit`; existing rows are pruned when their resource
    /// is next written.
    pub fn set_envelope_retention(&self, retention: crate::envelopes::EnvelopeRetention) {
        if let Ok(mut guard) = self.envelope_retention.write() {
            *guard = retention;
        }
    }

    pub fn envelope_retention(&self) -> crate::envelopes::EnvelopeRetention {
        self.envelope_retention
            .read()
            .map(|g| *g)
            .unwrap_or_default()
    }

    pub fn sync_policy(&self) -> Arc<dyn crate::sync::policy::SyncPolicy> {
        self.sync_policy
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| Arc::new(crate::sync::policy::OpenPolicy))
    }

    /// Record that the server asked a peer for `hash` while importing a
    /// `SYNC_PUSH` for `drive` (already admission-checked at that point).
    /// Consulted by the `BLOB_RESPONSE` handler (planning/unified-sync.md
    /// F4) so it can gate the write against that same drive instead of
    /// accepting arbitrary blob bytes unconditionally.
    pub fn note_pending_blob_request(&self, hash: [u8; 32], drive: String) {
        if let Ok(mut guard) = self.pending_blob_requests.write() {
            let now = web_time::Instant::now();
            guard.retain(|_, (_, requested_at)| {
                now.duration_since(*requested_at) < PENDING_BLOB_REQUEST_TTL
            });
            guard.insert(hash, (drive, now));
        }
    }

    /// Consume (remove) the drive a pending `BLOB_REQUEST` for `hash` was
    /// issued for, if any. `None` means this hash was never requested by
    /// this node (or the request expired — see `PENDING_BLOB_REQUEST_TTL`)
    /// — the caller should reject the response outright.
    pub fn take_pending_blob_request(&self, hash: &[u8; 32]) -> Option<String> {
        let (drive, requested_at) = self
            .pending_blob_requests
            .write()
            .ok()
            .and_then(|mut guard| guard.remove(hash))?;

        if requested_at.elapsed() < PENDING_BLOB_REQUEST_TTL {
            Some(drive)
        } else {
            None
        }
    }

    /// Persist the outcome of a startup compaction so `last_compaction`
    /// can report it after the log line is gone. Durable at once: the
    /// compaction it describes already cost seconds, a 100 ms flush
    /// window is nothing next to it.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub(super) fn record_compaction(
        &self,
        record: &compaction::CompactionRecord,
    ) -> AtomicResult<()> {
        let bytes = serde_json::to_vec(record)
            .map_err(|e| format!("Could not serialize the compaction record: {e}"))?;
        self.kv
            .insert(trees::Tree::PluginMeta, compaction::RECORD_KEY, &bytes)?;
        self.kv.flush()
    }

    /// The most recent automatic startup compaction of this store's file,
    /// if one ever ran. `None` on a store that was never compacted at
    /// startup, and on the in-memory, OPFS and sled backends.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub fn last_compaction(&self) -> Option<compaction::CompactionRecord> {
        let bytes = self
            .kv
            .get(trees::Tree::PluginMeta, compaction::RECORD_KEY)
            .ok()
            .flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Make `Durability::None` commits durable on a fixed cadence.
    ///
    /// Every redb write skips the fsync for throughput and only becomes
    /// durable at the next `flush`. This thread is that flush. It belongs to
    /// the library, not the host, so that no binding can open a file store
    /// and forget it: the Flutter app did exactly that and lost every edit
    /// since the last drive switch on an app kill. The tick is cheap when
    /// idle (`RedbStore::flush` returns early unless something was written)
    /// and blocks on fsync when not, hence a dedicated OS thread rather than
    /// a tokio task. It holds only a `Weak` to the store and exits once the
    /// last `Db` clone is dropped.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn spawn_durable_flush(&self, interval: std::time::Duration) {
        let kv: std::sync::Weak<dyn KvStore> = Arc::downgrade(&self.kv);
        std::thread::Builder::new()
            .name("durable-flush".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                let Some(kv) = kv.upgrade() else { break };
                if let Err(e) = kv.flush() {
                    tracing::warn!("periodic durable flush failed: {e}");
                }
            })
            .expect("spawn durable-flush thread");
    }

    /// Stores a secret, replacing any of the same name.
    ///
    /// There is deliberately no `get_plugin_secret` returning a value. The only
    /// reader is [`Db::use_plugin_secret`], which hands the value to a closure
    /// and never out of it, so no endpoint can serve one by accident.
    /// Sets the key stored secrets are wrapped with. Once per process.
    ///
    /// Silently ignored if already set: a second call would mean two parts of
    /// the process disagree about which key opens the store, and the loser
    /// would write secrets the winner cannot read.
    pub fn set_node_key(&self, key: [u8; crate::vault::keys::KEK_LEN]) {
        let _ = self.node_key.set(key);
    }

    /// A 32-byte key for one purpose, derived from the node key, or `None`
    /// when this node has no key. The node key itself never leaves the store;
    /// what comes out is bound to `context` (say what it is for, and version
    /// it), so a key made for signing tokens cannot open a wrapped secret.
    pub fn derive_node_key(&self, context: &str) -> Option<[u8; 32]> {
        self.node_key
            .get()
            .map(|key| blake3::derive_key(context, key))
    }

    /// Wraps a secret for storage, or passes it through when no key is set.
    ///
    /// Passing through is what lets a store predating the node key still be
    /// read and written. It is not a fallback anyone should rely on, which is
    /// why `has_node_key` exists for callers that must know.
    pub(super) fn wrap_secret(&self, value: &str) -> AtomicResult<String> {
        let Some(key) = self.node_key.get() else {
            return Ok(value.to_string());
        };

        crate::vault::secret_envelope::SecretEnvelope::create(
            value.as_bytes(),
            &[crate::vault::secret_envelope::NewWrapper::NodeKey { kek: *key }],
        )?
        .to_json()
    }

    /// Opens a stored secret, tolerating one written before there was a key.
    pub(super) fn unwrap_secret(&self, stored: &str) -> AtomicResult<String> {
        let Ok(envelope) = crate::vault::secret_envelope::SecretEnvelope::from_json(stored) else {
            // Written before this node had a key. Readable, and rewritten
            // wrapped the next time it is set.
            return Ok(stored.to_string());
        };

        let Some(key) = self.node_key.get() else {
            return Err("this secret is wrapped, but this node has no key to open it".into());
        };

        let opened = envelope.unwrap_secret(&crate::vault::secret_envelope::Unlock::Kek(*key))?;

        String::from_utf8(opened).map_err(|_| "a stored secret was not text".into())
    }

    /// Whether stored secrets are wrapped at all.
    pub fn has_node_key(&self) -> bool {
        self.node_key.get().is_some()
    }
}
