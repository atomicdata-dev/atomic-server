//! RedbStore: KvStore backed by redb — works natively and in WASM.
//! Uses InMemoryBackend by default. Can be swapped to OPFS backend for persistence.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use redb::{
    backends::InMemoryBackend, Database, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};

use crate::errors::AtomicResult;

use super::{
    kv_store::{KvIter, KvPair, KvStore},
    trees::{Method, Operation, Tree},
};

/// redb table definition: all our trees are `&[u8] -> &[u8]`, named after
/// [`Tree::name`] so redb and sled can never disagree on a tree's version.
fn table_def(tree: Tree) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    TableDefinition::new(tree.name())
}

/// Tables redb used to open under names that had drifted from `Tree::name`.
/// The query-members and watched-query layouts moved to v6 and v5 while
/// redb kept writing both into their v3 tables, so a store from before
/// this fix can hold rows in an older key layout. Both are caches that
/// rebuild on the next query, so dropping them is safe.
///
/// The search layout moved to v2 (document ids in the postings, no separate
/// token list); the v1 tables are rebuilt into it and only take up room.
const STALE_TABLES: [&str; 6] = [
    "members_index_v3",
    "watched_queries_v3",
    "search_postings_v1",
    "search_docs_v1",
    "search_doc_tokens_v1",
    "search_trigrams_v1",
];

fn create_all_tables(tx: &redb::WriteTransaction) {
    for tree in Tree::ALL {
        let _ = tx.open_table(table_def(tree));
    }
    for name in STALE_TABLES {
        let _ = tx.delete_table(TableDefinition::<&[u8], &[u8]>::new(name));
    }
}

/// A KvStore backed by redb.
/// Supports InMemoryBackend (default) or OPFS backend (WASM persistent).
/// Thread-safe via redb's internal locking (MVCC).
pub struct RedbStore {
    db: Arc<Database>,
    /// When Some, operations are buffered instead of committed immediately.
    /// Reads consult the buffer first (read-your-writes within a batch).
    /// Call `commit_batch()` to flush all buffered ops in a single transaction.
    batch_buffer: std::sync::Mutex<Option<BatchBuffer>>,
    /// Set by every `Durability::None` commit, cleared by `flush`. Lets the
    /// durable-flush tick skip the fsync (and the sentinel write) when nothing
    /// changed, which is most ticks on an idle node or a phone in a pocket.
    dirty: AtomicBool,
}

/// Per-tree map of pending operations. Used for fast read-your-writes lookups.
#[derive(Default)]
struct BatchBuffer {
    /// Insertion-ordered list of all operations (for the final transaction).
    ops: Vec<Operation>,
    /// Per-tree most-recent value for each key. None means deleted.
    /// Keyed by (tree_name, key_bytes).
    latest: std::collections::HashMap<(String, Vec<u8>), Option<Vec<u8>>>,
}

impl BatchBuffer {
    fn push(&mut self, op: Operation) {
        let key = (op.tree.to_string(), op.key.clone());
        let val = match op.method {
            Method::Insert => op.val.clone(),
            Method::Delete => None,
        };
        self.latest.insert(key, val);
        self.ops.push(op);
    }

    fn get(&self, tree: &Tree, key: &[u8]) -> Option<Option<Vec<u8>>> {
        self.latest.get(&(tree.to_string(), key.to_vec())).cloned()
    }
}

/// Open a redb file, run `Database::compact()`, close. Returns
/// `(size_before, size_after, did_compact)`. Designed for the
/// admin-triggered `atomic-server compact` CLI subcommand — the
/// caller MUST guarantee no atomic-server process is running against
/// the same file (redb takes an exclusive lock).
///
/// Compaction itself is `O(file size)` and intentionally slow; for a
/// multi-GB store expect several minutes. The win is that subsequent
/// boots `fsync` a much smaller file, which on macOS is the dominant
/// cost of `Database::create` (see redb `begin_writable()` at
/// `page_manager.rs:361-367`).
#[cfg(all(feature = "db", not(target_arch = "wasm32")))]
pub fn compact_file(path: &std::path::Path) -> AtomicResult<(u64, u64, bool)> {
    let size_before = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut db = redb::Database::create(path)
        .map_err(|e| format!("Failed to open redb at {}: {e}", path.display()))?;
    let did_compact = super::compaction::compact_database(&mut db)?;
    drop(db);
    let size_after = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    Ok((size_before, size_after, did_compact))
}

impl RedbStore {
    /// Create a RedbStore backed by a file on disk. No startup compaction;
    /// see `new_file_with_policy` for the path `Db::init_redb_file` takes.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_file(path: &std::path::Path) -> AtomicResult<Self> {
        Self::new_file_with_policy(path, &super::compaction::CompactionPolicy::disabled())
            .map(|(store, _)| store)
    }

    /// Open (or create) the file, log its size and open duration, and run
    /// the startup compaction `policy` on it before any table is touched.
    /// The second value says whether a compaction ran; a failure there is a
    /// `Skip::Failed`, never an error, so a store that cannot be compacted
    /// still opens.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_file_with_policy(
        path: &std::path::Path,
        policy: &super::compaction::CompactionPolicy,
    ) -> AtomicResult<(
        Self,
        Result<super::compaction::CompactionRecord, super::compaction::Skip>,
    )> {
        // `Database::create` with defaults uses a 1 GiB cache and the
        // slow full-scan repair path on any unclean shutdown. On a
        // multi-GB store that's 40+ seconds added to every boot
        // (see redb issue #1055). The Builder lets us drop the cache
        // to fit-for-purpose; per-transaction `set_quick_repair(true)`
        // below persists the allocator state on every commit so the
        // next open is "almost instant" (redb transactions.rs:1246-1258
        // describes the mechanism).
        let t = std::time::Instant::now();
        let mut db = Database::create(path)
            .map_err(|e| format!("Failed to create redb at {}: {e}", path.display()))?;
        let open_duration = t.elapsed();
        tracing::info!(
            "RedbStore::new_file: Database::create in {:?}",
            open_duration
        );

        // On the handle we already hold: the file lock is taken once, and
        // a bloated store is not opened a second time just to measure it.
        let compaction =
            super::compaction::run_startup_policy(&mut db, path, open_duration, policy);

        // Create all tables upfront
        let t = std::time::Instant::now();
        {
            let mut tx = db
                .begin_write()
                .map_err(|e| format!("Failed to begin write tx: {e}"))?;
            // 2-phase commit persists redb's allocator state alongside
            // each transaction. Without it, an unclean shutdown (SIGKILL,
            // crash, power loss) forces a full file scan + repair on next
            // open — measured at 44s on a 3.6 GiB store, all of it spent
            // in `Database::create` before the actor system even starts.
            // With 2PC the next open loads the allocator state and skips
            // the repair entirely. Trade-off: each write pays one extra
            // fsync; on a server doing a handful of commits/sec that's
            // imperceptible, and the boot-time win is dramatic.
            tx.set_quick_repair(true);
            create_all_tables(&tx);
            tx.commit()
                .map_err(|e| format!("Failed to commit initial tables: {e}"))?;
        }
        tracing::info!("RedbStore::new_file: table-create tx in {:?}", t.elapsed());

        Ok((
            RedbStore {
                db: Arc::new(db),
                batch_buffer: std::sync::Mutex::new(None),
                dirty: AtomicBool::new(false),
            },
            compaction,
        ))
    }

    /// Create a new in-memory RedbStore.
    pub fn new_memory() -> AtomicResult<Self> {
        let backend = InMemoryBackend::new();
        let db = Database::builder()
            .create_with_backend(backend)
            .map_err(|e| format!("Failed to create redb: {e}"))?;

        // Create all tables upfront so reads don't fail on missing tables
        {
            let mut tx = db
                .begin_write()
                .map_err(|e| format!("Failed to begin write tx: {e}"))?;
            tx.set_quick_repair(true);
            create_all_tables(&tx);
            tx.commit()
                .map_err(|e| format!("Failed to commit initial tables: {e}"))?;
        }

        Ok(RedbStore {
            db: Arc::new(db),
            batch_buffer: std::sync::Mutex::new(None),
            dirty: AtomicBool::new(false),
        })
    }

    /// Create a RedbStore backed by OPFS for persistent storage in WASM Workers.
    /// The file is created/opened in the Origin Private File System.
    ///
    /// With `encryption_key` set, all data is encrypted at rest via
    /// [`super::encrypted_backend::EncryptedBackend`]. Opening an encrypted
    /// file without the key (or with the wrong one) fails instead of exposing
    /// or corrupting data, as does opening a plaintext file with a key.
    #[cfg(target_arch = "wasm32")]
    pub async fn new_opfs(filename: &str, encryption_key: Option<&[u8; 32]>) -> AtomicResult<Self> {
        let backend = super::opfs_backend::OpfsBackend::open(filename)
            .await
            .map_err(|e| format!("Failed to open OPFS backend: {:?}", e))?;

        let db = match encryption_key {
            Some(key) => {
                let encrypted = super::encrypted_backend::EncryptedBackend::new(backend, key)
                    .map_err(|e| format!("Failed to open encrypted OPFS backend: {e}"))?;
                Database::builder()
                    .create_with_backend(encrypted)
                    .map_err(|e| format!("Failed to create encrypted redb with OPFS: {e}"))?
            }
            None => Database::builder()
                .create_with_backend(backend)
                .map_err(|e| format!("Failed to create redb with OPFS: {e}"))?,
        };

        // Create all tables upfront
        {
            let mut tx = db
                .begin_write()
                .map_err(|e| format!("Failed to begin write tx: {e}"))?;
            tx.set_quick_repair(true);
            create_all_tables(&tx);
            tx.commit()
                .map_err(|e| format!("Failed to commit initial tables: {e}"))?;
        }

        Ok(RedbStore {
            db: Arc::new(db),
            batch_buffer: std::sync::Mutex::new(None),
            dirty: AtomicBool::new(false),
        })
    }
}

/// Compute the exclusive upper bound for a prefix scan.
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();

    while let Some(last) = end.last_mut() {
        if *last < 0xff {
            *last += 1;

            return Some(end);
        }

        end.pop();
    }

    None
}

impl KvStore for RedbStore {
    fn get(&self, tree: Tree, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        // Read-your-writes: check the batch buffer first
        {
            let buf = self.batch_buffer.lock().unwrap();
            if let Some(buffer) = buf.as_ref() {
                if let Some(val) = buffer.get(&tree, key) {
                    return Ok(val);
                }
            }
        }
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read tx: {e}"))?;
        let table = tx
            .open_table(table_def(tree))
            .map_err(|e| format!("redb open table: {e}"))?;

        let result = table.get(key).map_err(|e| format!("redb get: {e}"))?;

        Ok(result.map(|guard| guard.value().to_vec()))
    }

    fn insert(&self, tree: Tree, key: &[u8], val: &[u8]) -> AtomicResult<()> {
        self.apply_batch(&[Operation {
            tree,
            method: Method::Insert,
            key: key.to_vec(),
            val: Some(val.to_vec()),
        }])
    }

    fn remove(&self, tree: Tree, key: &[u8]) -> AtomicResult<()> {
        self.apply_batch(&[Operation {
            tree,
            method: Method::Delete,
            key: key.to_vec(),
            val: None,
        }])
    }

    fn contains_key(&self, tree: Tree, key: &[u8]) -> AtomicResult<bool> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read tx: {e}"))?;
        let table = tx
            .open_table(table_def(tree))
            .map_err(|e| format!("redb open table: {e}"))?;

        let result = table
            .get(key)
            .map_err(|e| format!("redb contains_key: {e}"))?;

        Ok(result.is_some())
    }

    fn scan_prefix(&self, tree: Tree, prefix: &[u8]) -> KvIter {
        let tx = match self.db.begin_read() {
            Ok(tx) => tx,
            Err(e) => return Box::new(std::iter::once(Err(format!("redb read tx: {e}").into()))),
        };
        let table = match tx.open_table(table_def(tree)) {
            Ok(t) => t,
            Err(e) => {
                return Box::new(std::iter::once(Err(format!("redb open table: {e}").into())))
            }
        };

        // Collect results to avoid lifetime issues with the read transaction
        let results: Vec<KvPair> = if let Some(end) = prefix_upper_bound(prefix) {
            table
                .range(prefix..end.as_slice())
                .map(|iter| {
                    iter.filter_map(|r| r.ok())
                        .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            table
                .range(prefix..)
                .map(|iter| {
                    iter.filter_map(|r| r.ok())
                        .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
                        .collect()
                })
                .unwrap_or_default()
        };

        Box::new(results.into_iter().map(Ok))
    }

    fn range(&self, tree: Tree, start: Vec<u8>, end: Vec<u8>, reverse: bool) -> KvIter {
        let tx = match self.db.begin_read() {
            Ok(tx) => tx,
            Err(e) => return Box::new(std::iter::once(Err(format!("redb read tx: {e}").into()))),
        };
        let table = match tx.open_table(table_def(tree)) {
            Ok(t) => t,
            Err(e) => {
                return Box::new(std::iter::once(Err(format!("redb open table: {e}").into())))
            }
        };

        let results: Vec<KvPair> = table
            .range(start.as_slice()..end.as_slice())
            .map(|iter| {
                iter.filter_map(|r| r.ok())
                    .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
                    .collect()
            })
            .unwrap_or_default();

        if reverse {
            let mut reversed = results;
            reversed.reverse();
            Box::new(reversed.into_iter().map(Ok))
        } else {
            Box::new(results.into_iter().map(Ok))
        }
    }

    fn range_page(
        &self,
        tree: Tree,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: usize,
    ) -> crate::errors::AtomicResult<Vec<KvPair>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read tx: {e}"))?;
        let table = tx
            .open_table(table_def(tree))
            .map_err(|e| format!("redb open table: {e}"))?;
        let rows = table
            .range(start.as_slice()..end.as_slice())
            .map_err(|e| format!("redb range: {e}"))?;
        rows.take(limit)
            .map(|row| {
                let (k, v) = row.map_err(|e| format!("redb range entry: {e}"))?;
                Ok((k.value().to_vec(), v.value().to_vec()))
            })
            .collect()
    }

    fn range_value_sizes(
        &self,
        tree: Tree,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: usize,
    ) -> AtomicResult<Vec<(Vec<u8>, u64)>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read tx: {e}"))?;
        let table = tx
            .open_table(table_def(tree))
            .map_err(|e| format!("redb open table: {e}"))?;
        let rows = table
            .range(start.as_slice()..end.as_slice())
            .map_err(|e| format!("redb range: {e}"))?;
        rows.take(limit)
            .map(|row| {
                let (k, v) = row.map_err(|e| format!("redb range entry: {e}"))?;
                Ok((k.value().to_vec(), v.value().len() as u64))
            })
            .collect()
    }

    fn first_entry(&self, tree: Tree) -> AtomicResult<Option<KvPair>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read tx: {e}"))?;
        let table = tx
            .open_table(table_def(tree))
            .map_err(|e| format!("redb open table: {e}"))?;
        let first = table
            .first()
            .map_err(|e| format!("redb first entry: {e}"))?;
        Ok(first.map(|(key, value)| (key.value().to_vec(), value.value().to_vec())))
    }

    fn iter_tree(&self, tree: Tree) -> KvIter {
        let tx = match self.db.begin_read() {
            Ok(tx) => tx,
            Err(e) => return Box::new(std::iter::once(Err(format!("redb read tx: {e}").into()))),
        };
        let table = match tx.open_table(table_def(tree)) {
            Ok(t) => t,
            Err(e) => {
                return Box::new(std::iter::once(Err(format!("redb open table: {e}").into())))
            }
        };

        let results: Vec<KvPair> = table
            .iter()
            .map(|iter| {
                iter.filter_map(|r| r.ok())
                    .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
                    .collect()
            })
            .unwrap_or_default();

        Box::new(results.into_iter().map(Ok))
    }

    fn clear_tree(&self, tree: Tree) -> AtomicResult<()> {
        let mut tx = self
            .db
            .begin_write()
            .map_err(|e| format!("redb write tx: {e}"))?;
        tx.set_quick_repair(true);
        {
            // Delete and recreate the table
            let mut table = tx
                .open_table(table_def(tree))
                .map_err(|e| format!("redb open table: {e}"))?;
            // redb doesn't have a clear() — we drain the table
            let keys: Vec<Vec<u8>> = table
                .iter()
                .map(|iter| {
                    iter.filter_map(|r| r.ok())
                        .map(|(k, _)| k.value().to_vec())
                        .collect()
                })
                .unwrap_or_default();

            for key in keys {
                table
                    .remove(key.as_slice())
                    .map_err(|e| format!("redb remove in clear: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("redb commit clear: {e}"))?;
        Ok(())
    }

    fn apply_batch(&self, operations: &[Operation]) -> AtomicResult<()> {
        if operations.is_empty() {
            return Ok(());
        }

        // If in batch mode, buffer the operations instead of committing
        {
            let mut buf = self.batch_buffer.lock().unwrap();
            if let Some(buffer) = buf.as_mut() {
                for op in operations {
                    buffer.push(op.clone());
                }
                return Ok(());
            }
        }

        let mut tx = self
            .db
            .begin_write()
            .map_err(|e| format!("redb write tx: {e}"))?;
        // EXPERIMENT: relax durability to avoid an fsync per commit (was
        // set_quick_repair(true) → 2PC + Immediate fsync ≈ 23ms/commit).
        tx.set_durability(redb::Durability::None)
            .map_err(|e| format!("redb set_durability: {e}"))?;
        {
            for op in operations {
                let mut table = tx
                    .open_table(table_def(op.tree))
                    .map_err(|e| format!("redb open table: {e}"))?;

                match op.method {
                    Method::Insert => {
                        let val = op.val.as_deref().unwrap_or(b"");
                        table
                            .insert(op.key.as_slice(), val)
                            .map_err(|e| format!("redb batch insert: {e}"))?;
                    }
                    Method::Delete => {
                        table
                            .remove(op.key.as_slice())
                            .map_err(|e| format!("redb batch remove: {e}"))?;
                    }
                }
            }
        }
        tx.commit().map_err(|e| format!("redb commit batch: {e}"))?;
        self.dirty.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn flush(&self) -> AtomicResult<()> {
        // Nothing committed since the last durable point: skip. A write that
        // lands between this swap and the commit below sets the flag again
        // and is picked up by the next flush.
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        // Per-commit writes use Durability::None (no fsync) for throughput.
        // redb only persists those to disk once a *subsequent* Immediate
        // commit lands, so this flush — a quick Immediate commit — is what
        // actually makes recent commits durable. The server calls it on a
        // periodic tick (see `serve.rs`), amortizing one fsync across many
        // commits instead of paying one per commit. `set_quick_repair`
        // persists redb's allocator state so an unclean shutdown still boots
        // fast.
        let mut tx = self
            .db
            .begin_write()
            .map_err(|e| format!("redb flush begin_write: {e}"))?;
        tx.set_quick_repair(true);
        // Touch a sentinel key so the transaction is non-empty and redb
        // definitely writes (and, at Immediate durability, fsyncs) a new
        // commit point that persists all prior Durability::None commits.
        {
            let mut table = tx
                .open_table(table_def(Tree::DriveMapping))
                .map_err(|e| format!("redb flush open table: {e}"))?;
            table
                .insert(b"__flush_sentinel__".as_slice(), b"".as_slice())
                .map_err(|e| format!("redb flush sentinel: {e}"))?;
        }
        // Immediate is the default durability; committing flushes + fsyncs all
        // prior Durability::None commits.
        if let Err(e) = tx.commit() {
            self.dirty.store(true, Ordering::SeqCst);
            return Err(format!("redb flush commit: {e}").into());
        }
        Ok(())
    }

    fn len(&self, tree: Tree) -> AtomicResult<usize> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("redb read tx: {e}"))?;
        let table = tx
            .open_table(table_def(tree))
            .map_err(|e| format!("redb open table: {e}"))?;
        Ok(table.len().map_err(|e| format!("redb len: {e}"))? as usize)
    }

    fn begin_batch(&self) {
        let mut buf = self.batch_buffer.lock().unwrap();
        if buf.is_none() {
            *buf = Some(BatchBuffer::default());
        }
    }

    fn commit_batch(&self) -> AtomicResult<()> {
        let ops = {
            let mut buf = self.batch_buffer.lock().unwrap();
            buf.take().map(|b| b.ops).unwrap_or_default()
        };
        if ops.is_empty() {
            return Ok(());
        }
        // Apply all buffered operations in a single transaction
        let mut tx = self
            .db
            .begin_write()
            .map_err(|e| format!("redb write tx: {e}"))?;
        // EXPERIMENT: relax durability to avoid an fsync per commit.
        tx.set_durability(redb::Durability::None)
            .map_err(|e| format!("redb set_durability: {e}"))?;
        {
            for op in &ops {
                let mut table = tx
                    .open_table(table_def(op.tree))
                    .map_err(|e| format!("redb open table: {e}"))?;

                match op.method {
                    Method::Insert => {
                        let val = op.val.as_deref().unwrap_or(b"");
                        table
                            .insert(op.key.as_slice(), val)
                            .map_err(|e| format!("redb batch insert: {e}"))?;
                    }
                    Method::Delete => {
                        table
                            .remove(op.key.as_slice())
                            .map_err(|e| format!("redb batch remove: {e}"))?;
                    }
                }
            }
        }
        tx.commit().map_err(|e| format!("redb commit batch: {e}"))?;
        self.dirty.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use redb::TableHandle;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atomic-redb-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("atomic.redb")
    }

    /// A store written before redb's table names followed `Tree::name`
    /// kept query members and watched queries in `*_v3` tables, possibly in
    /// an older key layout. Opening it must switch to the current tables and
    /// drop the old ones rather than read their rows.
    #[test]
    fn opening_drops_tables_from_drifted_names() {
        let path = temp_path("stale-tables");
        {
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            for name in STALE_TABLES {
                let mut table = tx
                    .open_table(TableDefinition::<&[u8], &[u8]>::new(name))
                    .unwrap();
                table
                    .insert(b"old-layout".as_slice(), b"".as_slice())
                    .unwrap();
            }
            tx.commit().unwrap();
        }

        let store = RedbStore::new_file(&path).unwrap();
        assert_eq!(store.get(Tree::QueryMembers, b"old-layout").unwrap(), None);
        assert_eq!(
            store.get(Tree::WatchedQueries, b"old-layout").unwrap(),
            None
        );

        let tx = store.db.begin_read().unwrap();
        let names: Vec<String> = tx
            .list_tables()
            .unwrap()
            .map(|t| t.name().to_string())
            .collect();
        for name in STALE_TABLES {
            assert!(!names.iter().any(|n| n == name), "{name} should be gone");
        }
        for tree in Tree::ALL {
            assert!(names.iter().any(|n| n == tree.name()), "{tree} missing");
        }
    }

    const ABORT_CHILD_ENV: &str = "ATOMIC_REDB_ABORT_CHILD_PATH";
    const ABORT_TEST_NAME: &str =
        "db::redb_store::tests::unflushed_writes_are_lost_on_abort_and_flushed_ones_survive";

    /// Per-commit writes are `Durability::None`; only `flush` makes them
    /// survive an unclean exit. A clean `drop` closes redb durably, so the
    /// loss only shows when the process dies mid-flight: the Android app
    /// kill that motivated the library-owned flush tick. This test re-runs
    /// itself as a child that writes one flushed and one unflushed key, then
    /// aborts (no destructors), and checks what the parent can read back.
    #[test]
    fn unflushed_writes_are_lost_on_abort_and_flushed_ones_survive() {
        if let Ok(path) = std::env::var(ABORT_CHILD_ENV) {
            let store = RedbStore::new_file(std::path::Path::new(&path)).unwrap();
            store.insert(Tree::PluginMeta, b"kept", b"1").unwrap();
            assert!(store.dirty.load(Ordering::SeqCst));
            store.flush().unwrap();
            assert!(!store.dirty.load(Ordering::SeqCst));
            store.insert(Tree::PluginMeta, b"lost", b"1").unwrap();
            std::process::abort();
        }

        let path = temp_path("abort");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                ABORT_TEST_NAME,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ABORT_CHILD_ENV, &path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "the child must abort, not exit cleanly");

        let store = RedbStore::new_file(&path).unwrap();
        assert_eq!(
            store.get(Tree::PluginMeta, b"kept").unwrap(),
            Some(b"1".to_vec()),
            "a flushed write must survive an abort"
        );
        assert_eq!(
            store.get(Tree::PluginMeta, b"lost").unwrap(),
            None,
            "a Durability::None commit must not survive an abort without flush"
        );
        drop(store);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn flush_is_a_no_op_when_nothing_changed() {
        let path = temp_path("noop");
        let store = RedbStore::new_file(&path).unwrap();
        store.insert(Tree::PluginMeta, b"k", b"v").unwrap();
        store.flush().unwrap();
        let size_after_first_flush = std::fs::metadata(&path).unwrap().len();
        // The sentinel write would grow or rewrite the file; a clean store
        // must not touch it at all.
        for _ in 0..10 {
            store.flush().unwrap();
        }
        assert!(!store.dirty.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            size_after_first_flush
        );
        drop(store);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
