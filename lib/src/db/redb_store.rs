//! RedbStore: KvStore backed by redb — works natively and in WASM.
//! Uses InMemoryBackend by default. Can be swapped to OPFS backend for persistence.

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

/// redb table definition: all our trees are `&[u8] -> &[u8]`.
const TABLE_RESOURCES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("resources_v3");
const TABLE_PROP_VAL_SUB: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("prop_val_sub_index");
const TABLE_VAL_PROP_SUB: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("reference_index_v1");
// v3: QueryFilter key encoding changed to [drive_len][drive_bytes][msgpack rest].
// Must stay in sync with `QUERY_MEMBERS` / `QUERIES_WATCHED` in db/trees.rs.
const TABLE_QUERY_MEMBERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("members_index_v3");
const TABLE_WATCHED_QUERIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("watched_queries_v3");
const TABLE_PLUGIN_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("plugin_meta");
const TABLE_DRIVE_MAPPING: TableDefinition<&[u8], &[u8]> = TableDefinition::new("drive_mapping");
const TABLE_DID_MAPPING: TableDefinition<&[u8], &[u8]> = TableDefinition::new("did_mapping");
const TABLE_LORO_SNAPSHOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("loro_snapshots");
const TABLE_BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");
const TABLE_SEARCH_POSTINGS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("search_postings_v1");
const TABLE_SEARCH_DOCS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("search_docs_v1");
const TABLE_SEARCH_DOC_TOKENS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("search_doc_tokens_v1");
const TABLE_SEARCH_TRIGRAMS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("search_trigrams_v1");
const TABLE_ENVELOPES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("envelopes_v1");

fn table_def(tree: Tree) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    match tree {
        Tree::Resources => TABLE_RESOURCES,
        Tree::PropValSub => TABLE_PROP_VAL_SUB,
        Tree::ValPropSub => TABLE_VAL_PROP_SUB,
        Tree::QueryMembers => TABLE_QUERY_MEMBERS,
        Tree::WatchedQueries => TABLE_WATCHED_QUERIES,
        Tree::PluginMeta => TABLE_PLUGIN_META,
        Tree::DriveMapping => TABLE_DRIVE_MAPPING,
        Tree::DidMapping => TABLE_DID_MAPPING,
        Tree::LoroSnapshots => TABLE_LORO_SNAPSHOTS,
        Tree::Blobs => TABLE_BLOBS,
        Tree::SearchPostings => TABLE_SEARCH_POSTINGS,
        Tree::SearchDocs => TABLE_SEARCH_DOCS,
        Tree::SearchDocTokens => TABLE_SEARCH_DOC_TOKENS,
        Tree::SearchTrigrams => TABLE_SEARCH_TRIGRAMS,
        Tree::Envelopes => TABLE_ENVELOPES,
    }
}

fn create_all_tables(tx: &redb::WriteTransaction) {
    for tree in [
        Tree::Resources,
        Tree::PropValSub,
        Tree::ValPropSub,
        Tree::QueryMembers,
        Tree::WatchedQueries,
        Tree::PluginMeta,
        Tree::DriveMapping,
        Tree::DidMapping,
        Tree::LoroSnapshots,
        Tree::Blobs,
        Tree::SearchPostings,
        Tree::SearchDocs,
        Tree::SearchDocTokens,
        Tree::SearchTrigrams,
        Tree::Envelopes,
    ] {
        let _ = tx.open_table(table_def(tree));
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
#[cfg(all(feature = "db-redb", not(target_arch = "wasm32")))]
pub fn compact_file(path: &std::path::Path) -> AtomicResult<(u64, u64, bool)> {
    let size_before = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut db = redb::Database::create(path)
        .map_err(|e| format!("Failed to open redb at {}: {e}", path.display()))?;
    let did_compact = db
        .compact()
        .map_err(|e| format!("Compaction failed: {e}"))?;
    drop(db);
    let size_after = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    Ok((size_before, size_after, did_compact))
}

impl RedbStore {
    /// Create a RedbStore backed by a file on disk.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_file(path: &std::path::Path) -> AtomicResult<Self> {
        // `Database::create` with defaults uses a 1 GiB cache and the
        // slow full-scan repair path on any unclean shutdown. On a
        // multi-GB store that's 40+ seconds added to every boot
        // (see redb issue #1055). The Builder lets us drop the cache
        // to fit-for-purpose; per-transaction `set_quick_repair(true)`
        // below persists the allocator state on every commit so the
        // next open is "almost instant" (redb transactions.rs:1246-1258
        // describes the mechanism).
        let t = std::time::Instant::now();
        let db = Database::create(path)
            .map_err(|e| format!("Failed to create redb at {}: {e}", path.display()))?;
        tracing::info!("RedbStore::new_file: Database::create in {:?}", t.elapsed());

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

        Ok(RedbStore {
            db: Arc::new(db),
            batch_buffer: std::sync::Mutex::new(None),
        })
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
                    .open_table(table_def(op.tree.clone()))
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
        Ok(())
    }

    fn flush(&self) -> AtomicResult<()> {
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
                .open_table(TABLE_DRIVE_MAPPING)
                .map_err(|e| format!("redb flush open table: {e}"))?;
            table
                .insert(b"__flush_sentinel__".as_slice(), b"".as_slice())
                .map_err(|e| format!("redb flush sentinel: {e}"))?;
        }
        // Immediate is the default durability; committing flushes + fsyncs all
        // prior Durability::None commits.
        tx.commit().map_err(|e| format!("redb flush commit: {e}"))?;
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
                    .open_table(table_def(op.tree.clone()))
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
        Ok(())
    }
}
