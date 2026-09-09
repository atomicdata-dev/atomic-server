//! Abstract key-value store trait for the Db.
//! Allows swapping the storage backend (sled, BTreeMap, etc.) without changing query/index logic.

use crate::errors::AtomicResult;

use super::trees::{Operation, Tree};

/// A key-value pair where both key and value are owned byte vectors.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// Iterator over key-value pairs from a store.
pub type KvIter = Box<dyn Iterator<Item = AtomicResult<KvPair>> + Send>;

/// A storage backend for the Db.
/// All methods operate on named trees (namespaces).
///
/// Implementations must ensure that [`KvStore::apply_batch`] is atomic:
/// either all operations succeed or none are applied.
pub trait KvStore: Send + Sync {
    /// Get a value by key from a specific tree.
    fn get(&self, tree: Tree, key: &[u8]) -> AtomicResult<Option<Vec<u8>>>;

    /// Insert a key-value pair into a specific tree.
    fn insert(&self, tree: Tree, key: &[u8], val: &[u8]) -> AtomicResult<()>;

    /// Remove a key from a specific tree.
    fn remove(&self, tree: Tree, key: &[u8]) -> AtomicResult<()>;

    /// Check if a key exists in a specific tree.
    fn contains_key(&self, tree: Tree, key: &[u8]) -> AtomicResult<bool>;

    /// Iterate over all entries whose key starts with `prefix`, ordered lexicographically.
    fn scan_prefix(&self, tree: Tree, prefix: &[u8]) -> KvIter;

    /// Iterate over entries in key range [start, end).
    /// If `reverse` is true, iterate in reverse lexicographic order.
    fn range(&self, tree: Tree, start: Vec<u8>, end: Vec<u8>, reverse: bool) -> KvIter;

    /// Bounded range read. Backends with eager iterators should override this so
    /// the limit is applied before copying values into memory.
    fn range_page(
        &self,
        tree: Tree,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: usize,
    ) -> AtomicResult<Vec<KvPair>> {
        self.range(tree, start, end, false).take(limit).collect()
    }

    /// Iterate over all entries in a tree, ordered by key.
    fn iter_tree(&self, tree: Tree) -> KvIter;

    /// Remove all entries from a specific tree.
    fn clear_tree(&self, tree: Tree) -> AtomicResult<()>;

    /// Atomically apply a batch of operations across potentially multiple trees.
    fn apply_batch(&self, operations: &[Operation]) -> AtomicResult<()>;

    /// Flush all pending writes to durable storage. No-op for in-memory backends.
    fn flush(&self) -> AtomicResult<()>;

    /// Start buffering writes. All `insert`, `remove`, and `apply_batch` calls
    /// will be accumulated until `commit_batch()` is called.
    fn begin_batch(&self) {}

    /// Commit all buffered writes in a single transaction. No-op if not batching.
    fn commit_batch(&self) -> AtomicResult<()> {
        Ok(())
    }

    /// Return the number of entries in a tree.
    fn len(&self, tree: Tree) -> AtomicResult<usize>;
}
