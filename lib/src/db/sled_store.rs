//! SledStore: KvStore implementation backed by sled.

use std::path::Path;

use sled::{transaction::TransactionError, Transactional};

use crate::errors::AtomicResult;

use super::{
    kv_store::{KvIter, KvStore},
    trees::{Method, Operation, Tree},
};

/// A KvStore backed by sled, an embedded database.
pub struct SledStore {
    db: sled::Db,
    resources: sled::Tree,
    reference_index: sled::Tree,
    prop_val_sub_index: sled::Tree,
    query_index: sled::Tree,
    watched_queries: sled::Tree,
    plugin_meta: sled::Tree,
    drive_mapping: sled::Tree,
    did_mapping: sled::Tree,
    loro_snapshots: sled::Tree,
    blobs: sled::Tree,
    search_postings: sled::Tree,
    search_docs: sled::Tree,
    search_doc_tokens: sled::Tree,
    search_trigrams: sled::Tree,
    envelopes: sled::Tree,
}

impl SledStore {
    /// Opens or creates a sled database at the given path.
    pub fn open(path: &Path) -> AtomicResult<Self> {
        let db = sled::open(path).map_err(|e| {
            format!(
                "Failed opening DB at {:?}. Is another instance running? {}",
                path, e
            )
        })?;
        let resources = db
            .open_tree(Tree::Resources)
            .map_err(|e| format!("Failed building resources. Your DB might be corrupt. {}", e))?;
        let reference_index = db.open_tree(Tree::ValPropSub)?;
        let query_index = db.open_tree(Tree::QueryMembers)?;
        let prop_val_sub_index = db.open_tree(Tree::PropValSub)?;
        let watched_queries = db.open_tree(Tree::WatchedQueries)?;
        let plugin_meta = db.open_tree(Tree::PluginMeta)?;
        let drive_mapping = db.open_tree(Tree::DriveMapping)?;
        let did_mapping = db.open_tree(Tree::DidMapping)?;
        let loro_snapshots = db.open_tree(Tree::LoroSnapshots)?;
        let blobs = db.open_tree(Tree::Blobs)?;
        let search_postings = db.open_tree(Tree::SearchPostings)?;
        let search_docs = db.open_tree(Tree::SearchDocs)?;
        let search_doc_tokens = db.open_tree(Tree::SearchDocTokens)?;
        let search_trigrams = db.open_tree(Tree::SearchTrigrams)?;
        let envelopes = db.open_tree(Tree::Envelopes)?;

        Ok(SledStore {
            db,
            resources,
            reference_index,
            prop_val_sub_index,
            query_index,
            watched_queries,
            plugin_meta,
            drive_mapping,
            did_mapping,
            loro_snapshots,
            blobs,
            search_postings,
            search_docs,
            search_doc_tokens,
            search_trigrams,
            envelopes,
        })
    }

    /// Direct access to the raw sled::Db. Needed for migrations.
    pub fn raw_db(&self) -> &sled::Db {
        &self.db
    }

    fn tree(&self, id: Tree) -> &sled::Tree {
        match id {
            Tree::Resources => &self.resources,
            Tree::ValPropSub => &self.reference_index,
            Tree::PropValSub => &self.prop_val_sub_index,
            Tree::QueryMembers => &self.query_index,
            Tree::WatchedQueries => &self.watched_queries,
            Tree::PluginMeta => &self.plugin_meta,
            Tree::DriveMapping => &self.drive_mapping,
            Tree::DidMapping => &self.did_mapping,
            Tree::LoroSnapshots => &self.loro_snapshots,
            Tree::Blobs => &self.blobs,
            Tree::SearchPostings => &self.search_postings,
            Tree::SearchDocs => &self.search_docs,
            Tree::SearchDocTokens => &self.search_doc_tokens,
            Tree::SearchTrigrams => &self.search_trigrams,
            Tree::Envelopes => &self.envelopes,
        }
    }
}

impl KvStore for SledStore {
    fn get(&self, tree: Tree, key: &[u8]) -> AtomicResult<Option<Vec<u8>>> {
        Ok(self
            .tree(tree)
            .get(key)
            .map_err(|e| format!("sled get error: {}", e))?
            .map(|v| v.to_vec()))
    }

    fn insert(&self, tree: Tree, key: &[u8], val: &[u8]) -> AtomicResult<()> {
        self.tree(tree)
            .insert(key, val)
            .map_err(|e| format!("sled insert error: {}", e))?;
        Ok(())
    }

    fn remove(&self, tree: Tree, key: &[u8]) -> AtomicResult<()> {
        self.tree(tree)
            .remove(key)
            .map_err(|e| format!("sled remove error: {}", e))?;
        Ok(())
    }

    fn contains_key(&self, tree: Tree, key: &[u8]) -> AtomicResult<bool> {
        Ok(self
            .tree(tree)
            .contains_key(key)
            .map_err(|e| format!("sled contains_key error: {}", e))?)
    }

    fn scan_prefix(&self, tree: Tree, prefix: &[u8]) -> KvIter {
        Box::new(self.tree(tree).scan_prefix(prefix).map(|result| {
            let (k, v) = result.map_err(|e| format!("sled scan_prefix error: {}", e))?;
            Ok((k.to_vec(), v.to_vec()))
        }))
    }

    fn range(&self, tree: Tree, start: Vec<u8>, end: Vec<u8>, reverse: bool) -> KvIter {
        if reverse {
            Box::new(self.tree(tree).range(start..end).rev().map(|result| {
                let (k, v) = result.map_err(|e| format!("sled range error: {}", e))?;
                Ok((k.to_vec(), v.to_vec()))
            }))
        } else {
            Box::new(self.tree(tree).range(start..end).map(|result| {
                let (k, v) = result.map_err(|e| format!("sled range error: {}", e))?;
                Ok((k.to_vec(), v.to_vec()))
            }))
        }
    }

    fn iter_tree(&self, tree: Tree) -> KvIter {
        Box::new(self.tree(tree).into_iter().map(|result| {
            let (k, v) = result.map_err(|e| format!("sled iter error: {}", e))?;
            Ok((k.to_vec(), v.to_vec()))
        }))
    }

    fn clear_tree(&self, tree: Tree) -> AtomicResult<()> {
        self.tree(tree)
            .clear()
            .map_err(|e| format!("sled clear error: {}", e).into())
    }

    fn apply_batch(&self, operations: &[Operation]) -> AtomicResult<()> {
        let mut batch_resources = sled::Batch::default();
        let mut batch_propvalsub = sled::Batch::default();
        let mut batch_valpropsub = sled::Batch::default();
        let mut batch_watched_queries = sled::Batch::default();
        let mut batch_query_members = sled::Batch::default();
        let mut batch_plugin_meta = sled::Batch::default();
        let mut batch_drive_mapping = sled::Batch::default();
        let mut batch_did_mapping = sled::Batch::default();
        let mut batch_loro_snapshots = sled::Batch::default();
        let mut batch_blobs = sled::Batch::default();
        let mut batch_search_postings = sled::Batch::default();
        let mut batch_search_docs = sled::Batch::default();
        let mut batch_search_doc_tokens = sled::Batch::default();
        let mut batch_search_trigrams = sled::Batch::default();
        let mut batch_envelopes = sled::Batch::default();

        for op in operations {
            let batch = match op.tree {
                Tree::Resources => &mut batch_resources,
                Tree::PropValSub => &mut batch_propvalsub,
                Tree::ValPropSub => &mut batch_valpropsub,
                Tree::WatchedQueries => &mut batch_watched_queries,
                Tree::QueryMembers => &mut batch_query_members,
                Tree::PluginMeta => &mut batch_plugin_meta,
                Tree::DriveMapping => &mut batch_drive_mapping,
                Tree::DidMapping => &mut batch_did_mapping,
                Tree::LoroSnapshots => &mut batch_loro_snapshots,
                Tree::Blobs => &mut batch_blobs,
                Tree::SearchPostings => &mut batch_search_postings,
                Tree::SearchDocs => &mut batch_search_docs,
                Tree::SearchDocTokens => &mut batch_search_doc_tokens,
                Tree::SearchTrigrams => &mut batch_search_trigrams,
                Tree::Envelopes => &mut batch_envelopes,
            };
            match op.method {
                Method::Insert => {
                    batch.insert::<&[u8], &[u8]>(&op.key, op.val.as_ref().unwrap());
                }
                Method::Delete => {
                    batch.remove(op.key.as_slice());
                }
            }
        }

        (
            &self.resources,
            &self.prop_val_sub_index,
            &self.reference_index,
            &self.watched_queries,
            &self.query_index,
            &self.plugin_meta,
            &self.drive_mapping,
            &self.did_mapping,
        )
            .transaction(
                |(
                    tx_resources,
                    tx_prop_val_sub_index,
                    tx_reference_index,
                    tx_watched_queries,
                    tx_query_index,
                    tx_plugin_meta,
                    tx_drive_mapping,
                    tx_did_mapping,
                )| {
                    tx_resources.apply_batch(&batch_resources)?;
                    tx_prop_val_sub_index.apply_batch(&batch_propvalsub)?;
                    tx_reference_index.apply_batch(&batch_valpropsub)?;
                    tx_watched_queries.apply_batch(&batch_watched_queries)?;
                    tx_query_index.apply_batch(&batch_query_members)?;
                    tx_plugin_meta.apply_batch(&batch_plugin_meta)?;
                    tx_drive_mapping.apply_batch(&batch_drive_mapping)?;
                    tx_did_mapping.apply_batch(&batch_did_mapping)?;
                    Ok::<(), sled::transaction::ConflictableTransactionError<sled::Error>>(())
                },
            )
            .map_err(|e: TransactionError<_>| format!("Failed to apply transaction: {}", e))?;

        // LoroSnapshots, Blobs, and search trees sit outside the main
        // transaction (sled limits tuple size to 9).
        self.loro_snapshots
            .apply_batch(batch_loro_snapshots)
            .map_err(|e| format!("Failed to apply loro_snapshots batch: {}", e))?;

        self.blobs
            .apply_batch(batch_blobs)
            .map_err(|e| format!("Failed to apply blobs batch: {}", e))?;

        self.search_postings
            .apply_batch(batch_search_postings)
            .map_err(|e| format!("Failed to apply search_postings batch: {}", e))?;
        self.search_docs
            .apply_batch(batch_search_docs)
            .map_err(|e| format!("Failed to apply search_docs batch: {}", e))?;
        self.search_doc_tokens
            .apply_batch(batch_search_doc_tokens)
            .map_err(|e| format!("Failed to apply search_doc_tokens batch: {}", e))?;
        self.search_trigrams
            .apply_batch(batch_search_trigrams)
            .map_err(|e| format!("Failed to apply search_trigrams batch: {}", e))?;
        self.envelopes
            .apply_batch(batch_envelopes)
            .map_err(|e| format!("Failed to apply envelopes batch: {}", e))?;

        Ok(())
    }

    fn flush(&self) -> AtomicResult<()> {
        self.db
            .flush()
            .map_err(|e| format!("sled flush error: {}", e).into())
            .map(|_| ())
    }

    fn len(&self, tree: Tree) -> AtomicResult<usize> {
        Ok(self.tree(tree).len())
    }
}

impl Drop for SledStore {
    fn drop(&mut self) {
        if let Err(e) = self.db.flush() {
            eprintln!("Failed to flush sled on drop: {}", e);
        }
    }
}
