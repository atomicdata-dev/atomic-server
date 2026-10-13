//! Rebuilds the atom indexes when their key layout changed.
//!
//! `PropValSub` and `ValPropSub` keys write the core vocabulary's property
//! namespace as one byte ([`super::query_index::property_key_part`]). A store
//! from before holds the full URL in every row, and a prefix scan for the new
//! form would not find them, so the indexes are rebuilt once.
//!
//! The rebuild works in slices that resume where they stopped: the server
//! runs them to the end when it opens the store, the browser worker runs them
//! one at a time and shows how far it got. State lives in `Tree::PluginMeta`:
//! a restart in between carries on instead of starting over.

use serde::{Deserialize, Serialize};

use crate::{errors::AtomicResult, storelike::Storelike};

use super::trees::{Transaction, Tree};
use super::Db;

/// Set when the indexes have the current key layout.
pub const DONE_KEY: &[u8] = b"index-keys-v2";
/// Present while a rebuild is under way: `{ done, total, cursor }`.
const STATE_KEY: &[u8] = b"index-keys-v2-state";

/// How far the rebuild is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexMigration {
    /// Resources indexed so far.
    pub done: u64,
    /// Resources to index.
    pub total: u64,
    /// Nothing left to do.
    pub finished: bool,
}

#[derive(Serialize, Deserialize)]
struct State {
    done: u64,
    total: u64,
    /// Subject of the last resource indexed.
    cursor: Vec<u8>,
}

impl Db {
    /// Whether the indexes still have to be rebuilt for the current key layout.
    pub fn index_migration_pending(&self) -> AtomicResult<bool> {
        Ok(self.kv.get(Tree::PluginMeta, DONE_KEY)?.is_none())
    }

    /// Indexes up to `limit` more resources. The first call on an old store
    /// clears the indexes; a store with nothing in it is marked done at once.
    /// Call until `finished`.
    pub fn migrate_index_keys_step(&self, limit: usize) -> AtomicResult<IndexMigration> {
        if !self.index_migration_pending()? {
            return Ok(IndexMigration {
                done: 0,
                total: 0,
                finished: true,
            });
        }

        let mut state = match self.kv.get(Tree::PluginMeta, STATE_KEY)? {
            Some(bytes) => serde_json::from_slice::<State>(&bytes)
                .map_err(|e| format!("Unreadable index migration state: {e}"))?,
            None => {
                let total = self.kv.iter_tree(Tree::Resources).count() as u64;
                if total == 0 {
                    return self.finish_index_migration(0);
                }
                self.clear_index()?;
                State {
                    done: 0,
                    total,
                    cursor: Vec::new(),
                }
            }
        };

        // Keys are UTF-8, so `0xff` is past the last of them.
        let mut start = state.cursor.clone();
        start.push(0);
        let page = self
            .kv
            .range_page(Tree::Resources, start, vec![0xff], limit.max(1))?;
        if page.is_empty() {
            return self.finish_index_migration(state.total);
        }

        let base_domain = self.get_base_domain();
        let mut transaction = Transaction::new();
        for (subject, bytes) in &page {
            if let Some(resource) =
                Db::map_kv_item_to_resource(subject, bytes, true, base_domain.as_deref())
            {
                for atom in resource.to_atoms_iter() {
                    self.add_atom_to_index(&atom, &resource, &mut transaction)
                        .map_err(|e| format!("Failed to add atom to index {atom}. {e}"))?;
                }
            }
        }
        self.apply_transaction(&mut transaction)
            .map_err(|e| format!("Failed to commit transaction. {e}"))?;

        state.done += page.len() as u64;
        state.cursor = page.last().map(|(key, _)| key.clone()).unwrap_or_default();
        self.kv.insert(
            Tree::PluginMeta,
            STATE_KEY,
            &serde_json::to_vec(&state).map_err(|e| e.to_string())?,
        )?;

        Ok(IndexMigration {
            done: state.done,
            total: state.total,
            finished: false,
        })
    }

    fn finish_index_migration(&self, total: u64) -> AtomicResult<IndexMigration> {
        self.kv.insert(Tree::PluginMeta, DONE_KEY, b"1")?;
        self.kv.remove(Tree::PluginMeta, STATE_KEY)?;
        // Only a rebuild has anything worth an fsync; a store with nothing in
        // it must not pay one (the flush also touches a sentinel row).
        if total > 0 {
            self.kv.flush()?;
        }
        Ok(IndexMigration {
            done: total,
            total,
            finished: true,
        })
    }

    /// Runs the rebuild to the end, logging as it goes.
    pub fn migrate_index_keys(&self) -> AtomicResult<()> {
        if !self.index_migration_pending()? {
            return Ok(());
        }
        tracing::info!("Rebuilding the atom indexes for shorter keys");
        loop {
            let step = self.migrate_index_keys_step(500)?;
            if step.finished {
                tracing::info!("Atom indexes rebuilt ({} resources)", step.total);
                return Ok(());
            }
            tracing::info!("Rebuilding the atom indexes: {}/{}", step.done, step.total);
        }
    }
}
