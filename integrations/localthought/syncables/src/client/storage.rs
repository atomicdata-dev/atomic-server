//! Where the client keeps its local copy of each resource collection.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::{Map, Value};

use crate::error::Result;

/// Pluggable local storage for the client's copy of a collection.
///
/// Implement this to persist somewhere other than memory;
/// [`InMemoryStorageAdapter`] is the default.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageAdapter: Send + Sync {
    /// Every record held for `resource`.
    async fn list(&self, resource: &str) -> Result<Vec<Map<String, Value>>>;
    /// One record, by id.
    async fn get(&self, resource: &str, id: &str) -> Result<Option<Map<String, Value>>>;
    /// Inserts or replaces a record.
    async fn put(&self, resource: &str, id: &str, value: Map<String, Value>) -> Result<()>;
    /// Removes a record.
    async fn delete(&self, resource: &str, id: &str) -> Result<()>;
}

/// One collection per resource path, each keyed by record id.
type Collections = HashMap<String, IndexMap<String, Map<String, Value>>>;

/// The default [`StorageAdapter`]: everything in process memory.
#[derive(Debug, Default)]
pub struct InMemoryStorageAdapter {
    collections: Mutex<Collections>,
}

impl InMemoryStorageAdapter {
    /// An adapter with no collections.
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageAdapter for InMemoryStorageAdapter {
    async fn list(&self, resource: &str) -> Result<Vec<Map<String, Value>>> {
        let mut collections = self.collections.lock().expect("storage mutex poisoned");
        Ok(collections
            .entry(resource.to_string())
            .or_default()
            .values()
            .cloned()
            .collect())
    }

    async fn get(&self, resource: &str, id: &str) -> Result<Option<Map<String, Value>>> {
        let mut collections = self.collections.lock().expect("storage mutex poisoned");
        Ok(collections
            .entry(resource.to_string())
            .or_default()
            .get(id)
            .cloned())
    }

    async fn put(&self, resource: &str, id: &str, value: Map<String, Value>) -> Result<()> {
        let mut collections = self.collections.lock().expect("storage mutex poisoned");
        collections
            .entry(resource.to_string())
            .or_default()
            .insert(id.to_string(), value);
        Ok(())
    }

    async fn delete(&self, resource: &str, id: &str) -> Result<()> {
        let mut collections = self.collections.lock().expect("storage mutex poisoned");
        collections
            .entry(resource.to_string())
            .or_default()
            .shift_remove(id);
        Ok(())
    }
}
