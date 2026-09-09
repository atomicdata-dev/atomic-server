//! The mock server's in-memory CRUD store, one collection per resource path.

use std::collections::HashMap;
use std::time::SystemTime;

use indexmap::IndexMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
struct CollectionMeta {
    version: u64,
    last_modified: String,
}

/// One in-memory `Map` per collection path, with CRUD semantics based on
/// collection vs. item path and HTTP method.
#[derive(Debug, Default)]
pub struct ResourceStore {
    collections: HashMap<String, IndexMap<String, Map<String, Value>>>,
    meta: HashMap<String, CollectionMeta>,
}

impl ResourceStore {
    /// A store with no collections.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `resource`'s collection has been created (seeded) yet.
    pub fn has(&self, resource: &str) -> bool {
        self.collections.contains_key(resource)
    }

    /// Every record in `resource`'s collection, in insertion order.
    pub fn list(&mut self, resource: &str) -> Vec<Map<String, Value>> {
        self.collection(resource).values().cloned().collect()
    }

    /// One record, by id.
    pub fn get(&mut self, resource: &str, id: &str) -> Option<Map<String, Value>> {
        self.collection(resource).get(id).cloned()
    }

    /// Inserts or replaces a record.
    pub fn put(&mut self, resource: &str, id: &str, value: Map<String, Value>) {
        self.collection(resource).insert(id.to_string(), value);
        self.touch(resource);
    }

    /// Removes a record, reporting whether it existed.
    pub fn delete(&mut self, resource: &str, id: &str) -> bool {
        let deleted = self.collection(resource).shift_remove(id).is_some();
        if deleted {
            self.touch(resource);
        }
        deleted
    }

    /// Weak ETag for the current state of `resource`'s collection, once it
    /// has been populated at least once.
    pub fn etag(&self, resource: &str) -> Option<String> {
        self.meta
            .get(resource)
            .map(|meta| format!("W/\"{}\"", meta.version))
    }

    /// RFC 7231 HTTP-date of the last mutation to `resource`'s collection,
    /// if any.
    pub fn last_modified(&self, resource: &str) -> Option<String> {
        self.meta
            .get(resource)
            .map(|meta| meta.last_modified.clone())
    }

    fn touch(&mut self, resource: &str) {
        let version = self.meta.get(resource).map_or(0, |meta| meta.version) + 1;
        self.meta.insert(
            resource.to_string(),
            CollectionMeta {
                version,
                last_modified: httpdate::fmt_http_date(SystemTime::now()),
            },
        );
    }

    fn collection(&mut self, resource: &str) -> &mut IndexMap<String, Map<String, Value>> {
        self.collections.entry(resource.to_string()).or_default()
    }
}
