//! Host-provided persistence for records read by the sync engine.
//!
//! The engine (built in
//! [issue #9](https://github.com/localthought/syncables-rs/issues/9)) never
//! decides where the local-first copy of a synced dataset lives — it talks
//! to whatever implements [`Storage`]. [`InMemoryStorage`] is a reference
//! implementation used by this crate's own tests;
//! [`localthought/reflector-rs`](https://github.com/localthought/reflector-rs)'s
//! `AtomicStorage` (`src/store.rs`) is the intended real-world
//! implementation, storing records in an Atomic Data `Storelike`.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use super::ontology::Ontology;

/// One record read from or written to a host's [`Storage`].
///
/// Deliberately plain JSON: `value` is exactly the record's own fields.
/// The trait must not require `atomic_lib`, or any other host-side model,
/// to construct a `Record` — and this crate itself takes no `atomic_lib`
/// dependency.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Record {
    /// Separates otherwise-identical `resource`/`id` pairs that belong to
    /// different parents — e.g. every issue's comments share the resource
    /// name `issueComment`, so without a namespace two issues' comment
    /// sets would overwrite each other. The engine derives the namespace
    /// from the resource model's context parameters
    /// ([issue #3](https://github.com/localthought/syncables-rs/issues/3))
    /// and is consistent about it across a run, since a host indexes by
    /// it.
    pub namespace: String,
    /// The resource name, e.g. `issue` or `issueComment`.
    pub resource: String,
    /// The record's id within its `namespace`/`resource`.
    pub id: String,
    /// The record's own fields, as plain JSON.
    pub value: serde_json::Map<String, serde_json::Value>,
}

/// Something a host's [`Storage`] implementation failed to do.
///
/// A `StorageError` is fatal for the one call it came from, not for the
/// sync as a whole: the engine
/// ([issue #9](https://github.com/localthought/syncables-rs/issues/9))
/// collects errors like this into `SyncReport::errors` and continues
/// syncing the rest of the dataset.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct StorageError {
    /// What went wrong, in a form suitable for logging or for surfacing
    /// in a `SyncReport::errors` list.
    pub message: String,
    /// The underlying error from the host's storage backend, if any.
    #[source]
    pub source: Option<Box<dyn StdError + Send + Sync>>,
}

impl StorageError {
    /// Builds a [`StorageError`] with no underlying source error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a [`StorageError`] that wraps an underlying error from the
    /// host's storage backend.
    pub fn with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Host-provided persistence for the records and ontology a sync produces.
///
/// The engine talks to this trait rather than deciding for itself where
/// the local-first copy of a dataset lives — [`InMemoryStorage`] is a
/// reference implementation used by this crate's own tests, and
/// `AtomicStorage` in
/// [`localthought/reflector-rs`](https://github.com/localthought/reflector-rs)
/// (`src/store.rs`) is the intended real-world one, storing records in an
/// Atomic Data `Storelike` under `internal:/<namespace>/<resource>/<id>`
/// subjects.
///
/// # Contract
///
/// [`Storage::put_ontology`] is called once per sync, before any
/// [`Storage::put`] — this is documented behavior for callers of this
/// trait, not something enforced by the trait or by any implementation of
/// it. That ordering is the engine's responsibility
/// ([issue #9](https://github.com/localthought/syncables-rs/issues/9));
/// `reflector-rs`'s `AtomicStorage` is written against it.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Storage: Send + Sync {
    /// Inserts or replaces a record, keyed by its `namespace`, `resource`
    /// and `id`.
    async fn put(&self, record: &Record) -> Result<(), StorageError>;

    /// One record, by `namespace`, `resource` and id — `Ok(None)` if no
    /// such record has been [`put`](Storage::put).
    async fn get(
        &self,
        namespace: &str,
        resource: &str,
        id: &str,
    ) -> Result<Option<Record>, StorageError>;

    /// Every record held for `namespace`/`resource`.
    async fn list(&self, namespace: &str, resource: &str) -> Result<Vec<Record>, StorageError>;

    /// Removes a record, by `namespace`, `resource` and id. Removing a
    /// record that isn't present is not an error.
    async fn delete(&self, namespace: &str, resource: &str, id: &str) -> Result<(), StorageError>;

    /// Stores the ontology derived from the synced document. Called once
    /// per sync, before any [`put`](Storage::put) — see the trait-level
    /// "Contract" section.
    async fn put_ontology(&self, ontology: &Ontology) -> Result<(), StorageError>;
}

/// Key a [`Record`] is stored under: its `namespace`, `resource` and `id`.
type RecordKey = (String, String, String);

/// A reference [`Storage`] implementation that keeps everything in process
/// memory, analogous to [`crate::client::storage::InMemoryStorageAdapter`]
/// but namespace-keyed. Used by this crate's own tests; hosts that need
/// persistence implement [`Storage`] themselves.
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    records: Mutex<HashMap<RecordKey, Record>>,
    ontologies: Mutex<Vec<Ontology>>,
}

impl InMemoryStorage {
    /// A store with no records and no ontology.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every ontology passed to [`Storage::put_ontology`] so far, in call
    /// order. Exposed for tests to assert `put_ontology` was called.
    pub fn ontologies(&self) -> Vec<Ontology> {
        self.ontologies
            .lock()
            .expect("ontologies mutex poisoned")
            .clone()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Storage for InMemoryStorage {
    async fn put(&self, record: &Record) -> Result<(), StorageError> {
        let key = (
            record.namespace.clone(),
            record.resource.clone(),
            record.id.clone(),
        );
        self.records
            .lock()
            .expect("records mutex poisoned")
            .insert(key, record.clone());
        Ok(())
    }

    async fn get(
        &self,
        namespace: &str,
        resource: &str,
        id: &str,
    ) -> Result<Option<Record>, StorageError> {
        let key = (namespace.to_string(), resource.to_string(), id.to_string());
        Ok(self
            .records
            .lock()
            .expect("records mutex poisoned")
            .get(&key)
            .cloned())
    }

    async fn list(&self, namespace: &str, resource: &str) -> Result<Vec<Record>, StorageError> {
        Ok(self
            .records
            .lock()
            .expect("records mutex poisoned")
            .values()
            .filter(|record| record.namespace == namespace && record.resource == resource)
            .cloned()
            .collect())
    }

    async fn delete(&self, namespace: &str, resource: &str, id: &str) -> Result<(), StorageError> {
        let key = (namespace.to_string(), resource.to_string(), id.to_string());
        self.records
            .lock()
            .expect("records mutex poisoned")
            .remove(&key);
        Ok(())
    }

    async fn put_ontology(&self, ontology: &Ontology) -> Result<(), StorageError> {
        self.ontologies
            .lock()
            .expect("ontologies mutex poisoned")
            .push(ontology.clone());
        Ok(())
    }
}
