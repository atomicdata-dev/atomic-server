//! The API client: talks to any server implementing the document, and
//! keeps a local copy of each resource collection in sync.
//!
//! Reads are served from local storage ([`StorageAdapter`];
//! [`InMemoryStorageAdapter`] is the default). `sync()` and the standalone
//! `paginate()` both walk every page of a paginated GET operation before
//! returning.
//!
//! `create`/`update`/`remove` are local-first: each writes to storage
//! immediately and returns without waiting on the network, then applies
//! itself against the server in the background via a per-record write
//! queue (keyed by `{resource}:{id}`, one write in flight at a time so
//! writes to the same record land in server order), retrying failures with
//! exponential backoff.
//!
//! Nothing in this crate reads an OpenAPI document's
//! `security`/`securitySchemes` — there is no built-in notion of auth.
//! [`ApiClientOptions::fetch`] is the only extension point, so
//! authenticating (a bearer token, an API key from an env var, etc.) means
//! passing a [`Fetch`] implementation that adds the right header to every
//! request.
//!
//! # Port status
//!
//! Scaffolding. The public surface, options and types below are ported;
//! the sync/write/pagination machinery is not yet implemented.

// The `async` on the stubs below is part of the ported API surface,
// not an accident of the current `todo!()` bodies.
#![allow(clippy::unused_async)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::{Map, Value};

use crate::error::Result;
use crate::openapi::types::OpenApiDocument;
use crate::resources::discover::{discover_resources, ResourceRoute};

use super::storage::{InMemoryStorageAdapter, StorageAdapter};

/// Hard ceiling on pages walked in one traversal, mirroring the original's
/// `MAX_PAGES`.
pub const MAX_PAGES: usize = 50;

/// One outgoing HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Absolute URL.
    pub url: String,
    /// Request headers.
    pub headers: IndexMap<String, String>,
    /// Request body, if any.
    pub body: Option<Vec<u8>>,
}

/// One HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: IndexMap<String, String>,
    /// Response body.
    pub body: Vec<u8>,
}

/// The client's only extension point for how requests reach the network.
///
/// This is the Rust equivalent of the original's injectable `fetch`.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Fetch: FetchBounds {
    /// Sends one request and returns the response.
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse>;
}

/// How a failed background write is retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryOptions {
    /// Delay before the first retry of a failed write. Doubles on each
    /// subsequent attempt. Default 200ms.
    pub base_delay: Duration,
    /// Ceiling for the exponential backoff between retries. Default 30s.
    pub max_delay: Duration,
    /// Stop auto-retrying a write after this many attempts. Default is
    /// unlimited (keep retrying until it succeeds).
    pub max_attempts: Option<u32>,
}

impl Default for RetryOptions {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(30),
            max_attempts: None,
        }
    }
}

/// How to build an [`ApiClient`].
pub struct ApiClientOptions {
    /// Base URL of the server to talk to.
    pub base_url: String,
    /// Where the local copy lives. Defaults to [`InMemoryStorageAdapter`].
    pub storage: Option<Arc<dyn StorageAdapter>>,
    /// How requests reach the network.
    pub fetch: Option<Arc<dyn Fetch>>,
    /// How failed background writes are retried.
    pub retry: RetryOptions,
    /// Record property that holds a resource's identity — the value used
    /// as the local storage key, read back from a create response to
    /// reconcile the server-assigned id, and substituted into the item
    /// URL's path variable.
    ///
    /// Defaults to `id`. Set this when the API addresses a resource by a
    /// different field (e.g. GitHub issues are keyed by `number`, not the
    /// global `id` the payload also carries).
    pub identity_field: String,
}

impl ApiClientOptions {
    /// Options pointing at `base_url`, with everything else defaulted.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            storage: None,
            fetch: None,
            retry: RetryOptions::default(),
            identity_field: "id".to_string(),
        }
    }
}

/// Options for one [`ApiClient::paginate`] traversal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaginateOptions {
    /// Page size to request. Falls back to the server's own default when
    /// omitted.
    pub page_size: Option<u64>,
}

/// What one [`ApiClient::sync`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncResult {
    /// Collection paths whose local copy was actually added to, updated,
    /// or pruned by this sync.
    pub changed: Vec<String>,
}

/// Called after each sync while polling.
pub type SyncCallback = Box<dyn Fn(&SyncResult) + Send + Sync>;
/// Called when a sync fails while polling.
pub type ErrorCallback = Box<dyn Fn(&crate::error::Error) + Send + Sync>;

/// How [`ApiClient::start_polling`] should behave.
pub struct PollOptions {
    /// How often to call `sync()`. An initial sync runs immediately.
    pub interval: Duration,
    /// Called after every sync while polling, including ones where nothing
    /// changed.
    pub on_sync: Option<SyncCallback>,
    /// Called when a sync fails while polling; polling continues on the
    /// next interval.
    pub on_error: Option<ErrorCallback>,
}

/// Cancels a running poll loop.
#[derive(Debug)]
pub struct PollingHandle {
    _private: (),
}

impl PollingHandle {
    /// Stops future polling. Does not cancel a sync already in flight.
    pub fn stop(self) {
        todo!("port src/client/client.ts: startPolling")
    }
}

/// Which kind of write is still pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingWriteType {
    /// A `create` not yet confirmed by the server.
    Create,
    /// An `update` not yet confirmed by the server.
    Update,
    /// A `remove` not yet confirmed by the server.
    Delete,
}

/// A write local storage already reflects, but the server has not yet
/// confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWriteInfo {
    /// Collection path the write belongs to.
    pub resource: String,
    /// The id the write is filed under locally. For an unsettled `create`,
    /// this is the client-generated id, not (yet) whatever the server
    /// assigns.
    pub id: String,
    /// Which kind of write this is.
    pub write_type: PendingWriteType,
    /// How many attempts to reach the server have failed so far.
    ///
    /// If [`RetryOptions::max_attempts`] is set and reached, this stops
    /// growing and the write stops auto-retrying — it stays listed until
    /// `create`/`update`/`remove` is called again for the same record.
    pub attempts: u32,
    /// The most recent failure, if at least one attempt has failed.
    pub last_error: Option<String>,
}

/// A local-first client for a server implementing the document.
pub struct ApiClient {
    document: Arc<OpenApiDocument>,
    routes: Arc<Vec<ResourceRoute>>,
    storage: Arc<dyn StorageAdapter>,
    fetch: Option<Arc<dyn Fetch>>,
    options: Arc<ApiClientOptions>,
}

impl ApiClient {
    /// Collection paths this client knows how to sync.
    pub fn resources(&self) -> Vec<String> {
        self.routes
            .iter()
            .map(|route| route.collection_path.clone())
            .collect()
    }

    /// The document this client was built from.
    pub fn document(&self) -> &OpenApiDocument {
        &self.document
    }

    /// Where the local copy lives.
    pub fn storage(&self) -> &Arc<dyn StorageAdapter> {
        &self.storage
    }

    /// Pulls every discovered resource collection into local storage.
    ///
    /// Safe to call repeatedly: for a non-paginated collection it
    /// conditionally re-fetches, keyed by exact request URL, sending
    /// `If-None-Match`/`If-Modified-Since` from the prior response's
    /// `ETag`/`Last-Modified` and treating a `304` as "nothing to do".
    /// Even on a fresh `200`, or for a paginated collection, it only
    /// touches storage for items that actually changed.
    pub async fn sync(&self) -> Result<SyncResult> {
        let _ = &self.fetch;
        let _ = &self.options;
        todo!("port src/client/client.ts: sync")
    }

    /// Calls [`Self::sync`] on `options.interval`, skipping a tick if the
    /// previous sync is still running.
    // `options` is consumed by the poll loop once this is implemented.
    #[allow(clippy::needless_pass_by_value)]
    pub fn start_polling(&self, options: PollOptions) -> PollingHandle {
        let _ = options;
        todo!("port src/client/client.ts: startPolling")
    }

    /// Every locally held record of `resource`.
    pub async fn list(&self, resource: &str) -> Result<Vec<Map<String, Value>>> {
        self.storage.list(resource).await
    }

    /// One locally held record, by id.
    pub async fn get(&self, resource: &str, id: &str) -> Result<Option<Map<String, Value>>> {
        self.storage.get(resource, id).await
    }

    /// Writes `data` to local storage immediately, under a client-generated
    /// id (or `data[identity_field]`, if already set) and returns without
    /// waiting on the network.
    ///
    /// The write to the server happens in the background and is retried on
    /// failure — see [`Self::pending_writes`] for its outcome so far. If
    /// the server assigns a different id than the one used locally, the
    /// record is moved to it once the write settles.
    pub async fn create(
        &self,
        resource: &str,
        data: Map<String, Value>,
    ) -> Result<Map<String, Value>> {
        let _ = (resource, data);
        todo!("port src/client/client.ts: create")
    }

    /// Merges `data` into the local copy of `id` immediately and returns
    /// without waiting on the network; the corresponding `PUT` (or `PATCH`,
    /// per [`ResourceRoute::update_method`]) is sent, and retried on
    /// failure, in the background.
    pub async fn update(
        &self,
        resource: &str,
        id: &str,
        data: Map<String, Value>,
    ) -> Result<Map<String, Value>> {
        let _ = (resource, id, data);
        todo!("port src/client/client.ts: update")
    }

    /// Removes `id` from local storage immediately and returns without
    /// waiting on the network; the corresponding `DELETE` is sent, and
    /// retried on failure, in the background.
    pub async fn remove(&self, resource: &str, id: &str) -> Result<()> {
        let _ = (resource, id);
        todo!("port src/client/client.ts: remove")
    }

    /// Writes not yet confirmed by the server, across every resource (or
    /// just `resource`, if given).
    pub fn pending_writes(&self, resource: Option<&str>) -> Vec<PendingWriteInfo> {
        let _ = resource;
        todo!("port src/client/client.ts: pendingWrites")
    }

    /// Fetches every item from a GET list operation at `path`, walking
    /// every page per its resolved pagination scheme (explicit
    /// `x-pagination` or auto-detected from `components.paginationSchemes`).
    ///
    /// `path` need not be a discovered resource — any GET operation in the
    /// document works, e.g. a search/listing endpoint with no paired item
    /// route.
    pub async fn paginate(
        &self,
        path: &str,
        options: PaginateOptions,
    ) -> Result<Vec<Map<String, Value>>> {
        let _ = (path, options);
        todo!("port src/client/client.ts: paginate")
    }
}

/// Builds a client for `document` against the server in `options`.
pub fn create_api_client(document: OpenApiDocument, options: ApiClientOptions) -> ApiClient {
    let routes = discover_resources(&document.paths);
    let storage = options
        .storage
        .clone()
        .unwrap_or_else(|| Arc::new(InMemoryStorageAdapter::new()));
    let fetch = options.fetch.clone();
    ApiClient {
        document: Arc::new(document),
        routes: Arc::new(routes),
        storage,
        fetch,
        options: Arc::new(options),
    }
}

/// Native transports must be thread safe; browser transports run on one JS thread.
#[cfg(not(target_arch = "wasm32"))]
pub trait FetchBounds: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> FetchBounds for T {}
/// Browser transports may own JavaScript callbacks.
#[cfg(target_arch = "wasm32")]
pub trait FetchBounds {}
#[cfg(target_arch = "wasm32")]
impl<T> FetchBounds for T {}
