//! The mock server: an HTTP request handler generated from an OpenAPI
//! document.
//!
//! For a `GET` operation it first checks whether a pagination scheme
//! applies (see [`crate::pagination::autodetect`]) and, if so, serves it
//! as a paginated list; otherwise it treats the match as a resource
//! ([`ResourceStore`], CRUD semantics based on collection vs. item path
//! and HTTP method) or falls back to serving the operation's documented
//! example/generated schema response verbatim. Resource collections are
//! lazily seeded with [`SEED_COUNT`] fake records on first `GET`.
//!
//! # Port status
//!
//! Scaffolding. The types, constants and the public surface below are
//! ported; the request handler itself is not yet implemented.

// The `async` on the stubs below is part of the ported API surface,
// not an accident of the current `todo!()` bodies.
#![allow(clippy::unused_async)]

use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::openapi::types::OpenApiDocument;
use crate::resources::discover::{discover_resources, ResourceRoute};

use super::store::ResourceStore;

/// Fake records seeded into a resource collection on its first `GET`.
pub const SEED_COUNT: usize = 3;
/// Total fake items generated for a paginated list endpoint, once per path template.
pub const PAGINATED_TOTAL_COUNT: usize = 7;
/// Page size used when the request doesn't specify one.
pub const DEFAULT_PAGE_SIZE: usize = 3;

/// Where a started mock server is listening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddress {
    /// The bound TCP port.
    pub port: u16,
    /// The base URL clients should use, e.g. `http://127.0.0.1:8080`.
    pub url: String,
}

/// A mock server built from an OpenAPI document.
#[derive(Clone)]
pub struct MockServer {
    document: Arc<OpenApiDocument>,
    resources: Arc<Vec<ResourceRoute>>,
    store: Arc<Mutex<ResourceStore>>,
}

impl MockServer {
    /// The document this server implements.
    pub fn document(&self) -> &OpenApiDocument {
        &self.document
    }

    /// The resources discovered in the document.
    pub fn resources(&self) -> &[ResourceRoute] {
        &self.resources
    }

    /// The backing CRUD store.
    pub fn store(&self) -> &Mutex<ResourceStore> {
        &self.store
    }

    /// Binds a port and starts serving.
    ///
    /// Pass `None` for `port` to bind an ephemeral one.
    pub async fn listen(&self, port: Option<u16>) -> Result<ServerAddress> {
        let _ = port;
        todo!("port src/mock-server/server.ts: handleRequest and the HTTP listener")
    }

    /// Stops serving.
    pub async fn close(&self) -> Result<()> {
        todo!("port src/mock-server/server.ts: server shutdown")
    }
}

/// Builds a mock server for `document`.
pub fn create_mock_server(document: OpenApiDocument) -> MockServer {
    let resources = discover_resources(&document.paths);
    MockServer {
        document: Arc::new(document),
        resources: Arc::new(resources),
        store: Arc::new(Mutex::new(ResourceStore::new())),
    }
}
