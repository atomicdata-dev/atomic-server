//! Reads an OpenAPI document and gives you:
//!
//! - a **mock API server** ([`create_mock_server`]) that implements it,
//!   backed by a real (in-memory) CRUD store per resource, seeded with
//!   fake data generated from the document's schemas;
//! - an **API client** ([`create_api_client`]) that talks to any server
//!   implementing that OpenAPI document and keeps a local copy of each
//!   resource collection in sync.
//!
//! Both understand the [OpenAPI Pagination Schemes Extension](https://github.com/pondersource/openapi-pagination-schemes-extension)
//! when a document declares `components.paginationSchemes`.
//!
//! A "resource" is any pair of an OpenAPI collection path and its matching
//! item path, e.g. `/pets` and `/pets/{petId}`. Paths without that pairing
//! (health checks, one-off actions, etc.) are served from their documented
//! examples/schemas but aren't treated as syncable resources.
//!
//! # Port status
//!
//! This crate is a port of [localthought/syncables](https://github.com/localthought/syncables)
//! (TypeScript) and is **scaffolding**: the module layout mirrors the
//! original's `src/` one-to-one, and the document, resource, pagination
//! and storage layers are ported. The mock server's request handler
//! ([`mock_server::server`]) and the client's sync/write machinery
//! ([`client::client`]) carry their full public surface but are not
//! implemented yet — those functions `todo!()`, each naming the
//! TypeScript source it is to be ported from.

pub mod client;
pub mod error;
pub mod fake_data;
pub mod mock_server;
pub mod openapi;
pub mod pagination;
pub mod resources;
pub mod routing;
pub mod sync;

pub use crate::error::{Error, Result};

pub use crate::openapi::load::{load_open_api_document, OpenApiSource};
pub use crate::openapi::overlay::{
    apply_overlay, load_open_api_document_with_overlays, load_overlay, OverlayAction,
    OverlayDocument,
};
pub use crate::openapi::resolve_refs::resolve_refs;
pub use crate::openapi::types::{
    OpenApiDocument, OperationObject, ParameterObject, SchemaObject, ServerObject,
};

pub use crate::resources::discover::{discover_resources, ResourceRoute};

pub use crate::fake_data::generate::generate_from_schema;

pub use crate::mock_server::server::{create_mock_server, MockServer};

pub use crate::client::client::{
    create_api_client, ApiClient, ApiClientOptions, PaginateOptions, PollOptions, PollingHandle,
    SyncResult,
};
pub use crate::client::storage::{InMemoryStorageAdapter, StorageAdapter};

pub use crate::pagination::autodetect::{resolve_effective_scheme, EffectiveScheme};
pub use crate::pagination::types::{
    AutoDetectObject, PaginationApplicationObject, PaginationResponseState, PaginationSchemeObject,
    PaginationSchemesMap, RequestRole, ResponseRole, SchemeType,
};
pub use crate::pagination::validate::validate_pagination_scheme;

pub use crate::sync::client::{ClientConfig, SyncClient, SyncError, SyncReport};
pub use crate::sync::constants::{bind_url, validate_constants};
pub use crate::sync::credentials::{base_url, Credentials};
pub use crate::sync::ontology::{
    derive_ontology, ontology_shortname, Ontology, OntologyTerm, TermKind,
};
pub use crate::sync::resource_model::{
    crud_operation, discover_resource_model, AddedField, CollectionMembership, ContextProvider,
    CrudAction, CrudOperation, CrudResourceObject, IdentityBindingObject, ManagedCollection,
    ResourceCollectionObject, ResourceIdentityObject, ResourceModel,
};
pub use crate::sync::storage::{InMemoryStorage, Record, Storage, StorageError};
