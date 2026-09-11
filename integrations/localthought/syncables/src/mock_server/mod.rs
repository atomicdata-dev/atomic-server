//! A mock API server that implements an OpenAPI document, backed by a real
//! (in-memory) CRUD store per resource, seeded with fake data generated
//! from the document's schemas.

pub mod server;
pub mod store;
