//! The sync engine surface: `SyncClient`, `ClientConfig`, [`storage::Storage`]
//! and friends.
//!
//! This is a *different* surface from the crate's existing
//! [`crate::client`]/[`crate::mock_server`] pair (a port of the
//! TypeScript `syncables` package). It is new scope, tracked by
//! [localthought/syncables-rs#1](https://github.com/localthought/syncables-rs/issues/1)
//! and the issues under it: a generic engine that reads an OpenAPI
//! document plus a resource model derived from it, and syncs records into
//! a host-provided [`storage::Storage`] implementation.
//! [`localthought/reflector-rs`](https://github.com/localthought/reflector-rs)
//! is the first intended host.
//!
//! [`storage`] (issue #7), [`credentials`] (issue #5), [`resource_model`]
//! (issue #3), [`constants`] (issue #6), [`ontology`] (issue #8) and
//! [`client`] (issue #9 — the read half; local-first writes are a
//! follow-up) exist so far.

pub mod client;
pub mod constants;
pub mod credentials;
pub mod ontology;
pub mod resource_model;
pub mod storage;
