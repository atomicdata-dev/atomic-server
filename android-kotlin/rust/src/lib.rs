//! UniFFI bindings of `atomic_lib::host` for the native Kotlin Android app.
//!
//! The logic is `atomic_lib::host` (lists, recents, chats, search); this crate
//! binds it to one store per process and turns its JSON rows into typed
//! records for Kotlin. It is the Kotlin twin of `flutter/rust` (which cannot be
//! a dependency: its `crate-type` has no `rlib`), so the little glue that
//! `flutter/rust/src/api/simple.rs` holds (opening the store with recovery,
//! the search index catch-up, agent and drive calls) is copied here, not
//! shared.

uniffi::setup_scaffolding!();

mod api;
mod embed;
mod error;
mod home;
mod state;
mod store;
mod types;

pub use error::CoreError;
pub use types::*;

#[cfg(test)]
mod tests;
