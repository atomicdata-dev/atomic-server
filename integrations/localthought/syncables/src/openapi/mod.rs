//! Reading an OpenAPI document and preparing it for everything downstream.
//!
//! [`load`] reads a document from a file path or an in-memory value and
//! passes it through [`resolve_refs`], which inlines all local `#/...`
//! JSON-pointer `$ref`s. Everything downstream assumes refs are already
//! resolved; [`types`] holds the minimal OpenAPI type surface actually
//! used (not a full spec typing).

pub mod load;
pub mod overlay;
pub mod resolve_refs;
pub mod types;
