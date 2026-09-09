//! Loading an OpenAPI document from a file path or an in-memory value.

use std::path::Path;

use serde_json::Value;

use super::resolve_refs::resolve_refs;
use super::types::OpenApiDocument;
use crate::error::{Error, Result};

/// Where a document comes from: a file path, or an already-parsed value.
///
/// The TypeScript original takes `string | Record<string, unknown>`;
/// this is the same union, made explicit.
#[derive(Debug, Clone)]
pub enum OpenApiSource<'a> {
    /// A path to a YAML or JSON document on disk.
    Path(&'a Path),
    /// An in-memory document.
    Value(Value),
}

impl<'a> From<&'a str> for OpenApiSource<'a> {
    fn from(path: &'a str) -> Self {
        Self::Path(Path::new(path))
    }
}

impl<'a> From<&'a Path> for OpenApiSource<'a> {
    fn from(path: &'a Path) -> Self {
        Self::Path(path)
    }
}

impl From<Value> for OpenApiSource<'_> {
    fn from(value: Value) -> Self {
        Self::Value(value)
    }
}

/// Loads an OpenAPI document from a JSON/YAML file path or an in-memory
/// value, and resolves all local `$ref`s.
///
/// YAML is a superset of JSON, so the file format does not need to be
/// detected separately.
pub async fn load_open_api_document<'a>(
    source: impl Into<OpenApiSource<'a>> + Send,
) -> Result<OpenApiDocument> {
    let raw = match source.into() {
        OpenApiSource::Path(path) => load_yaml_file(path).await?,
        OpenApiSource::Value(value) => value,
    };
    let resolved = resolve_refs(&raw);
    serde_json::from_value(resolved).map_err(Error::from)
}

/// Parses YAML (or JSON) text into a [`Value`].
pub fn parse_yaml(text: &str) -> Result<Value> {
    serde_yaml_ng::from_str(text).map_err(Error::from)
}

/// Reads and parses a YAML/JSON file, wrapping any i/o or parse failure in
/// [`Error::FileLoad`] so it names the offending path — a bare
/// [`std::io::Error`] from a failed read doesn't otherwise mention which
/// file was missing or unreadable.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn load_yaml_file(path: &Path) -> Result<Value> {
    async {
        let text = tokio::fs::read_to_string(path).await?;
        parse_yaml(&text)
    }
    .await
    .map_err(|source| Error::FileLoad {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn load_yaml_file(path: &Path) -> Result<Value> {
    Err(Error::FileLoad {
        path: path.to_path_buf(),
        source: Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Use an in-memory OpenAPI document in the browser",
            )
            .into(),
        ),
    })
}
