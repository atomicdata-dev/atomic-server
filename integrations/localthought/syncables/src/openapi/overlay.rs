//! An intentionally minimal [OpenAPI Overlay](https://spec.openapis.org/overlay/v1.0.0.html)
//! implementation: `update`/`remove` actions against `$`, plain dot-paths
//! like `$.components`, and quoted bracket segments like
//! `$.paths['/pets/{petId}'].get` — not the full JSONPath grammar (no
//! wildcards, filters, or numeric/array indexing).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::load::{load_open_api_document, load_yaml_file, OpenApiSource};
use super::types::OpenApiDocument;
use crate::error::{Error, Result};

/// A single overlay action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayAction {
    /// JSONPath target — `$`, a dot-path such as `$.components`, or a
    /// dot-path with quoted bracket segments such as
    /// `$.paths['/pets/{petId}'].get`.
    pub target: String,
    /// Object to deep-merge onto the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<Map<String, Value>>,
    /// When true, delete the target instead of merging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<bool>,
}

/// Metadata of an overlay document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// Overlay title.
    pub title: String,
    /// Overlay version.
    pub version: String,
}

/// An OpenAPI Overlay document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayDocument {
    /// Overlay specification version.
    pub overlay: String,
    /// Overlay metadata.
    pub info: OverlayInfo,
    /// Actions to apply, in order.
    pub actions: Vec<OverlayAction>,
}

/// Loads an OpenAPI Overlay document from a YAML/JSON file path or value.
pub async fn load_overlay<'a>(
    source: impl Into<OpenApiSource<'a>> + Send,
) -> Result<OverlayDocument> {
    let raw = match source.into() {
        OpenApiSource::Path(path) => load_yaml_file(path).await?,
        OpenApiSource::Value(value) => value,
    };
    serde_json::from_value(raw).map_err(Error::from)
}

/// Loads an OpenAPI document and applies a list of Overlays to it, in the
/// order given — a later overlay may refine what an earlier one added. Each
/// overlay is loaded from a file path.
///
/// Overlays are applied to the document after its own `$ref`s are resolved
/// (mirroring the TypeScript original's `buildDocumentFrom` in
/// `src/sync/document.ts` of `localthought/reflector`), so an overlay's
/// `update` can safely assume there are no refs left to chase.
pub async fn load_open_api_document_with_overlays<'a>(
    document: impl Into<OpenApiSource<'a>> + Send,
    overlay_paths: &[PathBuf],
) -> Result<OpenApiDocument> {
    let document = load_open_api_document(document).await?;
    let mut value = serde_json::to_value(document).map_err(Error::from)?;
    for path in overlay_paths {
        let overlay = load_overlay(path.as_path()).await?;
        value = apply_overlay(&value, &overlay)?;
    }
    serde_json::from_value(value).map_err(Error::from)
}

fn deep_merge_value(existing: Option<&Value>, incoming: &Value) -> Value {
    match (existing, incoming) {
        (Some(Value::Object(existing)), Value::Object(incoming)) => {
            let mut merged = existing.clone();
            for (key, value) in incoming {
                merged.insert(key.clone(), deep_merge_value(merged.get(key), value));
            }
            Value::Object(merged)
        }
        _ => incoming.clone(),
    }
}

/// Tokenizes the intentionally small subset of Overlay JSONPath targets this
/// crate supports into property segments: `$` (the document root), a
/// dot-path like `$.components.schemas.Foo`, and quoted bracket segments
/// like `$.paths['/repos/{owner}/{repo}/issues'].get` — needed because a
/// path template contains slashes and braces that a plain `.split('.')`
/// would mangle. No wildcards, filters, or numeric/array indexing.
fn parse_target(target: &str) -> Result<Vec<String>> {
    let unsupported = || Error::UnsupportedOverlayTarget(target.to_string());

    if target == "$" {
        return Ok(Vec::new());
    }
    if !target.starts_with('$') {
        return Err(unsupported());
    }

    let mut segments = Vec::new();
    let bytes = target.as_bytes();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'.' => {
                index += 1;
                let start = index;
                while index < bytes.len() && bytes[index] != b'.' && bytes[index] != b'[' {
                    index += 1;
                }
                if index == start {
                    return Err(unsupported());
                }
                segments.push(target[start..index].to_string());
            }
            b'[' => {
                let quote = *bytes.get(index + 1).ok_or_else(unsupported)?;
                if quote != b'\'' && quote != b'"' {
                    return Err(unsupported());
                }
                let key_start = index + 2;
                let end = target[key_start..]
                    .find(quote as char)
                    .map(|offset| key_start + offset)
                    .ok_or_else(unsupported)?;
                segments.push(target[key_start..end].to_string());
                index = end + 1;
                if bytes.get(index) != Some(&b']') {
                    return Err(unsupported());
                }
                index += 1;
            }
            _ => return Err(unsupported()),
        }
    }
    Ok(segments)
}

fn navigate<'v>(
    root: &'v mut Value,
    segments: &[String],
    create_missing: bool,
) -> Result<Option<&'v mut Value>> {
    let mut node = root;
    for segment in segments {
        let object = node
            .as_object_mut()
            .ok_or_else(|| Error::OverlayTargetNotAnObject(segment.clone()))?;
        if !object.contains_key(segment) {
            if !create_missing {
                return Ok(None);
            }
            object.insert(segment.clone(), Value::Object(Map::new()));
        }
        let child = object
            .get_mut(segment)
            .expect("segment inserted or already present");
        if !child.is_object() {
            return Err(Error::OverlayTargetNotAnObject(segment.clone()));
        }
        node = child;
    }
    Ok(Some(node))
}

/// Applies an overlay to a document, returning a new document.
///
/// Supports `update` (deep-merged onto the target) and `remove` actions.
pub fn apply_overlay(document: &Value, overlay: &OverlayDocument) -> Result<Value> {
    let mut result = document.clone();

    for action in &overlay.actions {
        let segments = parse_target(&action.target)?;
        if action.remove == Some(true) {
            let Some((key, parent_segments)) = segments.split_last() else {
                return Err(Error::OverlayRemovesRoot);
            };
            if let Some(parent) = navigate(&mut result, parent_segments, false)? {
                if let Some(object) = parent.as_object_mut() {
                    object.shift_remove(key);
                }
            }
        } else if let Some(update) = &action.update {
            let target = navigate(&mut result, &segments, true)?
                .expect("navigate with create_missing always yields a node");
            let object = target
                .as_object_mut()
                .ok_or_else(|| Error::OverlayTargetNotAnObject(action.target.clone()))?;
            for (key, value) in update {
                let merged = deep_merge_value(object.get(key), value);
                object.insert(key.clone(), merged);
            }
        }
    }

    Ok(result)
}
