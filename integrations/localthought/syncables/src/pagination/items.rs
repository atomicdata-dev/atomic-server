//! Locating which response property actually holds the list of items.
//!
//! The extension itself only describes pagination metadata, not where
//! items live, so this excludes whatever fields the scheme claims as
//! metadata, then picks the remaining array-typed property (falling back
//! to common envelope names). This is also what makes real enveloped
//! responses (e.g. `{ data: [...], meta, pagination }`) work at all,
//! pagination or not.

use std::collections::HashSet;

use indexmap::IndexMap;

use super::types::PaginationSchemeObject;
use crate::openapi::types::SchemaObject;

/// Field names real-world APIs commonly wrap a list response in, tried
/// when the response schema itself doesn't unambiguously point at one
/// array property.
const COMMON_ITEMS_FIELDS: [&str; 5] = ["items", "data", "results", "records", "content"];

/// Flattens a schema's own properties together with any `allOf` branches'
/// properties into one map.
///
/// Real paginated response schemas often compose a shared "paging" base
/// schema with a branch that adds the concrete `items` property (e.g.
/// Spotify's `PagingSimplifiedAlbumObject`).
pub fn effective_properties(schema: Option<&SchemaObject>) -> IndexMap<String, SchemaObject> {
    let Some(schema) = schema else {
        return IndexMap::new();
    };
    if let Some(all_of) = &schema.all_of {
        let mut merged = IndexMap::new();
        for branch in all_of {
            merged.extend(effective_properties(Some(branch)));
        }
        return merged;
    }
    schema.properties.clone().unwrap_or_default()
}

/// The top-level field names a pagination scheme claims for its own metadata.
fn metadata_field_roots(scheme: Option<&PaginationSchemeObject>) -> HashSet<String> {
    scheme
        .and_then(|s| s.response.as_ref())
        .and_then(|r| r.body_fields.as_ref())
        .into_iter()
        .flatten()
        .map(|(key, _)| key.split('.').next().unwrap_or(key).to_string())
        .collect()
}

/// Finds the property in a response schema that holds the actual list of
/// items: the first array-typed property that isn't claimed by the
/// pagination scheme as a metadata field, falling back to common
/// enveloping field names.
pub fn locate_items_field(
    schema: Option<&SchemaObject>,
    scheme: Option<&PaginationSchemeObject>,
) -> Option<String> {
    let properties = effective_properties(schema);
    let excluded = metadata_field_roots(scheme);

    for (name, property_schema) in &properties {
        if !excluded.contains(name) && property_schema.schema_type.as_deref() == Some("array") {
            return Some(name.clone());
        }
    }

    COMMON_ITEMS_FIELDS
        .iter()
        .find(|name| properties.contains_key(**name) && !excluded.contains(**name))
        .map(|name| (*name).to_string())
}

/// The schema of a single item, given the schema of the whole (enveloped)
/// response.
pub fn item_schema_for(
    schema: Option<&SchemaObject>,
    scheme: Option<&PaginationSchemeObject>,
) -> Option<SchemaObject> {
    if let Some(schema) = schema {
        if schema.schema_type.as_deref() == Some("array") {
            return schema.items.as_deref().cloned();
        }
    }
    let field = locate_items_field(schema, scheme)?;
    effective_properties(schema)
        .get(&field)
        .and_then(|property| property.items.as_deref().cloned())
}
