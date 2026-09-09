//! Pairing collection paths with their item paths.
//!
//! This pairing is the core concept the rest of the crate builds on: a
//! "resource" only exists where a collection path (`/pets`) has a direct
//! item-path child (`/pets/{petId}`). Paths without such a pairing
//! (health checks, one-off actions) are not resources and are handled
//! separately as raw request/response passthroughs.

use indexmap::IndexMap;

use crate::openapi::types::PathItem;

/// HTTP method a background `update` sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpdateMethod {
    /// Full replace.
    Put,
    /// Partial update, for APIs (e.g. GitHub) that expose no `PUT`.
    Patch,
}

impl UpdateMethod {
    /// The method name as it goes on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Patch => "PATCH",
        }
    }
}

/// A collection path paired with its item path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRoute {
    /// The collection path, e.g. `/pets`.
    pub collection_path: String,
    /// The item path, e.g. `/pets/{petId}`.
    pub item_path: String,
    /// Name of the item path's trailing variable, e.g. `petId`.
    pub item_param: String,
    /// HTTP method a background `update` sends.
    ///
    /// Derived from the item path's declared operations: `PUT` when the
    /// item path has a `put` operation (a full replace), otherwise
    /// `PATCH` when it only offers a partial update.
    pub update_method: UpdateMethod,
}

/// Chooses the update method for an item path from the operations it
/// declares: prefer `PUT` (replace) when present, fall back to `PATCH`
/// when the path only offers a partial update, and default to `PUT` when
/// neither is declared.
fn update_method_for(paths: &IndexMap<String, PathItem>, item_path: &str) -> UpdateMethod {
    match paths.get(item_path) {
        Some(item) if item.put.is_none() && item.patch.is_some() => UpdateMethod::Patch,
        _ => UpdateMethod::Put,
    }
}

/// Pairs each collection path with its item path so mock server and
/// client can apply CRUD semantics.
pub fn discover_resources(paths: &IndexMap<String, PathItem>) -> Vec<ResourceRoute> {
    let all_paths: Vec<&String> = paths.keys().collect();

    let mut resources = Vec::new();
    for collection_path in all_paths.iter().filter(|p| !is_item_path(p)) {
        let item_path = all_paths
            .iter()
            .find(|p| is_item_path(p) && is_direct_child(collection_path, p));
        if let Some(item_path) = item_path {
            resources.push(ResourceRoute {
                collection_path: (*collection_path).clone(),
                item_path: (*item_path).clone(),
                item_param: extract_param_name(item_path),
                update_method: update_method_for(paths, item_path),
            });
        }
    }
    resources
}

fn is_item_path(path: &str) -> bool {
    path.split('/')
        .rfind(|s| !s.is_empty())
        .is_some_and(|last| last.starts_with('{') && last.ends_with('}'))
}

fn extract_param_name(item_path: &str) -> String {
    let last = item_path.split('/').rfind(|s| !s.is_empty()).unwrap_or("");
    last.get(1..last.len().saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

fn is_direct_child(collection_path: &str, candidate: &str) -> bool {
    let collection: Vec<&str> = collection_path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let candidate: Vec<&str> = candidate.split('/').filter(|s| !s.is_empty()).collect();
    candidate.len() == collection.len() + 1
        && collection
            .iter()
            .enumerate()
            .all(|(index, segment)| candidate.get(index) == Some(segment))
}
