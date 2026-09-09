//! Resolving which pagination scheme applies to an operation.

use std::collections::HashSet;

use indexmap::IndexMap;
use serde_json::Value;

use super::types::{
    AutoDetect, AutoDetectObject, PaginationApplicationObject, PaginationSchemeObject,
};
use super::validate::validate_pagination_scheme;
use crate::openapi::types::{OpenApiDocument, OperationObject, ParameterLocation};

/// The scheme that applies to an operation, and the name it is declared under.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveScheme {
    /// Key in `components.paginationSchemes`.
    pub scheme_name: String,
    /// The scheme itself, with any per-operation overrides merged in.
    pub scheme: PaginationSchemeObject,
}

/// Schemes that fail validation (spec §9) are excluded here rather than
/// thrown on eagerly — one malformed scheme in a document (see e.g.
/// Giphy's `type: offset`, which isn't a valid scheme type) shouldn't
/// prevent using the rest of the document or its other schemes.
fn valid_schemes(document: &OpenApiDocument) -> IndexMap<String, PaginationSchemeObject> {
    document
        .components
        .as_ref()
        .and_then(|c| c.pagination_schemes.as_ref())
        .into_iter()
        .flatten()
        .filter(|(name, scheme)| validate_pagination_scheme(name, scheme).is_empty())
        .map(|(name, scheme)| (name.clone(), scheme.clone()))
        .collect()
}

fn query_param_names(operation: &OperationObject) -> HashSet<&str> {
    operation
        .parameters
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|parameter| parameter.location == ParameterLocation::Query)
        .map(|parameter| parameter.name.as_str())
        .collect()
}

fn body_field_names(operation: &OperationObject) -> HashSet<&str> {
    operation
        .request_body
        .as_ref()
        .and_then(|body| body.content.as_ref())
        .and_then(|content| content.get("application/json"))
        .and_then(|media| media.schema.as_ref())
        .and_then(|schema| schema.properties.as_ref())
        .into_iter()
        .flatten()
        .map(|(name, _)| name.as_str())
        .collect()
}

/// Default auto-detection rules (spec §6.2/§6.3): a dimension only
/// contributes to the match when the scheme actually declares fields for
/// it — an empty declaration isn't treated as vacuously satisfied, or
/// every scheme with no query parameters would match every operation.
fn auto_detect_matches(scheme: &PaginationSchemeObject, operation: &OperationObject) -> bool {
    let options = match &scheme.auto_detect {
        Some(AutoDetect::Enabled(false)) => return false,
        Some(AutoDetect::Options(options)) => (**options).clone(),
        _ => AutoDetectObject::default(),
    };
    let require_all = options.require_all.unwrap_or(true);
    let mut results: Vec<bool> = Vec::new();

    let request = scheme.request.as_ref();

    if options.match_query_params.unwrap_or(true) {
        let required: Vec<&String> = request
            .and_then(|r| r.query_parameters.as_ref())
            .into_iter()
            .flatten()
            .map(|(name, _)| name)
            .collect();
        if !required.is_empty() {
            let declared = query_param_names(operation);
            results.push(required.iter().all(|name| declared.contains(name.as_str())));
        }
    }

    if options.match_body_fields.unwrap_or(true) {
        let required: Vec<&String> = request
            .and_then(|r| r.body_fields.as_ref())
            .into_iter()
            .flatten()
            .map(|(name, _)| name)
            .collect();
        if !required.is_empty() {
            let declared = body_field_names(operation);
            results.push(required.iter().all(|name| declared.contains(name.as_str())));
        }
    }

    if results.is_empty() {
        return false;
    }
    if require_all {
        results.iter().all(|matched| *matched)
    } else {
        results.iter().any(|matched| *matched)
    }
}

fn deep_merge(base: &Value, overrides: &Value) -> Value {
    match (base, overrides) {
        (Value::Object(base), Value::Object(overrides)) => {
            let mut result = base.clone();
            for (key, value) in overrides {
                let merged = match result.get(key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        deep_merge(existing, value)
                    }
                    _ => value.clone(),
                };
                result.insert(key.clone(), merged);
            }
            Value::Object(result)
        }
        _ => overrides.clone(),
    }
}

/// Resolves the pagination scheme that applies to an operation: an
/// explicit `x-pagination` application (with overrides merged in) takes
/// priority, falling back to auto-detection against the document's valid
/// `paginationSchemes`.
pub fn resolve_effective_scheme(
    document: &OpenApiDocument,
    operation: &OperationObject,
) -> Option<EffectiveScheme> {
    let schemes = valid_schemes(document);

    if let Some(explicit) = operation.extensions.get("x-pagination") {
        let applications: Vec<PaginationApplicationObject> =
            serde_json::from_value(explicit.clone()).unwrap_or_default();
        let application = applications.into_iter().next()?;
        let base = schemes.get(&application.scheme)?;
        let scheme = match &application.overrides {
            Some(overrides) => {
                let merged = deep_merge(&serde_json::to_value(base).ok()?, overrides);
                serde_json::from_value(merged).ok()?
            }
            None => base.clone(),
        };
        return Some(EffectiveScheme {
            scheme_name: application.scheme,
            scheme,
        });
    }

    schemes
        .into_iter()
        .find(|(_, scheme)| auto_detect_matches(scheme, operation))
        .map(|(scheme_name, scheme)| EffectiveScheme {
            scheme_name,
            scheme,
        })
}
