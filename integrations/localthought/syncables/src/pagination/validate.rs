//! Validating a pagination scheme against the extension's own rules (§9).

use indexmap::IndexMap;

use super::types::{PaginationSchemeObject, RequestFieldObject, ResponseFieldObject};

const SCHEME_TYPES: [&str; 3] = ["pageNumber", "pageToken", "nextLink"];
const REQUEST_ROLES: [&str; 5] = ["page", "pageSize", "offset", "pageToken", "cursor"];
const RESPONSE_ROLES: [&str; 7] = [
    "nextPageToken",
    "nextCursor",
    "nextLink",
    "totalCount",
    "totalPages",
    "pageSize",
    "currentPage",
];

fn is_extension_key(key: &str) -> bool {
    key.starts_with("x-")
}

fn check_request_roles(
    errors: &mut Vec<String>,
    path: &str,
    section: &str,
    fields: Option<&IndexMap<String, RequestFieldObject>>,
) {
    for (field_name, field) in fields.into_iter().flatten() {
        if let Some(role) = &field.role {
            if !is_extension_key(role) && !REQUEST_ROLES.contains(&role.as_str()) {
                errors.push(format!(
                    "{path}.request.{section}.{field_name}.role is not a valid request role (got \"{role}\")"
                ));
            }
        }
    }
}

fn check_response_roles(
    errors: &mut Vec<String>,
    path: &str,
    section: &str,
    fields: Option<&IndexMap<String, ResponseFieldObject>>,
) {
    for (field_name, field) in fields.into_iter().flatten() {
        if let Some(role) = &field.role {
            if !is_extension_key(role) && !RESPONSE_ROLES.contains(&role.as_str()) {
                errors.push(format!(
                    "{path}.response.{section}.{field_name}.role is not a valid response role (got \"{role}\")"
                ));
            }
        }
    }
}

/// Validates a single scheme against spec section 9.
///
/// Returns a list of human-readable errors (each naming the offending
/// location), empty if the scheme is valid. Schemes with errors are
/// excluded from auto-detection rather than thrown on — one malformed
/// scheme in a document shouldn't prevent using the others.
pub fn validate_pagination_scheme(name: &str, scheme: &PaginationSchemeObject) -> Vec<String> {
    let mut errors = Vec::new();
    let path = format!("paginationSchemes.{name}");

    let declared_type = scheme
        .scheme_type
        .as_str()
        .map_or_else(|| scheme.scheme_type.to_string(), str::to_string);
    if !SCHEME_TYPES.contains(&declared_type.as_str()) {
        errors.push(format!(
            "{path}.type must be one of pageNumber, pageToken, or nextLink (got \"{declared_type}\")"
        ));
    }

    if scheme.request.is_none() && scheme.response.is_none() {
        errors.push(format!(
            "{path} must define at least one of \"request\" or \"response\""
        ));
    }

    let request = scheme.request.as_ref();
    check_request_roles(
        &mut errors,
        &path,
        "queryParameters",
        request.and_then(|r| r.query_parameters.as_ref()),
    );
    check_request_roles(
        &mut errors,
        &path,
        "bodyFields",
        request.and_then(|r| r.body_fields.as_ref()),
    );

    let response = scheme.response.as_ref();
    check_response_roles(
        &mut errors,
        &path,
        "bodyFields",
        response.and_then(|r| r.body_fields.as_ref()),
    );
    check_response_roles(
        &mut errors,
        &path,
        "headers",
        response.and_then(|r| r.headers.as_ref()),
    );

    errors
}
