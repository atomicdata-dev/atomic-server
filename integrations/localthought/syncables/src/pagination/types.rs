//! Type definitions for the [OpenAPI Pagination Schemes Extension](https://github.com/pondersource/openapi-pagination-schemes-extension).
//!
//! Spec version 0.1.0. Field names, optionality, and enum values are taken
//! verbatim from the spec so a [`PaginationSchemeObject`] can be lifted
//! from an OAS document without transformation.
//!
//! Roles are modelled as string newtypes rather than closed enums: the
//! spec allows `x-`-prefixed extension roles alongside the standard ones,
//! and [`crate::pagination::validate`] is what decides validity, so an
//! unknown role has to survive deserialization to be reported.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which family of pagination a scheme belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchemeType {
    /// Page- or offset-numbered traversal.
    #[serde(rename = "pageNumber")]
    PageNumber,
    /// Opaque-token traversal.
    #[serde(rename = "pageToken")]
    PageToken,
    /// Follow-the-link traversal.
    #[serde(rename = "nextLink")]
    NextLink,
}

/// The role a request field plays. Spec-defined values are `page`,
/// `pageSize`, `offset`, `pageToken` and `cursor`.
pub type RequestRole = String;

/// The role a response field plays. Spec-defined values are
/// `nextPageToken`, `nextCursor`, `nextLink`, `totalCount`, `totalPages`,
/// `pageSize` and `currentPage`.
pub type ResponseRole = String;

/// One declared request field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestFieldObject {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Schema of the field's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
    /// The field's role in the scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<RequestRole>,
    /// Whether the field is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// Request-side fields a scheme declares, grouped by where they travel.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestPaginationFieldsObject {
    /// Query parameters.
    #[serde(
        rename = "queryParameters",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub query_parameters: Option<IndexMap<String, RequestFieldObject>>,
    /// Request body fields.
    #[serde(
        rename = "bodyFields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fields: Option<IndexMap<String, RequestFieldObject>>,
    /// Request headers.
    ///
    /// Part of the type surface (mirroring the spec); nothing reads it yet.
    #[serde(
        rename = "headerFields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub header_fields: Option<IndexMap<String, RequestFieldObject>>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// One declared response field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponseFieldObject {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Schema of the field's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
    /// The field's role in the scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ResponseRole>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// Response-side fields a scheme declares, grouped by where they travel.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponsePaginationFieldsObject {
    /// Response body fields; keys may be dotted paths into nested objects.
    #[serde(
        rename = "bodyFields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fields: Option<IndexMap<String, ResponseFieldObject>>,
    /// Response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<IndexMap<String, ResponseFieldObject>>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// Fine-grained auto-detection options.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AutoDetectObject {
    /// Match the scheme's declared query parameters against the operation's.
    #[serde(
        rename = "matchQueryParams",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_query_params: Option<bool>,
    /// Match the scheme's declared body fields against the operation's.
    #[serde(
        rename = "matchBodyFields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_body_fields: Option<bool>,
    /// Part of the type surface (mirroring the spec); nothing reads it yet.
    #[serde(
        rename = "matchResponseFields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_response_fields: Option<bool>,
    /// Part of the type surface (mirroring the spec); nothing reads it yet.
    #[serde(
        rename = "matchHeaders",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_headers: Option<bool>,
    /// Require every considered dimension to match, rather than any.
    #[serde(
        rename = "requireAll",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_all: Option<bool>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// `autoDetect` is either a plain toggle or a set of options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AutoDetect {
    /// `autoDetect: true` / `autoDetect: false`.
    Enabled(bool),
    /// `autoDetect: { ... }`.
    Options(Box<AutoDetectObject>),
}

/// One entry of `components.paginationSchemes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaginationSchemeObject {
    /// Which family of pagination this scheme belongs to.
    ///
    /// Deserialized leniently: an invalid value (e.g. Giphy's `offset`)
    /// has to survive parsing so [`crate::pagination::validate`] can
    /// report it rather than failing the whole document.
    #[serde(rename = "type")]
    pub scheme_type: Value,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether and how the scheme may be auto-detected.
    #[serde(
        rename = "autoDetect",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auto_detect: Option<AutoDetect>,
    /// Request-side declared fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestPaginationFieldsObject>,
    /// Response-side declared fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponsePaginationFieldsObject>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

impl PaginationSchemeObject {
    /// The scheme's type, when it is one the spec defines.
    pub fn typed(&self) -> Option<SchemeType> {
        serde_json::from_value(self.scheme_type.clone()).ok()
    }
}

/// One entry of an operation's `x-pagination` array.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaginationApplicationObject {
    /// Name of the scheme in `components.paginationSchemes`.
    pub scheme: String,
    /// Per-operation overrides, deep-merged onto the named scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<Value>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `x-`-prefixed extension keys.
    #[serde(flatten)]
    pub extensions: IndexMap<String, Value>,
}

/// `components.paginationSchemes`, keyed by scheme name.
pub type PaginationSchemesMap = IndexMap<String, PaginationSchemeObject>;

/// Everything derivable from a server response about the state of pagination.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PaginationResponseState {
    /// Token to request the next page with, if the response carried one.
    pub next_page_token: Option<String>,
    /// URL of the next page, if the response carried one.
    pub next_link: Option<String>,
    /// The page number this response represents.
    pub current_page: Option<f64>,
    /// Total number of items across all pages.
    pub total_count: Option<f64>,
    /// Total number of pages.
    pub total_pages: Option<f64>,
    /// Number of items per page.
    pub page_size: Option<f64>,
    /// Whether another page exists after this one.
    pub has_next_page: bool,
}

/// Query parameters to send for a single page request.
pub type PaginationQuery = IndexMap<String, String>;
