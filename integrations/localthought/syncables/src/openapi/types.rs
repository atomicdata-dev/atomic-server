//! The minimal OpenAPI type surface this crate actually uses — not a full
//! spec typing. Every struct keeps an `extensions` catch-all so a document
//! round-trips through these types without losing vendor extensions
//! (`x-pagination` in particular is read back out of `OperationObject`).

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pagination::types::PaginationSchemesMap;

/// A JSON object with insertion order preserved.
///
/// Order is load-bearing: [`crate::pagination::items::locate_items_field`]
/// picks the *first* array-typed property of a response schema.
pub type JsonMap = IndexMap<String, Value>;

/// A JSON Schema subset, as it appears inside an OpenAPI document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SchemaObject {
    /// `type` keyword (`string`, `integer`, `object`, `array`, ...).
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<String>,
    /// `format` keyword (`date-time`, `uuid`, `email`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Properties of an object schema, in document order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<IndexMap<String, SchemaObject>>,
    /// Names of required properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    /// Item schema of an array schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaObject>>,
    /// Allowed values; the first is used when generating fake data.
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<Value>>,
    /// A fixed example, preferred over synthesis when generating fake data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
    /// Lower bound for numeric schemas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    /// `oneOf` branches.
    #[serde(rename = "oneOf", default, skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<SchemaObject>>,
    /// `anyOf` branches.
    #[serde(rename = "anyOf", default, skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<SchemaObject>>,
    /// `allOf` branches, merged when generating data or listing properties.
    #[serde(rename = "allOf", default, skip_serializing_if = "Option::is_none")]
    pub all_of: Option<Vec<SchemaObject>>,
    /// Any other keyword present on the schema.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// One entry of a `content` map, keyed by media type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MediaTypeObject {
    /// Schema of the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaObject>,
    /// A fixed example payload, preferred over the schema when serving mocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
}

/// A documented response for one status code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponseObject {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Response payloads, keyed by media type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<IndexMap<String, MediaTypeObject>>,
}

/// A documented request body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestBodyObject {
    /// Whether the body is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Request payloads, keyed by media type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<IndexMap<String, MediaTypeObject>>,
}

/// Where a parameter is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterLocation {
    /// Query string parameter.
    Query,
    /// Path template variable.
    Path,
    /// Request header.
    Header,
    /// Cookie.
    Cookie,
}

/// A single operation parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParameterObject {
    /// Parameter name.
    pub name: String,
    /// Where the parameter is carried.
    #[serde(rename = "in")]
    pub location: ParameterLocation,
    /// Whether the parameter is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Schema of the parameter's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaObject>,
    /// Any other key present on the parameter.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// One HTTP operation on a path.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OperationObject {
    /// `operationId`, when the document declares one.
    #[serde(
        rename = "operationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub operation_id: Option<String>,
    /// Declared parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<ParameterObject>>,
    /// Declared request body.
    #[serde(
        rename = "requestBody",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_body: Option<RequestBodyObject>,
    /// Documented responses, keyed by status code.
    #[serde(default)]
    pub responses: IndexMap<String, ResponseObject>,
    /// Any other key on the operation — notably `x-pagination`.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// The set of operations declared on one path template.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PathItem {
    /// `GET` operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get: Option<OperationObject>,
    /// `PUT` operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub put: Option<OperationObject>,
    /// `POST` operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post: Option<OperationObject>,
    /// `PATCH` operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<OperationObject>,
    /// `DELETE` operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete: Option<OperationObject>,
    /// Any other key on the path item.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

impl PathItem {
    /// The operation declared for `method` (case-insensitive), if any.
    pub fn operation(&self, method: &str) -> Option<&OperationObject> {
        match method.to_ascii_uppercase().as_str() {
            "GET" => self.get.as_ref(),
            "PUT" => self.put.as_ref(),
            "POST" => self.post.as_ref(),
            "PATCH" => self.patch.as_ref(),
            "DELETE" => self.delete.as_ref(),
            _ => None,
        }
    }
}

/// Document metadata.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InfoObject {
    /// Document title.
    pub title: String,
    /// Document version.
    pub version: String,
}

/// One entry of the document's top-level `servers` list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerObject {
    /// Root URL of the API, e.g. `https://api.github.com`.
    pub url: String,
    /// Any other key on the server entry.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// The `components` section, narrowed to what this crate reads.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ComponentsObject {
    /// Reusable schemas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemas: Option<IndexMap<String, SchemaObject>>,
    /// Pagination schemes, per the OpenAPI Pagination Schemes Extension.
    #[serde(
        rename = "paginationSchemes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pagination_schemes: Option<PaginationSchemesMap>,
    /// Any other key under `components`.
    #[serde(flatten)]
    pub extensions: JsonMap,
}

/// An OpenAPI document with all local `$ref`s already resolved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OpenApiDocument {
    /// OpenAPI version string.
    #[serde(default)]
    pub openapi: String,
    /// Document metadata.
    #[serde(default)]
    pub info: InfoObject,
    /// Path templates, in document order.
    #[serde(default)]
    pub paths: IndexMap<String, PathItem>,
    /// The API's base URL(s). The credential layer targets requests at the
    /// first entry rather than any URL configured separately, so a document
    /// can't be pointed at the wrong host by mistake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<ServerObject>>,
    /// Reusable components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<ComponentsObject>,
    /// Any other top-level key.
    #[serde(flatten)]
    pub extensions: JsonMap,
}
