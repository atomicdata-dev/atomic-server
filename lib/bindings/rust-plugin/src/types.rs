use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, collections::HashMap};

pub type Body = serde_bytes::ByteBuf;

pub type ComplexAlias = ComplexGuestToHost;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ComplexGuestToHost {
    pub simple: Simple,
    pub map: BTreeMap<String, Simple>,
}

/// Multi-line doc comment with complex characters
/// & " , \ ! '
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplexHostToGuest {
    #[serde(flatten)]
    pub simple: Simple,
    pub list: Vec<f64>,
    pub points: Vec<Point<f64>>,
    pub recursive: Vec<Point<Point<f64>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complex_nested: Option<BTreeMap<String, Vec<FloatingPoint>>>,

    /// Raw identifiers are supported too.
    pub r#type: String,
    pub value: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExplicitedlyImportedType {
    pub you_will_see_this: bool,
}

pub type FloatingPoint = Point<f64>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GroupImportedType1 {
    pub you_will_see_this: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GroupImportedType2 {
    pub you_will_see_this: bool,
}

/// Similar to the `RequestOptions` struct, but using types from the `http` crate.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequestOptions {
    #[serde(deserialize_with = "fp_bindgen_support::http::deserialize_uri", serialize_with = "fp_bindgen_support::http::serialize_uri")]
    pub url: http::Uri,
    #[serde(deserialize_with = "fp_bindgen_support::http::deserialize_http_method", serialize_with = "fp_bindgen_support::http::serialize_http_method")]
    pub method: http::Method,
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_bytes::ByteBuf>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Point<T> {
    pub value: T,
}

/// Represents an error with the request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestError {
    /// Used when we know we don't have an active network connection.
    Offline,
    NoRoute,
    ConnectionRefused,
    Timeout,
    #[serde(rename_all = "snake_case")]
    ServerError {
        /// HTTP status code.
        status_code: u16,

        /// Response body.
        response: Body,
    },
    /// Misc.
    #[serde(rename = "other/misc")]
    Other { reason: String },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestMethod {
    Delete,
    Get,
    Options,
    Post,
    Put,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    pub url: String,
    pub method: RequestMethod,
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_bytes::ByteBuf>,
}

/// A response to a request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// Response headers, by name.
    pub headers: HashMap<String, String>,

    /// Response body.
    pub body: Body,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Simple {
    pub foo: i32,
    pub bar: String,
}

/// Tagged dynamic value.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Value {
    Integer(i64),
    Float(f64),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}
