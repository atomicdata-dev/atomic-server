/*
Contains the type definitions for the Plugins, including definitions for the imported and exported functions.
Is used to generate the `./generate_runtime` folder, and the `atomic-bindings` crate.

If you make changes to the plugin bindings, recompile them:

1. Compile the bindings folder in the root of the repo `cargo run --bin generate-bindings --features plugins`
2. Move the `rust-wasmer-runtime` files to `lib/src/plugins/generated_runtime`
*/

use fp_bindgen::{prelude::*, types::CargoDependency};
use http::{Method, Uri};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub type Body = ByteBuf;

pub type FloatingPoint = Point<f64>;

#[derive(Serializable)]
pub struct DeadCode {
    pub you_wont_see_this: bool,
}

#[derive(Serializable)]
#[fp(rename_all = "PascalCase")]
pub struct Point<T> {
    pub value: T,
}

#[derive(Serializable)]
pub struct Simple {
    pub foo: i32,
    pub bar: String,
}

/// Multi-line doc comment with complex characters
/// & " , \ ! '
#[derive(Serializable)]
#[fp(rename_all = "camelCase")]
pub struct ComplexHostToGuest {
    #[fp(flatten)]
    pub simple: Simple,
    pub list: Vec<f64>,
    pub points: Vec<Point<f64>>,
    pub recursive: Vec<Point<Point<f64>>>,
    pub complex_nested: Option<BTreeMap<String, Vec<FloatingPoint>>>,
    /// Raw identifiers are supported too.
    pub r#type: String,
    pub value: Value,
}

pub type ComplexAlias = ComplexGuestToHost;

#[derive(Serializable)]
pub struct ComplexGuestToHost {
    pub simple: Simple,
    pub map: BTreeMap<String, Simple>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Serializable)]
#[fp(rust_wasmer_runtime_module = "atomic_bindings")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestMethod {
    Delete,
    Get,
    Options,
    Post,
    Put,
}

#[derive(Clone, Debug, Deserialize, Serialize, Serializable)]
#[fp(rust_wasmer_runtime_module = "atomic_bindings")]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    pub url: String,
    pub method: RequestMethod,
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ByteBuf>,
}

/// Similar to the `RequestOptions` struct, but using types from the `http` crate.
#[derive(Clone, Debug, Serializable)]
#[fp(rename_all = "camelCase")]
pub struct HttpRequestOptions {
    pub url: Uri,
    pub method: Method,
    pub headers: HashMap<String, String>,
    #[fp(skip_serializing_if = "Option::is_none")]
    pub body: Option<ByteBuf>,
}

/// A response to a request.
#[derive(Clone, Debug, Deserialize, Serialize, Serializable)]
#[fp(rust_wasmer_runtime_module = "atomic_bindings")]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// Response headers, by name.
    pub headers: HashMap<String, String>,
    /// Response body.
    pub body: Body,
}

/// Represents an error with the request.
#[derive(Serializable)]
#[fp(tag = "type", rename_all = "snake_case")]
pub enum RequestError {
    /// Used when we know we don't have an active network connection.
    Offline,
    NoRoute,
    ConnectionRefused,
    Timeout,
    #[fp(rename_all = "snake_case")]
    ServerError {
        /// HTTP status code.
        status_code: u16,
        /// Response body.
        response: Body,
    },
    /// Misc.
    #[fp(rename = "other/misc")]
    Other {
        reason: String,
    },
}

/// Tagged dynamic value.
#[derive(Serializable)]
pub enum Value {
    Integer(i64),
    Float(f64),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

#[derive(Serializable)]
pub struct ExplicitedlyImportedType {
    pub you_will_see_this: bool,
}

mod foobar {
    use fp_bindgen::prelude::*;
    pub mod baz {
        use fp_bindgen::prelude::*;
        #[derive(Serializable)]
        pub struct GroupImportedType1 {
            pub you_will_see_this: bool,
        }
    }
    #[derive(Serializable)]
    pub struct GroupImportedType2 {
        pub you_will_see_this: bool,
    }
}

fp_import! {
    use ExplicitedlyImportedType;
    use foobar::{baz::GroupImportedType1, GroupImportedType2};

    // Aliases need to be explicitly mentioned in either `fp_import!` or `fp_export!`:
    type Body = ByteBuf;
    type ComplexAlias = ComplexGuestToHost;
    type FloatingPoint = Point<f64>;

    /// Logs a message to the (development) console.
    fn log(message: String);

    /// This is a very simple function that only uses primitives. Our bindgen should have little
    /// trouble with this.
    fn my_plain_imported_function(a: u32, b: u32) -> u32;

    /// This one passes complex data types. Things are getting interesting.
    fn my_complex_imported_function(a: ComplexAlias) -> ComplexHostToGuest;

    fn count_words(string: String) -> Result<u16, String>;

    async fn my_async_imported_function() -> ComplexHostToGuest;

    async fn make_request(opts: RequestOptions) -> Result<Response, RequestError>;
}

fp_export! {
    use ExplicitedlyImportedType;
    use HttpRequestOptions;

    fn my_plain_exported_function(a: u32, b: u32) -> u32;

    /// Example documentation
    fn my_complex_exported_function(a: ComplexHostToGuest) -> ComplexAlias;

    async fn my_async_exported_function() -> ComplexGuestToHost;

    async fn fetch_data(url: String) -> String;
}

const VERSION: &str = "0.0.1";
const AUTHORS: &str = r#"["Joep Meindertsma <joep@ontola.io>"]"#;
const NAME: &str = "atomic-bindings";

/// Generates the bindings in the repo `./bindings` folder
fn main() {
    for bindings_type in [
        BindingsType::RustPlugin(RustPluginConfig {
            name: NAME,
            authors: AUTHORS,
            version: VERSION,
            dependencies: BTreeMap::from([(
                "fp-bindgen-support",
                CargoDependency {
                    path: None,
                    features: BTreeSet::from(["async", "guest"]),
                    ..CargoDependency::default()
                },
            )]),
        }),
        BindingsType::RustWasmerRuntime,
        BindingsType::TsRuntime(TsRuntimeConfig {
            generate_raw_export_wrappers: true,
        }),
    ] {
        let output_path = format!("bindings/{}", bindings_type);

        fp_bindgen!(BindingConfig {
            bindings_type,
            path: &output_path,
        });
        println!("Generated bindings written to `{}/`.", output_path);
    }
}
