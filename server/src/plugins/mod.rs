/*!
# Plugins

Add custom functionality to Atomic-Server.
Plugins can have functions that are called at specific moments by Atomic-Server.

For example:

- Before returning a Resource. These are either Endpoints or Class Extenders.
- Before applying a Commit.

Atomic-Server supports class-extender plugins that are compiled to WASM Components.
These are loaded on startup.
Most plugins defined here are build-in.

## Extending resources

There are two ways of extending / modifying a Resource.
Endpoints are great for APIs that have a fixed route, and Class Extenders are great for APIs that don't have a fixed route.
Endpoints are easier to generate from Rust, and will be available the second a server is Running.

### Endpoints

Resources that typically parse query parameters and return a dynamic resource.
When adding an endpoint, add it to the list of endpoints in [lib/src/endpoints.rs]
Endpoints are all instances of the [crate] class.
They are presented in the UI as a form.

### Class Extenders

Similar to Endpoints, Class Extenders can modify their contents before creating a response.
Contrary to Endpoints, these can be any type of Class.
They are used for performing custom queries, or calculating dynamic attributes.
*/

#[cfg(feature = "wasm-plugins")]
pub mod apply;
pub mod bind_drive;
pub mod bookmark;
pub mod chatroom;
pub mod did;
pub mod egress;
pub mod export;
pub mod files;
pub mod importer;
pub mod invite;
#[cfg(feature = "wasm-plugins")]
pub mod js_runtime;
pub mod path;
#[cfg(feature = "wasm-plugins")]
pub mod plan;
pub mod plugin;
pub mod prunetests;
pub mod query;
pub mod replicate;
#[cfg(feature = "wasm-plugins")]
pub mod run_log;
#[cfg(feature = "wasm-plugins")]
pub mod scheduler;
pub mod search;
pub mod server_info;
#[cfg(feature = "wasm-plugins")]
pub mod store_host;
#[cfg(feature = "vector-search")]
pub mod vector_search;
pub mod versioning;
#[cfg(feature = "wasm-plugins")]
pub mod wasm;
