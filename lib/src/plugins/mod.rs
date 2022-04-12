/*!
# Plugins

Add custom functionality to Atomic-Server.
Plugins can have functions that are called at specific moments by Atomic-Server.

For example:

- Before returning a Resource. These are either Endpoints or Class Extenders.
- Before applying a Commit.

In the long term, these plugins will probably be powered by WASM and can be extended at runtime.
They are created at compile time, the same as all other code in Atomic-Server.
However, they are designed in such a way that they have a limited scope and a clearly defined API.

## Extending resources

There are two ways of extending / modifying a Resource.
Endpoints are great for APIs that have a fixed route, and Class Extenders are great for APIs that don't have a fixed route.
Endpoints are easier to generate from Rust, and will be available when the second a server is Running.

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

// Class Extenders
pub mod chatroom;
pub mod invite;

// Endpoints
pub mod files;
pub mod path;
pub mod search;
pub mod versioning;
