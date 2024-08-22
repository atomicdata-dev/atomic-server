/*!
# Plugins

Add custom functionality to Atomic-Server.
Plugins can have functions that are called at specific moments by Atomic-Server.

For example:

- Before returning a Resource. These are either [Endpoint]s or Class Extenders.
- Before applying a Commit.

In the long term, these plugins will probably be powered by WASM and can be extended at runtime.
They are created at compile time, the same as all other code in Atomic-Server.
However, they are designed in such a way that they have a limited scope and a clearly defined API.

## Extending resources

There are two ways of extending / modifying a Resource.
[Endpoint]s are great for APIs that have a fixed route, and Class Extenders are great for APIs that don't have a fixed route.
Endpoints are easier to generate from Rust, and will be available the second a server is Running.

### [Endpoint]s

Resources that typically parse query parameters and return a dynamic resource.
When adding an endpoint, add it to the list of [default_endpoints] in this file.
Endpoints are all instances of the [crate] class.
They are presented in the UI as a form.

### Class Extenders

Similar to Endpoints, Class Extenders can modify their contents before creating a response.
Contrary to Endpoints, these can be any type of Class.
They are used for performing custom queries, or calculating dynamic attributes.
Add these by registering the handler at [crate::db::Db::get_resource_extended].
*/

use crate::endpoints::Endpoint;

// Class Extenders
pub mod chatroom;
pub mod importer;
pub mod invite;

// Endpoints
pub mod add_pubkey;
#[cfg(feature = "html")]
pub mod bookmark;
pub mod export;
pub mod files;
pub mod path;
pub mod prunetests;
pub mod query;
pub mod register;
pub mod search;
pub mod versioning;

// Utilities / helpers
mod utils;

pub fn default_endpoints() -> Vec<Endpoint> {
    vec![
        versioning::version_endpoint(),
        versioning::all_versions_endpoint(),
        path::path_endpoint(),
        search::search_endpoint(),
        files::upload_endpoint(),
        register::register_endpoint(),
        register::confirm_email_endpoint(),
        add_pubkey::request_email_add_pubkey(),
        add_pubkey::confirm_add_pubkey(),
        #[cfg(feature = "html")]
        bookmark::bookmark_endpoint(),
    ]
}
