/*!
`atomic_lib` helps you to get, store, serialize, parse and validate Atomic Data.

See the [Atomic Data Docs](https://docs.atomicdata.dev) for more information.

## Features

- Two stores for Atomic Data:
  - **In-memory** [Store] for getting / setting data. Useful for client applications.
  - **On disk** [Db], powered by Sled. Useful for applications that persist Atomic Data, such as [`atomic-server`](https://crates.io/crates/atomic-server).
- [serialize] and [parse] tools for [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html), plain JSON, RDF, Turtle, N-Triples and JSON-LD.
- [Resource] with getters, setters and a `.save` function that creates Commits.
- [Value] converts Atomic Data to Rust native types
- Validate [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html)
- [Commit]s (transactions / delta's / changes / updates / versioning / history).
- [plugins] system (although not very mature)
- [collections] (pagination, sorting, filtering)
- Querying (using triple pattern fragments) (see [storelike::Query])
- [plugins::invite] for sharing
- [hierarchy] for authorization
- [crate::endpoints::Endpoint] for custom API endpoints
- [config::Config] files.

## Getting started

```
// Import the `Storelike` trait to get access to most functions
use atomic_lib::Storelike;
// Start with initializing the in-memory store
let store = atomic_lib::Store::init().unwrap();
// Pre-load the default Atomic Data Atoms (from atomicdata.dev),
// this is not necessary, but will probably make your project a bit faster
store.populate().unwrap();
// We can create a new Resource, linked to the store.
// Note that since this store only exists in memory, it's data cannot be accessed from the internet.
// Let's make a new Property instance! Let's create "age".
let mut new_property = atomic_lib::Resource::new_instance("https://atomicdata.dev/classes/Property", &store).unwrap();
// And add a description for that Property
new_property.set_propval_shortname("description", "the age of a person", &store).unwrap();
// A subject URL for the new resource has been created automatically.
let subject = new_property.get_subject().clone();
// Now we need to make sure these changes are also applied to the store.
// In order to change things in the store, we should use Commits,
// which are signed pieces of data that contain state changes.
// Because these are signed, we need an Agent, which has a private key to sign Commits.
let agent = store.create_agent(Some("my_agent")).unwrap();
store.set_default_agent(agent);
let _fails   = new_property.save_locally(&store);
// But.. when we commit, we get an error!
// Because we haven't set all the properties required for the Property class.
// We still need to set `shortname` and `datatype`.
new_property.set_propval_shortname("shortname", "age", &store).unwrap();
new_property.set_propval_shortname("datatype", atomic_lib::urls::INTEGER, &store).unwrap();
new_property.save_locally(&store).unwrap();
// Now the changes to the resource applied to the store, and we can fetch the newly created resource!
let fetched_new_resource = store.get_resource(&subject).unwrap();
assert!(fetched_new_resource.get_shortname("description", &store).unwrap().to_string() == "the age of a person");
```
*/

pub mod agents;
pub mod atoms;
pub mod authentication;
pub mod client;
pub mod collections;
pub mod commit;
#[cfg(feature = "config")]
pub mod config;
pub mod datatype;
#[cfg(feature = "db")]
pub mod db;
#[cfg(feature = "db")]
pub mod endpoints;
pub mod errors;
pub mod hierarchy;
pub mod mapping;
pub mod parse;
#[cfg(feature = "db")]
pub mod plugins;
pub mod populate;
pub mod resources;
pub mod schema;
pub mod serialize;
pub mod store;
pub mod storelike;
#[cfg(test)]
mod test_utils;
pub mod urls;
pub mod utils;
pub mod validate;
pub mod values;

pub use atoms::Atom;
pub use commit::Commit;
#[cfg(feature = "db")]
pub use db::Db;
pub use errors::AtomicError;
pub use errors::AtomicErrorType;
pub use resources::Resource;
pub use store::Store;
pub use storelike::Storelike;
pub use values::Value;
