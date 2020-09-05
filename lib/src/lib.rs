/*!
`atomic_lib` helps you to get, store, serialize, parse and validate [Atomic Data](https://docs.atomicdata.dev).

The [Store](struct.Store) contains most of the logic that you need.

# Getting started

```
// Import the `Storelike` trait for access to most functions
use atomic_lib::Storelike;
// Let's parse this AD3 string
let string = String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"Test\"]");
// Start with initializing our store
let mut store = atomic_lib::Store::init();
// Parse the string
let atoms = atomic_lib::parse::parse_ad3(&string).unwrap();
// Add the atoms to the store
store.add_atoms(atoms).unwrap();
// Get our resource...
let my_resource = store.get_resource_string("_:test").unwrap();
// Get our value by filtering on our property...
let my_value = my_resource.get("https://atomicdata.dev/properties/shortname").unwrap();
println!("My value: {}", my_value);
assert!(my_value == "Test")
```
*/

pub mod atoms;
#[cfg(feature="db")]
pub mod db;
pub mod delta;
pub mod errors;
pub mod fetcher;
pub mod mapping;
pub mod mutations;
pub mod resources;
pub mod parse;
pub mod serialize;
pub mod store;
pub mod store_native;
pub mod storelike;
pub mod urls;
pub mod values;

#[cfg(feature="db")]
pub use db::Db;
pub use delta::DeltaLine;
pub use store::Store;
pub use storelike::Storelike;
pub use atoms::Atom;
pub use atoms::RichAtom;
pub use values::Value;
pub use resources::Resource;
pub use resources::ResourceString;
