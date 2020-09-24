/*!
`atomic_lib` helps you to get, store, serialize, parse and validate [Atomic Data](https://docs.atomicdata.dev).

The [Store](struct.Store) contains most of the logic that you need.

# Getting started

```
// Import the `Storelike` trait to get access to most functions
use atomic_lib::Storelike;
// Start with initializing our store
let store = atomic_lib::Store::init();
// Load the default Atomic Data Atoms
store.populate().unwrap();
// Let's parse this AD3 string. It looks awkward because of the escaped quotes.
let string = r#"["_:test","https://atomicdata.dev/properties/description","Test"]"#;
// The parser returns a Vector of Atoms
let atoms = atomic_lib::parse::parse_ad3(&string).unwrap();
// Add the Atoms to the Store
store.add_atoms(atoms).unwrap();
// Get our resource...
let my_resource = store.get_resource("_:test").unwrap();
// Get our value by filtering on our property...
let my_value = my_resource
    .get("https://atomicdata.dev/properties/description")
    .unwrap();
assert!(my_value.to_string() == "Test");
// We can also use the shortname of description
let my_value_from_shortname = my_resource.get_shortname("description").unwrap();
assert!(my_value_from_shortname.to_string() == "Test");
// We can find any Atoms matching some value using Triple Pattern Fragments:
let found_atoms = store.tpf(None, None, Some("Test")).unwrap();
assert!(found_atoms.len() == 1);
```
*/

pub mod atoms;
pub mod client;
pub mod collections;
#[cfg(feature = "db")]
pub mod db;
pub mod delta;
pub mod datatype;
pub mod errors;
pub mod mapping;
pub mod mutations;
pub mod parse;
pub mod resources;
pub mod serialize;
pub mod store;
pub mod store_native;
pub mod storelike;
pub mod urls;
pub mod validate;
pub mod values;

pub use atoms::Atom;
pub use atoms::RichAtom;
#[cfg(feature = "db")]
pub use db::Db;
pub use delta::DeltaLine;
pub use resources::Resource;
pub use resources::ResourceString;
pub use store::Store;
pub use storelike::Storelike;
pub use values::Value;
