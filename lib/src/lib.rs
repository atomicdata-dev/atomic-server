//! `atomic_lib` helps you to get, store, serialize, parse and validate [Atomic Data](https://docs.atomicdata.dev).
//!
//! The [Store](struct.Store) contains most of the logic that you need.
//!
//! # Getting started
//!
//! ```
//! // Import the `Storelike` trait for access to most functions
//! use atomic_lib::Storelike;
//! // Let's parse this AD3 string
//! let string = String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"Test\"]");
//! // Start with initializing our store
//! let mut store = atomic_lib::Store::init();
//! // Run parse...
//! store.parse_ad3(&string).unwrap();
//! // Get our resource...
//! let my_resource = store.get_string_resource(&"_:test".into()).unwrap();
//! // Get our value by filtering on our property...
//! let my_value = my_resource.get("https://atomicdata.dev/properties/shortname").unwrap();
//! println!("My value: {}", my_value);
//! assert!(my_value == "Test")
//! ```

pub mod atoms;
#[cfg(feature="db")]
pub mod db;
pub mod errors;
pub mod mapping;
pub mod mutations;
pub mod resources;
pub mod serialize;
pub mod store;
pub mod store_native;
pub mod storelike;
pub mod urls;
pub mod values;

pub use db::Db;
pub use store::Store;
pub use storelike::Storelike;
pub use atoms::Atom;
pub use atoms::RichAtom;
pub use values::Value;
pub use resources::Resource;
