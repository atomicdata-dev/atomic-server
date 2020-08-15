//! `atomic_lib` helps you to get, store, serialize, parse and validate [Atomic Data](https://docs.atomicdata.dev).
//!
//! The [Store](struct.Store) contains most of the logic that you need.
//!
//! # Getting started
//!
//! ```
//! // Let's parse this AD3 string
//! let string = String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"Test\"]");
//! // Start with initializing our store
//! let mut store = atomic_lib::Store::init();
//! // Run parse...
//! store.parse_ad3(&string).unwrap();
//! // Get our resource...
//! let my_resource = store.get(&"_:test".into()).unwrap();
//! // Get our value by filtering on our property...
//! let my_value = my_resource.get("https://atomicdata.dev/properties/shortname").unwrap();
//! println!("My value: {}", my_value);
//! assert!(my_value == "Test")
//! ```

pub mod atoms;
pub mod errors;
pub mod mapping;
pub mod mutations;
pub mod serialize;
pub mod store;
pub mod urls;

pub use store::Store;
pub use atoms::Atom;
