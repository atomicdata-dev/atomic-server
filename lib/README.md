# atomic-lib

_Status: pre-alpha_

Rust library for using [Atomic Data](https://docs.atomicdata.dev).

[Docs](https://docs.rs/atomic_lib/latest/atomic_lib/)

The [`atomic` CLI](../cli/readme.md) and [`atomic-server`](../server/readme.md) applications both use this `atomic-lib` library.

- [x] In-memory store for getting / setting data
- [x] [Path](https://docs.atomicdata.dev/core/paths.html) traversal
- [x] Parse and serialize [AD3](https://docs.atomicdata.dev/core/serialization.html)
- [x] JSON + JSON-LD Serialization
- [ ] RDF (turtle / N-Triples) Serialization
- [ ] Mutations (linked-delta's)
- [x] Convert to Rust native types
- [x] Resolve / parse mappings (bookmarks)
- [x] Validate Atomic Graphs

## Usage

```sh
# Add it to your project
cargo add atomic_lib
```

```rs
use atomic_lib;

fn main() {
  // Let's parse this AD3 string
  let string = String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"Test\"]");
  // Start with initializing our store
  let mut store = atomic_lib::store::Store::init();
  // Run parse...
  store.parse_ad3(&string).unwrap();
  // Get our resource...
  let my_resource = store.get(&"_:test".into()).unwrap();
  // Get our value by filtering on our property...
  let my_value = my_resource.get("https://atomicdata.dev/properties/shortname").unwrap();
  println!("My value: {}", my_value);
  assert!(my_value == "Test")
}
```
