# atomic-lib

[![crates.io](https://meritbadge.herokuapp.com/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)
[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepipo/atomic)

_Status: Beta. [Changelog](https://github.com/joepio/atomic/blob/master/CHANGELOG.md)_

Rust library for using [Atomic Data](https://docs.atomicdata.dev).

[Docs](https://docs.rs/atomic_lib/latest/atomic_lib/)

The [`atomic` CLI](../cli/readme.md) and [`atomic-server`](../server/readme.md) applications both use this `atomic-lib` library.

- [x] In-memory store for getting / setting data (`Store`)
- [x] On disk ACID compliant store / database (`Db`, uses Sled)
- [x] [Path](https://docs.atomicdata.dev/core/paths.html) traversal
- [x] Parse and serialize [AD3](https://docs.atomicdata.dev/core/serialization.html)
- [x] JSON + JSON-LD Serialization
- [x] Convert to Rust native types
- [x] Resolve / parse mappings (bookmarks)
- [x] Validate Atomic Graphs
- [x] Mutations (linked-delta's)
- [x] RDF (turtle / N-Triples) Serialization
- [ ] Strategy for extending datatypes (Currently uses an `enum`)
- [x] TPF queries
- [ ] Performant TPF queries from Db (create index)
- [ ] Async resource fetching (faster)
- [ ] Store - server write interaction (update resource, send deltas to server)

## Usage

```sh
# Add it to your project
cargo add atomic_lib
```

```rs
use atomic_lib;

fn main() {
  // Let's parse this AD3 string
  let string = String::from(r#"["_:test","https://atomicdata.dev/properties/shortname","Test"]"#);
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

## Optional features

Some features of this library are optional, to minimize bundle size and compile times.

**db**

The db features adds persistence, which means that you can store stuff on an HDD / SSD.
It uses [Sled], a performant, embedded key-value store.

**rdf**

If you need RDF serialization options (Turtle / N-Triples), use this feature.

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
