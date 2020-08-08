# atomic-lib

_Status: pre-alpha_

Rust library for using [Atomic Data](https://docs.atomicdata.dev).
The [`atomic` CLI](../cli/readme.md) and [`atomic-server`](../server/readme.md) applications both use this `atomic-lib` library.

- [x] In-memory store for getting / setting data
- [x] [Path](https://docs.atomicdata.dev/core/paths.html) traversal
- [x] Parse and serialize [AD3](https://docs.atomicdata.dev/core/serialization.html)
- [x] JSON Serialization
  - [ ] Actually good JSON Serialization (converts arrays, numbers to native formats, adheres to JSON-LD)
- [ ] RDF (turtle / N-Triples) Serialization
- [x] Convert to Rust native types
- [x] Resolve / parse mappings (bookmarks)
- [ ] Validate Atomic Graphs
