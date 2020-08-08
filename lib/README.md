# atomic-lib

_Status: buggy, pre-alpha_

Rust library for using [Atomic Data](https://docs.atomicdata.dev).
The [`atomic` CLI](../cli/readme.md) and [`atomic-server`](../server/readme.md) applications both use this `atomic-lib` library.

- [x] Store for getting / setting data(using HashMap)
- [x] Path traversal
- [x] [AD3](https://docs.atomicdata.dev/core/serialization.html) Serialization
- [x] JSON Serialization
- [ ] RDF (turtle / N-Triples) Serialization
- [x] Convert to Rust native types
- [x] Parse AD3
- [x] Resolve / parse mappings (bookmarks)
- [ ] Validate Atomic Graphs
