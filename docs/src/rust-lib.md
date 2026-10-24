{{#title atomic_lib: local-first data engine}}
# atomic_lib: local-first data engine

`atomic_lib` is the library and product boundary for local-first resource
storage, identity, permissions, queries, search, and synchronization. It powers
`atomic-server`, `atomic-cli`, the WASM build inside the web app and the
[Flutter SDK](flutter.md). Its application API provides:

- A persistent local store (redb on native, OPFS in the browser through WASM) and an in-memory store
- Agents, `atomic:` identifiers and signing
- Loro CRDT documents per Resource, with history
- Commit validation and processing
- The transport-agnostic [sync engine](sync.md), with WebSocket and Iroh peer transports behind feature flags
- Full-text search index

`AtomicNode`, inside `atomic_lib::runtime`, is a convenience facade for selected
operations, including local saves with outbox delivery, query/search, and commit
ingestion policies. It is not a separate component boundary.

`Db` remains reachable as `atomic_lib::Db` for compatibility, but is documented
as internal, along with `AtomicNode::from_db` and `AtomicNode::db`. A public node
constructor that avoids `Db` is not implemented yet. Existing first-party
adapters still use these paths; the labels do not change Rust visibility.

Additional schema, interchange, collection, application, and operational helpers
also remain in the crate as internal extensions. The crate README lists the
application entry points, internal modules, and existing Cargo features.

The API reference is generated from Rust code comments with Rustdoc. Generate
it with the database and transport features enabled to include those APIs:

```sh
cargo doc --locked -p atomic_lib --no-deps --features db,iroh,ws,discovery
```

`atomic_lib` is beta; application-facing breaking changes are expected before
1.0. Internal extensions have no separate application API stability guarantee.

[docs.rs](https://docs.rs/atomic_lib/latest/atomic_lib/)

[repository + issue tracker](https://github.com/ontola/atomic-server).
