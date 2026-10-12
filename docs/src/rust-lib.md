{{#title atomic-lib: Rust library for Atomic Data}}
# atomic-lib: Rust library for Atomic Data

Library that powers `atomic-server`, `atomic-cli`, the WASM build inside the web app and the [Flutter SDK](flutter.md). Features:

- A persistent local store (redb on native, OPFS in the browser through WASM) and an in-memory store
- Parsing (JSON-AD) / Serialization (JSON-AD, JSON-LD, TTL, N-Triples)
- Agents, `atomic:` identifiers and signing
- Loro CRDT documents per Resource, with history
- Commit validation and processing
- The transport-agnostic [sync engine](sync.md), with WebSocket and Iroh peer transports behind feature flags
- Full-text search index
- Constructing Collections
- Path traversal
- Schema validation

[docs.rs](https://docs.rs/atomic_lib/latest/atomic_lib/)

[repository + issue tracker](https://github.com/ontola/atomic-server).
