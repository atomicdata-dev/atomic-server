# atomic_lib

[![crates.io](https://img.shields.io/crates/v/atomic_lib)](https://crates.io/crates/atomic_lib)
[![API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)

`atomic_lib` is an embeddable local-first data engine: resource storage, Loro
CRDT documents, signed commits, agent identities, inherited permissions,
indexed queries, full-text search, and synchronization. It powers AtomicServer
and native and browser applications. A local store does not require an HTTP
server.

The product and component boundary is **atomic_lib**, the Rust crate.
`AtomicNode` is a convenience facade inside the crate, rather than a separate
component or a mandatory layer for every library operation.

## Application API

| Area | Entry points |
| --- | --- |
| Resources and values | `Resource`, `Subject`, `Value`, `datatype`, `urls` |
| Identity and permissions | `agents::{Agent, ForAgent}`, `authentication`, `hierarchy` |
| Signed writes and history | `Commit`, `commit`, `envelopes`, `history` |
| In-memory resource access | `Store`, `Storelike` |
| Indexed queries | `storelike::{Query, QueryResult}`, `AtomicNode::query` |
| Local full-text search | `client::search::SearchOpts`, `search::SearchHit`, `AtomicNode::search` |
| Synchronization | `sync` sessions, transports, protocol, outbox, and admission policy |
| Convenience runtime | `runtime::{AtomicNode, IngestPolicy}` (requires `db`) |
| Errors | `errors::{AtomicResult, AtomicError, AtomicErrorType}` |

Resources include agents, properties, classes, and drives. Their Atomic Data
representation and validation still participate in ordinary writes, even when
implementation helpers for schemas and serialization are internal.

`AtomicNode` groups selected operations, including local saves with outbox
bookkeeping and commit ingestion policies. Use `save_locally` on the node when
an edit should enter its outbox automatically. Internal library operations can
use the storage implementation directly; they do not have to pass through the
facade to remain inside the `atomic_lib` component.

## Internal API boundary

The following extensions and implementation details remain in the crate for
first-party consumers and compatibility. Their documentation is labeled
**Internal**; they are outside the application API described above.

| Internal area | Types and modules |
| --- | --- |
| Database implementation | `db`, `db::Db` (also reachable as `atomic_lib::Db`), `AtomicNode::from_db`, `AtomicNode::db` |
| Schema implementation | `schema`, `class_constraints`, `class_extender`, `property_identity`, `validate` |
| Parsing and interchange helpers | `parse`, `serialize` |
| Higher-level data tools | `aggregate`, `collections`, `expression`, `lens`, `mapping` |
| Application functionality | `chat_log`, `conversation`, `document_markdown`, `endpoints`, `plugins`, `trash`, `website` |
| Operational helpers | `config`, `import_identity`, `metrics`, `populate`, `test_utils`, `utils`, `vault` |

These are documentation labels, not Rust privacy changes. Existing `pub`
paths, features, dependencies, and behavior remain unchanged. A public Rust
path alone does not make a labeled internal API part of the product contract.
Existing first-party consumers still need to be checked when internals change.

The application-facing node API is still being completed: `AtomicNode` currently
opens through `from_db`, and some operations require its `db()` accessor.
Both helpers expose the internal `Db` type. A public construction API that
avoids `Db` is not implemented yet; this documentation does not claim otherwise.
Existing adapters use these compatibility paths in the meantime.

## Cargo features

| Feature | Purpose |
| --- | --- |
| `db` / `db-redb` | Indexed redb storage and node runtime; native file, in-memory, and browser OPFS backends |
| `db-sled` | Legacy Sled storage compatibility and migrations; unavailable in WASM |
| `wasm` | Browser randomness, time, and OPFS support |
| `ws` | WebSocket client support; enables `db` |
| `iroh` | Native Iroh peer transport |
| `discovery` | Peer discovery through pkarr |
| `rdf` | Internal RDF interchange support |
| `config` | Internal filesystem configuration support |
| `telemetry` | OpenTelemetry integration |

Full-text search is currently included with `db`. Internal API labels do not
introduce new feature gates or remove functionality.

## Documentation and compatibility

Rustdoc generates the API reference from Rust code comments. For a local
reference including the database, runtime, and native transports, run:

```sh
cargo doc --locked -p atomic_lib --no-deps --features db,iroh,ws,discovery
```

The hosted [docs.rs reference](https://docs.rs/atomic_lib/latest/atomic_lib/)
describes the published crate version, which may differ from this checkout.
Feature-gated APIs require those features to be enabled when generating docs.

`atomic_lib` is beta; breaking changes are expected before 1.0. Application API
changes should be documented in releases. Internal APIs have no separate
application-facing stability guarantee. This boundary does not establish a
new release cadence, wire-protocol version, storage format, or trust model.
