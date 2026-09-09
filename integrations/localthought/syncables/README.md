# syncables-rs

A Rust port of [localthought/syncables](https://github.com/localthought/syncables).

Reads an OpenAPI document and gives you:

- a **mock API server** that implements it, backed by a real (in-memory)
  CRUD store per resource, seeded with fake data generated from the
  document's schemas;
- an **API client** that talks to any server implementing that OpenAPI
  document and keeps a local copy of each resource collection in sync.

Alongside that port, the crate also carries a second, unrelated surface:
a **sync engine** (`SyncClient`) that reads a document's
[CRUD Causality Extension](https://github.com/pondersource/openapi-extensions/tree/main/spec/crud-causality)
(`components.crudResources`) and syncs records — including nested
collections, walked once per parent record — into a host-provided
`Storage` implementation, deriving a neutral, Atomic-Data-shaped ontology
along the way without the crate itself depending on `atomic_lib`. This is
new scope, not part of the original TypeScript port; see
[Sync engine](#sync-engine) below.

## Port status

This section covers the original TypeScript port only — see
[Sync engine](#sync-engine) below for that surface's status.

This crate is **scaffolding**. The module tree mirrors the TypeScript
original's `src/` one-to-one, and the following are ported and tested:

| Area | Module | Status |
| --- | --- | --- |
| Document loading | `openapi::load`, `openapi::resolve_refs` | ported |
| Overlays | `openapi::overlay` | ported |
| OpenAPI type surface | `openapi::types` | ported |
| Resource discovery | `resources::discover` | ported |
| Path routing | `routing::router` | ported |
| Fake data | `fake_data::generate` | ported |
| Pagination | `pagination::{types, validate, autodetect, items, request_builder, response_parser}` | ported |
| Mock server store | `mock_server::store` | ported |
| Client storage | `client::storage` | ported |
| Mock server handler | `mock_server::server` | **scaffolded** — public surface only |
| Client sync/writes | `client::client` | **scaffolded** — public surface only |

The two scaffolded modules carry their full ported public API, doc
comments and constants; their function bodies are `todo!()`, each naming
the TypeScript source file and function it is to be ported from. Nothing
in this crate silently returns a wrong answer — the parts that exist are
covered by tests, including acceptance tests against unmodified real-world
documents.

## Usage

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Once the client and mock server are ported, the shape will be:

```rust,ignore
use syncables::{create_api_client, create_mock_server, load_open_api_document, ApiClientOptions};

let document = load_open_api_document("./petstore.yaml").await?;

let server = create_mock_server(document.clone());
let address = server.listen(None).await?;

let client = create_api_client(document, ApiClientOptions::new(address.url));
client.sync().await?; // pulls every discovered resource collection into local storage

let pets = client.list("/pets").await?;
```

A "resource" is any pair of an OpenAPI collection path and its matching
item path, e.g. `/pets` and `/pets/{petId}`. Paths without that pairing
(health checks, one-off actions, etc.) are served from their documented
examples/schemas but aren't treated as syncable resources.

## Sync engine

New scope, not part of the original TypeScript port; tracked by
[issues #1–#9](https://github.com/localthought/syncables-rs/issues/1).
Where the port above discovers resources from plain collection/item path
pairing, the sync engine derives a richer resource model from a
document's [CRUD Causality Extension](https://github.com/pondersource/openapi-extensions/tree/main/spec/crud-causality)
(`components.crudResources`) — including nested collections, like a
repository's issues and each issue's comments — and drives a full,
paginated read of every collection into a host-provided `Storage`,
deriving a neutral ontology (Classes and Properties, Atomic-Data-shaped
but not Atomic-Data-typed) along the way.

| Area | Module | Status |
| --- | --- | --- |
| Resource model (`crudResources`, `x-crud`) | `sync::resource_model` | ported and tested |
| Binding configured constants into path templates | `sync::constants` | ported and tested |
| Credentials, API base URL | `sync::credentials` | ported and tested |
| Ontology derivation | `sync::ontology` | ported and tested |
| `Storage` trait, `InMemoryStorage` | `sync::storage` | ported and tested |
| `SyncClient::sync()` — full read | `sync::client` | ported and tested |
| `SyncClient` — local-first write-back | `sync::client` | **not implemented** — [#9](https://github.com/localthought/syncables-rs/issues/9) |

```rust,ignore
use std::sync::Arc;
use syncables::{ClientConfig, Credentials, InMemoryStorage, SyncClient};

let config = ClientConfig {
    document: "./github-issues.openapi.yaml".into(),
    overlays: vec!["./auth-overlay.yaml".into(), "./crud-causality-overlay.yaml".into()],
    credentials: Credentials::Bearer(std::env::var("GITHUB_TOKEN")?),
    constants: [("owner".to_string(), "localthought".to_string()),
                ("repo".to_string(), "test-repo-1".to_string())].into(),
    ontology_base_url: "https://my-ontologies.com".to_string(),
};

let client = SyncClient::new(config, Arc::new(my_fetch_impl))?;
let storage = InMemoryStorage::new();
let report = client.sync(&storage).await?; // walks issues, then each issue's comments
```

`SyncClient::new` takes an `Arc<dyn Fetch>` (the same injectable-transport
trait `ApiClient` above uses) alongside `ClientConfig` — the crate has no
HTTP client dependency of its own, so a host supplies one. This is the one
deliberate divergence from the `ClientConfig`/`SyncClient` contract
[`localthought/reflector-rs`](https://github.com/localthought/reflector-rs)
is already written against in its `src/syncables.rs`, which otherwise this
module matches field-for-field; that module is meant to be deleted once
reflector-rs points its `use`s here instead.

## Differences from the TypeScript original

The port keeps the original's names, comments and behaviour wherever it
can. Where Rust forced a decision, it went like this:

- **`Record<string, unknown>` → `serde_json::Map<String, Value>`**, and
  `unknown` → `serde_json::Value`. Maps that need document order
  (schema properties, paths, collections) use `IndexMap`, and
  `serde_json` is built with `preserve_order`: `locate_items_field` picks
  the *first* array-typed property, so order is load-bearing.
- **The injectable `fetch` becomes a `Fetch` trait**
  (`client::client::Fetch`). As in the original, it is the only extension
  point — there is no built-in notion of auth, so authenticating means
  supplying an implementation that adds the right header to every request.
- **`StorageAdapter` is an `async_trait`**, with `InMemoryStorageAdapter`
  as the default, matching the original's pluggable adapter.
- **Pagination roles stay strings** rather than becoming closed enums: the
  spec allows `x-` extension roles, and `validate` is what decides
  validity, so an unknown role has to survive parsing to be reported.
  `PaginationSchemeObject::type` likewise deserializes leniently, so one
  malformed scheme (e.g. Giphy's former `type: offset`) does not fail the
  whole document.
- **Errors are a `thiserror` enum** (`syncables::Error`) instead of thrown
  strings; every fallible function returns `syncables::Result`.
- **Numbers are `f64`** in `PaginationResponseState`, mirroring JavaScript
  number semantics for values read out of arbitrary JSON bodies.

## Tests

`tests/unit/` mirrors the original's `__tests__/unit/` layout module for
module. Cargo builds it as one test binary (`tests/unit/main.rs`), so the
module tree is declared there rather than discovered per file.

`tests/fixtures/real-world/` holds real OpenAPI documents and pagination
overlays vendored unmodified from apis.guru and localthought/overlays (see
the header comment in each file for provenance). The acceptance tests run
the ported pipeline against these and deliberately document real quirks
rather than working around them. When extending them, keep that spirit:
assert what actually happens against the unmodified real document, not an
idealized result.

## NLnet milestone 1

The TypeScript original is the reference implementation for
[milestone 1](https://github.com/tubsproject/syncables/blob/main/nlnet-milestones.md#1-syncables)
of the project's NLnet grant. This port tracks it.

## Generative AI use

syncables-rs is developed collaboratively with **Claude Code**
(Anthropic), an agentic coding assistant: a human directs the design and
reviews, edits, and tests the changes it proposes before they're
committed.

As an NLnet-funded project, this follows
[NLnet's Generative AI policy](https://nlnet.nl/foundation/policies/generativeAI/):

- Commits produced with AI assistance carry a `Claude-Session: <url>`
  trailer identifying the session that produced them.
- [`docs/ai-logs/`](docs/ai-logs) holds prompt/output disclosure logs,
  redacted for secrets and personal information.
- AI-drafted content is reviewed and edited by a human before being
  committed; it is not represented as unassisted human work.

## License

Apache-2.0, matching the original.

## Browser / WASM

`cargo check --target wasm32-unknown-unknown --lib` builds the engine without
Tokio filesystem or native runtime dependencies. Load catalog text with
`openapi::load::parse_yaml`, pass the resulting value to
`load_open_api_document`, then call `SyncClient::sync_document(&doc, &storage)`.
This path never opens `ClientConfig.document` or `overlays`; apply overlays in
memory before calling it. File sources return an explicit unsupported error
in WASM. Implement browser `Fetch` with `#[async_trait(?Send)]`; it may hold
a JS callback. Native `Fetch` keeps its Send + Sync contract.
