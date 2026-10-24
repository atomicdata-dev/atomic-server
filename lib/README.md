# atomic-lib

[![crates.io](https://img.shields.io/crates/v/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/atomicdata-dev/atomic-server?style=social)](https://github.com/joepipo/atomic)

_Status: Beta. [Breaking changes](../CHANGELOG.md) are expected until 1.0._

**Rust library for using [Atomic Data](https://docs.atomicdata.dev).
Powers [`atomic-cli`](../cli/README.md) and [`atomic-server`](../server/README.md).**

[Check out the docs on docs.rs](https://docs.rs/atomic_lib/latest/atomic_lib/).
For code examples, see [`examples/basic.rs`](examples/basic.rs) and the many tests in the code.

## Features

- Two stores for Atomic Data:
  - In-memory store for getting / setting data (`Store`). Useful for clients.
  - Indexed database (`Db`) using redb with native file, in-memory, and browser OPFS backends. Sled is retained for legacy-store compatibility and migration.
- [JSON-AD Parser & Serializer](https://docs.atomicdata.dev/core/json-ad.html)
- Serialization of atomic data to JSON-AD, plain JSON, RDF, Turtle, N-Triples and JSON-LD.
- [Path](https://docs.atomicdata.dev/core/paths.html) traversal
- Convert Atomic Data to Rust native types
- Resolve / parse mappings (bookmarks)
- Validate [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html)
- [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html) (transactions / delta's / changes / updates / versioning / history)
- Plugin system (although not very mature)
- [Collections](https://docs.atomicdata.dev/schema/collections.html) (pagination, sorting, filtering)
- Querying (using triple pattern fragments)
- [Invites](https://docs.atomicdata.dev/invitations.html)
- [Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- Saving Atomic Config files.

## Optional features

Some features of this library are optional, to minimize bundle size and compile times.

**db**

The `db` feature enables the redb database and its indexes. Native applications
can use a file-backed or in-memory store; the WASM bindings can persist in OPFS.
`db-redb` is a compatibility alias for `db`. The separate `db-sled` feature adds
Sled compatibility and migrations and is unavailable in WASM.

**rdf**

If you need RDF serialization options (Turtle / N-Triples), use this feature.

**config**

Filesystem management of Atomic Config files.
Used in `atomic-cli` and `atomic-server`.
