# atomic-lib

[![crates.io](https://meritbadge.herokuapp.com/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)
[![Discord chat][https://img.shields.io/discord/723588174747533393.svg?logo=discord]][https://discord.gg/a72Rv2P]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepipo/atomic)

_Status: Alpha. Prone to breaking changes. [Changelog](https://github.com/joepio/atomic/blob/master/CHANGELOG.md)_

Rust library for using [Atomic Data](https://docs.atomicdata.dev).

[Docs](https://docs.rs/atomic_lib/latest/atomic_lib/).

For code examples, see [`examples/basic.rs`](examples/basic.rs) and the many tests in the code.
Also, the [`atomic-cli`](../cli/readme.md) and [`atomic-server`](../server/readme.md) applications both use this `atomic-lib` library.

## Features

- In-memory store for getting / setting data (`Store`). Useful for clients.
- On disk database (`Db`, uses Sled), which powers `atomic-server`.
- Parsing (JSON-AD) and serialization (RDF, Turtle, N-Triples, JSON, JSON-LD) of atomic data.
- [Path](https://docs.atomicdata.dev/core/paths.html) traversal
- Convert Atomic Data to Rust native types
- Resolve / parse mappings (bookmarks)
- Validate Atomic Schema
- Atomic Commits (transactions / delta's / changes / updates / versioning / history)
- Plugins (currently only Endpoints which enable dynamic resources)
- Collections (pagination, sorting, filtering)
- Querying (using triple pattern fragments)


## Optional features

Some features of this library are optional, to minimize bundle size and compile times.

**db**

The db features adds persistence, which means that you can store stuff on an HDD / SSD.
It uses [Sled], a performant, embedded key-value store.

**rdf**

If you need RDF serialization options (Turtle / N-Triples), use this feature.

**config**

Filesystem management of Atomic Config files.
Used in `atomic-cli` and `atomic-server`.
