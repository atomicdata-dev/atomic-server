![atomic data rust logo](./logo.svg)

[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepio/atomic)

**Create, share, fetch and model [Atomic Data](https://docs.atomicdata.dev)!
This repo consists of three components: A library, a server and a CLI.**

## `atomic-server`

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)

The easiest way to share Atomic Data on the web. Demo on [atomicdata.dev](https://atomicdata.dev)

- A (personal) server for storing and sharing Atomic Data. Provides abstractions for querying, versioning, authorization, and more.
- Serialization to HTML, JSON, Linked Data (RDF/XML, N-Triples / Turtle / JSON-LD) and [JSON-AD](https://docs.atomicdata.dev/core/serialization.html#json-ad)
- Embedded HTTP / HTTPS / HTTP2.0 server
- Virtually no runtime dependencies, fast, runs on most platforms (including on your Raspberry Pi)

[→ Read more](server/README.md)

## `atomic-cli`

[![crates.io](https://img.shields.io/crates/v/atomic-cli)](https://crates.io/crates/atomic-cli)

A simple Command Line Interface tool to fetch, create and query Atomic Data.
Especially useful for interacting with an `atomic-server`.

[→ Read more](cli/README.md)

## `atomic-lib`

[![crates.io](https://img.shields.io/crates/v/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)

A Rust library to serialize, parse, store, convert, validate, edit, fetch and store Atomic Data.
Powers both `atomic-cli` and `atomic-server`.

[→ Read more](lib/README.md)

## Motivation

I've been working with Linked Data for a couple of years, and I believe it has some incredible merits.
URLs are great identifiers, and using them for keys makes sense as well.
Linked data has the potential to help a more interoperable and decentralized web, where people control their own data.
However, the RDF data model has [some characteristics](https://docs.atomicdata.dev/interoperability/rdf.html) that make it difficult for many developers, and I think that limits adoption.
That's why I've been working on a new way to think about linked data: [Atomic Data](https://docs.atomicdata.dev/).
Atomic Data is heavily inspired by RDF (and converts nicely into RDF, as it is a strict subset), but introduces some new concepts that aim to make it easier to use for developers.

This repository serves the following purposes:

- Test and experiment with some of the core ideas of Atomic Data, such as [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html) (share models and data types), [Paths](https://docs.atomicdata.dev/core/paths.html) (traversing data), [JSON-AD Serialization](https://docs.atomicdata.dev/core/json-ad.html) and [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html) (storing signed state changes).
- Serve the first Atomic Data, including the core schema (now available on [https://atomicdata.dev](https://atomicdata.dev)), which is referred to by the constantly evolving [docs](https://docs.atomicdata.dev/)
- Provide developers with tools and inspiration to use Atomic Data in their own projects.

## Also check out

- [Atomic-Data-Browser](https://github.com/joepio/atomic-data-browser), an in-browser app for viewing and editing atomic data. Also contains a typescript / react front-end library. Will replace most of the html templating in this project.

## Contribute

Issues and PR's are welcome!
And join our [Discord][discord-url]!
[Read more.](CONTRIBUTE.md)

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
