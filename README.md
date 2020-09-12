# Atomic

[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Create, share, fetch and model linked [Atomic Data](https://docs.atomicdata.dev)!
This repo consists of three components: A library, a server and a CLI.

## `atomic-server`

[![crates.io](https://meritbadge.herokuapp.com/atomic-server)](https://crates.io/crates/atomic-server)

The easiest way to share Atomic Data on the web. Demo on [atomicdata.dev](https://atomicdata.dev)

- Host Atomic data over HTTP or HTTPS (built-in!)
- No runtime dependencies, crazy fast, runs on all platforms (including on your Raspberry Pi)
- Serialization to HTML, JSON, RDF (N-Triples / Turtle / JSON-LD) and AD3

[→ Read more](server/README.md)

## `atomic-cli`

[![crates.io](https://meritbadge.herokuapp.com/atomic-cli)](https://crates.io/crates/atomic-cli)

A simple Command Line Interface tool to fetch, create and query Atomic Data.

[→ Read more](cli/README.md)

## `atomic-lib`

[![crates.io](https://meritbadge.herokuapp.com/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)

A Rust library to serialize, parse, store, convert, validate and store Atomic Data.
Powers `atomic-cli` and `atomic-server`.

[→ Read more](lib/README.md)

## Motivation

I've been working with Linked Data for a couple of years, and I believe it has some incredible merits.
URLs are great identifiers, and using them for keys makes sense as well.
However, using the RDF data model has [some characteristics](https://docs.atomicdata.dev/interoperability/rdf.html) that make it difficult for many developers, and that limits adoption.
That's why I've been working on a new way to think about linked data: [Atomic Data](https://docs.atomicdata.dev/).
Atomic Data is heavily inspired by RDF (and converts nicely into RDF, as it is a strict subset), but introduces some new concepts that aim to make it easier to use for developers.

This repository serves the following purposes:

- Test some of the core ideas of Atomic Data ([Atomic Schema](https://docs.atomicdata.dev/schema/intro.html), [Paths](https://docs.atomicdata.dev/core/paths.html), [AD3 Serialization](https://docs.atomicdata.dev/core/serialization.html))
- Learn how Rust works (it's a cool language, and this is my first Rust project - keep that in mind while traversing the code!)
- Serve the first Atomic Data (now available on [atomicdata.dev](https://atomicdata.dev)), which is referred to by the constantly evolving [Atomic Data Docs](https://docs.atomicdata.dev/)
- Provide developers with tools and inspiration to use Atomic Data in their own projects.

## Contribute

Issues and PR's are welcome!
And join our [Discord][discord-url]!
[Read more.](CONTRIBUTE.md)

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
