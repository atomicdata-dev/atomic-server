{{#title Atomic Data}}
![# Atomic Data Docs - Overview](assets/atomic_data_logo_stroke.svg)

Atomic is a [personal data store, an all-in-one workspace and a local-first sync engine](why-atomic.md), built on an open specification.

**Atomic Data is a modular specification for sharing, modifying and modeling graph data. It combines the ease of use of JSON, the connectivity of RDF (linked data) and the reliability of type-safety.**

![Venn diagram showing Atomic Data is the combination of JSON, RDF and Type-Safety](assets/venn.svg)

Atomic Data uses links to connect pieces of data, and therefore makes it easier to connect datasets to each other - even when these datasets exist on separate machines.

It is also [local-first](local-first.md): your identity is a key you hold, your data lives on your own devices, every edit is signed by you, and devices [sync](sync.md) with each other whenever they can. A server is optional, useful as an always-on replica rather than as the place your data has to live.

## AtomicServer

[AtomicServer](atomic-server.md) is an open source, powerful graph database + headless CMS.
It's the reference implementation for the Atomic Data specification, written in Rust.
The same library, `atomic_lib`, runs in the browser (as WASM), in [Flutter apps](flutter.md) and in the CLI, so every client keeps a full local copy of its data and does its own signing and syncing.

## Atomic Data Core

Atomic Data has been designed with [the following goals in mind](motivation.md):

- Give people more control over their data
- Make linked data easier to use
- Make it easier for developers to build highly interoperable apps
- Make standardization easier and cheaper

Atomic Data is [Linked Data](https://ontola.io/blog/what-is-linked-data/), as it is a [strict subset of RDF](interoperability/rdf.md).
It is type-safe (you know if something is a `string`, `number`, `date`, `URL`, etc.) and extensible through [Atomic Schema](schema/intro.md), which means that you can re-use or define your own Classes, Properties and Datatypes.

The default serialization format for Atomic Data is [JSON-AD](core/json-ad.md), which is simply JSON where each key is a URL of an Atomic Property.
These Properties are responsible for setting the `datatype` (to ensure type-safety) and setting `shortnames` (which help to keep names short, for example in JSON serialization) and `descriptions` (which provide semantic explanations of what a property should be used for).

Every Resource, Property and Class is named by a URL. Which URL shapes exist, from `https://` vocabularies to location-independent `atomic:` identifiers, is explained in [URLs and identifiers](urls.md); read that first if you are new here.

[Read more about Atomic Data Core](core/concepts.md)

## Atomic Data Extended

Atomic Data Extended is a set of extra modules (on top of Atomic Data Core) that deal with identity, data that changes over time, authentication, authorization and synchronization between devices.

{{#include extended-table.md}}

## Tools & libraries

- [atomic.place](https://atomic.place) is the place to start: the hosted web app, plus the app downloads
- The **web app**: documents, tables, chat, files and an ontology editor, working offline in the browser
- The **desktop and mobile apps**, built with Tauri: the same app with a full node inside, so it can be paired with directly and act as an always-on device. Download them from [atomic.place](https://atomic.place) or the [GitHub releases](https://github.com/ontola/atomic-server/releases)
- Build a web app with [@tomic/lib](js.md), [@tomic/react](usecases/react.md) or [@tomic/svelte](svelte.md), or a native app with [Flutter / Dart](flutter.md), on top of the same Rust core
- Prefer to run your own always-on device? [Self-host atomic-server](atomicserver/installation.md), a single binary
- The command line tool [atomic-cli](rust-cli.md) and the Rust library [atomic_lib](rust-lib.md)

## Get involved

Make sure to [join our Discord](https://discord.gg/a72Rv2P) if you'd like to discuss Atomic Data with others.

## Status

Keep in mind that none of the Atomic Data projects has reached a v1, which means that breaking changes can happen.

## Reading these docs

This is written mostly as a book, so reading it in the order of the Table of Contents will probably give you the best experience.
That being said, feel free to jump around - links are often used to refer to earlier discussed concepts.
If you encounter any issues while reading, please leave an [issue on Github](https://github.com/ontola/atomic-data/issues).
Use the arrows on the side / bottom to go to the next page.

{{#include SUMMARY.md}}
