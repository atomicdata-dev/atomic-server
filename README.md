![atomic data rust logo](./logo.svg)

[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/joepio/atomic?style=social)](https://github.com/joepio/atomic)

**Create, share, fetch and model [Atomic Data](https://docs.atomicdata.dev)!
This repo consists of three components: A library, a server and a CLI.**

## [`atomic-server`](server/README.md)

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)

_Status: Beta. [Breaking changes](changelog.md) are expected until 1.0._

The easiest way to share [Atomic Data](https://docs.atomicdata.dev/) on the web.
`atomic-server` is a graph database server for storing and sharing typed linked data.
Demo on [atomicdata.dev](https://atomicdata.dev)

- ⚛️  **Dynamic schema validation** / type checking using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html). Combines safety of structured data with the
- 🚀  **Fast** (1ms responses on my laptop)
- 🪶  **Lightweight** (15MB binary, no runtime dependencies)
- 💻  **Runs everywhere** (linux, windows, mac, arm)
- 🌐  **Embedded server** with support for HTTP / HTTPS / HTTP2.0 and Built-in LetsEncrypt handshake.
- 🎛️  **Browser GUI included** powered by [atomic-data-browser](https://github.com/joepio/atomic-data-browser). Features dynamic forms, tables, authentication, theming and more.
- ↩️  **Event-sourced versioning** / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- 🧰  **Many serialization options**: to JSON, [JSON-AD](https://docs.atomicdata.dev/core/serialization.html#json-ad), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- 🔎  **Full-text search** with fuzzy search and various operators, often <3ms responses.
- 📖  **Pagination, sorting and filtering** using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html)
- 🔐  **Authorization** (read / write permissions) and Hierarchical structures powered by [Atomic Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- 📲  **Invite and sharing system** with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)
- 📂  **File management**: Upload, download and preview attachments.
- 🖥️  **Desktop app**: Easy desktop installation, with status bar icon, powered by [tauri](https://github.com/tauri-apps/tauri/).

Powered by Rust, [atomic-lib](https://crates.io/crates/atomic-lib), [actix-web](https://github.com/actix/actix-web), [sled](https://github.com/spacejam/sled), [tantivy](https://github.com/quickwit-inc/tantivy) and [more](Cargo.toml).

[→ Read more](server/README.md)

https://user-images.githubusercontent.com/2183313/139728539-d69b899f-6f9b-44cb-a1b7-bbab68beac0c.mp4

## [`atomic-cli`](cli/README.md)

[![crates.io](https://img.shields.io/crates/v/atomic-cli)](https://crates.io/crates/atomic-cli)

A simple Command Line Interface tool to fetch, create and query Atomic Data.
Especially useful for interacting with an `atomic-server`.

[→ Read more](cli/README.md)

## [`atomic-lib`](lib/README)

[![crates.io](https://img.shields.io/crates/v/atomic_lib)](https://crates.io/crates/atomic_lib)
[![Released API docs](https://docs.rs/atomic_lib/badge.svg)](https://docs.rs/atomic_lib)

A Rust library to serialize, parse, store, convert, validate, edit, fetch and store Atomic Data.
Powers both `atomic-cli` and `atomic-server`.

[→ Read more](lib/README.md)

## Also check out

- [Atomic-Data-Browser](https://github.com/joepio/atomic-data-browser), an in-browser app for viewing and editing atomic data. Also contains a typescript / react front-end library. Will replace most of the html templating in this project.
- [Atomic-Data-Docs](https://github.com/ontola/atomic-data-docs), a book containing detailed documentation of Atomic Data.
- [RayCast extension](https://www.raycast.com/joepio/atomic) for searching stuff
- [Click here to sign up to the Atomic Data Newsletter](http://eepurl.com/hHcRA1)
- [The Atomic Data Docs](https://docs.atomicdata.dev/)

## Contribute

Issues and PR's are welcome!
And join our [Discord][discord-url]!
[Read more.](CONTRIBUTE.md)

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
