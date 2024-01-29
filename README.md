![AtomicServer](./logo.svg)

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/atomicdata-dev/atomic-server?style=social)](https://github.com/atomicdata-dev/atomic-server)

**Create, share, fetch and model [Atomic Data](https://docs.atomicdata.dev)!
AtomicServer is a lightweight, yet powerful CMS / Graph Database.
Demo on [atomicdata.dev](https://atomicdata.dev).
Docs on [docs.atomicdata.dev](http://docs.atomicdata.dev/atomicserver/intro.html)**

This repo also includes:

- [Atomic Data Browser](/browser/data-browser/README.md), the React front-end for Atomic-Server.
- [`@tomic/lib`](/browser/lib/README.md) JS NPM library.
- [`@tomic/react`](/browser/react/README.md) React NPM library.
- [`@tomic/svelte`](/browser/svelte/README.md) Svelte NPM library.
- [`atomic_lib`](lib/README.md) Rust library.
- [`atomic-cli`](cli/README.md) terminal client.
- [`docs`](docs/README.md) documentation / specification for Atomic Data ([docs.atomicdata.dev](https://docs.atomicdata.dev)).

_Status: alpha. [Breaking changes](CHANGELOG.md) are expected until 1.0._

<!-- We re-use this table in various places, such as README.md and in the docs repo. Consider this the source. -->
- 🚀  **Fast** (less than 1ms median response time on my laptop), powered by [actix-web](https://github.com/actix/actix-web) and [sled](https://github.com/spacejam/sled)
- 🪶  **Lightweight** (8MB download, no runtime dependencies)
- 💻  **Runs everywhere** (linux, windows, mac, arm)
- 🔧  **Custom data models**: create your own classes and forms. All verified and sharable using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html)
- 📄  **Documents**, collaborative, rich text, similar to Google Docs / Notion.
- ⚙️ **Restful API**, with [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html) responses.
- 🗄️  **Tables**, with strict schema validation, keyboard support, copy / paste support. Similar to Airtable.
- 💬  **Group chat**,
- 💾  **Event-sourced versioning** / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- 🔄  **Synchronization using websockets**: communicates state changes with a client.
- 🌐  **Embedded server** with support for HTTP / HTTPS / HTTP2.0 and Built-in LetsEncrypt handshake.
- 🧰  **Many serialization options**: to JSON, [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- 🔎  **Full-text search** with fuzzy search and various operators, often <3ms responses. Powered by [tantivy](https://github.com/quickwit-inc/tantivy).
- 📖  **Pagination, sorting and filtering** queries using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html).
- 🔐  **Authorization** (read / write permissions) and Hierarchical structures powered by [Atomic Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- 📲  **Invite and sharing system** with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)
- 📂  **File management**: Upload, download and preview attachments.
- 🖥️  **Desktop app**: Easy desktop installation, with status bar icon, powered by [tauri](https://github.com/tauri-apps/tauri/).
- 📚  **Libraries**: [Javascript / Typescript](https://www.npmjs.com/package/@tomic/lib), [React](https://www.npmjs.com/package/@tomic/react), [Svelte](https://www.npmjs.com/package/@tomic/svelte)

Powered by Rust, [atomic-lib](https://crates.io/crates/atomic-lib) and [more](Cargo.toml).

https://user-images.githubusercontent.com/2183313/139728539-d69b899f-6f9b-44cb-a1b7-bbab68beac0c.mp4

## Documentation

Check out the [documentation] for installation instructions, API docs, and more.

## Contribute

Issues and PRs are welcome!
And join our [Discord][discord-url]!
[Read more in the Contributors guide.](CONTRIBUTE.md)

[documentation]:https://docs.atomicdata.dev/atomicserver/installation

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
