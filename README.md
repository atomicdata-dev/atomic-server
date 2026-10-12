<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./logo-dark.svg">
  <img alt="atomic.place" src="./logo.svg">
</picture>

[![crates.io](https://img.shields.io/crates/v/atomic-server)](https://crates.io/crates/atomic-server)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/github/license/atomicdata-dev/atomic-server.svg?color=blue&logo=github&logoColor=blue)](./LICENSE)
[![github](https://img.shields.io/github/stars/atomicdata-dev/atomic-server?style=social)](https://github.com/atomicdata-dev/atomic-server)

**atomic.place is a local-first workspace for documents, tables, files, chat and apps.**
It works on your device and can sync through a self-hosted AtomicServer or the hosted service at
[atomic.place](https://atomic.place). The underlying [Atomic Data](https://docs.atomicdata.dev/atomic-data-overview)
specification is open. It comes in three propositions:

- **[Personal Data Store](https://docs.atomicdata.dev/personal-data-store)**: your identity is a key, your data is encrypted on your own devices, and every edit is signed by you.
- **[All-in-One Workspace](https://docs.atomicdata.dev/all-in-one-workspace)**: documents, tables, chat, meetings, canvas, websites, AI and apps, with one permission model.
- **[Local-first Sync Engine](https://docs.atomicdata.dev/sync-engine)**: build apps on the same Loro CRDT store and sync protocol, with no backend of your own.

This repo includes:

- **atomic.place**, the workspace in the [browser](/browser/data-browser), on [desktop](/desktop)
  and on mobile.
- **AtomicServer**, the [self-hostable server](/server) for storage, search, sharing and sync.
- [`docs`](docs/README.md) documentation / specification for Atomic Data ([docs.atomicdata.dev](https://docs.atomicdata.dev)).
- [Atomic Data Browser](/browser/data-browser/README.md), the React front-end for atomic.place.
- [`@tomic/lib`](/browser/lib/README.md) JS NPM library.
- [`@tomic/react`](/browser/react/README.md) React NPM library.
- [`@tomic/svelte`](/browser/svelte/README.md) Svelte NPM library.
- [`atomic_lib`](lib/README.md) Rust library.
- [`atomic-cli`](cli/README.md) terminal client.
- [`flutter`](/flutter) a Dart / Flutter client (with demo app AtomicCanvas)

_Status: alpha. [Breaking changes](CHANGELOG.md) are expected until 1.0._

## Features

<!-- We re-use this table in various places, such as README.md and in the docs repo. Consider this the source. -->
- 🏠  **Local-first**: works offline in the browser, syncs when you reconnect with [Atomic Sync](https://docs.atomicdata.dev/sync).
- 🔄  **Real-time collaboration**: live cursors, typing indicators, and following what a teammate is doing.
- 📄  **Documents**: collaborative rich text, like Google Docs or Notion.
- 🗄️  **Tables**: strict schema, keyboard navigation, copy / paste. Like Airtable.
- 📋  **Kanban, calendar, dashboard and timer views** on any table.
- 🧰  **Templates**: issue tracker, CRM, project tasks, time tracker and more.
- 🌐  **Websites**: design pages in the browser, publish in one click, roll back any version.
- 🗂️  **Virtual drive**: mount your drive as a folder in Finder or Explorer (desktop app).
- ✨  **AI** with [MCP](https://modelcontextprotocol.io/) support, any model via OpenRouter or local Ollama.
- 🧩  **Apps**: custom screens in plain JavaScript, backed by your own data.
- 🔌  **Plugins and integrations**: Wasm plugins, and syncing from GitHub and more.
- 💬  **Group chat**: channels with attachments, search and replies.
- 🎥  **Meetings**: video calls with shared notes and presence.
- 🎨  **Canvas**: an infinite drawing surface, shared live.
- 📂  **Files**: upload, download and preview attachments.
- 🔧  **Custom data models**: your own classes and properties in the Ontology Editor, shared as [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html).
- 🔒  **Encrypted at rest**: each agent's local database is encrypted under their own key.
- 💾  **Versioning**: full history, every write a signed [Atomic Commit](https://docs.atomicdata.dev/commits/intro.html).
- 🔎  **Full-text search**: typeahead and fuzzy, often under 3ms, same index on server and client.
- 🔐  **Authorization**: read / write rights, [hierarchies](https://docs.atomicdata.dev/hierarchy.html) and [invite links](https://docs.atomicdata.dev/invitations.html).
- ⚙️  **RESTful API** with [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html), plus RDF, Turtle, N-Triples and JSON-LD.
- 📖  **Pagination, sorting and filtering** with [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html).
- 🚀  **Fast**: under 1ms median response time, powered by actix-web and redb.
- 🪶  **One binary** (~70MB): server, web app, search, database and automatic HTTPS.
- 💻  **Runs everywhere**: linux, windows, mac, arm, plus desktop and mobile apps.
- 📚  **Libraries** for JavaScript, React, Svelte, Rust and Dart / Flutter.

https://github.com/user-attachments/assets/32e82de5-11ca-4c2e-8c25-b293d79f6023

## Documentation

Check out the [documentation] for installation instructions, API docs, and more.

## Contribute

Issues and PRs are welcome!
And join our [Discord][discord-url]!
[Read more in the Contributors guide.](CONTRIBUTING.md)

## Funding

Atomic Data and AtomicServer have been supported by [NLnet](https://nlnet.nl) through the NGI
Assure, NGI0 Entrust and NGI0 Commons funds, with financial support from the European Commission's
[Next Generation Internet](https://ngi.eu) programme, and through Eurostars. This is a large part
of why the project is MIT licensed and has no proprietary core.
[Details and grant agreement numbers](https://docs.atomicdata.dev/acknowledgements.html).

## Licence and trademarks

The code is [MIT licensed](./LICENSE) — fork it, modify it, sell it.

The Atomic **names and logos** are not covered by that grant; they are
reserved. Trademark is what lets the code stay permissively licensed, so a
fork can do anything except present itself as the official Atomic Server. See
[TRADEMARKS.md](./TRADEMARKS.md) for the policy and [brand/](./brand/) for the
artwork, which is the single source of truth for every icon across all the
Atomic apps.

[documentation]:https://docs.atomicdata.dev/atomicserver/installation

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
