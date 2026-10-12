{{#title AtomicServer: the always-on device for your Atomic Data}}
# AtomicServer

[`AtomicServer`](https://github.com/ontola/atomic-server) is the _reference implementation_ of the Atomic Data Core + Extended specification: a single binary that is a graph database, a real-time headless CMS and a web app.
It was developed parallel to this specification, and it served as a testing ground for various ideas (some of which didn't work, and some of which ended up in the spec).

AtomicServer is how you self-host the three things described in [Why Atomic](why-atomic.md): a [Personal Data Store](personal-data-store.md) that is always reachable, the [All-in-One Workspace](all-in-one-workspace.md) served as a web app, and the always-on peer of the [Local-first Sync Engine](sync-engine.md).

## The always-on device

In a [local-first](local-first.md) system every device holds its own copy of the data and does its own signing.
What a phone or a browser tab cannot do is stay reachable.
That is AtomicServer's job: it is the device that never sleeps.

- A **browser tab** cannot accept connections, so it needs a server to reach any other device. AtomicServer is what the web app talks to.
- **Collaborators** fetch a Drive from it while your own devices are off.
- It holds a **backup** that survives a lost phone, without holding your key: every commit it stores is signed by the Agent that made it, so the server can replicate but never author.
- It serves the same data over **HTTP**, for `curl`, static site generators and search engines, next to the sync connection the apps use.

You can run one on a laptop, a Raspberry Pi, a VPS or a home NAS. [atomic.place](https://atomic.place) can run one for you.
The same `atomic_lib` also runs inside the browser and in [Flutter apps](flutter.md), which is why a phone can act as an always-on device for another phone, but a server is the shape most people want for the role.

If you are here to build an app, the [local-first guide](local-first-guide/1-index.md) starts without a server and adds one in step 4; the rest of this chapter is about running and using the server itself.

## Features

It's free, open source (MIT license), and has a ton of features:

<!-- Copied from root README -->
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

## Document undo and redo

While editing a document, use **Cmd-Z** on macOS or **Ctrl-Z** on Windows/Linux
to undo your local edits. Use **Cmd-Shift-Z** or **Ctrl-Shift-Z** to redo.

Undo and redo history survives switching to Data View and returning to the
document within the same signed-in browser session. It is kept in memory;
reloading the page, signing out, or switching accounts starts a new undo history.
Collaborators' edits are not added to your local undo history.
