{{#title AtomicServer: An open-source, realtime, headless CMS}}
# AtomicServer and its features

[`AtomicServer`](https://github.com/atomicdata-dev/atomic-server/blob/master/server/README.md) is the _reference implementation_ of the Atomic Data Core + Extended specification.
It was developed parallel to this specification, and it served as a testing ground for various ideas (some of which didn't work, and some of which ended up in the spec).

AtomicServer is a real-time headless CMS, graph database server for storing and sharing typed linked data.
It's free, open source (MIT license), and has a ton of features:

<!-- Copied from root README -->
- 🚀  **Fast** (less than 1ms median response time on my laptop), powered by [actix-web](https://github.com/actix/actix-web) and [sled](https://github.com/spacejam/sled)
- 🪶  **Lightweight** (8MB download, no runtime dependencies)
- 💻  **Runs everywhere** (linux, windows, mac, arm)
- 🔧  **Custom data models**: create your own classes and forms. All verified and sharable using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html)
- 📄  **Documents**, collaborative, rich text, similar to Google Docs / Notion.
- ⚙️ **Restful API**, with [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html) responses.
- 🗄️  **Tables**, with strict schema validation, keyboard support, copy / paste support. Similar to Airtable.
- 💬  **Group chat**, live updates, markdown support, replies
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
