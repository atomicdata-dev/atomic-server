## Atomic-Server and its features

[`Atomic-Server`](https://github.com/atomicdata-dev/atomic-server/blob/master/server/README.md) is the _reference implementation_ of the Atomic Data Core + Extended specification.
It was developed parallel to this specification, and it served as a testing ground for various ideas (some of which didn't work, and some of which ended up in the spec).

Atomic-Server is a graph database server for storing and sharing typed linked data.
It's free, open source (MIT license), and has a ton of features:

- ⚛️  **Dynamic schema validation** / type checking using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html). Combines safety of structured data with the
- 🚀  **Fast** (1ms responses on my laptop)
- 🪶  **Lightweight** (15MB binary, no runtime dependencies)
- 💻  **Runs everywhere** (linux, windows, mac, arm)
- 🌐  **Embedded server** with support for HTTP / HTTPS / HTTP2.0 and Built-in LetsEncrypt handshake.
- 🎛️  **Browser GUI included**: Features dynamic forms, tables, authentication, theming and more.
- 💾  **Event-sourced versioning** / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- 🔄  **Synchronization using websockets**: communicates state changes with a client. Send a `wss` request to `/ws` to open a webscocket.
- 🧰  **Many serialization options**: to JSON, [JSON-AD](https://docs.atomicdata.dev/core/json-ad.html), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- 🔎  **Full-text search** with fuzzy search and various operators, often <3ms responses.
- 📖  **Pagination, sorting and filtering** using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html)
- 🔐  **Authorization** (read / write permissions) and Hierarchical structures powered by [Atomic Hierarchy](https://docs.atomicdata.dev/hierarchy.html)
- 📲  **Invite and sharing system** with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)
- 📂  **File management**: Upload, download and preview attachments.
- 🖥️  **Desktop app**: Easy desktop installation, with status bar icon, powered by [tauri](https://github.com/tauri-apps/tauri/).

## When should you use this

- You want a powerful, lightweight, fast and easy to use **CMS or database** with live updates, editors, modelling capabilities and an intuitive API
- You want to build a webapplication, and like working with using [React](https://github.com/atomicdata-dev/atomic-data-browser) or [Svelte](https://github.com/atomicdata-dev/atomic-svelte).
- You want to make (high-value) **datasets as easily accessible as possible**
- You want to specify and share a **common vocabulary** / ontology / schema for some specific domain or dataset. Example classes [here](https://atomicdata.dev/classes).
- You want to use and **share linked data**, but don't want to deal with most of [the complexities of RDF](https://docs.atomicdata.dev/interoperability/rdf.html), SPARQL, Triple Stores, Named Graphs and Blank Nodes.
- You are interested in **re-decentralizing the web** or want want to work with tech that improves data ownership and interoperability.

## When _not_ to use this

- High-throughput **numerical data / numerical analysis**. AtomicServer does not have aggregate queries.
- If you need **high stability**, look further (for now). This is beta sofware and can change.
- You're dealing with **very sensitive / private data**. The built-in authorization mechanisms are relatively new and not rigorously tested. The database itself is not encrypted.
- **Complex query requirements**. We have queries with filters and features for path traversal, but it may fall short. Check out NEO4j, Apache Jena or maybe TerminusDB.
