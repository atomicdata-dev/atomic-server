# Strategy, history and roadmap for Atomic Data

We have the ambition to make the internet more interoperable.
We want Atomic Data to be a commonly used specification, enabling a vast amount of applications to work together and share information.
This means we need a lot of people to understand and contribute to Atomic Data.
In this document, discuss the strategic principles we use, the steps we took, and the path forward.
This should help you understand how and where you may be able to contribute.

## Strategy for adoption

- **Work on both specification and implementations (both client and server side) simultaneously** to make sure all ideas are both easily explainable and properly implementable. Don't design a spec with a large committee over many months, only to learn that it has implementation issues later on.
- **Create libraries whenever possible.** Enable other developers to re-use the technology in their own stacks. Keep the code as modular as possible.
- **Document everything**. Not just your APIs - also your ideas, considerations and decisions.
- **Do everything public**. All code is open source, all issues are publicly visible. Allow outsiders to learn everything and start contributing.
- **Make an all-in-one workspace app that stand on its own**. Atomic Data may be an abstract, technical story, but we still need end-user friendly applications that solve actual problems if we want to get as much adoption as possible.
- **Let realistic use cases guide API design**. Don't fall victim to spending too much time for extremely rare edge-cases, while ignoring more common issues and wishes.
- **Familiarity first**. Make tools and specs that feel familiar, build libraries for popular frameworks, and stick to conventions whenever possible.

## History

- **First draft of specification** (2020-06). Atomic Data started as an unnamed bundle of ideas and best practices to improve how we work with linked data, but quickly turned into a single (draft) specification. The idea was to start with a cohesive and easy to understand documentation, and use that as a stepping stone for writing the first code. After this, the code and specification should both be worked on simultaneously to make sure ideas are both easily explainable and properly implementable. Many of the earliest ideas were changed to make implementation easier.
- **[atomic-cli](https://crates.io/crates/atomic-cli) + [atomic-lib](https://docs.rs/atomic_lib/0.32.1/atomic_lib/)** (2020-07). The CLI functioned as the first platform to explore some of the most core ideas of Atomic Data, such as Properties and fetching. `atomic_lib` is the place where most logic resides. Written in Rust.
- **[AtomicServer](https://github.com/atomicdata-dev/atomic-server/)** (2020-08). The server (using the same `atomic_lib` as the CLI) should be a fast, lightweight server that must be easy to set-up. Functions as a graph database with no dependencies.
- **[Collections](schema/collections.md)** (2020-10). Allows users to perform basic queries, filtering, sorting and pagination.
- **[Commits](commits/intro.md)** (2020-11). Signed write envelopes that authorize a Loro CRDT update. Originally conceived as an event-sourced log; current state and versioning now live in the resource's Loro document.
- **[JSON-AD](core/json-ad.md)** (2021-02). Instead of the earlier proposed serialization format `.ad3`, we moved to the more familiar `json-ad`.
- **[Atomic-Data-Browser](https://github.com/atomicdata-dev/atomic-data-browser)** (2021-02). We wanted typescript and react libraries, as well as a nice interactive GUI that works in the browser. It should implement all relevant parts of the specification.
- **[Endpoints](endpoints.md)** (2021-03). Machine readable API endpoints (think Swagger / OpenAPI spec) for things like versioning, path traversal and more.
- **Classes and Properties editable from the browser** (2021-04). The data-browser is now powerful enough to use for managing the core ontological data of the project.
- **[Hierarchies](hierarchy.md) & [Invitations](invitations.md)** (2021-06). Users can set rights, structure Resources and invite new people to collaborate.
- **[Websockets](websockets.md)** (2021-08). Live synchronization between client and server.
- **Use case: Document Editor** (2021-09). Notion-like editor with real-time synchronization.
- **Full-text search** (2021-11). Powered by Tantivy.
- **Authentication for read access** (2021-11). Allows for private data.
- **Desktop support** (2021-12). Run Atomic-Server on the desktop, powered by Tauri. Easier install UX, system tray icon.
- **File management** (2021-12). Upload, download and view Files.
- **Indexed queries** (2022-01). Huge performance increase for queries. Allows for far bigger datasets.
- **Use case: ChatRoom** (2022-04). Group chat application. To make this possible, we had to extend the Commit model with a `push` action, and allow Plugins to create new Commits.
- **[JSON-AD Publishing and Importing](create-json-ad.md)** (2022-08). Creating and consuming Atomic Data becomes a whole lot easier.
- **[@tomic/svelte](https://github.com/atomicdata-dev/atomic-svelte)** (2022-12). Library for integrating Atomic Data with Svelte(Kit).
- **[Atomic Tables](https://github.com/atomicdata-dev/atomic-data-browser/issues/25)** (2023-09). A powerful table editor with keyboard / copy / paste / sort support that makes it easier to model and edit data.
- **Ontology Editor** (2023-10). Easily create & edit Classes, Properties and Ontologies.
- **Local-First & did:ad Schema** (2026-06). Transitioned to a Local-First architecture using the `did:ad` schema. Instead of relying on a hosted HTTP origin, resources resolve over Mainline DHT. Agents are decentralized, relying solely on an Ed25519 private key.
- **Collaborative Sync with Loro CRDT** (2026-06). Integrated Loro CRDTs for collaborative real-time sync across devices, making documents conflict-free.
- **Drafts and Suggestions** (2026-07). Added CMS publishing, drafts, and user suggestions as a clean, fork-based squash-merge mechanism.
- **Meetings & Follow-Me Tours** (2026-07). Shipped purpose-built meeting workspaces, collaborative live meeting notes, and follower follow-along live tours.
- **P2P pairing & Zero-scan auto-sync** (2026-07). Built routing-only deep-link QR pairing and SaaS-assisted zero-scan device synchronization.

## Where we're at

Most of the specification has matured and is stable.
Atomic Server is now a production-ready decentralized graph database with real-time sync, local-first persistence (WASM + OPFS / redb), and peer-to-peer transport (Iroh).
We are working on polishing the developer experience (SDKs/APIs), expanding offline-first integrations, and hardening the security boundaries.

## Roadmap

- **SaaS-assisted device directory & backup** (2026). Seamless multi-device sync and non-custodial cloud backup.
- **Passkey + PRF integration** (2026). Derive the encryption key directly from WebAuthn, making "sign in with passkey" a true one-step account restore.
- **Cross-Agent Suggestions / Distributor Mode** (2026). Enabling users to suggest edits to other agents' drives via direct mesh channels.
- **Multi-user P2P Presence** (2026). Ephemeral cursors and awareness syncing device-to-device directly over Iroh without a central hub.
- **1.0 release** (tbd). Mark the specification, the server, and the browser as *stable*.
