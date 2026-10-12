{{#title All-in-One Workspace: documents, tables, chat and apps in one place}}
# All-in-One Workspace

The web app on [atomic.place](https://atomic.place), the desktop and mobile apps and a self-hosted AtomicServer all serve the same workspace.
It replaces a stack of separate tools with one place where everything is linked, searchable and shared with the same permissions.

## What is in it

| Area | What you can do |
| --- | --- |
| **Documents** | Collaborative rich text with live cursors and full history. |
| **Tables** | A strict-schema table editor with keyboard navigation and copy / paste, plus Kanban, calendar, dashboard and timer views on any table. See [Tables](atomicserver/gui/tables.md). |
| **Templates** | Start from a ready-made setup such as an issue tracker, a CRM, project tasks, a time tracker, team handbook or lecture notes. |
| **Chat and meetings** | Group chat with attachments, search and replies, and video meetings with shared notes and presence. |
| **Canvas** | An infinite drawing surface, shared live. |
| **Files** | Upload, download and preview attachments, stored by content hash. See [Files](files.md). |
| **Websites** | Design pages in the browser, publish, and roll back to any earlier version. |
| **Forms** | Build forms on your own data models. |
| **Custom data models** | Your own Classes and Properties in the Ontology Editor, shared as [Atomic Schema](schema/intro.md). |
| **AI** | An assistant that can use [MCP](https://modelcontextprotocol.io/) servers as tools and works with any model through OpenRouter or a local Ollama. See [AI and Atomic Assistant](atomicserver/gui/ai-and-atomic-assistant.md). |
| **Apps and plugins** | Custom screens in plain JavaScript, and WebAssembly [plugins](plugins.md) that extend the server. |
| **Virtual drive** | Mount a Drive as a folder in Finder or Explorer (desktop app). |
| **Search** | Full-text search with typeahead and fuzzy matching, running on both server and client. |

## What makes it one workspace

- **One permission model.** The same read / write rights, [hierarchies](hierarchy.md) and [invite links](invitations.md) apply to a document, a table row, a chat channel and a website.
- **One data model.** A row in a table, a chat message and a page are all Resources, linked by URL. You can link and embed across areas without integration glue.
- **Real-time collaboration.** Live cursors, typing indicators, avatars and following a teammate work over the same [sync](sync.md) connection as the data itself.
- **Offline everywhere.** The whole workspace works without a connection, because the data is local.
- **Extensible.** Define your own Classes, add views, write apps, install plugins. Nothing in the workspace is special-cased: it is built on the same Classes, Properties and APIs you can use.

## Where to run it

- **Hosted:** open [atomic.place](https://atomic.place) in a browser, or install the desktop or mobile app.
- **Self-hosted:** one binary that holds the server, the web app, the database and search. See [installation](atomicserver/installation.md).
- **Both:** apps pair with a server of your choice and fall back to local-only. Moving between them does not change your identity or your data.

New to the interface? Read [Using the GUI](atomicserver/gui.md).

## Status

Atomic is alpha software and breaking changes are expected until 1.0. See the [roadmap](roadmap.md).
