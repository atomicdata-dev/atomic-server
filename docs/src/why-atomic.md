{{#title Why Atomic: a personal data store, a workspace and a sync engine}}
# Why Atomic

Atomic is one piece of software with three faces.
Which one you meet first depends on what you came for.

| If you want to… | You are looking at… | Start here |
| --- | --- | --- |
| Own your data, and keep it when an app or a company goes away | A **Personal Data Store** | [Personal Data Store](personal-data-store.md) |
| Write, plan, chat and build in one place, with your team | An **All-in-One Workspace** | [All-in-One Workspace](all-in-one-workspace.md) |
| Build an app whose data syncs between devices without writing a backend | A **Local-first Sync Engine** | [Local-first Sync Engine](sync-engine.md) |

They are the same system seen from three sides.
The workspace is an app that stores its data in your personal data store.
The personal data store stays in agreement across devices because of the sync engine.
The sync engine is what developers get when they build their own app on the same libraries.

## What they share

- **Your identity is a key.** An [Agent](agents.md) is an Ed25519 keypair. There is no account to sign up for and nobody who can lock you out of it.
- **Your data is on your device.** The browser app keeps an encrypted database in the browser, the desktop and mobile apps keep one on disk. Reading and writing never wait on the network.
- **Every edit is signed.** A [Commit](commits/intro.md) is a CRDT delta plus a signature, so anyone can check who changed what, and any machine can store and forward it without being trusted.
- **A server is optional.** [AtomicServer](atomic-server.md) is a device that never sleeps: it makes your data reachable for browsers and collaborators, and it holds a backup. It does not own anything.
- **It is open.** The code is MIT licensed, and the data model is the open [Atomic Data](atomic-data-overview.md) specification.

## Where to go next

- Try it: the hosted app at [atomic.place](https://atomic.place), or [run your own server](atomicserver/installation.md).
- Build on it: the [local-first guide](local-first-guide/1-index.md).
- Understand it: [local-first and data ownership](local-first.md), [Atomic Sync](sync.md) and [URLs and identifiers](urls.md).
