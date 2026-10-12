{{#title Personal Data Store: your data, on your devices, under your key}}
# Personal Data Store

A personal data store is the place where everything that is yours lives: documents, tables, files, messages, contacts, the settings of the apps you use.
Atomic makes that place **your own devices**, not a company's database, and lets any number of apps work on the same data.

## What you get

- **An identity nobody issues.** Your [Agent](agents.md) is a keypair generated on your device. Its identifier, `atomic:agent:{publicKey}`, is derived from the key. Log in with the agent secret, or let a passkey wrap a backup of it. Two stores, two servers and two apps all recognize the same identity without registering anywhere.
- **Encrypted at rest.** The local database of each agent is encrypted under a random 256-bit key, which is itself wrapped under that agent's credential. Signing out leaves a cache that the next person on the machine cannot read.
- **Works offline.** Reads and writes hit the local store first. Changes made without a connection wait in an outbox and sync later.
- **Every change is yours, and provable.** Each edit is a signed [Commit](commits/intro.md). Version history is kept per Resource, so you can see what changed, who did it, and go back.
- **Sharing is explicit.** Rights are per Resource, read and write, inherited down a [hierarchy](hierarchy.md) of folders and Drives, and handed out with [invite links](invitations.md). Sharing a Drive grants access to that Drive and nothing else.
- **Backed up without being handed over.** An always-on [AtomicServer](atomic-server.md), self-hosted or on [atomic.place](https://atomic.place), stores signed commits. It can replicate your data but never author it, because it does not hold your key.
- **Portable.** Everything is plain Atomic Data: [JSON-AD](core/json-ad.md) over the [HTTP API](atomicserver/API.md), with RDF, Turtle, N-Triples and JSON-LD serializations, and an importer for JSON-AD files. The data is not locked inside one app.

## Many apps, one store

Because data has a shared, typed model ([Atomic Schema](schema/intro.md)), a Class and its Properties mean the same thing in every app.
A task created in the workspace can be read by a script, a static website generator or your own app, with no export step and no per-app backend.
The [JavaScript](js.md), [React](usecases/react.md), [Svelte](svelte.md), [Rust](rust-lib.md) and [Flutter](flutter.md) libraries all talk to the same store.

## Where your data lives

| Place | What it is | Who can read it |
| --- | --- | --- |
| Your browser or app | The primary copy: an encrypted local database | You, once signed in |
| Your other devices | Copies, kept in agreement by [Atomic Sync](sync.md) | You, and whoever you shared a Drive with |
| An AtomicServer | An always-on replica, self-hosted or hosted for you | Whoever runs it can read what you sync to it, so pick one you trust (or run it yourself). Keep a Drive local-only to never send it. The server cannot forge your edits |

Be honest about the trade-offs: losing the only device that holds a Drive, and the secret, means losing the data, so keep the secret somewhere safe and keep an always-on replica. The [local-first page](local-first.md) lists these trade-offs in full.

## Related

- [Local-first and data ownership](local-first.md)
- [Personal data stores as a use case](usecases/personal-data-store.md)
- [Authentication](authentication.md) and [Agents](agents.md)
