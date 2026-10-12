{{#title Local-first: data ownership you can hold}}
# Local-first and data ownership

Atomic Data was started to give people [control over their data](motivation.md#give-people-more-control-over-their-data).
For years the answer to "where does my data live?" was "on an AtomicServer you host".
That is real ownership, but it asks a lot: a domain, a machine that stays on, and an app that stops working the moment it cannot reach that machine.

Since 2026 the answer is simpler. Your data lives **on your device**, and a server is one more device that happens to never sleep.

## What local-first means here

- **Your identity is a key, not an account.** An [Agent](agents.md) is an Ed25519 keypair. Its identifier, `atomic:agent:{publicKey}`, is derived from the key, so nobody issues it and nobody can take it away. There is no sign-up form and no server that has to exist first.
- **Your data is a local database.** The web app keeps an encrypted store in the browser (WASM plus OPFS). The desktop and mobile apps keep one on disk (redb). Reading and writing never wait on a network.
- **Every edit is signed by you.** A change is a [Commit](commits/intro.md): a Loro CRDT delta plus your signature. Anyone can verify who made it without asking a server, and nobody can forge one in your name.
- **Resources have location-independent names.** A `atomic:` identifier is derived from a signature, so the same Resource keeps the same name on your phone, your laptop and a replica in a data center. See [URLs and identifiers](urls.md).
- **Sync is optional and additive.** Devices that have been introduced to each other [reconcile](sync.md) whenever they can reach each other. Edits made apart merge without conflicts. Being offline is a state, not an error.

## Where the server fits

A server has not gone away; its role has changed.
An always-on device is useful for exactly the things a phone in a pocket cannot do:

- Be reachable by a browser tab, which cannot accept connections itself.
- Stay online so collaborators can fetch a Drive while your devices sleep.
- Hold a backup that survives a lost phone.
- Serve HTTP, so the same data is fetchable by `curl`, a static site generator, or a search engine.

None of that requires the server to be trusted with authorship.
Any node can replicate a Drive without holding the Drive owner's key, because every commit it forwards carries its own signature.
You can run that node yourself, use [atomic.place](https://atomic.place), or do both.

## What this means for a person

- A new device gets your identity from a secret or a passkey, and your data from any device that already has it. A secret restores *who you are*; a paired device or a server restores *what you have*.
- Losing a device does not mean losing an account: a WebAuthn passkey can wrap a backup of the agent secret.
- Signing out on a shared machine leaves the local cache encrypted under your key, unreadable to the next person.
- Two people editing the same document at once see each other's cursors and never a merge conflict.

## What this means for a developer

- **No backend to build.** Persistence, identity, authorization, history and sync come with the library. `@tomic/lib` in the browser and `atomic_lib` in Rust, Flutter and the CLI run the same store and the same sync engine.
- **Same code, every platform.** A [Flutter app](flutter.md) calls `atomic_lib` through `flutter_rust_bridge` and gets a local store, signing and peer sync, not a REST wrapper.
- **Schema still applies.** Local-first does not mean schemaless. Properties, Classes and datatypes are validated on every device, so data created offline is as well-formed as data created against a server.
- **History for free.** Every Resource's Loro oplog is its version history, so undo, time travel and audit views need no extra tables.

## Trade-offs

Local-first is not free, and these docs try not to pretend otherwise.

- **Key management is on the client.** The private key has to be on the device that signs. Passkeys and encrypted caches make this safer; they do not make it trivial.
- **Availability follows the devices.** If every device holding a Drive is off, nobody else can read it until one returns. An always-on replica is the fix.
- **Two browser tabs on two machines cannot reach each other on their own.** A tab is not a peer. They need a server in common or a WebRTC room.
- **Rights are per Resource, checked everywhere.** That is a feature, but it means "I paired my phone" is not the same as "my phone can see everything". What crosses a link is what the connecting Agent may read.

## Read on

- [URLs and identifiers](urls.md), for the naming scheme that makes location-independence work.
- [Atomic Sync](sync.md), for how devices reconcile.
- [Decentralized Identifiers](did.md), for the derivation and resolution details.
