{{#title Atomic Commits - Signed write envelopes}}
# Atomic Commits

Atomic Commits are **signed envelopes** that authorize a write to a Resource.
They are not an event-sourced history, and they are not a queryable class of
resources. Current state lives in the Resource's [Loro CRDT](https://loro.dev)
document. History and versioning read that document's oplog. A commit is the
small signed receipt the transport is not allowed to omit.

See [concepts](concepts.md) for the field list.

## Design goals

- **Verifiable writes**: cryptographic proof of who changed what, and when.
- **Traceable origin**: every applied write is attributable to an Agent.
- **CRDT merge**: concurrent edits merge deterministically via Loro. There is no linear commit chain to enforce.
- **Identifiable**: a commit has an id (`did:ad:commit:{signature}`). That id may be retained as a receipt; it is not required as a refetchable resource.
- **Decentralized**: envelopes can move over HTTP `/commit`, WebSocket `COMMIT`, or a peer sync path that carries the same signature.
- **ACID-compliant**: a commit is applied only if signature, rights, and schema checks pass.
- **Atomic**: all Atomic Data design goals also apply here.

## What a commit is not

- Not the source of current state. Loro is.
- Not a Git-style parent chain. `previousCommit` is optional audit metadata.
- Not a product surface. The `/commits` class collection is not created. UI reads author and dates from the resource's genesis certificate, not by fetching `did:ad:commit:…`.
- Not required to stay on disk after apply, except genesis and rights / parent / destroy.

## How a write lands

1. The client edits the resource's Loro document.
2. It exports a compact binary delta (`loroUpdate`).
3. It signs a commit containing `subject`, `signer`, `createdAt`, `loroUpdate`, and a signature.
4. The server verifies the signature and the signer's rights, imports the Loro bytes, and materializes properties. Ordinary content commits are not stored as resources; genesis and rights/parent/destroy are.

HTTP `POST /commit` remains the fallback. The WebSocket `COMMIT` frame is the live path.

## Motivation

Systems that only publish *current state* make synchronization expensive: you
re-fetch everything and diff. Atomic Commits let a writer prove a specific
mutation. The mutation itself is a Loro delta, so two writers do not need a
lock or a linear history. Versioning, undo, and audit of *content* come from
the CRDT oplog. The signed envelope is what makes that mutation admissible.
