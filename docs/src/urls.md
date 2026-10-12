{{#title URLs and identifiers in Atomic Data}}
# URLs and identifiers

Everything in Atomic Data is named by a URL.
A Resource has a Subject URL, every Property is a URL, and Values can be URLs that point to other Resources.
That is what makes the data a graph, and what makes datasets on different machines link to each other.

You will meet a handful of URL shapes in these docs and in the software.
This page is the map. Each shape names a different kind of thing, and each resolves in a different way.

## Two jobs a URL can do

A URL can tell you **what** something is (its identity), or **where** to get it (its location), or both.

- An `https://` URL bundles the two: the domain is the location, and the path is the name. If the server moves, the name breaks.
- A `atomic:` identifier only carries identity. It is derived from a signature or a key, so it stays the same no matter which device or server holds the data. Location is added separately, as a routing hint, or discovered over the network.

The legacy `did:ad:` spelling of every `atomic:` identifier below is still accepted and names the same thing; new data is written with `atomic:`.

Atomic Data started out HTTP-only. Since the move to [local-first](local-first.md), `atomic:` identifiers are the primary way to name Resources, Agents, Commits, blobs and nodes, and HTTP URLs remain for vocabularies, external linked data and older servers.
The [identifier specification](identifiers.md) has the full derivation rules and the resolution strategies; this page stays at the level of "which URL is which".

## The identifier families

| Shape | Names | Minted by | Resolves through |
| --- | --- | --- | --- |
| `atomic:{genesis}` | A Resource inside a Drive (documents, tables, folders, the Drive itself) | The signature over its genesis certificate | Local store, a paired device, an always-on device, or peer discovery |
| `atomic:agent:{publicKey}` | An [Agent](agents.md): a person, device or program that can sign | Generating an Ed25519 keypair | No network needed: the key is inside the identifier |
| `atomic:commit:{signature}` | A signed write envelope, see [Commits](commits/intro.md) | The signature over the commit | Usually kept only as a receipt; not something you fetch |
| `atomic:blob:{blake3}` | The raw bytes behind a [File](files.md) | The BLAKE3 hash of the bytes | Any device that holds the bytes; knowing the hash is the capability |
| `atomic:node:{nodeId}` | A device or server as a network endpoint | The device's transport keypair (Iroh) | Not a Resource; used for pairing and routing only |
| `https://example.com/…` | Properties, Classes, Ontologies, external linked data, Resources on HTTP-era servers | The domain owner | An HTTP `GET` with an `application/ad+json` accept header |
| `internal:/path` | A Resource on *this* server, in config files and server logs | The server | Rewritten to the server's own origin before it leaves the server |
| `localId` (a string, not a URL) | A stable name for a Resource *within its parent*, used by imports and plugins | The data producer | Looked up as `parent` + `localId`; the Resource keeps its normal Subject |

Three things to notice in the table.

First, only the `https://` family and `internal:` rows have a path.
`atomic:` identifiers are flat: there is no `atomic:abc/child`.
Structure comes from the [`parent` property](hierarchy.md), not from the URL.

Second, the Agent row needs no lookup.
The public key is part of the identifier, so any device can verify a signature from that Agent offline.
That is what lets a signed edit made on a train be checked on a laptop that has never seen the network.

Third, a `localId` is not a Subject. It is a property (`https://atomicdata.dev/properties/localId`) whose value is a string chosen by whoever produces the data, unique among the children of one parent.
When you [publish JSON-AD for others to import](create-json-ad.md), resources carry a `localId` instead of an `@id`: the importer mints a `atomic:` Subject on first import, finds the same Resource again by `parent` + `localId` on the next one, and rewrites references between `localId`s into real links.
Plugins use the same mechanism to find the resources they created, with a namespaced convention such as `atomic:example:table`.

## Routing hints

A pure identity says nothing about where to find the data.
For `atomic:` Resources, Commits and blobs, a client can append the Drive that is expected to hold it:

```text
atomic:{genesis}?drive=atomic:{drive_genesis}
```

The hint is not part of the identity.
Two URLs that differ only in the `?drive=` hint name the same Resource, and stores strip the hint before using the identifier as a key.
It is a hint in the literal sense: it tells a client which Drive to look up on the network, and a client that already has the Resource locally ignores it.

## HTTP forms of a DID

A browser tab cannot dial a peer directly, so an always-on device (an AtomicServer) exposes DID Resources over HTTP as well.
Any of these fetch the same Resource:

```text
GET https://example.com/did?subject=atomic:{genesis}
GET https://example.com/atomic:{genesis}
```

The response carries the canonical identity in a header, so a client that arrived through a location can switch to the identity:

```http
Link: <atomic:{genesis}>; rel="canonical"
```

The same applies to blobs: `https://example.com/download/files/{blake3}` is the HTTP alias for `atomic:blob:{blake3}`.
The alias is a convenience of one deployment. The DID is the name.

## URLs you see in the app

The web app puts the Subject in the query string, so a `atomic:` identifier survives copy and paste without escaping:

```text
https://example.com/app/show?subject=atomic:{genesis}
```

The desktop and mobile apps register the `atomic://` scheme for deep links, which is a transport for other identifiers rather than an identifier itself:

```text
atomic://pair?v=1&node=atomic:node:{nodeId}&drives=*
atomic://open?subject=atomic:{genesis}
```

A pairing code, as a QR code or a link, carries the *route* to a device. It never contains an Agent secret, and scanning it grants nothing by itself: what crosses the link is decided by the rights on each Resource, on every transport. See [Atomic Sync](sync.md).
An open link hands the app a Subject to navigate to.

## Strings that look like identifiers but are not

- `atomic:system` and `sys:init` are Loro commit *origins*, tags on an edit inside a Resource's CRDT document that the undo manager uses to skip internal writes. They never name anything.
- `_new:` and similar placeholders appeared in older clients before a Resource had signed its genesis. Current clients mint the `atomic:` Subject up front, so a placeholder should not reach the wire.
- A `localId` value (see above) is a name inside a parent, not a global identifier, even when it is written in a URL-like namespace.

## Encoding

Keys and signatures inside `atomic:` identifiers use URL-safe, unpadded base64 (`A–Z a–z 0–9 - _`), so an identifier can be dropped into a query string verbatim.
Blob hashes are hex.
Decoders also accept the older standard alphabet, so data written before this convention still resolves.
The [identifier specification](identifiers.md#encoding) explains why.

## Which one should I use?

- **Naming a Property, Class or Ontology**: an `https://` URL. Vocabularies are meant to be public, stable and fetchable by anyone, and `atomicdata.dev` hosts the core ones.
- **Naming a Resource you create in a Drive**: let the library mint a `atomic:` identifier. You never choose it, and it never changes.
- **Linking to a Resource from code or a document**: use the `atomic:` identifier, optionally with a `?drive=` hint if the reader may not have it yet.
- **Sharing a link with a person**: the app's `/app/show?subject=` form, from a device they can reach.
- **Configuring a server**: `internal:/` for "this server's root", or a `atomic:` for a specific Drive. Both work; see [installation](atomicserver/installation.md).
