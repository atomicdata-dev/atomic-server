{{#title Identifiers in Atomic Data }}
# Identifiers

_status: work in progress_

Atomic Data is moving from HTTP URLs to Decentralized Identifiers (identifiers) as the primary way to address resources.
This makes resources portable, self-authenticating, and resolvable over both the internet and local mesh networks.

## Design goals

- **Self-sovereign**: Identifiers don't depend on any server or domain name. You generate a keypair, and you have an identity.
- **Portable**: Resources can move between servers without changing their identifier.
- **Multi-transport**: The same identifier can be resolved by asking paired devices, an always-on replica, or the pkarr relay network for peers that hold the Drive (a mesh transport over Reticulum is planned, not built).
- **Verifiable**: Trust comes from [Commit](commits/intro.md) signatures, not from who hosts the data.
- **Replicatable**: Any node can replicate and serve a Drive without holding the Drive's private key.

## The `atomic:` scheme

Atomic Data defines the `atomic:` method with five forms, distinguished by an explicit type prefix (or its absence, for Resources):

### Encoding

All binary parts of a `atomic:` identifier — public keys and signatures — are encoded with **URL-safe, unpadded base64** (RFC 4648 §5: alphabet `A–Z a–z 0–9 - _`, no `=` padding). Blob hashes are the exception: they are hex (see [Blob identifiers](#blob-identifiers)).

This matters because identifiers travel inside URLs (`/app/show?subject=atomic:…`, the `?drive=` routing hint, deep links). The *standard* base64 alphabet contains `+` and `/`: a `+` is turned into a space by form-decoders (`application/x-www-form-urlencoded`), and `/` and the `=` padding are path/query-significant — any of them silently corrupts a subject on a URL round-trip. The URL-safe alphabet avoids all three, so a `atomic:` subject can be dropped into a URL verbatim and survive parsing.

Decoders accept the legacy standard alphabet (`+` `/`, padded) as well, so data written before this convention still resolves.

### Node identifiers

Atomic nodes are identified by the `node` prefix followed by the transport's
stable node identifier:

```text
atomic:node:{nodeId}
```

`atomic:node:` is the canonical user-facing and HTTP API form. A transport may
use a raw binary or hex value internally (for example, Iroh's `NodeId`), but
that transport-specific representation is not an alternative public
identifier.

A Node identifier identifies a replication endpoint for discovery and routing. It is
**not a Resource**, does not have Atomic properties or commit history, and does
not grant read or write authority. Transport authentication can prove which
node is connected; authorization still comes from Agent identities, grants,
and signed mutations.

### Agent identifiers

[Agents](agents.md) are identified by the `agent` prefix followed by their public key:

```text
atomic:agent:{publicKey}
```

The `publicKey` is an Ed25519 public key, [URL-safe base64-encoded](#encoding).
The `agent` prefix disambiguates agents from drive resources and signals that the identifier is primarily a verification key.

Agents are **not scoped to any Drive**.
An agent identity is independent — you generate a keypair and immediately have a globally unique, self-sovereign identity.
This avoids tying an agent to a specific server, avoids chicken-and-egg problems (agents create drives, so they must exist first), and keeps the identity stable even if the agent's home server changes.

#### Agent resolution

For most operations, agents don't need to be "resolved" at all:

- **Verifying a commit**: The public key is embedded in the identifier itself. No network call needed.
- **Granting permissions**: The identifier is all you need to reference an agent in `read`/`write` lists.
- **Displaying profile info** (name, avatar): Drives cache agent metadata when agents interact with them (e.g. accepting an [Invite](invitations.md), making a [Commit](commits/intro.md)). The drive you're connected to typically already has it.

If a client encounters an unknown agent, it can show the truncated public key as a fallback.
More sophisticated resolution (e.g. announcing agent profiles over [peer discovery](#3-peer-discovery-pkarr-relay)) can be layered on later without changing the identifier format.

### Commit identifiers

[Commits](commits/intro.md) are the fundamental events in Atomic Data. They are identified by the `commit` prefix followed by their cryptographic signature:

```text
atomic:commit:{signature}
```

The `signature` is the [URL-safe base64-encoded](#encoding) Ed25519 signature of the commit.
Using a identifier for commits ensures that the history of a resource is fully portable and not tied to the server where the commit was originally created.

Like resources, commits can include a routing hint to help discover them over decentralized networks:

```text
atomic:commit:{signature}?drive=atomic:{drive_genesis}
```

### Blob identifiers

Binary file contents (the bytes behind a [File](files.md) resource) are identified by the `blob` prefix followed by the BLAKE3 hash of the bytes:

```text
atomic:blob:{blake3}
```

The `blake3` is a 32-byte BLAKE3 hash, hex-encoded (64 characters). Hex rather than base64 because BLAKE3 tooling consumes and produces hex by convention, and because a content hash is conceptually a different thing from a key or signature.

Blobs are **not Resources**. They have no parent, no class, no ACL, no commit history — they are raw, content-addressed bytes. The File resource that *describes* a blob is a normal Resource and carries all the metadata (filename, mimetype, parent for permissions); it points at its blob via a `blob` property whose value is a `atomic:blob:` reference.

#### Capability semantics

Knowing a `atomic:blob:` identifier is, by itself, the capability to retrieve the bytes — there is no second authorization check inside the blob store. This works because:

- A 256-bit BLAKE3 hash is unforgeable: you cannot guess one.
- The only ways to obtain it are to already have the bytes (and compute it yourself), or to read a Resource that references it.
- Reading that Resource passes through the normal [hierarchy](hierarchy.md) authorization. That is where access control lives — the bytes simply follow.

So the auth boundary is the **File resource**, not the blob. This is the same model used by Git objects, IPFS CIDs, S3 presigned URLs, and Iroh tickets. Treat a leaked blob identifier the same as a leaked file.

#### Resolution and routing

Like resources and commits, blob identifiers accept a routing hint pointing at a Drive that is expected to hold the bytes:

```text
atomic:blob:{blake3}?drive=atomic:{drive_genesis}
```

A client looks up peers for the Drive through [peer discovery](#3-peer-discovery-pkarr-relay), then asks any of them for the blob. Over the v2 sync protocol, blobs travel as raw 32-byte hashes inside `BLOB_REQUEST`/`BLOB_RESPONSE` frames — the identifier is for *identity*, the bytes on the wire are the underlying hash. (This parallels commits: the identifier is `atomic:commit:{sig}`, but the wire never re-prepends the prefix.)

The HTTP form `<origin>/download/files/{blake3}` is a deployment-specific alias for `atomic:blob:{blake3}` and remains supported for browsers and existing tooling.

### Resource identifiers

Resources live inside [Drives](hierarchy.md).
The **Core Identity** of a resource is derived from its **Self-Verifying Genesis Certificate**:

```text
atomic:{genesis}
```

#### Genesis Certificate Derivation

New certificates use version byte `0x02` and serialize parent/drive subjects in `atomic:` form. Existing v1 certificates (`0x01`) verify with the strings they stored (typically `did:ad:`). The personal-drive singleton stays v1 so its identity does not remint.

#### Genesis Certificate layout

To ensure authorship and identity are verifiable offline without fetching previous commits, a new identifier resource carries its own inline, binary **Genesis Certificate** (`GenesisCert`), stored as an immutable property `genesis` (`https://atomicdata.dev/properties/genesis`) on the resource.

The `atomic:{genesis}` subject is the URL-safe base64-encoded Ed25519 signature over the binary layout of the certificate:
1. `version`: `0x01` (1 byte)
2. `flags`: `u8` (bit0 = has `stateHash`) (1 byte)
3. `signerPubKey`: Ed25519 public key of the creating agent (32 bytes)
4. `createdAt`: UNIX timestamp in milliseconds (8 bytes i64)
5. `nonce`: CSPRNG random unique bytes (16 bytes)
6. `stateHash` (Optional): Blake3 hash of the canonical genesis projection (32 bytes)
7. `parent`: Subject of the parent resource (variable length)
8. `drive`: Subject of the owning drive (variable length)

The identifier of the resource is `atomic:<base64url(signature_of_cert)>`. This enables instant offline verification of authorship, parentage, and drive membership from the resource payload alone.

#### Legacy Genesis Commit Derivation (v1)

For backward compatibility (including legacy or browser-minted resources), resources can be derived using the legacy path:
- A genesis commit is signed with `isGenesis: true` and no `previousCommit`.
- The `subject` field is **excluded** from the canonical bytes during signing to prevent a circular dependency.
- The subject is derived as `atomic:{signature}` of the first commit.

However, to discover this resource over a decentralized network, a client needs to know *which* Drive theoretically hosts it. This is done by appending a standard W3C identifier query parameter containing the Drive's identifier as a routing hint:

```text
atomic:{genesis}?drive=atomic:{drive_genesis}
```

For example:

```text
atomic:4f7ba2...910?drive=atomic:7e6a9d...038
```

### Drive identity

A Drive is a first-class resource identified by its own `atomic:` identifier.

When a Drive is used as a routing hint (the `?drive=` parameter), discovery needs a key to publish and look up under.
It is derived on the fly from the Drive's identifier and never stored as a property: a [pkarr](https://github.com/Pubky/pkarr) keypair seeded from the first 32 bytes of the Drive's genesis signature.
Because anyone who knows the identifier can derive the same keypair, replicas can announce themselves without holding the Drive owner's key. Trust never comes from who published the record; it comes from the Commit signatures in the data.

This ensures:
- **Consistency**: Everything is a `atomic:` identifier.
- **Portability**: The identifier depends only on the Drive's genesis state, not its location.
- **Protocol Independence**: The same identifier can be mapped to different binary formats required by different networks.

### Drive replication

A core principle is that **any node can replicate a Drive without holding the Drive's private key**.
Trust comes from [Commit signatures](commits/intro.md), not from who serves the data:

1. The Drive owner creates resources and signs [Commits](commits/intro.md) with their Agent key.
2. A replica node syncs the data and verifies every Commit signature.
3. The replica announces itself as a peer for this Drive (as an Iroh node ID, published through the pkarr relay) under the key derived from the Drive's identifier.
4. Clients fetching data derive the same key from the `?drive=` hint and look up peers.
5. Clients fetch data and verify Commit signatures themselves — they don't need to trust the serving node.

## Resolution

Resolving a `atomic:` URL means finding a network node that holds the requested Drive and resource.
Multiple resolution strategies can be tried in order:

### 1. Local cache

If the resource has been fetched before, serve it from the local store.

### 2. Paired devices and always-on replicas

If the Drive was shared with or paired to this device, ask those devices first. Over [Atomic Sync](sync.md) a paired peer or an AtomicServer answers with exactly the Resources the asking Agent may read.

### 3. Peer discovery (pkarr relay)

For a Drive you only know by identifier, a node holding the Drive publishes its Iroh node ID to the [pkarr](https://github.com/Pubky/pkarr) relay network under the key derived from the Drive (see [Drive identity](#drive-identity)), and a client looks that key up:

1. A node hosting a Drive publishes `drive identifier -> [node ID, ...]`. Several replicas can be listed at once.
2. A client resolving the Drive reads the list and dials a node over Iroh. Addressing (relay URL, direct addresses) is handled by Iroh.
3. The client requests the Resource and verifies the Commit signatures itself.

The same record can also carry a second TXT value, `_atomic_http`: a JSON array of the public `https://` origins of servers hosting the Drive. A browser cannot dial Iroh, but it can read the relay over HTTPS (`GET https://dns.iroh.link/pkarr/<z-base-32 public key>`, answered with CORS enabled). A client that holds only the person's secret derives the key from the Drive's identifier, verifies the signed packet against that key, and checks that each origin serves the Drive's genesis certificate before using it (see the threat model below). Servers skip origins that are not reachable from outside (plain `http`, `localhost`, IP addresses, single-label or `.local` hosts) and publish again every hour, because the record expires. As with node IDs the record is only a hint: anyone who knows the identifier can write to it, so clients ignore unusable origins and still verify Commit signatures.

**Threat model.** The key is derived from the public identifier, so anyone who knows a Drive's identifier can publish a newer `_atomic_http` record for it, naming their own server. That is accepted: the record is a hint, never proof. A malicious record can make a client contact a server of the attacker's choosing, waste a few requests, or hide the honest entries (denial of discovery). It cannot make the client accept data that is not signed by the Drive's owner, and it cannot make the client follow a server that does not hold the Drive. Before a client moves to an announced origin it fetches the Drive's genesis certificate from that origin with `GET /genesis?subject=<identifier>`, an anonymous request that refuses redirects, and checks that the certificate signs to the Drive's identifier. The identifier is that signature, so only a holder of the owner's key can produce one; a server that is merely a node, or serves another Drive, is skipped. At most three origins are tried per lookup.

`/genesis` is a read-only route that any visitor may call, even for a private Drive, because the client has no credentials the candidate server could be trusted with yet. It answers `{"@id": <identifier>, "https://atomicdata.dev/properties/genesis": <certificate>}` and nothing else. The certificate reveals the signer's public key, the creation time, a random nonce and the `parent` / `drive` fields it was minted with, and the route confirms that this server holds a Drive with that identifier. It never reads the Drive's other properties, children or history, and it is not subject to the Drive's read rights. Only Drives answer; any other subject (a resource inside a Drive, an agent, an URL, an unknown or malformed identifier) is a plain 404, so the route cannot be used to look for private resources. A Drive minted before genesis certificates existed has none to serve and cannot be verified this way. Whatever server is chosen this way is remembered as an inferred choice, not a pinned one: it does not outrank a server the person picked or a device's own node later, and Commit signatures are still verified on everything fetched.

The relay speaks HTTP, so this works through NAT and in places where raw UDP does not. It is a pure _discovery_ mechanism: all trust and authenticity comes from the Commit signatures in the data.
Reticulum, for resolution over a mesh without internet access, is planned but not implemented.

### 4. Direct connection

If the node's IP or domain is already known (e.g. from configuration or a previous session), connect directly.

## HTTP Discovery

While `atomic:` identifiers are the primary way to address resources, many users still access Atomic Data via standard HTTP URLs (e.g., `https://atomicdata.dev/about`). To bridge the gap between **Location** (the URL) and **Identity** (the identifier), Atomic Server includes a `Link` header in its HTTP responses:

```http
Link: <atomic:{genesis}>; rel="canonical"
```

This header provides several benefits:
- **Portability**: It explicitly signals that the resource has a permanent, location-independent identity.
- **Client Transition**: Sophisticated clients (like the Atomic Data Browser) can see this header and "upgrade" the connection from a specific server URL to a decentralized identifier-based resolution.
- **SEO for Data**: Similar to how `rel="canonical"` is used in HTML to prevent duplicate content, it tells the network which identifier is the authoritative "name" for the data, regardless of which server is currently hosting it.

## Relationship to the internal `Subject` type

Internally, AtomicServer uses the [`Subject`](https://github.com/ontola/atomic-server/blob/main/lib/src/subject.rs) enum to represent resource identifiers.
The three variants map to different resolution strategies:

| `Subject` variant | Format | Use case |
|---|---|---|
| `Internal` | `internal:/path` | Local resources on this server. Resolved to an absolute URL using the server's origin for serialization. |
| `Did` | `atomic:...` | Agents (by public key), Commits (by signature), Blobs (by BLAKE3 hash), Nodes (as routing identities), and Resources in Drives (by genesis commit signature). Routing hints (`?drive=atomic:...`) are used for peer discovery through the pkarr relay. |
| `External` | `https://...` | Resources on other servers. Resolved via HTTP. Used for backward compatibility and external linked data. |

When serializing to [JSON-AD](core/json-ad.md), `Internal` subjects are resolved to absolute URLs using the server's configured origin.
`Did` subjects are serialized as-is — they are already globally unique and location-independent.

## Comparison with other identifier methods

| | `atomic:` | `atomic:web` | `atomic:dht` | `did:key` |
|---|---|---|---|---|
| **Decentralized** | ✅ No server dependency | ❌  Depends on DNS | ✅ Mainline DHT | ✅ Self-contained |
| **Mesh-capable** | 🚧 Reticulum planned | ❌ | ❌ | ✅ But no routing |
| **Updatable** | ✅ Drive can move | ✅ Update DNS | ✅ Mutable records | ❌ Static |
| **Replicatable** | ✅ Any node can serve | ❌ Single server | ❌ Key holder only | N/A |
| **Trust model** | Commit signatures | TLS + DNS | BEP44 signatures | Key-based |
| **Resources** | ✅ Granular via `genesis` | ❌ One doc per identifier | ❌ One doc per identifier | ❌ One key per identifier |

The main distinction of `atomic:` is that it separates mathematically pure identity (`atomic:{genesis}`) from network discovery routing hints (`?drive=atomic:{drive_genesis}`).
Combined with Atomic Data's Commit-based trust model, this enables multi-node replication where any peer can serve verified data seamlessly.

## Path Restrictions
Unlike `http(s):` or `internal:` identifiers which are highly hierarchical, `atomic:` identifiers **do not support sub-paths** (e.g. `atomic:123/my-property`).
Every individual resource within a identifier hierarchy must be explicitly created with its own standalone genesis commit, leading to a flat namespace of `atomic:<hash>` identifiers that relate to each other through the `parent` property, rather than structurally via paths.

## Compatibility with `did:ad:`

`did:ad:` is the previous spelling of the same identifiers. Parsers accept both prefixes forever. Identity is the genesis, commit, or public-key bytes, not the string prefix: `atomic:{x}` and `did:ad:{x}` name the same resource.

New identifiers are emitted as `atomic:`. Stores canonicalize at the lookup boundary (`pure_id()` in Rust, `normalizeSubject` in TypeScript) so a resource written under one prefix is found under the other. Verification of signed commits and genesis certificates uses the bytes as stored — prefixes inside signed material are never rewritten.

Vocabulary URLs stay `https://atomicdata.dev/…`. `internal:/path` stays.

## HTTP resolution

`GET /resource?subject=` is the HTTP endpoint for an `atomic:` (or `did:ad:`) identifier. `GET /atomic?subject=` and `GET /did?subject=` are aliases. Path forms such as `https://host/atomic:{genesis}` and `https://host/did:ad:{genesis}` also resolve.

## Pairing and deep links

The scheme is opaque (no `//`). There are no reserved words such as `open`, `pair`, or `app`.

- A **node** identifier with query hints is a pairing code: `atomic:node:{id}?v=1&drives=*`.
- Any other `atomic:` identifier navigates to that resource.
- Legacy `atomic://pair` and `atomic://open` still parse.

## Sync capability

A peer that understands `atomic:` on the wire lists the `canonical-scheme` capability: a WebSocket client and an Iroh dialer in their `HELLO`, a responder in its `AUTH_OK`. Every subject the other side then puts on the wire follows that list, on both transports:

- `UPDATE` and `DESTROY` fan-out, and the answers to `GET` and `GET_MANY` (subject and `lastCommit`);
- `SYNC_OK`, `SYNC_RESEND`, `SYNC_DIFF` (drive, `pull`, `push`, `remove` and the keys of `pullFrom` / `removeCommits`) and every `SYNC_PUSH` entry;
- the drive and agent in an `EPHEMERAL` frame header.

A peer that lists nothing predates the rename and receives `did:ad:`, which it can parse. A client that sends no `HELLO` (the workspace inspection handshake, for one) is answered in `did:ad:` and canonicalizes what it reads. Signed material is never rewritten: a commit's JSON-AD and the envelopes that ride in a `SYNC_PUSH` verify as stored, whichever spelling they carry.

## Certificates and stored data

A genesis certificate's version byte says which spelling its parent and drive strings were signed in: v1 as stored (typically `did:ad:`), v2 `atomic:`. A v2 certificate that carries a `did:ad:` string is refused when decoded. The parent and drive a certificate binds are compared with the resource's materialized values in one spelling, so a v1 certificate from before the rename still verifies against canonical propvals.

A store filled before the rename is rewritten once, on open: resource and snapshot keys, DID-mapping keys and the routing-hint values they hold, retained envelopes, tombstones and the outbox all move to the canonical key, and the query and search indexes are rebuilt when a resource or snapshot moved. The pass streams each tree and keeps only the keys it has to touch in memory.
