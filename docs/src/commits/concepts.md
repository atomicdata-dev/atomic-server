{{#title Atomic Commits: Concepts}}
# Atomic Commits: Concepts

## Commit

_url: [https://atomicdata.dev/classes/Commit](https://atomicdata.dev/classes/Commit)_

A Commit is a signed envelope that authorizes a Loro CRDT update on a Resource.
It is **not** a queryable event log. Current state and version history live in
the Resource's Loro document. The commit may be discarded after apply, except
for the must-retain floor (genesis, rights / parent / destroy).

All state changes in Atomic Data are carried as [Loro CRDT](https://loro.dev) binary updates.
This means that concurrent edits from multiple clients merge automatically without conflicts.

The **required fields** are:

- `subject` - The thing being changed. A Resource Subject URL that the Commit is changing. Must not contain query parameters.
- `signer` - Who's making the change. The DID of the Agent (`did:ad:agent:{publicKey}`).
- `signature` - Cryptographic proof of the change. An Ed25519 signature of the deterministically serialized Commit (without the `signature` field). The signature is also used as the identifier of the commit (`did:ad:commit:{signature}`).
- `created-at` - When the change was made. A UNIX timestamp in milliseconds.

The **optional fields** are:

- `loroUpdate` - A [Loro CRDT](https://loro.dev) binary update, encoded as a base64 string. This is the primary way to carry property changes. The server imports this update into the resource's Loro document, materializes the properties, and computes index diffs.
- `destroy` - If true, the entire Resource will be removed.
- `previousCommit` - Optional audit pointer at an earlier envelope. **Not a causal gate** — concurrent edits merge via Loro. Clients may still send it; servers do not require it.
- `isGenesis` - If true, this is the first commit for a DID resource. The subject DID is derived from either the self-verifying genesis certificate signature (`did:ad:<sig_of_cert>`) or, in legacy mode, the signature of the genesis commit itself.

### Loro CRDT updates

Each Resource is backed by a [Loro](https://loro.dev) document. Properties are stored in a Loro Map container called `"properties"`.
When a client edits a resource:

1. The client writes to the resource's Loro document (e.g. `doc.getMap("properties").set("name", "Alice")`)
2. The client exports the Loro binary delta since the last save
3. The delta is base64-encoded and placed in the `loroUpdate` field of the commit
4. The commit is signed and sent to the server

The server:

1. Imports the Loro update into the resource's existing Loro document (creating one if this is the first commit)
2. Materializes the Loro document's properties into the resource's property-value store
3. Computes add/remove atom diffs for search indexing
4. Stores the updated Loro snapshot for future merges

Because Loro is a CRDT, concurrent updates from different clients merge deterministically without conflicts.

### Deprecated: `set`, `push`, `remove`

Previous versions of Atomic Server used `set`, `push`, and `remove` fields to describe property changes.
These fields are **no longer accepted** by the server.
All property changes must be carried as `loroUpdate` instead.

### Posting commits using HTTP

Since Commits contain cryptographic proof of authorship, they can be accepted at a public endpoint.
There is no need for authentication.

A commit should be sent (using an HTTPS POST request) to a `/commit` endpoint of an Atomic Server.
The server then checks the signature and the author rights, and responds with a `2xx` status code if it succeeded, or an `5xx` error if something went wrong.
The error will be a JSON object.

### Serialization with JSON-AD

Here is an example Commit with a Loro update:

```json
{
  "@id": "did:ad:commit:4BHIig/9/JdmT1QeMXEe...",
  "https://atomicdata.dev/properties/createdAt": 1775492021374,
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Commit"
  ],
  "https://atomicdata.dev/properties/loroUpdate": "bG9ybwAAAAAAAA...",
  "https://atomicdata.dev/properties/signature": "4BHIig/9/JdmT1QeMXEe...",
  "https://atomicdata.dev/properties/signer": "did:ad:agent:HkPPFpaVesldOutQqQioozu1yblBDIT2t7hYWJWBJyw=",
  "https://atomicdata.dev/properties/previousCommit": "did:ad:commit:hgtP8Smpew2ciWBW9pa2...",
  "https://atomicdata.dev/properties/subject": "did:ad:Nca6liMVPNgXtv..."
}
```

Note that `loroUpdate` is a plain base64-encoded string containing the Loro binary.

### Calculating the signature

The signature is a base64 encoded Ed25519 signature of the deterministically serialized Commit.
Calculating the signature is a delicate process that should be followed to the letter - even a single character in the wrong place will result in an incorrect signature, which makes the Commit invalid.

The first step is **serializing the commit deterministically**.
This means that the process will always end in the exact same string.

- Serialize the Commit as JSON-AD.
- Do not serialize the signature field.
- Do not include `undefined` or `null` fields.
- If `destroy` is false or absent, do not include it.
- All keys are sorted alphabetically.
- The JSON-AD is minified: no newlines, no spaces.
- For legacy DID genesis commits (`isGenesis: true` without an inline genesis certificate), exclude the `subject` field (since it is derived from the commit signature). For certificate-backed genesis commits, the `subject` DID is derived from the genesis certificate and included in the serialized commit body.

This will result in a string.
The next step is to sign this string using the Ed25519 private key from the Author.
This signature is a byte array, which should be encoded in base64 for serialization.

### Applying the Commit

If you're on the receiving end of a Commit (e.g. if you're writing a server), you will _apply_ the Commit to your Store.
Here's how:

1. Check if the Subject URL is valid.
2. Validate the signature: serialize the Commit deterministically (see above), look up the Agent's public key, verify the signature matches.
3. Check if the timestamp is reasonable (within ~10 seconds).
4. Fetch the existing resource (or create a new one for genesis commits).
5. Validate the rights of the signer.
6. Import the `loroUpdate` into the resource's Loro document.
7. Materialize the Loro document's properties into the resource's property-value store.
8. If `destroy` is true, delete the resource.
9. Validate schema (check required properties for the resource's classes).
10. Store the Commit as a resource, and store the modified resource.

### Real-time sync

In addition to persistent commits, Atomic Server supports real-time sync via WebSocket:

- `EPHEMERAL` frames of kind `DOC` broadcast Loro binary updates for real-time document collaboration (not persisted; use commits for persistence).
- `EPHEMERAL` frames of kind `LORO` and `PRESENCE` broadcast ephemeral data like cursor positions and user presence via Loro's `EphemeralStore` (never persisted, auto-expires).

## Limitations

- Commits adjust **only one Resource at a time**, which means that you cannot change multiple in one commit.
- The one creating the Commit will **need to sign it**, which may make clients that write data more complicated than you'd like.
- Commits require signatures, which means **key management**. Doing this securely is no trivial matter.
- The signatures **require JSON-AD** serialization.
