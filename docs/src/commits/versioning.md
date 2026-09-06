# Atomic Data Versioning

When Atomic Commits are applied to some Resource, the resource will change.
However, its identifier (the Subject) will often remain the same.

- Versioned representations should provide a link to the authority that might update it, and a link to where the latest version can be found.
- The latest version should have a link to its permanent version.
- Should [IPFS](../interoperability/ipfs.md) content-hash URLs be used for Versioned resources?

## Versioned Resources

Properties:

<!-- Maybe this is not required, if we assume that the subject URL should always show the latest? -->
- latest: (ResourceArray, optional)
- versions: (ResourceArray, optional)
- currentVersion: (ResourceURL, required)

## Static Resource

A static resource has a _content addressable_ URL, which means that its URL will never change.

## Hashing

- Serialize all Atoms of the Subject (the entire Resource) as Atomic-NDJSON
- Sort all lines (every atom) alphabetically


## Who signed a version

Every applied commit leaves its signed JSON-AD on the resource it changed, in
a side tree on the node (`Tree::Envelopes`). It is not a resource and it is
not indexed: it never appears in queries or collections. A node keeps either
the envelope that produced the current state (`--envelope-retention latest`,
the default) or every envelope (`all`), which turns the Loro history into a
signed audit log.

Each commit's Loro change carries a token in its message, and the envelope
that introduced that change carries the same token inside its `loroUpdate`.
That is how a version in History maps to its signer.

`GET /history-attribution?subject=<subject>` returns, for a resource the
caller may read:

```json
{
  "subject": "did:ad:…",
  "retention": "all",
  "complete": true,
  "attributions": [
    {
      "signer": "did:ad:agent:…",
      "created_at": 1757060000000,
      "signature": "…",
      "verified": true,
      "tokens": ["c-1a07140ba9b-uvdzz0"],
      "destroy": false,
      "genesis": false
    }
  ]
}
```

`verified` means the answering node re-checked the signature with the same
code it applies commits with. `complete` means every client-authored change
in the oplog is claimed by a verified envelope. A version no envelope covers
is shown as *Unattributed*; a signer is never guessed.
