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

The Loro document of a resource holds every change, but not the proof of who
made it. That proof is the signed commit itself, so after applying a commit a
node can keep it. Kept commits live in a side tree on the node (internally
`Tree::Envelopes`, the code's name for a stored commit). They are not resources
and are not indexed: they never appear in queries or collections. A node keeps
either the commit that produced the current state (`--envelope-retention
latest`, the default) or every commit (`all`), which turns the Loro history
into a signed audit log.

The Loro document already holds every change, so a kept commit stores only
what proves it: the signer, the previous commit, which range of Loro changes
it introduced, and a hash of them (about 63 bytes for a small edit). When it is
read, the node rebuilds the exact signed JSON-AD from the Loro history, and the
signature is checked against that. If a commit cannot be rebuilt byte for byte
when it is stored, the full JSON is kept instead. A kept commit that can no
longer be rebuilt is reported as unreadable, never guessed.

A resource can ask for the audit log itself. Set its `retention` property to
`audit` (the default is `compact`) and the node keeps every commit of that
resource and of everything below it. The setting is inherited down the parent
chain and only ever raises what a node keeps: `compact` on a child does not
lower an `audit` above it, and a node running `--envelope-retention all` audits
everything. Only `compact` and `audit` are accepted; other values are refused.

Setting `audit` later protects history from that moment on; commits a node
already dropped are not recovered. Taking `audit` off, or moving the resource
out of an audited folder, never deletes what was kept: the commit that does it
is kept beside the audit-era commits, and later commits replace only the newest
one. That newest one is the lowering commit itself, so after one more edit the
envelope row of who lowered `audit` is replaced, but the commit that changed
`retention` is kept like a rights change, so who lowered it stays provable.
Any writer can change `retention`; who may lower it is an open question for an
owner level. A
receiver that already holds a newer commit for a compact resource still drops
an older incoming one, audit-era or not. A node that has not yet received an
ancestor of a resource keeps every commit it is sent until it can read the
whole chain. Each node applies the setting to the resources it holds, so a
device that is short on space can still keep less than a server does.

Each commit's Loro change carries a token in its message, and the kept commit
that introduced that change carries the same token inside its `loroUpdate`.
That is how a version in History maps to its signer.

`GET /history-attribution?subject=<subject>` returns, for a resource the
caller may read:

```json
{
  "subject": "atomic:…",
  "retention": "all",
  "complete": true,
  "attributions": [
    {
      "signer": "atomic:agent:…",
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
in the oplog is claimed by a verified kept commit. A version no kept commit covers
is shown as *Unattributed*; a signer is never guessed.
