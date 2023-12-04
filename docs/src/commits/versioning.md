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
