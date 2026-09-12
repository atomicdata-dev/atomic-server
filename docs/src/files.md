{{#title Uploading, downloading and describing files with Atomic Data}}
# Uploading, downloading and describing files with Atomic Data

The Atomic Data model (Atomic Schema) is great for describing structured data, but for many types of existing data, we already have a different way to represent them: files.
In Atomic Data, files have two URLs.
One _describes_ the file and its metadata, and the other is a URL that downloads the file.
This allows us to present a better view when a user wants to take a look at some file, and learn about its context before downloading it.

## The File class

_url: [https://atomicdata.dev/classes/File](https://atomicdata.dev/classes/File)_

Files always have a downloadURL.
They often also have a filename, a filesize, a checksum, a mimetype, and an internal ID (more on that later).
They also often have a [`parent`](https://atomicdata.dev/properties/parent), which can be used to set permissions / rights.
If the file is an image they will also get an `imageWidth` and `imageHeight` property.

## Uploading a file

In `atomic-server`, a `/upload` endpoint exists for uploading a file.

- Decide where you want to add the file in the [hierarchy](hierarchy.md) of your server. You can add a file to any resource - your file will refer to this resource as its [`parent`](https://atomicdata.dev/properties/parent). Make sure you have `write` rights on this parent.
- Use that parent to add a query parameter to the server's `/upload` endpoint, e.g. `/upload?parent=https%3A%2F%2Fatomicdata.dev%2Ffiles`.
- Send an HTTP `POST` request to the server's `/upload` endpoint containing [`multi-part-form-data`](https://developer.mozilla.org/en-US/docs/Web/API/FormData/Using_FormData_Objects). You can upload multiple files in one request. Add [authentication](authentication.md) headers, and sign the HTTP request with the
- The server will check your authentication headers, your permissions, and will persist your uploaded file(s). It will now create File resources.
- The server will reply with an array of created Atomic Data Files

## Downloading a file

Simply send an HTTP GET request to the File's [`download-url`](https://atomicdata.dev/properties/downloadURL) (make sure to authenticate this request).

### Image compression

AtomicServer can automatically generate compressed versions of images in modern image formats (WebP, AVIF).
To do this add one or more of the following query parameters to the download URL:

| Query parameter | Description |
| --- | --- |
| f | The format of the image. Can be `webp` or `avif`. |
| q | The quality used to encode the image. Can be a number between 0 and 100. (Only works when `f` is set to `webp` or `avif`). Default is 75|
| w | The width of the image. Height will be scaled based on the width to keep the right aspect-ratio |

Example: `https://atomicdata.dev/download/files/af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262?f=avif&q=60&w=500` (the path segment is the file's BLAKE3 hash).

## Storage model: content-addressed blobs

Files are stored using a [content-addressed](https://en.wikipedia.org/wiki/Content-addressable_storage) model. Every file's bytes are hashed with [BLAKE3](https://github.com/BLAKE3-team/BLAKE3), and the bytes are stored under that hash in a key-value blob store. The hash is the blob's identity — its canonical form is a [DID](did.md):

```text
did:ad:blob:{blake3}
```

where `{blake3}` is the 32-byte BLAKE3 hash, hex-encoded. See [Blob identifiers](did.md#blob-identifiers) for the full identifier definition.

This separates the file's *metadata* (the File resource — filename, mimetype, parent, ACL) from its *data* (the bytes), and lets the same blob be referenced by any number of File resources without duplication. The File resource points at its blob via a `blob` property whose value is a `did:ad:blob:` reference. Bytes flow over the peer-to-peer sync protocol independently of the resource graph: a peer that receives a File resource looks up the blob locally, and if it doesn't have the bytes, asks any connected peer for them.

The HTTP form `<origin>/download/files/{blake3}` is a deployment-specific alias for the underlying DID and remains the URL clients use over plain HTTP.

## Authorization model: hashes are bearer capabilities

The blob store has no permission system of its own. Knowing a `did:ad:blob:` identifier is the capability to retrieve the bytes — there is no second authorization check inside the blob store, and there does not need to be. The reasoning:

- A 256-bit BLAKE3 hash is unforgeable. You cannot guess one.
- The only ways to obtain a blob DID are: you already had the bytes (and computed the hash yourself), or you read the File resource that referenced it.
- Reading a File resource passes through the normal resource-level [hierarchy](hierarchy.md) authorization. That check is where access control happens — the bytes simply follow.

In other words, **the auth boundary is the File resource, not the blob.** Once a client legitimately holds a blob DID, they can fetch the corresponding bytes from any peer that happens to have them. This is the same model used by Git objects, IPFS CIDs, S3 presigned URLs, and Iroh tickets.

Three properties follow from this and should not be tangled up later:

1. **Blobs are facts, not resources.** They have no subject metadata, no parent, no ACL, no class. They are addressed only by content hash.
2. **The File resource is where read permission is enforced.** Any client that can read the File resource can read its bytes.
3. **Blob DIDs are bearer tokens.** Treat a leaked `did:ad:blob:` the same as a leaked file — equivalent to leaking an S3 presigned URL.

### A note on existence side-channels

A consequence of content-addressed storage is that an attacker who already knows the BLAKE3 hash of some specific byte-string (for example, by hashing a publicly-leaked document) can ask a server "do you have this blob?" and learn the answer from the response. This is intrinsic to any CAS system and is generally accepted; mitigations like rate-limiting unauthenticated blob fetches are orthogonal to the capability model and can be applied at the deployment layer if needed.

## Discussion

- [Discussion on specification](https://github.com/ontola/atomic-data-docs/issues/57)
- [Discussion on Rust server implementation](https://github.com/atomicdata-dev/atomic-server/issues/72)
- [Discussion on Typescript client implementation](https://github.com/atomicdata-dev/atomic-data-browser/issues/121)

## Server file storage

By default, file bytes are stored in the local database. Operators can select
S3-compatible storage with `ATOMIC_BLOB_BACKEND=s3`, `ATOMIC_S3_BUCKET`,
`ATOMIC_S3_REGION`, and optionally `ATOMIC_S3_ENDPOINT`. Set the paired
`ATOMIC_S3_ACCESS_KEY_ID` / `ATOMIC_S3_SECRET_ACCESS_KEY` credentials, or use
instance credentials. `ATOMIC_S3_PREFIX` defaults to `blobs`;
`ATOMIC_S3_PATH_STYLE=true` selects path-style addressing for services such as
MinIO. HTTPS is required unless `ATOMIC_S3_ALLOW_HTTP=true` is explicitly set
for local testing.

Uploads, downloads, peer sync and image renditions all use the selected
backend. In S3 mode there is no local file cache or fallback: an unavailable
object store causes an error. The server checks read/write access before
serving traffic, then migrates existing database blobs one at a time, verifying
each remote copy before removing its local row. Database pages become reusable
but the database file may not shrink. Keep the bucket and prefix stable across
node replacements, and use an S3-capable binary for rollback after migration.

This is primary storage for hosted files. It does not provide client-encrypted
Vault backups, and the server still buffers file contents in memory while
proxying requests.
