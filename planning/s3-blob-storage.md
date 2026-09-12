# Implementation status — September 12

Server-wide S3 file storage is implemented; the original roadmap below contains
future phases and is not an as-built specification.

- [x] Async blob backend, default local database for standalone/browser use.
- [x] S3 backend for all server upload/download, preview, plugin and peer-sync paths.
- [x] Fail startup on invalid S3 config or failed read/write readiness.
- [x] Verified, resumable migration of local blobs at startup, one blob in memory
  at a time, before serving requests. No local fallback/cache in S3 mode.
- [x] Remote HEAD for size accounting instead of downloading file contents.
- [x] SaaS requires S3; deployment and provisioning share a hosted-blobs namespace.
- [x] Tests for HTTP upload/download, image previews, peer frames, node replacement,
  migration verification, and storage failure without local writes.
- [ ] Streaming/proxy range requests and direct presigned downloads.
- [ ] Blob garbage collection and per-tenant buckets.
- [ ] Encrypted Vault attachment backup/recovery (separate from hosted primary storage).

Configuration: `ATOMIC_BLOB_BACKEND=redb|s3` (default redb), `ATOMIC_S3_BUCKET`,
`ATOMIC_S3_REGION`, `ATOMIC_S3_ENDPOINT`, paired `ATOMIC_S3_ACCESS_KEY_ID` /
`ATOMIC_S3_SECRET_ACCESS_KEY`, optional `ATOMIC_S3_PREFIX` (default blobs),
`ATOMIC_S3_PATH_STYLE=true|false`, `ATOMIC_S3_ALLOW_HTTP=true|false` (test only).
Credentials may be omitted for the object store instance credential provider.
No hybrid mode or disk cache is implemented. Files remain normal hosted bytes;
this is not client-side Vault encryption. Keep hosted prefixes outside Vault GC.

When migration removes local rows, redb can reuse the pages; physical file
shrinking and old filesystem backups require separate operator maintenance.
New large uploads and downloads still buffer one object in RAM.

The ignored `s3_files_survive_node_replacement` test takes the above environment
pointing to a scratch S3 bucket. Standard tests use an in-memory object service;
SaaS representative CI runs the real S3-compatible test against MinIO.

---

# S3-compatible Blob Storage

**Status:** Proposal. Nothing built.

## Problem

`Tree::Blobs` (the content-addressed store for file bytes, keyed by BLAKE3 hash) currently lives inside the same redb instance as resources, indexes, and Loro snapshots. That works for a single-server install with modest file volume, but it conflates two very different storage workloads:

- **Metadata / indexes / CRDT state** — small, transactional, range-scanned, latency-critical, must stay in-process.
- **File bytes** — large, opaque, accessed by hash, compresses badly, dominates disk usage.

Forcing both into one redb file means: backups grow with file uploads, multi-server deployments need to copy every blob, and we cap practical drive size at whatever fits on a single disk. Worse, redb's transaction model is wrong for blobs — there is no benefit to transactional writes here, only the cost of locking out other writers while a multi-megabyte upload commits.

## Goals

- Move `Tree::Blobs` to a pluggable backend that can target any S3-compatible object store (AWS S3, Cloudflare R2, MinIO, Backblaze B2, Wasabi, Azure Blob via gateway, GCS via interop).
- Keep redb for everything else.
- Keep the wire protocol (`BLOB_REQUEST` / `BLOB_RESPONSE`) and the `/download/files/<hash>` endpoint unchanged from the client perspective.
- Support both **server-wide** configuration (operator sets one bucket via env vars) and **per-tenant** configuration (drives declare their own bucket, tenants own their storage).
- Ship in phases that are individually deployable; migration must be zero-downtime.

## Non-goals (v1)

- Presigned-URL direct downloads from S3 (CORS, auth, logs — separate effort, see Phase 3).
- Erasure coding or cross-region replication.
- Per-blob encryption with per-tenant keys (rely on S3-side SSE for v1).
- Browser/WASM ClientDb using S3 directly. Browser keeps using its in-OPFS redb. The unit of replication is the BLAKE3 hash, not the storage medium.

## Architecture

### The `BlobBackend` trait

Today, `lib/src/sync/engine.rs:518` and `server/src/handlers/upload.rs` call `store.kv.insert(Tree::Blobs, hash, bytes)` and `store.kv.get(Tree::Blobs, hash)` directly. That tight coupling between blob storage and the KV store is the thing to break first.

```rust
// lib/src/db/blob_backend.rs
#[async_trait]
pub trait BlobBackend: Send + Sync {
    async fn get(&self, hash: &[u8; 32]) -> AtomicResult<Option<Vec<u8>>>;
    async fn put(&self, hash: &[u8; 32], bytes: &[u8]) -> AtomicResult<()>;
    async fn has(&self, hash: &[u8; 32]) -> AtomicResult<bool>;
    async fn delete(&self, hash: &[u8; 32]) -> AtomicResult<()>;

    /// Streaming variant for /download — avoids buffering large blobs in RAM.
    async fn get_stream(&self, hash: &[u8; 32])
        -> AtomicResult<Option<BlobStream>>;
}
```

`Db` gains a `blob_backend: Arc<dyn BlobBackend>` field. All blob call sites switch from `kv.get(Tree::Blobs, ...)` to `blob_backend.get(...).await`.

Three implementations:

| Impl | Purpose |
| --- | --- |
| `RedbBlobBackend` | Wraps `Tree::Blobs`, today's behavior. Default. |
| `ObjectStoreBlobBackend` | Backed by [`object_store`](https://docs.rs/object_store) — covers S3, R2, MinIO, B2, Azure, GCS, and a local-filesystem variant for tests. |
| `HybridBlobBackend` | Read-through cache: try local, fall back to remote, optionally write-back. Bridges live migrations. |

**Why `object_store`** instead of `aws-sdk-s3`: one dependency, one config surface, all S3-compatible providers, plus the local-fs backend keeps dev workflows working without code changes. Tradeoff: thinner abstractions than the AWS SDK, less tuning surface (multipart upload internals, intelligent tiering). For our blob workload — write-once, read-mostly, BLAKE3-keyed — the abstraction loss is irrelevant.

### Phase 1: Server-wide config

Operator sets env vars (mirroring existing `ATOMIC_*` style):

```
ATOMIC_BLOB_BACKEND       = redb | s3 | hybrid           (default: redb)
ATOMIC_S3_ENDPOINT        = https://s3.amazonaws.com     (or R2/MinIO endpoint URL)
ATOMIC_S3_REGION          = us-east-1
ATOMIC_S3_BUCKET          = my-atomic-blobs
ATOMIC_S3_ACCESS_KEY_ID   = AKIA...                      (or omit to use IAM role)
ATOMIC_S3_SECRET_ACCESS_KEY = ...
ATOMIC_S3_PREFIX          = optional/key/prefix          (multiple servers per bucket)
ATOMIC_S3_PATH_STYLE      = true                         (MinIO and some R2 setups need this)

ATOMIC_BLOB_DOWNLOAD_MODE = proxy | redirect             (Phase 3: redirect for presigned)
ATOMIC_BLOB_CACHE_BYTES   = 1073741824                   (in-memory LRU in front of S3)
```

Validation on startup:

- If `ATOMIC_BLOB_BACKEND=s3` and any required S3 var is missing → refuse to start with a clear error message.
- On boot, do a `HEAD bucket` to confirm credentials and connectivity. Discovering bad creds at first upload is a much worse failure mode.

Wire-up lives in `server/src/appstate.rs` next to `init_redb_file`: build the `BlobBackend` from config, hand it to `Db`.

### Phase 2: Per-tenant config

The `Drive` resource gains optional properties:

```
https://atomicdata.dev/properties/blob-backend         = "s3"
https://atomicdata.dev/properties/s3-endpoint
https://atomicdata.dev/properties/s3-region
https://atomicdata.dev/properties/s3-bucket
https://atomicdata.dev/properties/s3-prefix
https://atomicdata.dev/properties/s3-credentials       → did:ad:secret:...
```

The `s3-credentials` property points to a separate `Secret` resource (new class), never an inline string. The `Secret` resource holds an encrypted blob using a server-held data-encryption key. Read access is restricted to:

- The agent that created the Secret.
- The server itself (must decrypt to make S3 calls on the agent's behalf).

Resolution at request time:

1. Resource being uploaded/downloaded → walk to its drive (existing parent-tree helper in `class_extender.rs`).
2. Drive resource → check for `blob-backend` property.
3. If present, build (or fetch from cache) a per-drive `BlobBackend` instance.
4. Otherwise fall through to the server default backend.

Cache the per-drive backends in an `Arc<RwLock<HashMap<DriveSubject, Arc<dyn BlobBackend>>>>` on `Db`. Invalidate on commit to the drive resource (hook into the existing `class_extender` after-commit path).

#### Hard questions to resolve before Phase 2 ships

- **Test-on-write.** When a user adds S3 creds to their drive, validate by uploading a tiny canary blob (e.g. `blake3("atomic-canary")`) before persisting the commit. Without this, users save broken config and only discover it on the next file upload — confusing.
- **Stale credentials.** If creds rotate and stale ones remain in the drive resource, we should surface `503 Backend Unavailable` with `WWW-Authenticate: blob-backend-rejected` so the client knows to ask the user to re-enter. Don't silently fall back to the server default (that would leak data into the operator's bucket).
- **Cross-server sync of creds.** A drive on server X synced to server Y carries the `s3-credentials` reference, but Y can't decrypt the `Secret` (different server-held key). So secrets must be re-provided per server. Document this prominently — it's a footgun otherwise.
- **Sudo bypass.** Sudo (the operator) can decrypt any Secret because it holds the master key. That's acceptable — operators can already read the redb file directly. But every Secret read must be logged with the requesting agent.

## Migration

Existing blobs in `Tree::Blobs` (or on disk under `uploads/`) need to migrate. Two complementary paths:

### Lazy (zero-downtime)

`HybridBlobBackend` reads from both, writes to the new backend, lazily backfills:

```rust
async fn get(&self, hash: &[u8; 32]) -> AtomicResult<Option<Vec<u8>>> {
    if let Some(b) = self.remote.get(hash).await? {
        return Ok(Some(b));
    }
    if let Some(b) = self.local.get(hash).await? {
        let _ = self.remote.put(hash, &b).await; // copy-on-read, best effort
        return Ok(Some(b));
    }
    Ok(None)
}
```

Operator flips `ATOMIC_BLOB_BACKEND=hybrid`. Hot blobs migrate themselves under load. Cold blobs stay in redb until either the eager command runs or they're requested.

### Eager (admin command)

```
atomic-server migrate-blobs --from redb --to s3 [--delete-source]
```

Walks `Tree::Blobs` with `iter_tree`, uploads each blob, optionally deletes from redb after verifying the upload (HEAD + size match). Idempotent; can resume after interruption (skips blobs already present in destination).

Operators run lazy first (flip the switch, observe), then eager when they're ready to reclaim disk.

## GC / refcounting

CAS means deleting a `File` resource cannot blindly delete its blob — another resource may reference the same hash (intentional or via the natural dedup property of CAS). Today there is **no GC at all**: blobs accumulate forever. Adding S3 forces this conversation because S3 storage costs real money.

Approach:

- **Don't refcount inline.** Refcounts are fragile under crashes, sync, or concurrent destroys.
- **Periodic mark-and-sweep.** Walk all `File` resources (cheap — they're a known class), collect BLAKE3 hashes into a `HashSet<[u8; 32]>`, then iterate the blob backend and delete anything not in that set.
- **Configurable cadence and grace period.**

```
ATOMIC_BLOB_GC_INTERVAL = 24h
ATOMIC_BLOB_GC_GRACE    = 72h    # don't delete blobs younger than this
```

The grace period protects against races: a client uploads a blob via `BLOB_RESPONSE` before the corresponding `File` resource has fully committed; GC must not kill it.

- **Admin command** for visibility: `atomic-server gc-blobs --dry-run` reports candidates without deleting.

This applies to the redb backend too — it's a pre-existing gap. Worth doing in Phase 1 as a cleanup pass that's not S3-specific. S3 then inherits it.

## Sync engine changes

`lib/src/sync/engine.rs:506-525` checks `store.kv.contains_key(Tree::Blobs, ...)` synchronously inside a hot loop. With S3, every miss costs a network round trip (50–200ms typical, much worse cross-region). Three changes:

1. **Replace direct KV calls.** `store.kv.contains_key(Tree::Blobs, ...)` becomes `store.blob_backend.has(hash).await`.
2. **In-memory LRU in front.** Configured via `ATOMIC_BLOB_CACHE_BYTES`. For sync, this is dominated by hot blobs (recently uploaded files), so a small cache has high hit rate.
3. **Pipeline blob requests.** The QUIC peer path at `lib/src/sync/peer.rs:790` writes blob request frames sequentially. Switch to issuing them all eagerly and letting responses come back interleaved. WS already does this; verify and fix any lingering serialization.

Browser clients are unaffected — they don't talk to S3, the server proxies on their behalf via `BLOB_RESPONSE`.

## Download endpoint

`server/src/handlers/download.rs` has the new CAS shortcut at line 39 (added in the unified upload refactor). Today it reads bytes via `appstate.store.kv.get(Tree::Blobs, ...)` and returns them in the response body. Two adjustments:

1. **Stream from backend.** Switch to `appstate.store.blob_backend.get_stream(hash).await` and pipe into `HttpResponse::Ok().streaming(...)`. Avoids buffering 100MB videos in RAM.
2. **Optional redirect mode** (Phase 3). When `ATOMIC_BLOB_DOWNLOAD_MODE=redirect`, generate a presigned URL (5-minute expiry, `GET`-only) and return `302 Found`. Bypasses the server entirely for byte transfer. Caveats:
   - Won't work cross-origin without CORS on the bucket. Document required CORS rules.
   - Exposes the bucket URL to clients. Some operators consider this a leak.
   - Default stays `proxy`. Redirect is opt-in.

## Testing

- **Unit tests.** Implement `MemoryBlobBackend` for in-test use. The existing flow already exercises `RedbBlobBackend`.
- **S3 integration via MinIO.** Extend `browser/lib/tests/server-fixture.ts`: when `ATOMIC_TEST_S3=1`, spin up MinIO via `docker run -d --rm -p :9000`, set the `ATOMIC_S3_*` env vars on the spawned `atomic-server`, run the same upload-roundtrip tests. Same tests, different backend — proves equivalence.
- **Hybrid migration test.** Start with redb backend, populate blobs, switch to hybrid, assert reads succeed and blobs migrate to S3 lazily and that the eager admin command completes the rest.
- **Failure injection.** Configure MinIO to return `503` on a percentage of requests; assert the server retries appropriately and surfaces useful errors.

## Phasing

| Phase | Scope | Unblocks |
| --- | --- | --- |
| **1a** | Add `BlobBackend` trait, refactor existing redb code behind it. **No behavior change.** | All later phases. |
| **1b** | `ObjectStoreBlobBackend` + env-var config for server-wide. `HybridBlobBackend` for migration. | Self-hosters with one S3 bucket — the 80% case. |
| **1c** | Streaming downloads (`get_stream`), in-memory LRU cache. | Reduces server RAM and S3 read costs on hot paths. |
| **1d** | Mark-and-sweep GC + admin command. | Reclaims storage. Not S3-specific but blocked-by-it in practice. |
| **2a** | `Secret` resource class + property-level encryption with server-held key. | Per-tenant credentials without leaking via `/query`. |
| **2b** | Per-drive backend properties + cache + creds-validation hook. | True multi-tenant blob isolation. |
| **3** | Presigned-URL redirect downloads. CORS documentation. | Bandwidth offload for large files; lower egress costs. |

Ship 1a–1c as one PR series. Phase 2 is a separate design conversation — the `Secret` resource is the hard part, not the S3 plumbing.

## Open questions

- **Multipart upload threshold.** Files >5GB require multipart on AWS S3. We currently buffer the entire upload in RAM (`upload.rs:88-95` after the recent CAS refactor). Two options:
  - Hard cap via `ATOMIC_MAX_UPLOAD_BYTES=5gb`, fail above.
  - Streaming hash + multipart upload — real work but unblocks large files.
  Lean toward the cap initially, with a follow-up for streaming once there's demand.
- **Should the WASM client know about S3?** No, for v1. The browser uploads to the server, server hashes + stores in S3, server serves downloads. If we ever want browser-direct-to-S3 (presigned PUT), that's a separate design (CORS, auth, hash verification on the server side after the fact).
- **Per-drive backend selection at the property level vs the resource level.** A drive could conceivably want some files in S3 and others local (e.g. preview thumbnails locally for speed). v1 punts: backend is per-drive, not per-file. If a use case emerges, add a `blob-backend-override` property on `File` resources later.
