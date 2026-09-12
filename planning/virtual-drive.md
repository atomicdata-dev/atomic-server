# Virtual Drive: Atomic as a Filesystem

**Status:** Shipped in the Tauri desktop app as a local NFS mount
(`desktop/src/vfs.rs`, first landed 2026-07-15, #1154) — see "Implementation
status" below for what is done. Still proposal: a mount from the headless
server, FUSE/WinFSP, native cloud-sync APIs, and the mobile providers.
Header corrected 2026-09-01; it previously said "Nothing built".

AtomicServer runs offline-first as a desktop app and syncs across devices.
A natural extension is to expose its hierarchy as a filesystem that the OS can
mount — similar to how Google Drive or Dropbox surface remote storage. Files
and folders inside the Atomic drive appear in Finder / Explorer / your file
manager; opening, editing, renaming, and moving them produces Atomic Commits
that flow through the existing sync protocol.

Benefits:

- Search the drive's contents through Atomic — by filename, folder,
  mimetype, size, ACL, or any property — for free. This works because
  everything in the mount is, by construction, an Atomic resource that the
  server already indexes; we are not scanning an external OS filesystem.
  Atomic Documents (Loro-backed rich text) are already text-extracted into
  the Tantivy index today (`server/src/search.rs`). Full-text search inside
  other binary formats (PDF, docx, images) rides on the planned **Atomizer**
  pipeline — see the [roadmap](../docs/src/roadmap.md) — and is not work the
  VFS itself takes on. The VFS just guarantees that every file landing in
  the mount becomes a normal Atomic resource and inherits whatever
  indexing exists.
- Share files and folders with collaborators using existing ACLs
- Use the Assistant to ask questions about your files
- Back up important data to multiple devices with content-addressed dedup
- Open arbitrary file types via OS apps; non-file resources still open in the
  Atomic UI via a stub file association

## Implementation status (desktop NFS)

Shipped in the **Tauri desktop app** (`desktop/src/vfs.rs`), not the headless
server — the embedded node mounts an in-process `nfsserve` v3 server at
`~/AtomicDrive`, toggled from Settings → Virtual drive. GitHub issue #1154.

Done:

- Read + write path (create / edit / rename / remove → signed commits), with
  the ~500 ms write-quiet debounce (commit coalescing) and a content-addressed
  no-op-commit skip.
- Content-defined chunking (FastCDC) for files > 4 MiB; small files stay a
  single whole-file blob. The server download path reconstructs chunked files.
- Stable fileids persisted to `Tree::PluginMeta`, minted in memory and written
  in one batched transaction off the hot path.
- Root lists the **signed-in agent's own drives** (`personalDrive` + agent
  `drives`), *not* every Drive (Sudo) — a synced node holds thousands the user
  can't open.
- Non-file/non-folder resources surface as read-only macOS `.inetloc` link
  files that open in Atomic desktop via an `atomic:open?subject=…` deep link.
- Listing performance: shallow (propvals-only) reads, a dir cache, and
  cache-backed `lookup`/`getattr` — a cold root listing of 2578 drives went
  from ~762 s to ~0.01 s.
- Read performance: a reconstruct-once read cache (keyed by fileid + whole-file
  hash) turns a sequential read-through from O(size²) back to O(size).

### Benchmarks

`#[ignore]` benches live in `desktop/src/vfs.rs` (`mod benches`). Run:

```
cargo test -p atomic-server-tauri --lib benches -- --ignored --nocapture
```

Indicative numbers on the dev machine (temp store, not the 2.1 GB real one):

| Bench | Result |
| --- | --- |
| Sequential read, 32 MiB / 1 MiB windows | 137 → **387 MiB/s** after the read-cache fix |
| Save (1-byte edit of 32 MiB, re-chunk + store) | ~28 MiB/s |
| 50 edits of a 256 KiB file | **+49 orphan blobs, +12.5 MiB, never GC'd** |
| Cold `readdir` of 1000 children | ~84 ms |

Known remaining perf gaps (see [Hard problems](#hard-problems-the-docs-dont-yet-resolve)):

- **No blob GC.** Every edit orphans the prior blob(s); storage grows
  unbounded. Needs refcounting or a sweep (blocked on the same design as
  s3-blob-storage.md Phase 1d).
- **Write amplification.** A 1-byte edit re-hashes and re-chunks the whole
  file (`store_bytes`), and the whole file sits in RAM in staging.
- **True range reads.** The read cache holds one whole file; interleaving two
  large files, or a single file bigger than comfortable RAM, still rebuilds
  per window. A real fix stores per-chunk sizes so `read` can fetch only the
  chunks covering `[offset, len)` — the `read ... with range` the mapping
  below always intended.

## Why the primitives already fit

Three pieces of existing work make this much smaller than it would otherwise
be:

1. **The blob / File split already models a filesystem.** `did:ad:blob:{blake3}`
   is bytes; the File resource is metadata plus ACL; folders are resources with
   `parent`. A virtual drive layer walks the parent tree to materialize
   directories, and for each File child either inlines the blob or presents it
   as a placeholder that pulls bytes on demand via `BLOB_REQUEST`. The
   content-addressed model means renames and moves don't move bytes — only a
   commit updates the File resource. Deduplication is free.

2. **The WS commit work solves the FS-watcher echo problem.** The OS-side mount
   is just another local client of the embedded server. Give it a
   `connection_id`, route its commits through the same `apply_commit_json`
   path, and the existing source-id suppression keeps it from reading its own
   writes back as `UPDATE` frames. No new mechanism is needed — same shape as
   a browser tab.

3. **DIDs give stable identity across devices.** A file's identity
   (`did:ad:{genesis}`) survives moving between drives, so the same file
   appearing in two paired devices is provably the same resource, not just
   "same name and size."

QR pairing is device handshake, not authorization — both devices are already
signed in as the same agent. Mounting your own drive on a second device needs
no consent flow. Cross-agent sharing is a separate problem — primitives and
trust model in
[`authorization-sync.md`](./authorization-sync.md#application-patterns);
handshake/UX notes in [`sync.md`](./sync.md).

## Platform layer — pick the abstraction

Three realistic paths, ordered by cost-to-ship.

### Option A — NFS server (recommended for v1)

Run a local NFS v3 server on 127.0.0.1; each OS mounts it with its built-in
NFS client. One Rust implementation covers macOS, Linux, and Windows Pro /
Enterprise. This is what `rclone` switched to on macOS once macFUSE got
painful, and what several Iroh-adjacent tools use.

- Crate: [`nfsserve`](https://crates.io/crates/nfsserve) — exposes a
  `NFSFileSystem` trait you implement against the store.
- Mount on startup:
  - macOS / Linux: `mount -t nfs -o nolocks,vers=3 localhost:/atomic ~/Atomic`
  - Windows: `mount \\127.0.0.1\atomic Z:`
- Downsides: NFS v3 has weak locking semantics, no native xattrs, Windows Home
  does not ship the client, and the drive shows up as a network mount (not
  cloud-sync UI). Acceptable for v1.

### Option B — FUSE + WinFSP

Most mature path for full POSIX semantics.

- [`fuser`](https://crates.io/crates/fuser) on Linux and macOS (via macFUSE).
- [`winfsp`](https://crates.io/crates/winfsp) on Windows (FUSE-like API; no
  kext needed on Windows because WinFSP is signed).
- Downside: macFUSE on Apple Silicon requires the user to weaken SIP. A real
  onboarding cliff.

### Option C — Native cloud-sync APIs

Best long-term UX (placeholder files, on-demand download, native Finder /
Explorer integration with sync-status overlays).

- macOS File Provider: no good Rust binding. Write a Swift extension that
  talks to atomic-server over a local socket or via `objc2` / `block2`.
- Windows Cloud Files API: same story via `windows-rs`.
- Linux: nothing native — fall back to FUSE.
- Months of work per platform. Defer until v1 proves the model.

**Recommendation:** start with A on desktop. Plan for C as the eventual
destination. B is a fallback for environments where NFS clients are
restricted. Mobile cannot use A or B at all and goes straight to C-shaped
provider APIs (see [Mobile platforms](#mobile-platforms-ios-and-android)) —
which is a reason to invest in the cross-platform VFS backend trait early,
since the mobile work will exercise it before any desktop native-API work
does.

## Integration into atomic-server

Add `server/src/vfs/` with two pieces.

### 1. `AtomicNfsFs` implementing `nfsserve::NFSFileSystem`

Each operation maps to a `Store` call:

- `readdir(parent_fileid)` — TPF query for resources with `parent = <did>`,
  filtered to Files and Folders.
- `getattr(fileid)` — read File properties, project into POSIX `fattr3`.
- `read(fileid, offset, len)` — `FileStore::read_blob(blob_did)` with range.
- `write(fileid, offset, data)` — buffer in a per-handle staging blob; on
  `close` / `commit`, hash with BLAKE3, write the blob, sign a Commit updating
  `File.blob` and `File.checksum`, and submit through `apply_commit_json`.
- `mkdir` / `create` / `rename` / `remove` — commits that mutate `parent`,
  `name`, or destroy the resource.

### 2. A VFS connection source-id

Generate one `connection_id` for the VFS at startup and pass it through
`CommitOpts` so the VFS does not receive echo `UPDATE`s for its own writes.
The plumbing for this exists from the WS commit work — reuse it directly.

### Cache invalidation (remote → VFS)

The inverse direction is the trickier half. NFS v3 has no server push, so
clients rely on attribute-cache TTLs (`actimeo`) and re-stat. This is
acceptable for v1 — bounded staleness on the order of seconds. FUSE and the
native APIs let you push invalidations explicitly when a remote commit
arrives; that's a v2 win, not a blocker.

### Auth

Local user equals the agent whose private key the daemon holds. Bind the NFS
listener to 127.0.0.1 and refuse non-loopback, matching the desktop pattern
already in use. **This is not isolation** — every local process gets full
agent-level access through the mount. See the [Security model](#security-model)
section for the full picture, including filename sanitization requirements
and admission-control invariants. For multi-user Linux hosts, prefer a Unix
domain socket with peer-credential verification over TCP loopback.

## Mapping Atomic resources to filesystem entries

- **File resource** → regular file. `filename` becomes the basename.
  Collisions within a parent: append ` (2)`, ` (3)` like Finder, or reject
  the commit at the VFS layer.
- **Folder resource** → directory.
- **Non-File resources** → `.atomic` JSON-AD stub files associated with the
  desktop app. Hide them behind a config flag if users find them noisy. The
  cleaner alternative is hiding non-File resources entirely, but then it
  isn't really a "drive of your Atomic data" — it's just a file-sync product.
- **Atomic properties beyond name / size / mtime** → xattrs where the FS
  supports them; otherwise drop from the FS view (still visible in the Atomic
  UI).

## Security model

The VFS does not add a new authorization layer; it projects the existing
Atomic ACL model onto a filesystem surface. The invariants below must hold
for any implementation, on any platform.

### Trust boundary

**Mounting equals delegating full agent capability to every local process.**
The VFS daemon holds the agent's private key and signs commits on behalf of
any process that writes through the mount. NFS v3 over loopback uses
`AUTH_UNIX`, in which the client asserts its own UID — a malicious local
process can claim any UID. This is the same model as Google Drive Desktop
and Dropbox: accepted, but not a security control. Loopback binding only
prevents off-host connections; it does not provide intra-host isolation.

State this clearly in user-visible documentation. Do not let the loopback
bind imply that there is per-app or per-user enforcement.

Stronger isolation, not v1:

- Unix domain socket with `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS)
  for per-user enforcement on multi-user hosts.
- Per-app entitlements require OS sandboxing (macOS App Sandbox, iOS,
  Windows AppContainer) and are out of scope for desktop v1.

### Filename sanitization

Atomic resource names are free-form Unicode strings. The VFS surface
demands FS-safe basenames. The mapping is **load-bearing** — every
cloud-sync product has had a path-traversal or filename-injection CVE
here. Apply at the materialization boundary, in one direction only (the
canonical name in Atomic remains the original string).

| Input | Action |
| --- | --- |
| `/`, `\`, NUL | Replace with U+FF0F (fullwidth solidus) or `_` |
| `..` or `.` as the entire name | Suffix with U+2024 (one-dot leader) |
| Control characters (U+0000–U+001F, U+007F) | Replace with U+FFFD |
| Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1–9`, `LPT1–9`) | Suffix with `_` |
| Trailing dot or space on Windows | Strip |
| > 255 bytes UTF-8 | Truncate at codepoint boundary, append short hash |
| Surrogate halves, non-characters | Replace with U+FFFD |
| RTL / bidi override (U+202A–U+202E, U+2066–U+2069) | Strip |

Two resources whose sanitized names collide get the `(2)` / `(3)` suffix
already described in [Mapping](#mapping-atomic-resources-to-filesystem-entries).

### ACL revocation latency

Commit-driven cache invalidation evicts VFS-layer entries immediately, but
the kernel page cache and the NFS attribute cache hold bytes and attrs for
seconds to minutes. A process that already held an open file descriptor
keeps reading until close. **ACL revocation is not real-time through the
VFS.** Document the limitation. Sub-second revocation requires unmount-
remount, or the explicit invalidation hooks that FUSE and the native
cloud-sync APIs provide.

### Stub file safety

`.atomic` JSON-AD stubs are pointers, not capabilities. The desktop app
**must not** auto-execute, auto-navigate, or perform agent-side actions
based on stub contents. A stub is untrusted input from whoever wrote it
(sync peer, local process, anyone with mount write access) and must be
treated like a `.url` file or `.desktop` file — display and require
explicit user action.

### Credential storage threat model

The "encrypted Secret with server-held DEK" design in
[s3-blob-storage.md](./s3-blob-storage.md) protects S3 credentials against
a leaked `/query` response or a backup of the redb file *without* its
sibling keystore. It does **not** protect against an attacker with local
disk read — DEK and Secret live on the same filesystem in the daemon's
state directory. State this explicitly so operators do not over-trust the
encryption.

### Admission control against hostile peers

A paired peer can push arbitrary numbers of resources into a synced drive.
The VFS surfaces every committed resource, so a malicious peer can DoS the
local mount by pushing pathological data: million-child folders, names
crafted to thrash caches, deep folder nesting. Hard caps must be applied
at commit-accept time, **not** at the VFS layer, so they also protect
non-VFS workloads (search, sync engine, browser pagination).

- Max children per parent (configurable; default ~100k).
- Max name length after sanitization (255 bytes).
- Max folder depth (default ~64).
- Max File resource size for in-RAM staging (default 100 MB; above this,
  spill to disk staging).

### iOS provider exposure

iOS File Provider extensions are accessible to **any iOS app** the user
opens a file in. Bytes flow through the standard share/picker UI to
whichever app receives them; there is no per-app allowlist. Same model as
iCloud Drive. Document this; there is no remediation other than choosing
not to expose sensitive drives through the provider.

## Mobile platforms (iOS and Android)

Neither mobile OS supports FUSE or NFS mounts. Both ship a system-level
provider API that, end-to-end, is closer to desktop Option C than to A or B —
so mobile lands in the same place desktop is eventually heading, just sooner.
A Flutter app already exists in the repo (`flutter/`), which sets the
host-app pattern: the embedded atomic-server compiles to a static library
linked into the mobile app, and a thin platform-native provider extension
shares that library.

### iOS — File Provider extension

Same API family as macOS File Provider, specifically
`NSFileProviderReplicatedExtension` (iOS 16+). The provider appears in the
Files app as a top-level location alongside iCloud Drive. Every "Open in…"
picker, Photos, Pages, and most third-party apps can read and write through
it.

Constraints that shape the design:

- The extension runs in a **separate process** from the host app, with a
  tight memory cap (~24 MB on older devices, more on recent ones). Cannot
  load a large in-memory store there.
- The extension can be killed and respawned at any time. Cold-start must be
  cheap.
- No background WebSockets. Push-triggered sync (APNs) plus fetch-on-open is
  the realistic model.
- Written in Swift; calls Rust over FFI.

Architecture: keep the embedded server running in the host Flutter app
whenever it is alive. The extension is a thin proxy that talks to the host
process via XPC or a Unix domain socket inside the App Group container. When
the host is not running, the extension opens a minimal read-mostly view
directly against the on-disk store — enough to satisfy `readdir` and
`getattr` and to stream blob bytes lazily — without booting the full sync
engine.

### Android — DocumentsProvider via SAF

Storage Access Framework with a `DocumentsProvider`. Shows up in the system
file picker and the Files app. Apps don't see it as a POSIX mount; they
request `content://` URIs through the picker and can hold long-lived
permission grants.

Constraints:

- Written in Kotlin; calls Rust over JNI.
- Reads and writes go through `openDocument` returning a
  `ParcelFileDescriptor`. For streamed I/O, a pipe pair backed by a worker
  thread.
- Background sync needs `WorkManager` or a foreground service. Same battery
  concerns as iOS.
- The provider lives in the host app's process — simpler than iOS, but
  cold-start latency still matters because the system file picker invokes it
  on demand.

Architecture: same shape as iOS, simpler because there is no separate
process. The embedded server lives in the host app; the DocumentsProvider is
a thin wrapper calling into it.

### Shared backend

Define a single `VfsBackend` trait inside `atomic-lib` (or a new
`atomic-vfs` crate) that all four frontends share:

- NFS server (`nfsserve`) — macOS / Linux / Windows desktop
- FUSE / WinFSP — alternative desktop path
- iOS File Provider extension (Swift, calls via FFI)
- Android DocumentsProvider (Kotlin, calls via FFI)

This is the same trait the macOS / Windows native APIs will eventually use,
so the mobile work is also the groundwork for desktop Option C.

### Tooling

- [`uniffi-rs`](https://crates.io/crates/uniffi) — generates Swift and Kotlin
  bindings from a Rust UDL. Mature; used by Firefox Sync, Matrix Rust SDK,
  and others. Better than hand-rolled FFI for an API that will be called
  from two platforms.
- [`cargo-ndk`](https://crates.io/crates/cargo-ndk) — Android cross-compile.
- [`cargo-lipo`](https://crates.io/crates/cargo-lipo) or `xcodebuild` for
  iOS universal static libraries.
- [`flutter_rust_bridge`](https://crates.io/crates/flutter_rust_bridge) —
  already worth considering for the Flutter app itself. The provider
  extensions run *outside* Flutter, so they should bind through uniffi
  rather than this.
- [`jni`](https://crates.io/crates/jni) and [`objc2`](https://crates.io/crates/objc2)
  for the small amount of platform-specific code that has to live below
  uniffi (lifecycle methods on the extension classes).

### Mobile-specific open questions

- **iOS extension memory budget.** The embedded sync engine probably
  exceeds it. Decide between (a) extension-as-proxy with the host app as
  the engine, (b) a stripped-down read-mostly engine in the extension, or
  (c) accepting that sync only happens when the app is open.
- **Background sync.** WS does not survive mobile suspension. Push (APNs /
  FCM) for "data changed, wake up" with WS reconnect on resume is the
  standard pattern but requires server-side push infrastructure — material
  scope outside the VFS itself.
- **Blob storage location on iOS.** Only the App Group container is shared
  between host app and extension. The blob path needs to live there from
  day one; migrating later is painful.
- **Conflict handling is worse on mobile.** Users routinely edit the same
  file across phone and laptop while offline. Conflicted-copy naming has to
  be solid *before* mobile ships, not after.
- **Android background services and battery.** A foreground service with a
  persistent notification is the most reliable option but the most
  user-hostile. `WorkManager` with constraint-based wake-ups is friendlier
  but less timely.

## Other crates

- [`notify`](https://crates.io/crates/notify) — only for Option C, where we
  push changes to the OS. Not needed for A or B; the OS calls us.
- [`tokio-uring`](https://crates.io/crates/tokio-uring) on Linux if blob reads
  become a bottleneck.
- BLAKE3 — already a dependency.
- [`lru`](https://crates.io/crates/lru) for a metadata cache that mirrors the
  kernel attribute cache, so `getattr` does not hit the store on every `ls`.

## Interaction with S3 blob storage

The VFS does blob I/O through `BlobBackend` (see
[s3-blob-storage.md](./s3-blob-storage.md)) and inherits S3 support for free
once that lands. The user-facing pitch — "give me your S3 creds and I back
up your files there cheaply" — is exactly the per-drive Phase 2 design in
that doc: a drive declares its own bucket and credentials, blobs for that
drive go to that bucket, and storage cost lives with the tenant. No new
mechanism is needed on the VFS side.

There are a few places where the two designs actually touch and need to be
designed together rather than independently:

- **Read latency dominates VFS UX when blobs live in S3.** A `cp -r` across
  a 1 GB folder pays 50–200 ms per blob if every byte round-trips through
  S3. The in-memory LRU planned in s3-blob-storage.md Phase 1c is necessary
  for the VFS to feel acceptable, not just nice-to-have. Size it generously
  by default on desktop (≥ 1 GB).
- **Eager materialization is dangerous.** NFS clients tend to prefetch
  directory contents and run `getattr` on every child. That's fine when
  metadata is local, but if the VFS were to also prefetch *bytes* of every
  visible file we would download (and pay egress for) every blob the user
  glances at. VFS reads must be strictly lazy: bytes only on actual `read`
  syscalls, never on `readdir` or `getattr`. Document this contract.
- **Placeholder UX needs native APIs.** Without iOS File Provider /
  Windows Cloud Files / macOS File Provider, the user has no UI signal
  that a file "is not yet local" — clicking it just hangs while S3
  downloads. This is one of the strongest arguments for prioritizing the
  Option C frontends, especially on mobile where the user is also paying
  for the bytes on a metered connection.
- **Presigned redirects don't directly help the NFS / FUSE read path.**
  Phase 3 of s3-blob-storage.md returns `302 Found` to HTTP clients. NFS
  and FUSE call `BlobBackend::get_stream` directly and pay full S3 egress
  through the desktop server. Where presigned URLs *do* land is the native
  cloud-sync APIs (iOS File Provider's `fetchContents`, Windows Cloud
  Files placeholder fetch, macOS File Provider's
  `fileProvider(_:fetchContentsFor:)`) — those can hand a presigned URL
  to the OS for direct download, bypassing the server. NFS/FUSE workloads
  need either generous local blob caching (the LRU at minimum, ideally a
  pin-on-disk policy for frequently-read blobs) or acceptance that bytes
  always proxy through the server.
- **GC matters more with the VFS in play.** Every file edit produces a new
  blob; binary editing churn (e.g. opening a docx, saving, opening, saving)
  generates orphan blobs fast. The mark-and-sweep design in
  s3-blob-storage.md Phase 1d should ship before the VFS goes
  read-write, otherwise users will see their S3 bill grow with no obvious
  cause.
- **Mobile metering.** On a phone with metered data, downloading a 500 MB
  blob because Files.app previewed a folder is a complaint waiting to
  happen. Mobile frontends need a "Wi-Fi only" gate at the VFS layer,
  applied before the `BlobBackend` is asked for bytes.

The split of responsibilities to keep clear: `BlobBackend` is *where bytes
live*, the VFS is *when and how bytes are requested*. The VFS does not need
to know what backend a drive uses — but it does need to assume that any
`read` may be slow and expensive, and design its prefetch and caching
accordingly.

## Caching layers

There are five conceptual cache layers in the read path once the VFS exists,
ordered from cheapest to most expensive on a miss:

1. **Kernel attribute / page cache.** Free, configured at mount time
   (`actimeo` for NFS, `entry_timeout` / `attr_timeout` for FUSE). A few
   seconds is the right default: the OS won't re-stat after every `ls`, but
   remote edits become visible without manual refresh.
2. **VFS metadata LRU (new).** In-process, keyed by `did:ad:...` → `FileAttr`.
   Sized in entries, not bytes. Invalidated on commit via the same `DbEvent`
   subscription that drives WS push.
3. **VFS directory-listing LRU (new).** Parent DID → children DIDs. Same
   invalidation policy. Critical because directory enumeration is the
   chattiest operation an OS does.
4. **Blob LRU.** Already planned in
   [s3-blob-storage.md](./s3-blob-storage.md) Phase 1c. The VFS just needs
   it sized generously (≥ 1 GiB on desktop) and is otherwise an unaware
   consumer.
5. **redb / `BlobBackend`.** The cold path. For S3-backed drives this is
   the 50–200 ms hop.

Two existing caches in the codebase do real work and the VFS should not
replicate:

- **Processed image renditions** (`server/src/handlers/download.rs:133–170`).
  Encoded WebP/AVIF results are stored back into `Tree::Blobs` under a
  deterministic content-derived key, so the rendition cache is itself
  content-addressed and is shared automatically between peers that produce
  the same output. When the VFS serves a thumbnail-like read with image
  params, this path is already efficient.
- **Watched-queries cache** (`lib/src/db.rs`). Powers WS live-query push and
  is what the VFS's commit-driven invalidation should subscribe to rather
  than reinventing.

### Caching things the VFS must *not* do

- **No prefetch of blob bytes on `readdir` or `getattr`.** Bytes only on
  actual `read` syscalls. Eager prefetch turns a folder glance into a
  multi-gigabyte S3 download.
- **No long-lived negative cache.** A short (< 1s) negative cache helps
  with autocomplete misfires, but anything longer hides files that just
  arrived via sync.
- **No cross-agent metadata cache reuse.** Each agent has its own ACL view;
  cache entries are scoped per agent. On a single-user desktop install this
  is one bucket, but the abstraction matters for the multi-tenant server
  case.

### Cache invariants

- All VFS caches drop entries on the `source_id`-aware commit notification
  path, regardless of whether the commit came from this connection or
  another. Self-originated commits already update the store before the
  notification fires, so re-reading is cheap.
- Mount-level cache statistics (`hit_rate`, `evictions`, `size`) should be
  exposed through the existing metrics surface (`lib/src/metrics.rs`) for
  operator visibility — caching mistakes in a VFS are very expensive and
  silent, and the easiest way to find them is a hit-rate chart.

## Performance considerations

The VFS turns Atomic commits from a human-paced event stream into a
machine-paced one. Several existing assumptions break at the new rate;
each needs an explicit countermeasure before the write path goes live.

### Write amplification on large files

Content-addressed storage means any byte change produces an entirely new
blob. A 1 KB write to a 1 GB file = 1 GB blob write + 1 GB BLAKE3 + 1 GB
S3 transfer + commit + index update. SQLite databases, log files,
mailboxes, and Electron app state all mutate large files in small
increments continuously. Without mitigation, a user dragging
`~/Library/Application Support` into the mount produces multi-GB-per-minute
churn.

Two viable paths:

- **Content-defined chunking (preferred long-term).** Store File resources
  as ordered concatenations of chunk-blobs (FastCDC or Rabin). Restic,
  borg, IPFS, and Tahoe all do this. A 1 KB edit in the middle of a 1 GB
  file re-uploads one ~1 MB chunk, not the whole file. Major design
  change: affects the `File` schema (`blob` becomes `chunks`, an ordered
  list), the HTTP download path (concatenate-on-stream), and the sync
  protocol (per-chunk `BLOB_REQUEST`).
- **Path-based exclusion (interim).** Ship a `.atomic.ignore` mechanism
  like `.dropbox.ignore` and document common patterns to exclude. Cheap,
  punts the problem to the user. Acceptable for an alpha but not for a
  general-purpose virtual drive.

**Decide this before writing the write path.** Refactoring chunking in
later requires migrating every existing File resource.

### Commit coalescing

VFS writes are machine-paced: editors invoke `write` dozens of times per
save; build systems and indexers produce thousands of writes per second.
The per-handle staging buffer already batches within an open file. Add a
write-quiet-period debounce (~500 ms) before committing, so an editor's
rapid open / write / write / close loop produces one commit, not one per
save. `fsync` semantics should flush immediately so applications that
demand durability still get it.

Without coalescing, the WS broadcast cost and Tantivy index churn alone
make the VFS unusable on a build server.

### Hash-then-write streaming

The naive write path: stage bytes to disk, re-read to compute BLAKE3,
write to the blob backend. Triple I/O on large files. Use BLAKE3's
incremental hashing during write for append-only patterns (the common
case for new files). Fall back to re-read only when the writer seeks
backwards.

### fileid ↔ DID storage

NFS and FUSE require stable `u64` fileids. DIDs are ~80-byte strings. A
1 M-resource drive needs a 1 M-entry bidirectional map. In RAM that is
~250 MB; on an iOS extension (24 MB cap) it is impossible. Use a
disk-backed map (a dedicated redb tree is fine) with an LRU front; accept
that cold lookups cost a redb read. Plan for this from the start — fileid
stability is part of the public protocol and cannot be patched in later.

### Readdir pagination and hard caps

Atomic does not bound children per parent. Without an indexed cursor, NFS
readdir cookies cause O(N²/page) enumeration on large folders. Two fixes,
both required:

- The TPF query for children must accept a cursor (`after = <last_did>`)
  resuming pagination in O(log N). This is likely needed for browser
  pagination too.
- The admission-control cap from the [Security model](#admission-control-against-hostile-peers)
  (e.g. 100k children) returns `EFBIG`-equivalent above the limit.

### Sync update fanout

Every commit broadcasts `UPDATE` to every subscriber of the touched
resource. With multiple paired devices and machine-paced VFS writes, a
single drive can produce thousands of outbound WS frames per second. Add
a per-subscriber debounce (~100 ms) at the broadcast layer. Mobile clients
on metered connections will otherwise see severe data and battery cost.
This change benefits sync.md's broader load profile too.

### iOS extension cold-start budget

Files.app expects sub-100 ms responses. Loading the full sync engine on
the extension cold path does not fit. The extension's read-only fallback
must:

- Open redb with no migrations or warmup.
- Skip rebuilding the watched-queries cache (only needed for live push).
- Defer Tantivy index opening until first search query.
- Respond to `readdir` and `getattr` from a minimal handler that does
  only the necessary store lookups.

Target: < 100 ms to first response on a typical phone, measured under
throttled-disk conditions. Numbers, not adjectives.

### NFS attribute cache (`actimeo`)

Consumer macOS NFS clients default to `actimeo=60` — remote edits remain
invisible for up to a minute. Overriding via mount-time flags is not
universally honored, and Finder-initiated mounts inherit the OS default.
**Validate empirically per OS** before promising bounded staleness in
seconds.

### Per-commit signature verification cost

Commits flow over WS as JSON-AD. Every VFS write triggers full Ed25519
verification plus JSON parsing on the server. At human rates this is
invisible; at VFS rates it is measurable. The v2 binary commit format
deferred in [sync.md](./sync.md) becomes more pressing once the VFS is
the dominant commit source.

## Hard problems the docs don't yet resolve

- **Non-file resources on disk.** `.atomic` stubs leak the abstraction (users
  will try to edit them in a text editor). The cleaner alternative — hide
  non-File resources entirely — costs the "Atomic as your filesystem" pitch.
  Worth a deliberate decision before v1 ships.
- **Binary file conflicts.** CRDTs help for structured resources but not for
  `.psd` or `.docx`. Need Dropbox-style conflicted-copy naming, because
  last-write-wins on binary bytes silently destroys work.
- **Cross-agent share UX.** The pairing-UX gap in [sync.md](./sync.md) gets
  worse when "share" means mounting someone's folder tree on your filesystem.
  Close that gap before exposing cross-agent shares through the VFS.
- **Blob lifecycle.** File → blob is a forward reference and the CAS docs do
  not describe GC. A virtual drive that rewrites files constantly will
  accumulate orphan blobs fast. Refcounting or a sweep pass is required —
  not VFS-specific but the VFS will surface the need immediately.
- **Rendition cache vs. blob GC.** Processed image renditions
  (`server/src/handlers/download.rs:133–170`) are stored in `Tree::Blobs`
  under content-derived keys, but **no `File` resource references them.**
  The mark-and-sweep GC in [s3-blob-storage.md](./s3-blob-storage.md)
  Phase 1d walks File resources and deletes anything not in the
  referenced-hash set — it will eat the entire rendition cache on its
  first run. Fix before either ships: move renditions to a separate redb
  tree, or add an allow-list in GC for the content-derived cache-key
  namespace. Cheap fix; needs to be made deliberately, not discovered in
  production.
- **Write-amplification mitigation strategy.** See
  [Performance considerations](#write-amplification-on-large-files). The
  choice between content-defined chunking and a `.atomic.ignore` mechanism
  has to be made before the write path lands; chunking is hard to retrofit.

## v1 slice

Two tracks, sharing the `VfsBackend` trait.

**Desktop (NFS):**

1. **Read-only NFS mount.** Lists folders, serves blob bytes on `read`.
   Validates OS integration and the Store → VFS mapping. ~1–2 weeks.
2. **Writes.** `write` / `create` / `rename` / `remove`, routing through
   `apply_commit_json` with a VFS source-id. ~1–2 weeks.
3. **Conflict handling.** On commit rejection (remote version differs), write
   the local version back as `filename (conflicted copy from <device>).ext`
   and re-fetch the remote.
4. **Blob GC sweep.** Separate task; not VFS-specific but newly urgent.

**Gating items before step 2 (the write path) goes live:**

These are not optional and should not be discovered in production. Several
also benefit the rest of the system independently.

- **Filename sanitization** per the
  [Security model](#filename-sanitization) table. Without this the write
  path is a path-traversal vulnerability.
- **Write-amplification decision.** Content-defined chunking vs.
  `.atomic.ignore` — pick one before writing the write path. See
  [Performance considerations](#write-amplification-on-large-files).
- **Commit coalescing.** Per-handle write-quiet-period debounce. Without
  this the WS broadcast cost alone makes machine-paced workloads
  unusable.
- **Admission-control caps** on the commit path (children-per-parent,
  name length, folder depth, max in-RAM file size). Protects all
  workloads against pathological data from hostile peers.
- **Rendition cache namespace fix** in
  [s3-blob-storage.md](./s3-blob-storage.md). Otherwise the first GC run
  destroys every cached thumbnail.
- **Readdir cursor support** in the TPF child query, so large folders
  don't quadratic-scan during NFS pagination.
- **fileid ↔ DID storage decision.** Disk-backed redb tree with LRU
  front, not a pure in-memory map. Cannot be retrofitted later (fileid
  stability is on the wire).

**Mobile (after desktop step 2 stabilizes the `VfsBackend` trait):**

5. **uniffi bindings for `VfsBackend`.** Generate Swift + Kotlin bindings,
   wire into the existing Flutter app's Rust build.
6. **Android DocumentsProvider, read-only.** Validates the JNI path and the
   Files-app integration. Simpler of the two mobile targets; do it first.
7. **iOS File Provider extension, read-only.** Decide and prototype the
   extension ↔ host-app IPC model on the way in. Higher complexity due to
   the separate-process and memory-cap constraints.
8. **Mobile writes.** Same commit path as desktop, but with mobile-specific
   battery and background-execution guards.

Holding off on the macOS / Windows native cloud-sync API frontends until
desktop steps 1–3 and mobile steps 6–7 are real means the data model is
proved out across five frontends sharing one `VfsBackend` before any
platform-specific cloud-sync code lands.

## Open questions

- Where does the VFS live in the binary — always-on inside `atomic-server`,
  or a separate `atomic-mount` daemon talking to the server over the existing
  HTTP / WS APIs? The latter keeps `atomic-server` itself headless and lets
  the desktop app ship the mount as an optional component.
  - *Desktop-daemon note (folded from the deleted `on-device-atomic-daemon.md`,
    2026-09-01).* That plan proposed one local daemon per device that owns
    the redb store, the agent secret and the Iroh node, with every app on the
    device (data-browser, the desktop shell, this mount, third-party apps) as
    an ordinary HTTP/WS client of `localhost`. Its four hard problems still
    apply if the mount becomes a separate process: a single redb owner (two
    processes cannot open the store), process lifecycle (who starts and
    supervises the daemon), and — the one that decides the key question
    above — *localhost is not trust*: any local process can reach a
    localhost port, so a daemon holding the agent key must hand out
    delegated per-app credentials rather than sign as the user for whoever
    connects. On Android this went the Binder/`ContentProvider` route
    ([`android-data-reuse.md`](./android-data-reuse.md)); on desktop, where
    the Tauri app already runs the server in-process and the NFS mount lives
    in `desktop/src/vfs.rs`, the daemon split stays an option, not a plan.
- Drive selection: one mount per Drive, or a single root that lists all
  Drives the agent has access to as top-level directories?
- How are blobs cached locally for offline use — full mirror, LRU eviction,
  or pinned-by-folder?
- What does the placeholder story look like before we have native cloud-sync
  APIs? NFS can lazy-fetch blobs on `read`, but the user has no way to see
  "this file is not yet local."
- How is the agent's signing key surfaced to the VFS daemon, and what
  process boundary protects it? On a single-user desktop this is moot
  (daemon process == user process), but the question becomes real for
  multi-user Linux and for any future per-app entitlement model.
- Should the v1 mount be read-only by default, opt-in to read-write? The
  gating items above are substantial; shipping read-only first lets the
  data-model integration prove out without exposing the write surface
  while the chunking and coalescing decisions are still being made.
