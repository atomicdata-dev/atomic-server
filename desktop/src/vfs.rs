//! Virtual Drive: mount your Atomic drives as a filesystem over local NFS v3.
//!
//! Desktop feature from `planning/virtual-drive.md`: a read-write NFS server
//! bound to loopback that the OS mounts. The mount root lists every Drive the
//! node can see, Folders are directories, and Files stream their blob bytes.
//! Neither mobile OS can mount NFS, so this module is compiled only on desktop
//! (see the `cfg` gate on `mod vfs` in `lib.rs`).
//!
//! **Reads** are lazy (bytes only on `read`, never on readdir/getattr).
//!
//! **Writes** stage bytes in RAM and commit them once the file has been quiet
//! for `WRITE_DEBOUNCE` (commit coalescing, so an editor's write burst is one
//! commit, not one per syscall). `create`/`mkdir`/`remove`/`rename` map to
//! ordinary signed commits. Commits are signed by the store's default agent —
//! which the desktop app sets to the signed-in user via `adopt_agent` — so
//! writes are attributed to the user and sync with the user's rights.
//!
//! Addressed here: filename sanitization at the materialization boundary,
//! commit coalescing, admission caps (max file size, name length), persisted
//! stable fileids, a per-directory listing cache (paging is O(N) per enumeration
//! rather than O(N²)), and content-defined chunking so a small edit to a large
//! file rewrites only the changed chunks (`chunks` File property; large files
//! only).
//!
//! Deferred (see the doc): a *store-level* `readdir` cursor (O(log N) per page
//! via an index range-seek — the cache here removes the per-page re-scan but
//! still fetches the whole listing once, and a real cursor would also help
//! browser pagination); and conflicted-copy naming for concurrent binary edits.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use atomic_lib::db::trees::{Method, Operation, Tree};
use atomic_lib::values::SubResource;
use atomic_lib::{urls, Db, Resource, Storelike, Subject, Value};
use nfsserve::nfs::{
  fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, set_size3, specdata3,
};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};

/// The synthetic mount root. Its children are the node's Drives. Real resources
/// get ids >= 2 from the id map.
const ROOT_ID: fileid3 = 1;

/// Loopback address + port the NFS server listens on. The OS mounts it with
/// `port=`/`mountport=` pointing here, so no privileged (<1024) port is needed.
pub const NFS_ADDR: &str = "127.0.0.1:11111";

/// Permission bits. Read-write now: dirs traversable + writable, files
/// read/write. World-accessible so the mount works regardless of which uid the
/// NFS client asserts over AUTH_UNIX.
const DIR_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;
/// Read-only: link (`.inetloc`) files have generated content, not editable bytes.
const LINK_MODE: u32 = 0o444;

/// Admission caps (a subset of `planning/virtual-drive.md`'s hostile-peer
/// limits). Bytes are staged in RAM until flushed, so bound file size; bound the
/// FS name length too.
const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 255;

/// Content-defined chunking (FastCDC): files larger than the threshold are
/// stored as an ordered list of variable-size chunk-blobs, so a small edit
/// rewrites only the changed chunks (and unchanged chunks dedupe by hash)
/// instead of a whole-file blob. Smaller files stay a single blob.
const CHUNK_MIN: u32 = 256 * 1024;
const CHUNK_AVG: u32 = 1024 * 1024;
const CHUNK_MAX: u32 = 4 * 1024 * 1024;
const CHUNK_THRESHOLD: usize = CHUNK_MAX as usize;

/// Commit coalescing (the doc's gating item): a file is committed once its
/// writes have been quiet for this long, so an editor's open/write*/close burst
/// produces one commit, not one per `write` syscall.
const WRITE_DEBOUNCE: Duration = Duration::from_millis(500);
/// How often the flusher wakes to look for quiesced files.
const FLUSH_TICK: Duration = Duration::from_millis(250);

/// A file being written: bytes accumulate here across `write` syscalls and are
/// committed (hashed → blob → signed commit) once quiet. Reads and getattr see
/// the staged bytes so an editor's write-then-read is consistent before flush.
struct StagedFile {
  subject: String,
  data: Vec<u8>,
  dirty: bool,
  last_write: Instant,
}

/// Per-mount write staging, shared between the filesystem (which fills it) and
/// the background flusher (which drains it).
#[derive(Default)]
struct Staging {
  files: Mutex<HashMap<fileid3, StagedFile>>,
}

/// How long a cached directory listing is reused. A fresh `ls` always starts at
/// cookie 0, which rebuilds the listing, so this only bounds staleness within a
/// single multi-page enumeration.
const DIR_CACHE_TTL: Duration = Duration::from_secs(5);

/// A directory's children, built once per enumeration and paged from, so a
/// large folder isn't re-fetched and re-sorted on every `readdir` page (which
/// would be O(N²)). `DirEntry` isn't `Clone`, so its parts are cached and the
/// entry is rebuilt per page.
struct DirListing {
  at: Instant,
  entries: Vec<(fileid3, filename3, fattr3)>,
}

// Persistent-map key namespaces inside `Tree::PluginMeta`.
const ID_SUBJECT_TO_ID: &[u8] = b"vfs:s2i:";
const ID_ID_TO_SUBJECT: &[u8] = b"vfs:i2s:";
const ID_NEXT: &[u8] = b"vfs:next";

/// Bidirectional `fileid3 <-> Subject` map. NFS needs small `u64` file ids that
/// are **stable across restarts** (the OS and NFS clients cache them and assume
/// they never change for a given file); Atomic subjects are long strings. The
/// mapping is persisted in the store's `PluginMeta` tree so a file keeps its id
/// across remounts, with an in-memory cache in front so getattr/read don't hit
/// the kv store on every call. `get_or_alloc` also mints the id for a freshly
/// created resource (`create`/`mkdir`).
struct IdMap {
  store: Db,
  cache: Mutex<IdCache>,
  /// Ids minted since the last `persist_pending`, waiting to be written to the
  /// store in a single batched transaction. Kept off the hot path because each
  /// separate kv write is its own redb commit; minting 3 keys per entry
  /// synchronously turned a directory listing into hundreds of commits that
  /// contend with the live server's writer (see `persist_pending`).
  pending: Mutex<Vec<(fileid3, String)>>,
}

#[derive(Default)]
struct IdCache {
  to_subject: HashMap<fileid3, String>,
  to_id: HashMap<String, fileid3>,
  /// Next id to hand out; lazily loaded from `ID_NEXT` on first allocation.
  next: Option<fileid3>,
}

impl IdMap {
  fn new(store: Db) -> Self {
    IdMap {
      store,
      cache: Mutex::new(IdCache::default()),
      pending: Mutex::new(Vec::new()),
    }
  }

  /// Return the stable id for a subject, minting (and persisting) one if this is
  /// the first time we've seen it.
  fn get_or_alloc(&self, subject: &str) -> fileid3 {
    let mut cache = self.cache.lock().unwrap();

    if let Some(id) = cache.to_id.get(subject) {
      return *id;
    }

    // Reuse the persisted id if this subject was seen in a previous session.
    if let Some(id) = self.read_persisted_id(subject) {
      cache.remember(id, subject);

      return id;
    }

    // Mint the next id and persist both directions + the counter.
    let next = cache.next.unwrap_or_else(|| {
      self
        .read_u64(ID_NEXT)
        // 1 is the synthetic root; real resources start at 2.
        .unwrap_or(ROOT_ID + 1)
    });
    let id = next;
    cache.next = Some(next + 1);
    cache.remember(id, subject);
    drop(cache);

    // Persist off the hot path — see `pending` / `persist_pending`. The id is
    // already usable from the in-memory cache; durability only matters across
    // remounts, and a lost-on-crash id just gets re-minted next session.
    self.pending.lock().unwrap().push((id, subject.to_string()));

    id
  }

  /// Write every id minted since the last call in a single batched transaction,
  /// instead of one redb commit per key. Called after a listing is built and
  /// after create/mkdir; a no-op when nothing is pending.
  fn persist_pending(&self) {
    let pending: Vec<(fileid3, String)> = {
      let mut p = self.pending.lock().unwrap();
      if p.is_empty() {
        return;
      }
      std::mem::take(&mut *p)
    };

    let next = self.cache.lock().unwrap().next.unwrap_or(ROOT_ID + 1);

    let mut ops = Vec::with_capacity(pending.len() * 2 + 1);
    ops.push(Operation {
      tree: Tree::PluginMeta,
      method: Method::Insert,
      key: ID_NEXT.to_vec(),
      val: Some(next.to_be_bytes().to_vec()),
    });
    for (id, subject) in &pending {
      ops.push(Operation {
        tree: Tree::PluginMeta,
        method: Method::Insert,
        key: subject_to_id_key(subject),
        val: Some(id.to_be_bytes().to_vec()),
      });
      ops.push(Operation {
        tree: Tree::PluginMeta,
        method: Method::Insert,
        key: id_to_subject_key(*id),
        val: Some(subject.as_bytes().to_vec()),
      });
    }

    let _ = self.store.kv.apply_batch(&ops);
  }

  fn subject(&self, id: fileid3) -> Option<String> {
    let mut cache = self.cache.lock().unwrap();

    if let Some(subject) = cache.to_subject.get(&id) {
      return Some(subject.clone());
    }

    let bytes = self
      .store
      .kv
      .get(Tree::PluginMeta, &id_to_subject_key(id))
      .ok()
      .flatten()?;
    let subject = String::from_utf8_lossy(&bytes).to_string();
    cache.remember(id, &subject);

    Some(subject)
  }

  /// Forget a subject's id (both directions + cache), for a resource that was
  /// removed, so the persistent map doesn't accumulate dead entries.
  fn forget(&self, id: fileid3, subject: &str) {
    // Drop it from the not-yet-persisted queue too, so a later flush can't
    // resurrect a removed entry.
    self.pending.lock().unwrap().retain(|(pid, _)| *pid != id);

    let _ = self
      .store
      .kv
      .remove(Tree::PluginMeta, &subject_to_id_key(subject));
    let _ = self
      .store
      .kv
      .remove(Tree::PluginMeta, &id_to_subject_key(id));

    let mut cache = self.cache.lock().unwrap();
    cache.to_subject.remove(&id);
    cache.to_id.remove(subject);
  }

  fn read_persisted_id(&self, subject: &str) -> Option<fileid3> {
    let bytes = self
      .store
      .kv
      .get(Tree::PluginMeta, &subject_to_id_key(subject))
      .ok()
      .flatten()?;

    read_u64_bytes(&bytes)
  }

  fn read_u64(&self, key: &[u8]) -> Option<fileid3> {
    self
      .store
      .kv
      .get(Tree::PluginMeta, key)
      .ok()
      .flatten()
      .and_then(|bytes| read_u64_bytes(&bytes))
  }
}

impl IdCache {
  fn remember(&mut self, id: fileid3, subject: &str) {
    self.to_id.insert(subject.to_string(), id);
    self.to_subject.insert(id, subject.to_string());
  }
}

fn subject_to_id_key(subject: &str) -> Vec<u8> {
  [ID_SUBJECT_TO_ID, subject.as_bytes()].concat()
}

fn id_to_subject_key(id: fileid3) -> Vec<u8> {
  [ID_ID_TO_SUBJECT, &id.to_be_bytes()].concat()
}

fn read_u64_bytes(bytes: &[u8]) -> Option<fileid3> {
  bytes.try_into().ok().map(u64::from_be_bytes)
}

/// The most-recently reconstructed file's bytes. The OS issues one `read` per
/// window when streaming a file, so without this each window would rebuild the
/// whole file from its blobs — an O(size²) read. Caching the last file makes a
/// sequential read-through reconstruct once (O(size)). Keyed by fileid + the
/// file's whole-file hash (`internalId`), so an edit (new hash) misses and
/// re-reads. Single-entry: interleaving two large files degrades to
/// rebuild-per-window, which is rare and still correct.
struct ReadCache {
  id: fileid3,
  internal_id: String,
  bytes: Arc<Vec<u8>>,
}

pub struct AtomicNfsFs {
  store: Db,
  ids: IdMap,
  staging: Arc<Staging>,
  dir_cache: Mutex<HashMap<fileid3, DirListing>>,
  read_cache: Mutex<Option<ReadCache>>,
  /// Echo-suppression identity for the commits this mount signs. Threaded into
  /// the commit path so the VFS doesn't read its own writes back as change
  /// notifications once cache invalidation subscribes to them.
  #[allow(dead_code)]
  source_id: String,
}

impl AtomicNfsFs {
  pub fn new(store: Db) -> Self {
    AtomicNfsFs {
      ids: IdMap::new(store.clone()),
      store,
      staging: Arc::new(Staging::default()),
      dir_cache: Mutex::new(HashMap::new()),
      read_cache: Mutex::new(None),
      source_id: format!("vfs-{}", std::process::id()),
    }
  }

  /// The subject of a writable directory (a Folder or Drive). The mount root is
  /// the drive *list* — you cannot create resources directly in it.
  async fn dir_subject(&self, dirid: fileid3) -> Result<String, nfsstat3> {
    if dirid == ROOT_ID {
      return Err(nfsstat3::NFS3ERR_PERM);
    }

    let subject = self.ids.subject(dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
    let resource = self
      .store
      .get_resource(&Subject::from(subject.as_str()))
      .await
      .map_err(|_| nfsstat3::NFS3ERR_NOENT)?;

    if is_dir(&resource) {
      Ok(subject)
    } else {
      Err(nfsstat3::NFS3ERR_NOTDIR)
    }
  }

  /// Find a File/Folder child of `parent` by its (sanitized) filesystem name.
  async fn find_child(&self, parent: &str, name: &[u8]) -> Result<Resource, nfsstat3> {
    for child in self.children(parent).await? {
      if sanitize_name(&display_name(&child)).as_bytes() == name {
        return Ok(child);
      }
    }

    Err(nfsstat3::NFS3ERR_NOENT)
  }

  /// The current persisted bytes of a file, for seeding a staging buffer before
  /// a partial (offset) write.
  async fn current_blob(&self, subject: &str) -> Vec<u8> {
    let Ok(resource) = self.store.get_resource(&Subject::from(subject)).await else {
      return Vec::new();
    };

    read_blob(&self.store, &resource).unwrap_or_default()
  }

  /// The staged (unflushed) size of a file, if it is being written.
  fn staged_size(&self, id: fileid3) -> Option<u64> {
    self
      .staging
      .files
      .lock()
      .unwrap()
      .get(&id)
      .map(|file| file.data.len() as u64)
  }

  /// Ensure a staging buffer exists for `id`, seeded from the file's current
  /// bytes so a partial (offset) write extends rather than truncates.
  /// Reject a mutation aimed at a read-only link (`.inetloc`) resource before it
  /// gets staged as if it were a File — staging + flushing one would overwrite
  /// the real resource with location-file bytes. Only checks on first touch (an
  /// already-staged id is a real file being edited), so real writes pay nothing
  /// after the first.
  fn deny_if_link(&self, id: fileid3) -> Result<(), nfsstat3> {
    if self.staging.files.lock().unwrap().contains_key(&id) {
      return Ok(());
    }

    if is_link_resource(&self.get_shallow(id)?) {
      return Err(nfsstat3::NFS3ERR_ROFS);
    }

    Ok(())
  }

  async fn ensure_staged(&self, id: fileid3, subject: &str) {
    if self.staging.files.lock().unwrap().contains_key(&id) {
      return;
    }

    let current = self.current_blob(subject).await;
    self
      .staging
      .files
      .lock()
      .unwrap()
      .entry(id)
      .or_insert_with(|| StagedFile {
        subject: subject.to_string(),
        data: current,
        dirty: false,
        last_write: Instant::now(),
      });
  }

  /// Create an empty, valid File under `parent` and return its fileid.
  async fn create_file(&self, parent: &str, name: &str) -> Result<fileid3, nfsstat3> {
    let hash = blake3::hash(&[]);
    self
      .store
      .kv
      .insert(Tree::Blobs, hash.as_bytes(), &[])
      .map_err(|_| nfsstat3::NFS3ERR_IO)?;

    // A File requires all of these to be a valid resource (see the upload
    // handler), not just the blob pointer.
    let mut props = hash_props(&self.store, &hash.to_hex().to_string(), 0);
    props.push((urls::FILENAME, Value::String(name.to_string())));
    props.push((
      urls::MIMETYPE,
      Value::String("application/octet-stream".to_string()),
    ));

    let subject = self
      .store
      .create_resource(urls::FILE, parent, name, Some(props))
      .await
      .map_err(|_| nfsstat3::NFS3ERR_IO)?;

    let id = self.ids.get_or_alloc(&subject);
    self.ids.persist_pending();

    Ok(id)
  }

  /// The Drives the mount root exposes as top-level directories: the signed-in
  /// user's own drives (their `personalDrive` plus everything on the agent's
  /// `drives` list).
  ///
  /// Deliberately *not* every Drive in the store. A desktop node syncs drives
  /// from other peers, so `Sudo` would list thousands the user has no rights to
  /// — and opening one hands the auth-gated UI a resource it bounces to the
  /// welcome page. Scoping to the agent's drives keeps the mount to what the
  /// user can actually open, and empties it when signed out.
  async fn drives(&self) -> Result<Vec<Subject>, nfsstat3> {
    let Ok(agent) = self.store.get_default_agent() else {
      return Ok(Vec::new());
    };

    let Ok(agent_resource) = self.store.get_resource_shallow(&agent.subject) else {
      return Ok(Vec::new());
    };

    let mut drives: Vec<Subject> = Vec::new();

    // The home drive first, so it sorts as the user's primary entry.
    if let Ok(value) = agent_resource.get(urls::PRIVATE_DRIVE) {
      if let Some(subject) = value_string(value) {
        drives.push(Subject::from(subject.as_str()));
      }
    }

    if let Ok(Value::ResourceArray(list)) = agent_resource.get(urls::DRIVES) {
      for item in list {
        let subject = item.to_string();
        if !drives.iter().any(|drive| drive.as_str() == subject) {
          drives.push(Subject::from(subject.as_str()));
        }
      }
    }

    Ok(drives)
  }

  /// The File/Folder children of a container (drive or folder), by `parent`.
  async fn children(&self, parent: &str) -> Result<Vec<Resource>, nfsstat3> {
    // Non-nested for the same reason as `drives`: a listing needs subjects
    // only, and each child is then read raw via `get_resource`. Nested fetching
    // runs the extender + durable-flush path per child on every readdir.
    let mut query = atomic_lib::storelike::Query::new_prop_val(urls::PARENT, parent);
    query.include_nested = false;

    let result = self
      .store
      .query(&query)
      .await
      .map_err(|_| nfsstat3::NFS3ERR_SERVERFAULT)?;

    // With a non-nested query the resources come back as subjects; fetch each
    // one raw. (`result.resources` stays populated on any backend that returns
    // full resources anyway, in which case the fallback is skipped.)
    let mut resources = result.resources;

    if resources.is_empty() && !result.subjects.is_empty() {
      for subject in &result.subjects {
        // Shallow read — a listing needs names/attrs, not full Loro state.
        if let Ok(resource) = self.store.get_resource_shallow(subject) {
          resources.push(resource);
        }
      }
    }

    // The whole hierarchy is mirrored: Folders become directories, Files become
    // files, and every other resource becomes a `.inetloc` link that opens in
    // Atomic desktop (see `entry_parts` / `is_link_resource`).
    Ok(resources)
  }

  /// A shallow (propvals-only) read of the resource behind a fileid — for
  /// `getattr` and `read`, which need the projected name/size/type/blob refs but
  /// not the resource's full Loro state. A full decode here would make attribute
  /// stat storms and per-window reads O(store) / O(history).
  fn get_shallow(&self, id: fileid3) -> Result<Resource, nfsstat3> {
    let subject = self.ids.subject(id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
    self
      .store
      .get_resource_shallow(&Subject::from(subject.as_str()))
      .map_err(|_| nfsstat3::NFS3ERR_NOENT)
  }

  /// The cacheable parts of a directory entry for a resource: mint its id,
  /// sanitize its name, project its attributes.
  fn entry_parts(&self, resource: &Resource) -> (fileid3, filename3, fattr3) {
    let id = self.ids.get_or_alloc(resource.get_subject().as_str());
    let mut name = sanitize_name(&display_name(resource));

    // Non-file, non-container resources surface as `.inetloc` link files.
    if is_link_resource(resource) {
      name = format!("{name}.{LINK_EXT}");
    }

    (id, name.into_bytes().into(), attr_for(id, resource))
  }

  /// Every child entry of a directory (drives at the root; File/Folder children
  /// elsewhere), sorted by id for a deterministic, pageable listing.
  async fn collect_dir_entries(
    &self,
    dirid: fileid3,
  ) -> Result<Vec<(fileid3, filename3, fattr3)>, nfsstat3> {
    let mut entries: Vec<(fileid3, filename3, fattr3)> = if dirid == ROOT_ID {
      let mut out = Vec::new();

      for drive in self.drives().await? {
        // Shallow read: a listing only needs the name/attrs, not the full
        // Loro-materialized resource (see `get_resource_shallow`).
        if let Ok(resource) = self.store.get_resource_shallow(&drive) {
          out.push(self.entry_parts(&resource));
        }
      }

      out
    } else {
      let subject = self.ids.subject(dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;
      self
        .children(&subject)
        .await?
        .iter()
        .map(|resource| self.entry_parts(resource))
        .collect()
    };

    // Flush the ids minted above in one transaction rather than per entry.
    self.ids.persist_pending();

    entries.sort_by_key(|(id, _, _)| *id);

    Ok(entries)
  }

  /// Drop a directory's cached listing so a create/remove/rename is reflected on
  /// the next `readdir` rather than waiting for the TTL.
  fn invalidate_dir(&self, dirid: fileid3) {
    self.dir_cache.lock().unwrap().remove(&dirid);
  }

  /// Ensure `dirid`'s listing is cached and within its TTL, building it once if
  /// absent or stale. `readdir` pages from it, and `lookup` scans it by name —
  /// so resolving every entry the OS asks about after a listing costs no extra
  /// store reads (previously each `lookup` re-enumerated the whole directory,
  /// making a folder open O(entries²)).
  async fn ensure_dir_cached(&self, dirid: fileid3) -> Result<(), nfsstat3> {
    let fresh = matches!(
      self.dir_cache.lock().unwrap().get(&dirid),
      Some(listing) if listing.at.elapsed() < DIR_CACHE_TTL
    );

    if !fresh {
      let entries = self.collect_dir_entries(dirid).await?;
      self.dir_cache.lock().unwrap().insert(
        dirid,
        DirListing {
          at: Instant::now(),
          entries,
        },
      );
    }

    Ok(())
  }
}

#[async_trait]
impl NFSFileSystem for AtomicNfsFs {
  fn capabilities(&self) -> VFSCapabilities {
    VFSCapabilities::ReadWrite
  }

  fn root_dir(&self) -> fileid3 {
    ROOT_ID
  }

  async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
    if id == ROOT_ID {
      return Ok(dir_attr(ROOT_ID));
    }

    let resource = self.get_shallow(id)?;
    let mut attr = attr_for(id, &resource);

    // A file mid-write reports its staged size, so an editor sees the bytes it
    // just wrote before the debounced commit lands.
    if let Some(size) = self.staged_size(id) {
      attr.size = size;
      attr.used = size;
    }

    Ok(attr)
  }

  async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
    let target = filename.as_ref();

    // Resolve against the cached directory listing rather than re-enumerating
    // the directory. The OS issues a `lookup` per entry right after a `readdir`;
    // re-reading every sibling on each one made opening a folder O(entries²).
    // The ids were already minted (and persisted) when the listing was built.
    self.ensure_dir_cached(dirid).await?;

    let cache = self.dir_cache.lock().unwrap();
    let listing = cache.get(&dirid).ok_or(nfsstat3::NFS3ERR_NOENT)?;

    listing
      .entries
      .iter()
      .find(|(_, name, _)| name.as_ref() == target)
      .map(|(id, _, _)| *id)
      .ok_or(nfsstat3::NFS3ERR_NOENT)
  }

  async fn readdir(
    &self,
    dirid: fileid3,
    start_after: fileid3,
    max_entries: usize,
  ) -> Result<ReadDirResult, nfsstat3> {
    // Build the full listing once per enumeration (a fresh `ls` starts at
    // cookie 0), cache it, and page from the cache — so a large folder isn't
    // re-fetched and re-sorted on every `readdir` page.
    if start_after == 0 {
      self.invalidate_dir(dirid);
    }
    self.ensure_dir_cached(dirid).await?;

    let cache = self.dir_cache.lock().unwrap();
    let listing = cache.get(&dirid).ok_or(nfsstat3::NFS3ERR_IO)?;

    let start = listing
      .entries
      .iter()
      .position(|(id, _, _)| *id > start_after)
      .unwrap_or(listing.entries.len());
    let remaining = &listing.entries[start..];
    let end = remaining.len() <= max_entries;
    let page: Vec<DirEntry> = remaining
      .iter()
      .take(max_entries)
      .map(|(id, name, attr)| DirEntry {
        fileid: *id,
        name: name.clone(),
        attr: *attr,
      })
      .collect();

    Ok(ReadDirResult { entries: page, end })
  }

  async fn read(&self, id: fileid3, offset: u64, count: u32) -> Result<(Vec<u8>, bool), nfsstat3> {
    // Staged (unflushed) bytes win, so a read right after a write is consistent.
    // Bytes are read lazily — only on `read`, never on readdir/getattr (the
    // doc's no-prefetch contract).
    if let Some(data) = self
      .staging
      .files
      .lock()
      .unwrap()
      .get(&id)
      .map(|file| file.data.clone())
    {
      return Ok(slice_read(&data, offset, count));
    }

    // A shallow read (no Loro decode) is enough to project the file; each `read`
    // window would otherwise pay a full decode too.
    let resource = self.get_shallow(id)?;

    if is_link_resource(&resource) {
      return Ok(slice_read(
        &link_file_bytes(resource.get_subject().as_str()),
        offset,
        count,
      ));
    }

    let internal_id = resource
      .get(urls::INTERNAL_ID)
      .ok()
      .and_then(value_string)
      .unwrap_or_default();

    // Reconstruct the whole file from its blobs at most once per read-through,
    // then serve every window from the cache (see `ReadCache`). Without range
    // support on the blob store, the alternative is rebuilding it per window.
    let cached = {
      let cache = self.read_cache.lock().unwrap();
      cache
        .as_ref()
        .filter(|entry| entry.id == id && entry.internal_id == internal_id)
        .map(|entry| entry.bytes.clone())
    };

    let bytes = match cached {
      Some(bytes) => bytes,
      None => {
        let bytes = Arc::new(read_blob(&self.store, &resource)?);
        *self.read_cache.lock().unwrap() = Some(ReadCache {
          id,
          internal_id,
          bytes: bytes.clone(),
        });
        bytes
      }
    };

    Ok(slice_read(&bytes, offset, count))
  }

  async fn readlink(&self, _id: fileid3) -> Result<nfspath3, nfsstat3> {
    // No symlink resources are surfaced yet.
    Err(nfsstat3::NFS3ERR_NOTSUPP)
  }

  // --- Write path. Commits are signed by the store's default agent, which the
  //     desktop app sets to the signed-in user via `adopt_agent` — so writes
  //     are attributed to the user and sync with their rights. ---

  /// Truncate/extend (editors call this with size 0 before rewriting a file).
  /// Other attributes (mode/uid/times) are accepted but not persisted.
  async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
    if let set_size3::size(new_size) = setattr.size {
      if new_size as usize > MAX_FILE_BYTES {
        return Err(nfsstat3::NFS3ERR_FBIG);
      }

      self.deny_if_link(id)?;

      let subject = self.ids.subject(id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
      self.ensure_staged(id, &subject).await;

      let mut files = self.staging.files.lock().unwrap();

      if let Some(file) = files.get_mut(&id) {
        file.data.resize(new_size as usize, 0);
        file.dirty = true;
        file.last_write = Instant::now();
      }
    }

    self.getattr(id).await
  }

  async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
    let end = (offset as usize).saturating_add(data.len());

    if end > MAX_FILE_BYTES {
      return Err(nfsstat3::NFS3ERR_FBIG);
    }

    self.deny_if_link(id)?;

    let subject = self.ids.subject(id).ok_or(nfsstat3::NFS3ERR_NOENT)?;
    self.ensure_staged(id, &subject).await;

    let size = {
      let mut files = self.staging.files.lock().unwrap();
      let file = files.get_mut(&id).ok_or(nfsstat3::NFS3ERR_IO)?;

      if file.data.len() < end {
        file.data.resize(end, 0);
      }

      file.data[offset as usize..end].copy_from_slice(data);
      file.dirty = true;
      file.last_write = Instant::now();
      file.data.len() as u64
    };

    Ok(file_attr(id, size))
  }

  async fn create(
    &self,
    dirid: fileid3,
    filename: &filename3,
    _attr: sattr3,
  ) -> Result<(fileid3, fattr3), nfsstat3> {
    let parent = self.dir_subject(dirid).await?;
    let name = decode_name(filename.as_ref())?;
    let id = self.create_file(&parent, &name).await?;
    self.invalidate_dir(dirid);

    Ok((id, file_attr(id, 0)))
  }

  async fn create_exclusive(
    &self,
    dirid: fileid3,
    filename: &filename3,
  ) -> Result<fileid3, nfsstat3> {
    let parent = self.dir_subject(dirid).await?;

    if self.find_child(&parent, filename.as_ref()).await.is_ok() {
      return Err(nfsstat3::NFS3ERR_EXIST);
    }

    let name = decode_name(filename.as_ref())?;
    let id = self.create_file(&parent, &name).await?;
    self.invalidate_dir(dirid);

    Ok(id)
  }

  async fn mkdir(
    &self,
    dirid: fileid3,
    dirname: &filename3,
  ) -> Result<(fileid3, fattr3), nfsstat3> {
    let parent = self.dir_subject(dirid).await?;
    let name = decode_name(dirname.as_ref())?;

    let subject = self
      .store
      .create_resource(urls::FOLDER, &parent, &name, None)
      .await
      .map_err(|_| nfsstat3::NFS3ERR_IO)?;

    let id = self.ids.get_or_alloc(&subject);
    self.ids.persist_pending();
    self.invalidate_dir(dirid);

    Ok((id, dir_attr(id)))
  }

  async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
    let parent = self.dir_subject(dirid).await?;
    let mut resource = self.find_child(&parent, filename.as_ref()).await?;
    let subject = resource.get_subject().to_string();

    // Drop any pending staged writes for it before it goes away.
    let id = self.ids.get_or_alloc(&subject);
    self.staging.files.lock().unwrap().remove(&id);

    resource
      .destroy(&self.store)
      .await
      .map_err(|_| nfsstat3::NFS3ERR_IO)?;

    // Reclaim its persisted fileid entry.
    self.ids.forget(id, &subject);
    self.invalidate_dir(dirid);

    Ok(())
  }

  async fn rename(
    &self,
    from_dirid: fileid3,
    from_filename: &filename3,
    to_dirid: fileid3,
    to_filename: &filename3,
  ) -> Result<(), nfsstat3> {
    let from_parent = self.dir_subject(from_dirid).await?;
    let to_parent = self.dir_subject(to_dirid).await?;
    let mut resource = self
      .find_child(&from_parent, from_filename.as_ref())
      .await?;
    let new_name = decode_name(to_filename.as_ref())?;

    resource
      .set(
        urls::NAME.into(),
        Value::String(new_name.clone()),
        &self.store,
      )
      .await
      .map_err(|_| nfsstat3::NFS3ERR_IO)?;

    if is_file(&resource) {
      resource
        .set(urls::FILENAME.into(), Value::String(new_name), &self.store)
        .await
        .map_err(|_| nfsstat3::NFS3ERR_IO)?;
    }

    // A move to a different directory re-parents the resource.
    if to_parent != from_parent {
      resource
        .set(
          urls::PARENT.into(),
          Value::AtomicUrl(to_parent.into()),
          &self.store,
        )
        .await
        .map_err(|_| nfsstat3::NFS3ERR_IO)?;
    }

    resource
      .save_locally(&self.store)
      .await
      .map_err(|_| nfsstat3::NFS3ERR_IO)?;

    self.invalidate_dir(from_dirid);

    if to_dirid != from_dirid {
      self.invalidate_dir(to_dirid);
    }

    Ok(())
  }

  async fn symlink(
    &self,
    _dirid: fileid3,
    _linkname: &filename3,
    _symlink: &nfspath3,
    _attr: &sattr3,
  ) -> Result<(fileid3, fattr3), nfsstat3> {
    // Symlinks have no Atomic representation yet.
    Err(nfsstat3::NFS3ERR_NOTSUPP)
  }
}

/// Directories in the mount: Folders and Drives (the mount root's drives are
/// top-level directories). Everything else that is surfaced is a regular file.
fn is_dir(resource: &Resource) -> bool {
  classes(resource)
    .iter()
    .any(|class| class == urls::FOLDER || class == urls::DRIVE)
}

fn is_file(resource: &Resource) -> bool {
  classes(resource).iter().any(|class| class == urls::FILE)
}

/// A resource that is neither a File nor a container (Folder/Drive). These are
/// surfaced as macOS "internet location" files: opening one hands off to Atomic
/// desktop via the `atomic:` deep link instead of downloading bytes.
fn is_link_resource(resource: &Resource) -> bool {
  !is_dir(resource) && !is_file(resource)
}

/// macOS location-file extension. `.inetloc` (unlike `.webloc`, which only
/// resolves http/https) opens custom URL schemes like `atomic:`.
const LINK_EXT: &str = "inetloc";

/// The `.inetloc` (plist) bytes that open `subject` in Atomic desktop. The OS
/// resolves the embedded `atomic:` URL to the registered desktop app, whose
/// deep-link handler forwards it to the frontend to navigate to the resource.
fn link_file_bytes(subject: &str) -> Vec<u8> {
  let url = xml_escape(&format!(
    "atomic:open?subject={}",
    percent_encode(subject)
  ));
  format!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
     \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
     <plist version=\"1.0\">\n<dict>\n\t<key>URL</key>\n\t<string>{url}</string>\n</dict>\n</plist>\n"
  )
  .into_bytes()
}

/// Percent-encode a subject so it survives as an `atomic:…?subject=` query
/// value (its `:`, `/`, `?` etc. would otherwise break the URL).
fn percent_encode(input: &str) -> String {
  let mut out = String::with_capacity(input.len());
  for &byte in input.as_bytes() {
    match byte {
      b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
      _ => out.push_str(&format!("%{byte:02X}")),
    }
  }
  out
}

fn xml_escape(input: &str) -> String {
  input
    .replace('&', "&amp;")
    .replace('<', "&lt;")
    .replace('>', "&gt;")
}

/// Read a File resource's bytes: concatenate its chunk blobs when it is chunked,
/// otherwise the single blob. (Whole file into memory; there is no range API
/// yet.)
fn read_blob(store: &Db, resource: &Resource) -> Result<Vec<u8>, nfsstat3> {
  if let Ok(Value::ResourceArray(chunks)) = resource.get(urls::CHUNKS) {
    if !chunks.is_empty() {
      let mut out = Vec::new();

      for chunk in chunks {
        out.extend_from_slice(&blob_by_did(store, &chunk.to_string())?);
      }

      return Ok(out);
    }
  }

  let internal_id = resource
    .get(urls::INTERNAL_ID)
    .map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
  let hash_hex = value_string(internal_id).ok_or(nfsstat3::NFS3ERR_INVAL)?;

  blob_by_hash_hex(store, &hash_hex)
}

/// Slice the `[offset, offset+count)` window out of a file's bytes and report
/// whether the window reaches EOF — the shape every `read` returns.
fn slice_read(bytes: &[u8], offset: u64, count: u32) -> (Vec<u8>, bool) {
  let start = (offset as usize).min(bytes.len());
  let end = start.saturating_add(count as usize).min(bytes.len());

  (bytes[start..end].to_vec(), end >= bytes.len())
}

/// Fetch a blob by a `did:ad:blob:{hex}` reference.
fn blob_by_did(store: &Db, did: &str) -> Result<Vec<u8>, nfsstat3> {
  let hash_hex = Subject::from(did)
    .blob_hash_hex()
    .ok_or(nfsstat3::NFS3ERR_IO)?
    .to_string();

  blob_by_hash_hex(store, &hash_hex)
}

fn blob_by_hash_hex(store: &Db, hash_hex: &str) -> Result<Vec<u8>, nfsstat3> {
  let hash_bytes = hex::decode(hash_hex).map_err(|_| nfsstat3::NFS3ERR_IO)?;

  store
    .kv
    .get(Tree::Blobs, &hash_bytes)
    .map_err(|_| nfsstat3::NFS3ERR_IO)?
    .ok_or(nfsstat3::NFS3ERR_NOENT)
}

/// The blob-dependent File properties — everything that changes when the bytes
/// change. A File requires `downloadURL`, so a VFS-written File must carry the
/// same shape a server upload produces, not just the blob hash.
fn hash_props(store: &Db, hash_hex: &str, size: usize) -> Vec<(&'static str, Value)> {
  let base = store
    .get_base_domain()
    .unwrap_or_else(|| "https://localhost".to_string());

  vec![
    (urls::INTERNAL_ID, Value::String(hash_hex.to_string())),
    (
      urls::BLOB,
      Value::AtomicUrl(format!("did:ad:blob:{hash_hex}").into()),
    ),
    (urls::FILESIZE, Value::Integer(size as i64)),
    (
      urls::DOWNLOAD_URL,
      Value::String(format!("{base}/download/files/{hash_hex}")),
    ),
  ]
}

/// Turn a filesystem basename into an Atomic name: valid UTF-8, within the FS
/// length cap (an admission-control limit).
fn decode_name(name: &[u8]) -> Result<String, nfsstat3> {
  if name.is_empty() || name.len() > MAX_NAME_BYTES {
    return Err(nfsstat3::NFS3ERR_INVAL);
  }

  String::from_utf8(name.to_vec()).map_err(|_| nfsstat3::NFS3ERR_INVAL)
}

fn classes(resource: &Resource) -> Vec<String> {
  match resource.get(urls::IS_A) {
    Ok(Value::ResourceArray(array)) => array.iter().map(|sub| sub.to_string()).collect(),
    _ => Vec::new(),
  }
}

/// The name to show in the filesystem: a File's `filename`, else `name`, else
/// `shortname`, else the last path segment of the subject.
fn display_name(resource: &Resource) -> String {
  for property in [urls::FILENAME, urls::NAME, urls::SHORTNAME] {
    if let Ok(value) = resource.get(property) {
      if let Some(string) = value_string(value) {
        if !string.is_empty() {
          return string;
        }
      }
    }
  }

  subject_fallback(resource.get_subject().as_str())
}

fn subject_fallback(subject: &str) -> String {
  subject
    .trim_end_matches('/')
    .rsplit('/')
    .next()
    .filter(|segment| !segment.is_empty())
    .unwrap_or(subject)
    .to_string()
}

fn value_string(value: &Value) -> Option<String> {
  match value {
    Value::String(string) | Value::Markdown(string) | Value::Slug(string) => Some(string.clone()),
    Value::AtomicUrl(subject) => Some(subject.to_string()),
    _ => None,
  }
}

fn attr_for(id: fileid3, resource: &Resource) -> fattr3 {
  if is_dir(resource) {
    dir_attr(id)
  } else if is_link_resource(resource) {
    // A read-only location file; its size is the generated `.inetloc` content.
    let size = link_file_bytes(resource.get_subject().as_str()).len() as u64;
    link_attr(id, size)
  } else {
    let size = resource
      .get(urls::FILESIZE)
      .ok()
      .and_then(|value| match value {
        Value::Integer(number) => u64::try_from(*number).ok(),
        _ => None,
      })
      // Size is read from the `filesize` property only — never by reading
      // the blob (that would violate the no-prefetch-on-getattr contract).
      .unwrap_or(0);

    file_attr(id, size)
  }
}

fn dir_attr(id: fileid3) -> fattr3 {
  base_attr(id, ftype3::NF3DIR, DIR_MODE, 2, 4096)
}

fn file_attr(id: fileid3, size: u64) -> fattr3 {
  base_attr(id, ftype3::NF3REG, FILE_MODE, 1, size)
}

/// A link (`.inetloc`) file is a regular file to the OS but read-only — its
/// bytes are generated, not stored, and editing it would be meaningless.
fn link_attr(id: fileid3, size: u64) -> fattr3 {
  base_attr(id, ftype3::NF3REG, LINK_MODE, 1, size)
}

fn base_attr(id: fileid3, ftype: ftype3, mode: u32, nlink: u32, size: u64) -> fattr3 {
  let time = nfstime3 {
    seconds: 0,
    nseconds: 0,
  };

  fattr3 {
    ftype,
    mode,
    nlink,
    uid: 0,
    gid: 0,
    size,
    used: size,
    rdev: specdata3 {
      specdata1: 0,
      specdata2: 0,
    },
    fsid: 0,
    fileid: id,
    atime: time,
    mtime: time,
    ctime: time,
  }
}

/// Map a free-form Atomic name to an FS-safe basename. Applied only at the
/// materialization boundary (the canonical name in Atomic keeps the original
/// string). This is load-bearing security once the write path exists — every
/// cloud-sync product has shipped a path-traversal CVE here — so it lands with
/// the read-only mount rather than being bolted on later. This is a v1 subset of
/// the full table in `planning/virtual-drive.md`; collision `(2)`/`(3)`
/// suffixing is a follow-up.
fn sanitize_name(name: &str) -> String {
  if name.is_empty() {
    return "_".to_string();
  }

  if name == "." || name == ".." {
    // U+2024 one-dot leader keeps it visually a dot without being one.
    return name.replace('.', "\u{2024}");
  }

  let sanitized: String = name
    .chars()
    .map(|character| match character {
      '/' | '\\' => '\u{ff0f}',                 // fullwidth solidus
      '\0'..='\u{1f}' | '\u{7f}' => '\u{fffd}', // control chars
      // Strip bidi/RTL overrides that can spoof the displayed name.
      '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => '\u{fffd}',
      other => other,
    })
    .collect();

  // Bound to the FS limit, on a codepoint boundary.
  if sanitized.len() > 255 {
    let mut truncated = String::new();

    for character in sanitized.chars() {
      if truncated.len() + character.len_utf8() > 247 {
        break;
      }

      truncated.push(character);
    }

    return truncated;
  }

  sanitized
}

/// Where the drive is mounted: `~/AtomicDrive`.
fn mount_point() -> Option<std::path::PathBuf> {
  let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
  Some(std::path::PathBuf::from(home).join("AtomicDrive"))
}

/// Status of the virtual drive, surfaced to the desktop UI.
#[derive(serde::Serialize)]
pub struct VfsStatus {
  /// The NFS server is listening.
  pub running: bool,
  /// The drive is mounted into the filesystem at `mount_path`.
  pub mounted: bool,
  pub mount_path: Option<String>,
}

/// Serve the NFS filesystem until `shutdown` resolves (fired, or its sender
/// dropped). Bound to loopback. Runs a background flusher that commits quiesced
/// writes, and flushes anything still pending on the way out.
async fn serve_until(
  store: Db,
  shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
  let fs = AtomicNfsFs::new(store.clone());
  let staging = fs.staging.clone();
  let listener = NFSTcpListener::bind(NFS_ADDR, fs).await?;

  let flush_store = store.clone();
  let flush_staging = staging.clone();
  let flusher = tokio::spawn(async move { flush_loop(flush_store, flush_staging).await });

  let result = tokio::select! {
    result = listener.handle_forever() => result,
    _ = shutdown => Ok(()),
  };

  flusher.abort();
  flush_ready(&store, &staging, false).await; // final flush, ignore debounce
  result
}

/// Commit the file bytes: hash → blob → a signed commit updating the File
/// resource's `internalId` + `filesize`. Signed by the store's default agent.
async fn commit_file(store: &Db, subject: &str, data: &[u8]) {
  let hash = blake3::hash(data);
  let hash_hex = hash.to_hex().to_string();

  let Ok(mut resource) = store.get_resource(&Subject::from(subject)).await else {
    return;
  };

  // Content-addressed no-op skip: if the bytes are unchanged, there's nothing to
  // commit — avoids a redundant blob write + commit when an editor saves a file
  // it didn't actually change.
  if resource
    .get(urls::INTERNAL_ID)
    .ok()
    .and_then(value_string)
    .as_deref()
    == Some(hash_hex.as_str())
  {
    return;
  }

  // Store bytes: chunk large files, single blob for small ones.
  let chunks = match store_bytes(store, data) {
    Ok(chunks) => chunks,
    Err(()) => return,
  };

  for (prop, value) in hash_props(store, &hash_hex, data.len()) {
    if let Err(error) = resource.set(prop.into(), value, store).await {
      eprintln!("[vfs] flush set {prop} failed for {subject}: {error}");

      return;
    }
  }

  // Record the chunk list (or clear a stale one if the file shrank below the
  // chunking threshold), so a read reconstructs the bytes correctly.
  let chunk_result = match chunks {
    Some(refs) => resource
      .set(urls::CHUNKS.into(), Value::ResourceArray(refs), store)
      .await
      .map(|_| ()),
    None if resource.get(urls::CHUNKS).is_ok() => resource.remove_propval(urls::CHUNKS),
    None => Ok(()),
  };

  if let Err(error) = chunk_result {
    eprintln!("[vfs] flush set chunks failed for {subject}: {error}");

    return;
  }

  if let Err(error) = resource.save_locally(store).await {
    eprintln!("[vfs] flush commit failed for {subject}: {error}");
  }
}

/// Persist a file's bytes: a single blob for small files, or FastCDC chunk-blobs
/// for large ones. Returns the ordered chunk references, or `None` for a single
/// blob. Chunk (and whole-file) blobs dedupe by hash, so an unchanged chunk is a
/// no-op insert.
fn store_bytes(store: &Db, data: &[u8]) -> Result<Option<Vec<SubResource>>, ()> {
  if data.len() <= CHUNK_THRESHOLD {
    store
      .kv
      .insert(Tree::Blobs, blake3::hash(data).as_bytes(), data)
      .map_err(|_| ())?;

    return Ok(None);
  }

  let mut refs = Vec::new();

  for chunk in fastcdc::v2020::FastCDC::new(data, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX) {
    let bytes = &data[chunk.offset..chunk.offset + chunk.length];
    let hash = blake3::hash(bytes);
    store
      .kv
      .insert(Tree::Blobs, hash.as_bytes(), bytes)
      .map_err(|_| ())?;
    refs.push(SubResource::from(format!("did:ad:blob:{}", hash.to_hex())));
  }

  Ok(Some(refs))
}

/// Flush files whose writes have quiesced (or all dirty files when `gated` is
/// false). Snapshots the ready set, releases the lock, commits, then clears the
/// dirty flag only if no newer write arrived meanwhile.
async fn flush_ready(store: &Db, staging: &Staging, gated: bool) {
  let ready: Vec<(fileid3, String, Vec<u8>, Instant)> = {
    let files = staging.files.lock().unwrap();
    files
      .iter()
      .filter(|(_, file)| file.dirty && (!gated || file.last_write.elapsed() >= WRITE_DEBOUNCE))
      .map(|(id, file)| {
        (
          *id,
          file.subject.clone(),
          file.data.clone(),
          file.last_write,
        )
      })
      .collect()
  };

  for (id, subject, data, wrote_at) in ready {
    commit_file(store, &subject, &data).await;

    let mut files = staging.files.lock().unwrap();

    if let Some(file) = files.get_mut(&id) {
      if file.last_write == wrote_at {
        file.dirty = false;
      }
    }
  }
}

async fn flush_loop(store: Db, staging: Arc<Staging>) {
  loop {
    tokio::time::sleep(FLUSH_TICK).await;
    flush_ready(&store, &staging, true).await;
  }
}

/// Wait for the NFS server to accept connections before mounting, so `mount`
/// doesn't race the listener's bind. ~3s budget.
fn wait_until_listening() -> bool {
  for _ in 0..30 {
    if std::net::TcpStream::connect(NFS_ADDR).is_ok() {
      return true;
    }

    std::thread::sleep(std::time::Duration::from_millis(100));
  }

  false
}

/// Mount the running NFS server into the filesystem. On macOS a normal user can
/// mount NFS to a directory they own (no sudo); on Linux `mount` usually needs
/// privilege, so the error is surfaced to the UI.
#[cfg(unix)]
fn os_mount(mount_point: &std::path::Path) -> Result<(), String> {
  // A previous run that was hard-killed (rather than cleanly stopped) leaves a
  // dead NFS mount here; mounting onto it fails with EPERM. Clear any stale
  // mount first so toggling the drive on always works.
  force_unmount(&mount_point.to_string_lossy());

  std::fs::create_dir_all(mount_point)
    .map_err(|e| format!("Could not create the mount folder: {e}"))?;

  let port = NFS_ADDR.rsplit(':').next().unwrap_or("11111");
  let options = format!("nolocks,vers=3,tcp,port={port},mountport={port},soft");

  let output = std::process::Command::new("mount")
    .args(["-t", "nfs", "-o", &options, "127.0.0.1:/"])
    .arg(mount_point)
    .output()
    .map_err(|e| format!("Could not run mount: {e}"))?;

  if output.status.success() {
    Ok(())
  } else {
    Err(format!(
      "mount failed: {}",
      String::from_utf8_lossy(&output.stderr).trim()
    ))
  }
}

#[cfg(unix)]
fn os_unmount(mount_point: &str) {
  force_unmount(mount_point);
}

/// Best-effort force-unmount. Used to tear down on stop and to clear a dead
/// mount left by a hard-killed previous run before mounting again. All errors
/// are ignored: unmounting a path that isn't mounted is a harmless no-op.
#[cfg(unix)]
fn force_unmount(mount_point: &str) {
  let _ = std::process::Command::new("umount")
    .arg("-f")
    .arg(mount_point)
    .output();

  // macOS: `umount -f` sometimes refuses a wedged NFS mount that `diskutil`
  // still clears.
  #[cfg(target_os = "macos")]
  {
    let _ = std::process::Command::new("diskutil")
      .args(["unmount", "force"])
      .arg(mount_point)
      .output();
  }
}

#[cfg(not(unix))]
fn os_mount(_mount_point: &std::path::Path) -> Result<(), String> {
  Err("Mounting the virtual drive isn't supported on this platform yet.".into())
}

#[cfg(not(unix))]
fn os_unmount(_mount_point: &str) {}

/// Open the mounted folder in the OS file manager.
pub fn open_mount() -> Result<(), String> {
  let path = mount_point().ok_or("No mount location.")?;
  #[cfg(target_os = "macos")]
  let opener = "open";
  #[cfg(all(unix, not(target_os = "macos")))]
  let opener = "xdg-open";
  #[cfg(windows)]
  let opener = "explorer";

  std::process::Command::new(opener)
    .arg(&path)
    .spawn()
    .map(|_| ())
    .map_err(|e| format!("Could not open the folder: {e}"))
}

/// Owns the virtual drive's lifecycle — the NFS server *and* the OS mount — so
/// the app (via a Tauri command) turns it on and off with one action.
#[derive(Default)]
pub struct VfsController {
  running: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
  mount_path: Mutex<Option<String>>,
}

impl VfsController {
  /// Start the NFS server (if needed) and mount it into the filesystem. The
  /// server runs on its own thread + runtime, independent of the embedded
  /// server's actix reactor.
  pub fn start(&self, store: Db) -> Result<(), String> {
    {
      let mut running = self.running.lock().unwrap();

      if running.is_none() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        std::thread::Builder::new()
          .name("atomic-vfs-nfs".to_string())
          .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
              .enable_all()
              .build()
            {
              Ok(runtime) => runtime,
              Err(error) => {
                eprintln!("[vfs] could not start the NFS runtime: {error}");
                return;
              }
            };

            if let Err(error) = runtime.block_on(serve_until(store, shutdown_rx)) {
              eprintln!("[vfs] NFS server stopped: {error}");
            }
          })
          .expect("failed to spawn the atomic-vfs-nfs thread");

        *running = Some(shutdown_tx);
        println!("[vfs] virtual drive listening on {NFS_ADDR}");
      }
    }

    if self.mount_path.lock().unwrap().is_some() {
      return Ok(()); // already mounted
    }

    if !wait_until_listening() {
      return Err("The virtual drive did not start listening.".into());
    }

    let mount_point = mount_point().ok_or("Could not find a home folder to mount into.")?;
    os_mount(&mount_point)?;

    let path = mount_point.to_string_lossy().to_string();
    println!("[vfs] virtual drive mounted at {path}");
    *self.mount_path.lock().unwrap() = Some(path);

    Ok(())
  }

  /// Unmount and stop the server. Dropping the shutdown sender ends the accept
  /// loop; the worker thread then exits on its own.
  pub fn stop(&self) {
    if let Some(path) = self.mount_path.lock().unwrap().take() {
      os_unmount(&path);
    }

    self.running.lock().unwrap().take();
  }

  pub fn status(&self) -> VfsStatus {
    let mount_path = self.mount_path.lock().unwrap().clone();

    VfsStatus {
      running: self.running.lock().unwrap().is_some(),
      mounted: mount_path.is_some(),
      mount_path,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn name_of(entry: &DirEntry) -> String {
    String::from_utf8_lossy(entry.name.as_ref()).to_string()
  }

  /// Walk root → drive → folder → file through the NFS trait and confirm the
  /// store maps onto the filesystem: drives are dirs at the root, folders
  /// nest, and a File streams its blob bytes.
  #[tokio::test(flavor = "multi_thread")]
  async fn maps_store_hierarchy_and_reads_a_blob() {
    let store = Db::init_temp("vfs_maps_hierarchy").await.unwrap();

    let drive = store.create_drive("Test Drive").await.unwrap();
    let folder = store
      .create_resource(urls::FOLDER, &drive, "MyFolder", None)
      .await
      .unwrap();

    // A blob keyed by an arbitrary 32-byte hash; the File points at it by
    // hex-encoded internalId, which is exactly what `read` decodes.
    let blob = b"hello vfs".to_vec();
    let hash = [7u8; 32];
    store.kv.insert(Tree::Blobs, &hash, &blob).unwrap();
    store
      .create_resource(
        urls::FILE,
        &folder,
        "hello.txt",
        Some(vec![
          (urls::FILENAME, Value::String("hello.txt".into())),
          (urls::INTERNAL_ID, Value::String(hex::encode(hash))),
          (urls::FILESIZE, Value::Integer(blob.len() as i64)),
        ]),
      )
      .await
      .unwrap();

    let fs = AtomicNfsFs::new(store);

    // Root lists the drive as a directory.
    let root = fs.readdir(ROOT_ID, 0, 100).await.unwrap();
    let drive_entry = root
      .entries
      .iter()
      .find(|entry| name_of(entry) == "Test Drive")
      .expect("drive should appear at the mount root");
    assert!(matches!(drive_entry.attr.ftype, ftype3::NF3DIR));
    assert_eq!(
      fs.lookup(ROOT_ID, &b"Test Drive"[..].into()).await.unwrap(),
      drive_entry.fileid
    );

    // The drive lists the folder as a directory.
    let drive_listing = fs.readdir(drive_entry.fileid, 0, 100).await.unwrap();
    let folder_entry = drive_listing
      .entries
      .iter()
      .find(|entry| name_of(entry) == "MyFolder")
      .expect("folder should appear under the drive");
    assert!(matches!(folder_entry.attr.ftype, ftype3::NF3DIR));

    // The folder lists the file as a regular file with its byte size.
    let folder_listing = fs.readdir(folder_entry.fileid, 0, 100).await.unwrap();
    let file_entry = folder_listing
      .entries
      .iter()
      .find(|entry| name_of(entry) == "hello.txt")
      .expect("file should appear under the folder");
    assert!(matches!(file_entry.attr.ftype, ftype3::NF3REG));
    assert_eq!(file_entry.attr.size, blob.len() as u64);

    // Reading the file returns the blob bytes and flags EOF.
    let (bytes, eof) = fs.read(file_entry.fileid, 0, 1024).await.unwrap();
    assert_eq!(bytes, blob);
    assert!(eof);

    // A partial read respects offset/count and does not flag EOF early.
    let (head, eof) = fs.read(file_entry.fileid, 0, 5).await.unwrap();
    assert_eq!(head, b"hello");
    assert!(!eof);
  }

  /// A resource that is neither a File nor a container surfaces as a read-only
  /// `.inetloc` link file whose bytes open it in Atomic desktop.
  #[tokio::test(flavor = "multi_thread")]
  async fn non_file_resources_surface_as_openable_links() {
    let store = Db::init_temp("vfs_links").await.unwrap();
    let drive = store.create_drive("Link Drive").await.unwrap();
    let table_subject = store
      .create_resource(urls::TABLE, &drive, "My Table", None)
      .await
      .unwrap();

    let fs = AtomicNfsFs::new(store);

    let drive_id = fs.lookup(ROOT_ID, &fname("Link Drive")).await.unwrap();
    let listing = fs.readdir(drive_id, 0, 100).await.unwrap();
    let link = listing
      .entries
      .iter()
      .find(|entry| name_of(entry) == "My Table.inetloc")
      .expect("a non-file resource should appear as a .inetloc link");

    // A read-only regular file.
    assert!(matches!(link.attr.ftype, ftype3::NF3REG));
    assert_eq!(link.attr.mode, LINK_MODE);

    // Its content is the deep link that opens the resource in Atomic desktop.
    let (bytes, _eof) = fs.read(link.fileid, 0, 4096).await.unwrap();
    let content = String::from_utf8(bytes).unwrap();
    assert!(content.contains("atomic:open?subject="));
    assert!(content.contains(&percent_encode(&table_subject)));

    // Lookup resolves the link by its `.inetloc` name.
    assert_eq!(
      fs.lookup(drive_id, &fname("My Table.inetloc"))
        .await
        .unwrap(),
      link.fileid
    );

    // Writes are refused — a link is not an editable File.
    let err = fs.write(link.fileid, 0, b"nope").await.unwrap_err();
    assert!(matches!(err, nfsstat3::NFS3ERR_ROFS));
  }

  #[test]
  fn sanitizes_unsafe_names() {
    assert_eq!(sanitize_name("a/b"), "a\u{ff0f}b");
    assert_eq!(sanitize_name(""), "_");
    assert_eq!(sanitize_name(".."), "\u{2024}\u{2024}");
    assert_eq!(sanitize_name("normal.txt"), "normal.txt");
  }

  #[test]
  fn falls_back_to_the_last_subject_segment() {
    assert_eq!(subject_fallback("https://x.com/foo/bar"), "bar");
    assert_eq!(subject_fallback("https://x.com/baz/"), "baz");
  }

  fn fname(name: &str) -> filename3 {
    name.as_bytes().into()
  }

  fn no_op_sattr() -> sattr3 {
    use nfsserve::nfs::{set_atime, set_gid3, set_mode3, set_mtime, set_uid3};

    sattr3 {
      mode: set_mode3::Void,
      uid: set_uid3::Void,
      gid: set_gid3::Void,
      size: set_size3::Void,
      atime: set_atime::DONT_CHANGE,
      mtime: set_mtime::DONT_CHANGE,
    }
  }

  /// Create → write → (staged) read → flush → persist, plus mkdir, rename,
  /// truncate and remove, all through the NFS trait against a real store.
  #[tokio::test(flavor = "multi_thread")]
  async fn writes_create_edit_rename_truncate_and_remove() {
    let store = Db::init_temp("vfs_write").await.unwrap();
    let drive = store.create_drive("Write Drive").await.unwrap();
    let _ = drive;
    let fs = AtomicNfsFs::new(store.clone());

    let root = fs.readdir(ROOT_ID, 0, 100).await.unwrap();
    let drive_id = root
      .entries
      .iter()
      .find(|entry| name_of(entry) == "Write Drive")
      .unwrap()
      .fileid;

    // mkdir under the drive.
    let (folder_id, folder_attr) = fs.mkdir(drive_id, &fname("Docs")).await.unwrap();
    assert!(matches!(folder_attr.ftype, ftype3::NF3DIR));

    // create + write; a read sees the staged bytes before the flush commits.
    let (file_id, _) = fs
      .create(folder_id, &fname("note.txt"), no_op_sattr())
      .await
      .unwrap();
    let attr = fs.write(file_id, 0, b"hello vfs").await.unwrap();
    assert_eq!(attr.size, 9);
    let (staged, _) = fs.read(file_id, 0, 100).await.unwrap();
    assert_eq!(staged, b"hello vfs");

    // flush → the File resource persists the bytes as a signed commit.
    flush_ready(&store, &fs.staging, false).await;
    let subject = fs.ids.subject(file_id).unwrap();
    let resource = store
      .get_resource(&Subject::from(subject.as_str()))
      .await
      .unwrap();
    assert_eq!(read_blob(&store, &resource).unwrap(), b"hello vfs");

    // truncate to empty via setattr(size = 0), then flush.
    fs.setattr(file_id, {
      let mut attr = no_op_sattr();
      attr.size = set_size3::size(0);
      attr
    })
    .await
    .unwrap();
    flush_ready(&store, &fs.staging, false).await;
    let resource = store
      .get_resource(&Subject::from(subject.as_str()))
      .await
      .unwrap();
    assert_eq!(read_blob(&store, &resource).unwrap().len(), 0);

    // rename within the folder.
    fs.rename(
      folder_id,
      &fname("note.txt"),
      folder_id,
      &fname("renamed.txt"),
    )
    .await
    .unwrap();
    assert!(fs.lookup(folder_id, &fname("renamed.txt")).await.is_ok());
    assert!(fs.lookup(folder_id, &fname("note.txt")).await.is_err());

    // remove.
    fs.remove(folder_id, &fname("renamed.txt")).await.unwrap();
    assert!(fs.lookup(folder_id, &fname("renamed.txt")).await.is_err());
  }

  /// A file keeps its NFS fileid across a remount (a fresh `AtomicNfsFs` with an
  /// empty cache), because the map is persisted in the store.
  #[tokio::test(flavor = "multi_thread")]
  async fn fileids_are_stable_across_remounts() {
    let store = Db::init_temp("vfs_stable_ids").await.unwrap();
    let drive = store.create_drive("Stable Drive").await.unwrap();
    let folder = store
      .create_resource(urls::FOLDER, &drive, "F", None)
      .await
      .unwrap();

    async fn folder_id(fs: &AtomicNfsFs) -> fileid3 {
      let root = fs.readdir(ROOT_ID, 0, 100).await.unwrap();
      let drive_id = root
        .entries
        .iter()
        .find(|entry| name_of(entry) == "Stable Drive")
        .unwrap()
        .fileid;
      let listing = fs.readdir(drive_id, 0, 100).await.unwrap();
      listing
        .entries
        .iter()
        .find(|entry| name_of(entry) == "F")
        .unwrap()
        .fileid
    }

    let first = folder_id(&AtomicNfsFs::new(store.clone())).await;

    // A second mount starts with an empty in-memory cache but reads the
    // persisted map, so the same subject yields the same id.
    let fs2 = AtomicNfsFs::new(store.clone());
    let second = folder_id(&fs2).await;

    assert_eq!(first, second);
    assert_eq!(fs2.ids.subject(second).unwrap(), folder);
  }

  /// Paging a directory in small chunks returns every child exactly once — the
  /// listing is built once (cookie 0) and served from cache across pages.
  #[tokio::test(flavor = "multi_thread")]
  async fn readdir_pages_through_a_directory() {
    let store = Db::init_temp("vfs_readdir_pages").await.unwrap();
    let drive = store.create_drive("Paging Drive").await.unwrap();
    let folder = store
      .create_resource(urls::FOLDER, &drive, "Many", None)
      .await
      .unwrap();

    for i in 0..25 {
      store
        .create_resource(
          urls::FILE,
          &folder,
          &format!("f{i:02}"),
          Some(vec![
            (urls::FILENAME, Value::String(format!("f{i:02}.txt"))),
            (urls::INTERNAL_ID, Value::String(hex::encode([0u8; 32]))),
            (urls::FILESIZE, Value::Integer(0)),
          ]),
        )
        .await
        .unwrap();
    }

    let fs = AtomicNfsFs::new(store.clone());
    let root = fs.readdir(ROOT_ID, 0, 100).await.unwrap();
    let drive_id = root
      .entries
      .iter()
      .find(|entry| name_of(entry) == "Paging Drive")
      .unwrap()
      .fileid;
    let drive_listing = fs.readdir(drive_id, 0, 100).await.unwrap();
    let folder_id = drive_listing
      .entries
      .iter()
      .find(|entry| name_of(entry) == "Many")
      .unwrap()
      .fileid;

    let mut names = std::collections::HashSet::new();
    let mut cursor = 0;

    loop {
      let page = fs.readdir(folder_id, cursor, 10).await.unwrap();

      for entry in &page.entries {
        names.insert(name_of(entry));
      }

      if page.end || page.entries.is_empty() {
        break;
      }

      cursor = page.entries.last().unwrap().fileid;
    }

    assert_eq!(names.len(), 25);
    assert!(names.contains("f00.txt"));
    assert!(names.contains("f24.txt"));
  }

  fn chunk_hashes(resource: &Resource) -> Vec<String> {
    match resource.get(urls::CHUNKS) {
      Ok(Value::ResourceArray(chunks)) => chunks.iter().map(|c| c.to_string()).collect(),
      _ => Vec::new(),
    }
  }

  /// A large file is stored as content-defined chunks; a small overwrite reuses
  /// (dedupes) all but the touched chunk, and reads reconstruct exactly.
  #[tokio::test(flavor = "multi_thread")]
  async fn large_files_are_chunked_and_dedupe_on_edit() {
    let store = Db::init_temp("vfs_chunking").await.unwrap();
    let _drive = store.create_drive("Chunk Drive").await.unwrap();
    let fs = AtomicNfsFs::new(store.clone());
    let root = fs.readdir(ROOT_ID, 0, 100).await.unwrap();
    let drive_id = root
      .entries
      .iter()
      .find(|entry| name_of(entry) == "Chunk Drive")
      .unwrap()
      .fileid;

    // ~10 MB of varied content so FastCDC finds several boundaries.
    let mut data: Vec<u8> = (0..10_000_000u32)
      .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
      .collect();

    let (file_id, _) = fs
      .create(drive_id, &fname("big.bin"), no_op_sattr())
      .await
      .unwrap();
    fs.write(file_id, 0, &data).await.unwrap();
    flush_ready(&store, &fs.staging, false).await;

    let subject = fs.ids.subject(file_id).unwrap();
    let resource = store
      .get_resource(&Subject::from(subject.as_str()))
      .await
      .unwrap();
    let chunks_v1 = chunk_hashes(&resource);
    assert!(chunks_v1.len() > 1, "a 10 MB file should be many chunks");
    // Reconstruction from chunks matches the original.
    assert_eq!(read_blob(&store, &resource).unwrap(), data);

    // Overwrite a few bytes near the start; the rest of the file is unchanged.
    data[100..110].copy_from_slice(b"CHANGEDXYZ");
    fs.write(file_id, 100, b"CHANGEDXYZ").await.unwrap();
    flush_ready(&store, &fs.staging, false).await;

    let resource = store
      .get_resource(&Subject::from(subject.as_str()))
      .await
      .unwrap();
    let chunks_v2 = chunk_hashes(&resource);
    let shared = chunks_v1.iter().filter(|h| chunks_v2.contains(*h)).count();
    assert!(
      shared as f64 > chunks_v1.len() as f64 * 0.5,
      "a localized edit should reuse most chunks (shared {shared} of {})",
      chunks_v1.len()
    );

    // And the edit is reflected on read.
    assert_eq!(read_blob(&store, &resource).unwrap(), data);
  }
}

/// Opt-in performance benchmarks. They print throughput/latency numbers (the
/// planning doc asks for "numbers, not adjectives") and a couple assert a floor
/// so a real regression fails rather than merely prints. Run with:
///   cargo test -p atomic-server-tauri --lib benches -- --ignored --nocapture
#[cfg(test)]
mod benches {
  use super::*;
  use std::time::Instant;

  /// Deterministic pseudo-random bytes, so content-defined chunking finds real
  /// boundaries (a constant fill collapses to uniform max-size chunks).
  fn pseudo_random(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    while out.len() < len {
      state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
      out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
  }

  /// A drive holding one File whose `bytes` are stored exactly as a flush would
  /// (chunked when large) — but *without* going through write staging, so reads
  /// take the blob-reconstruction path rather than returning staged RAM.
  async fn drive_with_stored_file(name: &str, bytes: &[u8]) -> (Db, String) {
    let store = Db::init_temp("vfs_bench").await.unwrap();
    let drive = store.create_drive("Bench Drive").await.unwrap();
    let subject = store
      .create_resource(
        urls::FILE,
        &drive,
        name,
        Some(vec![
          (urls::FILENAME, Value::String(name.to_string())),
          (
            urls::MIMETYPE,
            Value::String("application/octet-stream".to_string()),
          ),
          (
            urls::INTERNAL_ID,
            Value::String(blake3::hash(&[]).to_hex().to_string()),
          ),
          (urls::FILESIZE, Value::Integer(0)),
        ]),
      )
      .await
      .unwrap();

    commit_file(&store, &subject, bytes).await;

    (store, subject)
  }

  /// Count of stored blobs and their total size — a proxy for on-disk growth.
  fn blob_stats(store: &Db) -> (usize, u64) {
    let mut count = 0;
    let mut bytes = 0u64;
    for item in store.kv.iter_tree(Tree::Blobs).flatten() {
      count += 1;
      bytes += item.1.len() as u64;
    }
    (count, bytes)
  }

  fn file_id_named(listing: &ReadDirResult, name: &str) -> fileid3 {
    listing
      .entries
      .iter()
      .find(|entry| String::from_utf8_lossy(entry.name.as_ref()) == name)
      .unwrap_or_else(|| panic!("{name} not in listing"))
      .fileid
  }

  #[tokio::test(flavor = "multi_thread")]
  #[ignore = "perf benchmark; run with --ignored --nocapture"]
  async fn bench_sequential_read_throughput() {
    const SIZE: usize = 32 * 1024 * 1024; // 32 MiB
    const WINDOW: usize = 1024 * 1024; // 1 MiB, an NFS-ish read window

    let data = pseudo_random(SIZE);
    let (store, _subject) = drive_with_stored_file("big.bin", &data).await;
    let fs = AtomicNfsFs::new(store); // empty staging → reads take the blob path

    let drive_id = fs
      .lookup(ROOT_ID, &b"Bench Drive"[..].into())
      .await
      .unwrap();
    let listing = fs.readdir(drive_id, 0, 100).await.unwrap();
    let file_id = file_id_named(&listing, "big.bin");

    let start = Instant::now();
    let mut offset = 0u64;
    let mut total = 0usize;
    loop {
      let (chunk, eof) = fs.read(file_id, offset, WINDOW as u32).await.unwrap();
      total += chunk.len();
      offset += chunk.len() as u64;
      if eof || chunk.is_empty() {
        break;
      }
    }
    let secs = start.elapsed().as_secs_f64();
    let mib = SIZE as f64 / (1024.0 * 1024.0);
    println!(
      "[bench] sequential read {:.0} MiB in {} x {} KiB windows: {:.3}s -> {:.1} MiB/s",
      mib,
      SIZE / WINDOW,
      WINDOW / 1024,
      secs,
      mib / secs
    );
    assert_eq!(total, SIZE, "read back the whole file");
  }

  #[tokio::test(flavor = "multi_thread")]
  #[ignore = "perf benchmark; run with --ignored --nocapture"]
  async fn bench_save_latency() {
    const SIZE: usize = 32 * 1024 * 1024;

    let data = pseudo_random(SIZE);
    let (store, subject) = drive_with_stored_file("save.bin", &data).await;

    // One-byte edit, then time the re-save (re-chunk + store).
    let mut edited = data.clone();
    edited[SIZE / 2] ^= 0xFF;

    let start = Instant::now();
    commit_file(&store, &subject, &edited).await;
    let secs = start.elapsed().as_secs_f64();
    let mib = SIZE as f64 / (1024.0 * 1024.0);
    println!(
      "[bench] save {:.0} MiB (1-byte edit, re-chunk+store): {:.3}s -> {:.1} MiB/s",
      mib,
      secs,
      mib as f64 / secs
    );
  }

  #[tokio::test(flavor = "multi_thread")]
  #[ignore = "perf benchmark; run with --ignored --nocapture"]
  async fn bench_db_growth_per_edit() {
    const EDITS: usize = 50;
    const SIZE: usize = 256 * 1024; // small file: single blob, no chunk dedup

    let (store, subject) = drive_with_stored_file("doc.bin", &pseudo_random(SIZE)).await;
    let (c0, b0) = blob_stats(&store);

    for i in 0..EDITS {
      let mut data = pseudo_random(SIZE);
      data[0] = i as u8; // guarantee distinct content each edit
      commit_file(&store, &subject, &data).await;
    }

    let (c1, b1) = blob_stats(&store);
    println!(
      "[bench] {EDITS} edits of a {} KiB file: blobs {c0}->{c1} (+{}), stored bytes {}->{} KiB (+{} KiB) — old blobs are never GC'd",
      SIZE / 1024,
      c1 - c0,
      b0 / 1024,
      b1 / 1024,
      (b1 - b0) / 1024
    );
  }

  #[tokio::test(flavor = "multi_thread")]
  #[ignore = "perf benchmark; run with --ignored --nocapture"]
  async fn bench_listing_latency() {
    const N: usize = 1000;

    let store = Db::init_temp("vfs_bench_list").await.unwrap();
    let drive = store.create_drive("List Drive").await.unwrap();
    for i in 0..N {
      store
        .create_resource(urls::FOLDER, &drive, &format!("folder{i:04}"), None)
        .await
        .unwrap();
    }

    let fs = AtomicNfsFs::new(store);
    let drive_id = fs.lookup(ROOT_ID, &b"List Drive"[..].into()).await.unwrap();

    let start = Instant::now();
    let listing = fs.readdir(drive_id, 0, N + 10).await.unwrap();
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    println!(
      "[bench] readdir cold build of {} children: {:.1}ms ({} entries)",
      N,
      ms,
      listing.entries.len()
    );
    assert!(listing.entries.len() >= N);
  }
}
