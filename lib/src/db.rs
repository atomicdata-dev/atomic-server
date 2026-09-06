//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by Sled - an embedded database.

pub mod btreemap_store;
mod encoding;
#[cfg(feature = "db-redb")]
pub mod encrypted_backend;
pub mod kv_store;
#[cfg(feature = "db-sled")]
mod migrations;
#[cfg(all(feature = "db-redb", target_arch = "wasm32"))]
pub mod opfs_backend;
pub mod plugin_meta;
pub(crate) mod prop_val_sub_index;
mod query_index;
#[cfg(feature = "db-redb")]
pub mod redb_store;
pub use query_index::{drive_prefix_from_subject, query_id, QueryFilter};
#[cfg(feature = "db-sled")]
pub mod sled_store;
#[cfg(test)]
pub mod test;
pub mod trees;
#[cfg(feature = "db-sled")]
mod v1_types;
#[cfg(feature = "db-sled")]
mod v2_types;
mod val_prop_sub_index;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
    vec,
};

use crate::{
    agents::ForAgent,
    atoms::IndexAtom,
    class_extender::{
        ClassExtender, ClassExtenderScope, CommitExtenderContext, GetExtenderContext,
    },
    commit::{CommitOpts, CommitResponse},
    db::{
        encoding::{decode_propvals, encode_propvals},
        plugin_meta::{PluginMeta, PluginMetaKey},
        query_index::requires_query_index,
        val_prop_sub_index::find_in_val_prop_sub_index,
    },
    endpoints::{Endpoint, HandleGetContext},
    errors::{AtomicError, AtomicResult},
    hierarchy::RightsCache,
    resources::PropVals,
    storelike::{Query, QueryResult, ResourceResponse, Storelike},
    urls, Atom, Commit, Resource, Subject, Value,
};
use async_trait::async_trait;
use tracing::{info, instrument};
use trees::{Method, Operation, Transaction, Tree};

use self::{
    kv_store::KvStore,
    prop_val_sub_index::{add_atom_to_prop_val_sub_index, find_in_prop_val_sub_index},
    query_index::{
        check_if_atom_matches_watched_query_filters, query_sorted_indexed, update_indexed_member,
        IndexIterator,
    },
    val_prop_sub_index::add_atom_to_valpropsub_index,
};

// A function called by the Store when a Commit is accepted
type HandleCommit = Box<dyn Fn(&CommitResponse) + Send + Sync>;

/// Live-collaboration state received from a peer over the sync link:
/// presence, cursors, or the ops of an edit someone has not saved yet.
///
/// Separate from [`DbEvent`] because none of it is written here: it exists only
/// to be handed to whatever is currently rendering (websocket clients), then
/// forgotten. Uncommitted ops become durable only if a local user saves the
/// document they land in, which produces a signed commit under that user's own
/// identity. The originating agent travels with it because a peer link is
/// node-to-node while this state is per-agent — one node may relay several
/// people's cursors and edits.
#[derive(Debug, Clone)]
pub struct EphemeralEvent {
    /// Which channel this belongs to — per-document Loro ephemeral,
    /// drive-scoped presence, or an edit in progress. They fan out to different
    /// subscribers, so the distinction has to survive the trip. See
    /// `protocol::ephemeral_kind`.
    pub kind: u8,
    /// What the state is scoped to: the drive for presence, the resource for
    /// the other two.
    pub drive: String,
    /// The agent this came from.
    pub agent: String,
    /// Opaque Loro update — `EphemeralStore` bytes for presence and cursors,
    /// document ops for an edit in progress.
    pub payload: Vec<u8>,
    /// The peer that relayed it, so it is not sent straight back.
    pub from_peer: String,
}

/// Event emitted when a resource is created, updated, or deleted.
#[derive(Debug, Clone)]
pub enum DbEvent {
    /// Resource changed. Carries the subject (pure_id) and the Loro delta if available.
    Changed {
        subject: Subject,
        /// The Loro delta (from the commit's loro_update). None for non-Loro changes.
        delta: Option<Vec<u8>>,
        /// Optional transport/source identity for echo suppression.
        source_id: Option<String>,
        /// True when this change created the resource (no prior version).
        is_new: bool,
        /// Whether an applied commit produced this change.
        ///
        /// A commit also runs `handle_commit`, which is how `atomic-server`
        /// tells subscribed WebSocket clients that something moved. Writes that
        /// arrive as raw CRDT state — a peer's live `UPDATE` frame, a bulk
        /// `SYNC_PUSH` import — have no commit, so nothing announces them and
        /// the local UI renders a store it no longer matches. Listeners use
        /// this to fan out exactly the changes the commit hook won't.
        from_commit: bool,
    },
    /// Resource destroyed.
    Destroyed {
        subject: Subject,
        /// The drive this resource belonged to, read before it was removed.
        ///
        /// Carried rather than looked up: by the time a listener reacts, the
        /// resource is gone from the store, so the drive is unrecoverable. It
        /// is what routes the removal to the drive's subscribers — and since
        /// clients subscribe per drive and not per resource, a `None` here
        /// means no client is ever told.
        drive: Option<Subject>,
        /// Optional transport/source identity for echo suppression.
        source_id: Option<String>,
        /// See [`DbEvent::Changed::from_commit`].
        from_commit: bool,
        /// The signed destroy commit that caused this, as JSON-AD, when a
        /// commit did. This is what a peer transport forwards: a destroy
        /// crosses the link as a `COMMIT` frame the receiver validates
        /// (signature + the signer's rights), never as a naked `DESTROY`.
        /// `None` for removals no commit authorises (a cascade-deleted
        /// child, a local cache eviction) — those are not propagated live;
        /// the peer's own apply of the parent commit cascades there too.
        commit_json: Option<String>,
    },
    /// A resource entered or left the result set of a watched query. Emitted
    /// from `apply_transaction` after a successful write that touches
    /// `Tree::QueryMembers`. `query_id` is the compact filter id
    /// ([`query_index::query_id`] of the encoded `QueryFilter`); subscribers
    /// derive the same id from the filter they registered.
    ///
    /// Note: a sort-key change on an already-matching resource produces a
    /// (Removed, Added) pair for the same `(query_id, subject)` within a
    /// single commit. Consumers that want true add/remove semantics should
    /// dedup; consumers that want every membership-touching event (the
    /// current text `QUERY_UPDATE` model) can pass them through.
    QueryMembershipChanged {
        query_id: Vec<u8>,
        subject: String,
        added: bool,
        /// Optional transport/source identity for echo suppression.
        source_id: Option<String>,
    },
}

/// A drive with its subject and display name.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DriveInfo {
    pub subject: String,
    pub name: String,
}

/// Per-drive storage usage. A managed node reports these to its control plane
/// (`POST /api/node-usage`) for quota tracking; field names match that wire
/// contract. See [`Db::per_drive_usage`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct DriveUsage {
    pub drive_subject: String,
    pub name: Option<String>,
    pub resource_count: u64,
    pub blob_bytes: u64,
    pub loro_bytes: u64,
}

/// Result of loading an agent from a secret.
pub struct AgentLoadResult {
    pub agent: crate::agents::Agent,
    /// If true, the drive DID from the secret doesn't exist locally.
    /// The caller must sync with another device to obtain the genesis commit.
    pub drive_needs_sync: bool,
}

/// Result of mapping an incoming request target to a canonical subject.
pub struct ResolvedTarget {
    pub subject: Subject,
    pub alias_subject: Option<String>,
}

/// Inside the reference_index, each value is mapped to this type.
/// The String on the left represents a Property URL, and the second one is the set of subjects.
pub type PropSubjectMap = HashMap<String, HashSet<String>>;

/// A remote Atomic Server that a drive is replicated to.
///
/// Deliberately server-local: see [`Db::get_replication_targets`] for why this
/// must never be stored inside the drive it describes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplicationTarget {
    /// WebSocket URL of the remote server, e.g. `wss://example.com/ws`.
    pub url: String,
    /// The agent that asked for this replication. Its *read* rights bound what
    /// gets exported, so a later boot-time re-run stays scoped to what the
    /// person who authorized it could actually see.
    pub authorized_by: String,
}

const REPLICATION_PREFIX: &str = "replication:";

/// `Tree::PluginMeta` key holding the fingerprint of the built-in defaults
/// last seeded into this store. See `populate::bootstrap`.
const DEFAULTS_FINGERPRINT_KEY: &[u8] = b"defaults_fingerprint";

fn replication_key(drive: &str) -> String {
    format!("{REPLICATION_PREFIX}{drive}")
}

/// One drive's watched query filters, routed by the properties they touch so
/// a changed atom only evaluates filters that could care about it.
#[derive(Default, Debug)]
struct DriveFilters {
    /// Every watched filter for this drive. Kept alongside the routed views
    /// so rebuilds and full enumerations stay simple.
    all: Vec<Arc<query_index::QueryFilter>>,
    /// Filters indexed under every property they reference: each constraint's
    /// property plus `sort_by`. A filter appears once per distinct property.
    by_property: HashMap<String, Vec<Arc<query_index::QueryFilter>>>,
    /// Filters with at least one value-only constraint (no property) — an
    /// atom of *any* property can flip their membership, so they are
    /// consulted for every atom.
    unrouted: Vec<Arc<query_index::QueryFilter>>,
}

impl DriveFilters {
    fn insert(&mut self, filter: Arc<query_index::QueryFilter>) {
        self.all.push(filter.clone());
        if filter.filters.iter().any(|c| c.property.is_none()) {
            self.unrouted.push(filter);
            return;
        }
        let mut props: HashSet<&String> = filter
            .filters
            .iter()
            .filter_map(|c| c.property.as_ref())
            .collect();
        if let Some(sort) = &filter.sort_by {
            props.insert(sort);
        }
        let props: Vec<String> = props.into_iter().cloned().collect();
        for prop in props {
            self.by_property
                .entry(prop)
                .or_default()
                .push(filter.clone());
        }
    }

    /// The filters a changed atom with `property` must be checked against.
    fn for_property(&self, property: &str) -> Vec<Arc<query_index::QueryFilter>> {
        let mut out: Vec<Arc<query_index::QueryFilter>> =
            self.by_property.get(property).cloned().unwrap_or_default();
        out.extend(self.unrouted.iter().cloned());
        out
    }
}

/// The Db is a persistent on-disk Atomic Data store.
/// It's an implementation of [Storelike].
/// It uses a [KvStore] backend for key-value storage (sled, BTreeMap, etc.).
/// It stores [Resource]s as [PropVals]s by their subject as key.
/// It builds a value index for performant [Query]s.
/// It keeps track of Queries and updates their index when [crate::Commit]s are applied.
/// You can pass a custom `on_commit` function to run at Commit time.
/// `Db` should be easily, cheaply clone-able, as users of this library could have one `Db` per connection.
#[derive(Clone)]
pub struct Db {
    /// The key-value store backend. Abstracted behind a trait so different
    /// backends (sled, BTreeMap, etc.) can be used interchangeably.
    pub kv: Arc<dyn KvStore>,
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
    /// Endpoints are checked whenever a resource is requested. They calculate (some properties of) the resource and return it.
    endpoints: Vec<Endpoint>,
    /// List of class extenders.
    class_extenders: Arc<RwLock<Vec<ClassExtender>>>,
    /// Function called whenever a Commit is applied.
    on_commit: Option<Arc<HandleCommit>>,
    /// Broadcast channel for all resource mutations.
    db_events: tokio::sync::broadcast::Sender<DbEvent>,
    /// Presence arriving from a peer. Deliberately NOT `db_events`: presence is
    /// ephemeral and must never reach the store, and every consumer of
    /// `DbEvent` writes or indexes. Cursor positions merged into the CRDT would
    /// be persisted and synced forever.
    ///
    /// Small buffer on purpose — presence is worth dropping under load, unlike
    /// a resource change. A lagging subscriber loses cursors, not data.
    ephemeral_events: tokio::sync::broadcast::Sender<EphemeralEvent>,
    /// In-memory authoritative map of watched query filters, keyed by drive
    /// prefix (e.g. `"https://example.com"` for HTTP drives, the DID for
    /// DID-form drives) and routed by property within each drive (see
    /// [`DriveFilters`]). The KV `Tree::WatchedQueries` is the persistence
    /// layer; this map is the runtime lookup. Populated from the KV at Db
    /// open, kept in sync by `Db::register_watched_query`. The hot path in
    /// `check_if_atom_matches_watched_query_filters` reads from here and
    /// never touches msgpack on a commit.
    watched_queries_by_drive: Arc<RwLock<HashMap<String, DriveFilters>>>,
    /// Serialises writers that read-modify-write the same subject's state, so
    /// a commit and a sync apply cannot replace each other's snapshot. Per
    /// store, not global — see [`crate::subject_lock`].
    pub(crate) subject_locks: crate::subject_lock::SubjectLocks,
    /// Where the DB is stored on disk.
    #[allow(dead_code)]
    path: std::path::PathBuf,
    /// The base domain of the store.
    pub base_domain: Option<String>,
    /// Sync admission/quota policy consulted before importing a `SYNC_PUSH`.
    /// Defaults to the permissive [`crate::sync::policy::OpenPolicy`] so
    /// self-hosted / local-first nodes are unrestricted; a managed node
    /// installs a concrete policy via [`Db::set_sync_policy`].
    sync_policy: Arc<RwLock<Arc<dyn crate::sync::policy::SyncPolicy>>>,
    /// Which signed envelopes `apply_commit` keeps per resource
    /// (`crate::envelopes`). `Latest` by default; a node that wants a signed
    /// audit log runs `All`.
    envelope_retention: Arc<RwLock<crate::envelopes::EnvelopeRetention>>,
    /// Short-lived hash → (drive-subject, requested-at) map for blob hashes
    /// the server has asked a peer for (via `BLOB_REQUEST`, emitted from
    /// `import_sync_push` for an already-admitted drive). Consulted when
    /// the matching `BLOB_RESPONSE` arrives — a frame with no matching
    /// entry here was never requested and is rejected outright; one with a
    /// match is gated through `sync_policy().admit_drive_write` before the
    /// bytes are stored (planning/unified-sync.md F4). Node-wide rather
    /// than per-connection: cloning `Db` shares the same `Arc`, so it
    /// works uniformly whether the response arrives over the WS or Iroh
    /// transport. Entries are normally consumed (removed) on first use; a
    /// peer that never responds would otherwise leak one entry per missing
    /// blob forever, so `note_pending_blob_request` also lazily prunes
    /// anything older than `PENDING_BLOB_REQUEST_TTL`.
    pending_blob_requests: Arc<RwLock<HashMap<[u8; 32], (String, std::time::Instant)>>>,
}

/// How long an unanswered `BLOB_REQUEST` stays in `pending_blob_requests`
/// before lazy pruning drops it. Generous relative to a realistic peer
/// round trip (seconds) — this bounds a slow leak from peers that vanish
/// mid-sync, not a normal-latency budget.
const PENDING_BLOB_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The default (permissive) sync policy reference used by every `Db` until a
/// managed node installs one.
fn default_sync_policy() -> Arc<RwLock<Arc<dyn crate::sync::policy::SyncPolicy>>> {
    Arc::new(RwLock::new(Arc::new(crate::sync::policy::OpenPolicy)))
}

impl Db {
    /// Install a sync admission/quota policy (managed nodes). The default is
    /// [`crate::sync::policy::OpenPolicy`] (allow everything, no quotas).
    pub fn set_sync_policy(&self, policy: Arc<dyn crate::sync::policy::SyncPolicy>) {
        if let Ok(mut guard) = self.sync_policy.write() {
            *guard = policy;
        }
    }

    /// The currently-installed sync policy.
    /// Set how many signed envelopes are kept per resource. Takes effect on
    /// the next `apply_commit`; existing rows are pruned when their resource
    /// is next written.
    pub fn set_envelope_retention(&self, retention: crate::envelopes::EnvelopeRetention) {
        if let Ok(mut guard) = self.envelope_retention.write() {
            *guard = retention;
        }
    }

    pub fn envelope_retention(&self) -> crate::envelopes::EnvelopeRetention {
        self.envelope_retention
            .read()
            .map(|g| *g)
            .unwrap_or_default()
    }

    pub fn sync_policy(&self) -> Arc<dyn crate::sync::policy::SyncPolicy> {
        self.sync_policy
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| Arc::new(crate::sync::policy::OpenPolicy))
    }

    /// Record that the server asked a peer for `hash` while importing a
    /// `SYNC_PUSH` for `drive` (already admission-checked at that point).
    /// Consulted by the `BLOB_RESPONSE` handler (planning/unified-sync.md
    /// F4) so it can gate the write against that same drive instead of
    /// accepting arbitrary blob bytes unconditionally.
    pub fn note_pending_blob_request(&self, hash: [u8; 32], drive: String) {
        if let Ok(mut guard) = self.pending_blob_requests.write() {
            let now = std::time::Instant::now();
            guard.retain(|_, (_, requested_at)| {
                now.duration_since(*requested_at) < PENDING_BLOB_REQUEST_TTL
            });
            guard.insert(hash, (drive, now));
        }
    }

    /// Consume (remove) the drive a pending `BLOB_REQUEST` for `hash` was
    /// issued for, if any. `None` means this hash was never requested by
    /// this node (or the request expired — see `PENDING_BLOB_REQUEST_TTL`)
    /// — the caller should reject the response outright.
    pub fn take_pending_blob_request(&self, hash: &[u8; 32]) -> Option<String> {
        let (drive, requested_at) = self
            .pending_blob_requests
            .write()
            .ok()
            .and_then(|mut guard| guard.remove(hash))?;

        if requested_at.elapsed() < PENDING_BLOB_REQUEST_TTL {
            Some(drive)
        } else {
            None
        }
    }

    /// Creates a new store at the specified path, or opens the store if it already exists.
    /// Uses sled as the storage backend.
    #[cfg(feature = "db-sled")]
    pub async fn init(path: &std::path::Path, base_domain: Option<String>) -> AtomicResult<Db> {
        tracing::info!("Opening database at {:?}", path);

        let sled_store = sled_store::SledStore::open(path)?;

        // Run migrations before wrapping in Arc (migrations need direct sled access)
        migrations::migrate_maybe(&sled_store, base_domain.as_deref())
            .map(|e| format!("Error during migration of database: {:?}", e))?;

        let store = Db {
            path: path.into(),
            kv: Arc::new(sled_store),
            default_agent: Arc::new(Mutex::new(None)),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),

            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
        };

        store.add_class_extender(crate::collections::get_collection_class_extender())?;

        // Load persisted watched-queries (if any) into the in-memory map
        // before bootstrap, so any filter-matching commits during bootstrap
        // see the right state.
        store.populate_watched_queries_cache()?;

        // Runs on every open, but only writes when the embedded defaults
        // (`lib/defaults/*.json` + base models) changed since this store was
        // last seeded: `bootstrap` compares a fingerprint of them against the
        // one stored in `Tree::PluginMeta` and adds what is missing.
        crate::populate::bootstrap(&store)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        crate::search::maybe_rebuild_search_index(&store)?;
        Ok(store)
    }

    /// Creates a Db backed by an in-memory BTreeMap store.
    /// Useful for tests and WASM targets.
    pub async fn init_memory(base_domain: Option<String>) -> AtomicResult<Db> {
        let store = Db {
            path: std::path::PathBuf::new(),
            kv: Arc::new(btreemap_store::BTreeMapStore::new()),
            default_agent: Arc::new(Mutex::new(None)),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),

            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
        };

        store.add_class_extender(crate::collections::get_collection_class_extender())?;

        store.populate_watched_queries_cache()?;
        crate::populate::bootstrap(&store)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        crate::search::maybe_rebuild_search_index(&store)?;
        Ok(store)
    }

    /// Creates a Db backed by redb with an in-memory backend.
    /// Useful for WASM targets where redb provides proper B-tree indexing.
    /// Can be upgraded to OPFS persistence in the future.
    #[cfg(feature = "db-redb")]
    pub async fn init_redb(base_domain: Option<String>) -> AtomicResult<Db> {
        let redb_store = redb_store::RedbStore::new_memory()?;

        let store = Db {
            path: std::path::PathBuf::new(),
            kv: Arc::new(redb_store),
            default_agent: Arc::new(Mutex::new(None)),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),

            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
        };

        store.add_class_extender(crate::collections::get_collection_class_extender())?;

        store.populate_watched_queries_cache()?;
        crate::populate::bootstrap(&store)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        crate::search::maybe_rebuild_search_index(&store)?;
        Ok(store)
    }

    /// Creates a Db backed by redb with file-based persistent storage.
    /// Works on all native targets (not WASM — use init_redb_opfs for that).
    #[cfg(all(feature = "db-redb", not(target_arch = "wasm32")))]
    pub async fn init_redb_file(
        path: &std::path::Path,
        base_domain: Option<String>,
        uploads_path: &std::path::Path,
    ) -> AtomicResult<Db> {
        tracing::info!("Opening ReDB database at {:?}", path);

        std::fs::create_dir_all(path).map_err(|e| {
            format!(
                "Failed to create database directory {}: {e}",
                path.display()
            )
        })?;

        let redb_path = path.join("atomic.redb");

        // Migration logic: if a sled store exists but redb doesn't, migrate it.
        #[cfg(feature = "db-sled")]
        if !redb_path.exists() {
            let sled_path = path.join("sled");

            // Pre-redb servers stored the sled DB directly in the store dir
            // (`store/db`, `store/conf`), NOT in a `sled/` subdir. Detect that
            // legacy layout and relocate the sled files into `sled/` first.
            // Without this the auto-migration never fires on a real in-place
            // upgrade, and `migrate_from_sled`'s rename-to-`.bak` would try to
            // rename the whole store dir — clobbering the redb we just wrote.
            let legacy_root_sled =
                !sled_path.exists() && path.join("db").exists() && path.join("conf").exists();
            if legacy_root_sled {
                tracing::warn!(
                    "Detected a legacy sled store at the store root; relocating it into `sled/` before migration."
                );
                std::fs::create_dir_all(&sled_path)?;
                // Collect first, then move — don't mutate the dir mid-iteration.
                // Everything in the store dir is sled's (uploads live elsewhere);
                // skip the `sled/` dir we just created.
                let names: Vec<std::ffi::OsString> = std::fs::read_dir(path)?
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .filter(|name| name.as_os_str() != "sled")
                    .collect();
                for name in names {
                    std::fs::rename(path.join(&name), sled_path.join(&name))?;
                }
            }

            if sled_path.exists() {
                Self::migrate_from_sled(
                    &sled_path,
                    &redb_path,
                    uploads_path,
                    base_domain.as_deref(),
                )
                .await?;
            }
        } else {
            let _ = uploads_path;
        }

        #[cfg(not(feature = "db-sled"))]
        let _ = uploads_path;

        let redb_store = redb_store::RedbStore::new_file(&redb_path)?;

        let store = Db {
            path: path.to_path_buf(),
            kv: Arc::new(redb_store),
            default_agent: Arc::new(Mutex::new(None)),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),

            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
        };

        store.add_class_extender(crate::collections::get_collection_class_extender())?;

        store.populate_watched_queries_cache()?;
        crate::populate::bootstrap(&store)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        crate::search::maybe_rebuild_search_index(&store)?;
        Ok(store)
    }

    #[cfg(all(feature = "db-redb", feature = "db-sled", not(target_arch = "wasm32")))]
    async fn migrate_from_sled(
        sled_path: &std::path::Path,
        redb_path: &std::path::Path,
        uploads_path: &std::path::Path,
        base_domain: Option<&str>,
    ) -> AtomicResult<()> {
        tracing::warn!("Migrating data from Sled to ReDB and files to CAS...");

        let sled_store = sled_store::SledStore::open(sled_path)?;

        // Bring the sled schema fully up to date BEFORE reading Tree::Resources.
        // A pre-v3 backup keeps its data in `resources_v2` (or `resources_v1`);
        // without this, the loop below reads the empty `resources_v3` tree and
        // silently migrates ZERO user resources — then renames the source dir to
        // `.bak`. `migrate_maybe` chains v0→v1→v2→v3 in place so the read sees
        // every resource. (Verified against a real v2 backup: 61,804 resources
        // were invisible without this call.)
        migrations::migrate_maybe(&sled_store, base_domain)?;

        let redb_store = redb_store::RedbStore::new_file(redb_path)?;

        let mut count_resources = 0;
        let mut count_snapshots = 0;
        let mut count_blobs = 0;

        // Migrate Resources
        for item in sled_store.iter_tree(Tree::Resources) {
            let (subject_bytes, propvals_bin) = item?;
            let subject_str = String::from_utf8_lossy(&subject_bytes).to_string();

            // Try to decode with various versions
            let mut propvals = if let Ok(pv) = rmp_serde::from_slice::<PropVals>(&propvals_bin) {
                pv
            } else if let Ok(pv_v2) = rmp_serde::from_slice::<v2_types::PropValsV2>(&propvals_bin) {
                v2_types::propvals_v2_to_v3(pv_v2, base_domain.unwrap_or("localhost"))
            } else if let Ok(pv_v1) = bincode1::deserialize::<v1_types::PropValsV1>(&propvals_bin) {
                v1_types::propvals_v1_to_v2(pv_v1)
            } else {
                tracing::error!("Failed to migrate resource: {}", subject_str);
                continue;
            };

            // Migrate File resources to CAS
            let is_file = propvals
                .get(urls::IS_A)
                .map(|v| v.to_string().contains(urls::FILE))
                .unwrap_or(false);

            if is_file && !propvals.contains_key(urls::BLOB) {
                if let Some(internal_id) = propvals.get(urls::INTERNAL_ID).map(|v| v.to_string()) {
                    let file_path = uploads_path.join(&internal_id);
                    if file_path.exists() {
                        if let Ok(bytes) = std::fs::read(&file_path) {
                            let hash = blake3::hash(&bytes);
                            let hash_hex = hash.to_hex().to_string();
                            let hash_bytes = hash.as_bytes();

                            redb_store.insert(Tree::Blobs, hash_bytes, &bytes)?;
                            propvals.insert(
                                urls::BLOB.to_string(),
                                Value::AtomicUrl(
                                    format!("did:ad:blob:{}", hash_hex.clone()).into(),
                                ),
                            );
                            propvals.insert(urls::INTERNAL_ID.to_string(), Value::String(hash_hex));
                            count_blobs += 1;
                        }
                    }
                }
            }

            redb_store.insert(
                Tree::Resources,
                &subject_bytes,
                &rmp_serde::to_vec(&propvals).unwrap(),
            )?;
            count_resources += 1;
        }

        // Migrate LoroSnapshots
        for item in sled_store.iter_tree(Tree::LoroSnapshots) {
            let (key, val) = item?;
            redb_store.insert(Tree::LoroSnapshots, &key, &val)?;
            count_snapshots += 1;
        }

        // Migrate other metadata trees
        for tree in [Tree::PluginMeta, Tree::DriveMapping, Tree::DidMapping] {
            for item in sled_store.iter_tree(tree.clone()) {
                let (key, val) = item?;
                redb_store.insert(tree.clone(), &key, &val)?;
            }
        }

        tracing::info!(
            "Migration complete: {} resources, {} snapshots, {} blobs migrated.",
            count_resources,
            count_snapshots,
            count_blobs
        );

        // Optionally rename old sled dir
        let mut backup_path = sled_path.to_path_buf();
        backup_path.set_extension("bak");
        let _ = std::fs::rename(sled_path, backup_path);

        Ok(())
    }

    /// Creates a Db backed by redb with OPFS persistent storage.
    /// Only available in WASM Workers. Data survives page reloads.
    ///
    /// `encryption_key` (32 bytes) enables at-rest encryption of the OPFS
    /// file; the browser passes a per-agent key so one agent's cache is
    /// unreadable to other sessions on the same origin.
    #[cfg(all(feature = "db-redb", target_arch = "wasm32"))]
    pub async fn init_redb_opfs(
        base_domain: Option<String>,
        filename: &str,
        encryption_key: Option<&[u8; 32]>,
    ) -> AtomicResult<Db> {
        let redb_store = redb_store::RedbStore::new_opfs(filename, encryption_key).await?;

        let store = Db {
            path: std::path::PathBuf::new(),
            kv: Arc::new(redb_store),
            default_agent: Arc::new(Mutex::new(None)),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),

            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
        };

        store.add_class_extender(crate::collections::get_collection_class_extender())?;

        store.populate_watched_queries_cache()?;
        crate::populate::bootstrap(&store)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        crate::search::maybe_rebuild_search_index(&store)?;
        Ok(store)
    }

    /// Creates a clone of the store with a different base_domain.
    /// This is useful for multi-tenant applications.
    /// Cloning is very cheap, as it only clones Arc pointers.
    pub fn clone_with_url(&self, base_domain: String) -> Db {
        let mut clone = self.clone();
        clone.base_domain = Some(base_domain);
        clone
    }

    /// Create a temporary in-memory Db. Useful for testing.
    /// Populates the database, creates a default agent, and sets the server_url to "http://localhost/".
    /// This variant covers `db` builds without a disk backend (e.g. `ws`
    /// alone) by running on the same BTreeMap store WASM targets use.
    #[cfg(all(not(feature = "db-sled"), not(feature = "db-redb")))]
    pub async fn init_temp(_id: &str) -> AtomicResult<Db> {
        let store = Db::init_memory(Some("https://localhost".into())).await?;
        let agent = store.create_agent(None).await?;
        store.set_default_agent(agent);
        store.populate().await?;
        Ok(store)
    }

    /// Create a temporary Db in `.temp/db/{id}`. Useful for testing.
    /// Populates the database, creates a default agent, and sets the server_url to "http://localhost/".
    #[cfg(all(feature = "db-sled", not(feature = "db-redb")))]
    pub async fn init_temp(id: &str) -> AtomicResult<Db> {
        let tmp_dir_path = format!(".temp/db/{}", id);
        let _try_remove_existing = std::fs::remove_dir_all(&tmp_dir_path);
        let store = Db::init(
            std::path::Path::new(&tmp_dir_path),
            Some("https://localhost".into()),
        )
        .await?;
        let agent = store.create_agent(None).await?;
        store.set_default_agent(agent);
        store.populate().await?;
        Ok(store)
    }

    /// Create a temporary Db backed by ReDB. Useful for testing.
    #[cfg(all(feature = "db-redb", not(target_arch = "wasm32")))]
    pub async fn init_temp(id: &str) -> AtomicResult<Db> {
        let tmp_dir_path = format!(".temp/db/{}", id);
        let uploads_path = format!(".temp/db/{}/uploads", id);
        let _try_remove_existing = std::fs::remove_dir_all(&tmp_dir_path);
        std::fs::create_dir_all(&uploads_path)
            .map_err(|e| format!("Failed to create temp dir: {e}"))?;
        let store = Db::init_redb_file(
            std::path::Path::new(&tmp_dir_path),
            Some("https://localhost".into()),
            std::path::Path::new(&uploads_path),
        )
        .await?;
        let agent = store.create_agent(None).await?;
        store.set_default_agent(agent);
        store.populate().await?;
        Ok(store)
    }

    // ── High-level SDK helpers ──────────────────────────────────────────────────

    /// Get the active drive subject, if one is set.
    pub fn get_active_drive(&self) -> Option<String> {
        self.kv
            .get(trees::Tree::PluginMeta, b"active_drive")
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Set the active drive subject. Persisted in the database.
    pub fn set_active_drive(&self, drive: &str) -> AtomicResult<()> {
        self.kv
            .insert(trees::Tree::PluginMeta, b"active_drive", drive.as_bytes())?;
        // Durable now: with Durability::None a freshly adopted drive is rolled
        // back on the next app kill, and the auto-connect loop (which needs an
        // active drive) then has nothing to reconnect to. Rare write; cheap.
        let _ = self.flush();
        Ok(())
    }

    /// Clear the default agent.
    pub fn clear_default_agent(&self) {
        self.default_agent.lock().unwrap().take();
    }

    /// Create a new drive owned by the current agent.
    /// Signs a genesis commit to produce a `did:ad:` subject.
    /// Sets it as the active drive. Returns the drive DID.
    pub async fn create_drive(&self, name: &str) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;

        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::DRIVE.into()]),
        );
        builder.set(urls::NAME.into(), Value::String(name.into()));
        builder.set(
            urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        builder.set(
            urls::READ.into(),
            Value::ResourceArray(vec![urls::PUBLIC_AGENT.into()]),
        );

        let commit = crate::commit::Commit::create_did(builder, &agent, self).await?;
        let did = commit.subject.to_string();

        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        self.apply_commit(commit, &opts).await?;
        self.set_active_drive(&did)?;

        // Record the new drive on the private drive's `drives` list when
        // that home already exists. Otherwise keep writing to the Agent so
        // `create_drive` in tests / first-run does not mint a second drive.
        let listed = if let Ok(personal) = self.private_drive_subject() {
            self.get_resource(&personal.as_str().into())
                .await
                .ok()
                .map(|_| personal)
        } else {
            None
        };
        if let Some(personal) = listed {
            if personal != did {
                self.push_drive_to_list(&personal, &did).await?;
            }
        } else {
            let agent = self.get_default_agent()?;
            self.push_drive_to_list(&agent.subject.to_string(), &did)
                .await?;
        }

        Ok(did)
    }

    /// The agent's derived personal-drive DID. Same key → same subject.
    pub fn private_drive_subject(&self) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;
        let private_key = agent
            .private_key
            .as_ref()
            .ok_or("Cannot derive a private drive without a private key")?;
        crate::genesis::GenesisCert::private_drive_subject(private_key)
    }

    /// Materialize the derived private drive if it is not already stored.
    /// Repeat genesis for the same subject merges.
    pub async fn ensure_private_drive(&self) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;
        let did = self.private_drive_subject()?;
        if self.get_resource(&did.as_str().into()).await.is_ok() {
            return Ok(did);
        }

        let signer_pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)?
            .try_into()
            .map_err(|_| "Agent public key must be 32 bytes")?;
        let cert = crate::genesis::GenesisCert::for_private_drive(signer_pubkey);

        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::DRIVE.into()]),
        );
        builder.set(urls::NAME.into(), Value::String("My drive".into()));
        builder.set(
            urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        builder.set(
            urls::READ.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
        builder.set(
            urls::DESCRIPTION.into(),
            Value::String("Your private drive.".into()),
        );

        let commit =
            crate::commit::Commit::create_did_with_cert(builder, &agent, self, Some(cert)).await?;
        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        self.apply_commit(commit, &opts).await?;
        Ok(did)
    }

    async fn push_drive_to_list(&self, list_subject: &str, drive_did: &str) -> AtomicResult<()> {
        let mut resource = self.get_resource(&list_subject.into()).await?;
        let mut drives: Vec<crate::values::SubResource> = resource
            .get(urls::DRIVES)
            .ok()
            .and_then(|v| match v {
                Value::ResourceArray(arr) => Some(arr.clone()),
                _ => None,
            })
            .unwrap_or_default();
        if !drives.iter().any(|d| d.to_string() == drive_did) {
            drives.push(drive_did.to_string().into());
            resource.set_unsafe(urls::DRIVES.into(), Value::ResourceArray(drives))?;
            self.add_resource_opts(&resource, false, true, true).await?;
        }
        Ok(())
    }

    /// Create a new resource with a `did:ad:` subject via genesis commit.
    pub async fn create_resource(
        &self,
        class: &str,
        parent: &str,
        name: &str,
        props: Option<Vec<(&str, Value)>>,
    ) -> AtomicResult<String> {
        let agent = self.get_default_agent()?;

        let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
        builder.set(urls::IS_A.into(), Value::ResourceArray(vec![class.into()]));
        builder.set(urls::NAME.into(), Value::String(name.into()));
        builder.set(urls::PARENT.into(), Value::AtomicUrl(parent.into()));

        if let Some(extra) = props {
            for (prop, val) in extra {
                builder.set(prop.into(), val);
            }
        }

        let commit = crate::commit::Commit::create_did(builder, &agent, self).await?;
        let did = commit.subject.to_string();

        let opts = crate::commit::CommitOpts {
            validate_signature: true,
            validate_timestamp: false,
            validate_rights: false,
            update_index: true,
            ..crate::commit::CommitOpts::no_validations_no_index()
        };
        self.apply_commit(commit, &opts).await?;
        Ok(did)
    }

    /// Load an agent from a secret and set it as the default agent.
    /// Persists the agent resource so its `drives` property is queryable.
    /// If the secret contains a drive DID, sets it as the active drive.
    ///
    /// Returns `AgentLoadResult` which indicates whether the drive exists locally.
    /// If `drive_needs_sync` is true, the caller must sync with another device
    /// before the user can create resources — the drive's genesis commit is missing.
    pub async fn load_agent_from_secret(&self, secret: &str) -> AtomicResult<AgentLoadResult> {
        let agent = crate::agents::Agent::from_secret(secret)?;
        self.set_default_agent(agent.clone());

        // Persist so list_drives() can read the agent's `drives` property
        let agent_resource = agent.to_resource()?;
        self.add_resource_opts(&agent_resource, false, false, true)
            .await?;

        let mut drive_needs_sync = false;

        if let Some(drive) = &agent.initial_drive {
            let drive_str = drive.to_string();
            let _ = self.set_active_drive(&drive_str);

            // Check if the drive resource actually exists locally.
            // Without the genesis commit, the DID is just a string — the device
            // can't create resources under it.
            //
            // `has_stored_resource`, not `get_resource`: the latter falls back to
            // fetching the subject over the network, so asking whether a drive is
            // *here* would go looking for it *there* — a DID resolution that can
            // hang for half a minute while it holds up everything waiting on this
            // call. Signing in on a device that doesn't have the drive yet is the
            // normal case, not the exception.
            let drive_subject = Subject::from_raw(&drive_str, self.get_base_domain().as_deref());
            if !self.has_stored_resource(&drive_subject) {
                tracing::warn!(
                    "Drive {} from secret does not exist locally — needs sync from another device",
                    &drive_str[..drive_str.len().min(30)]
                );
                drive_needs_sync = true;
            }
        }

        Ok(AgentLoadResult {
            agent,
            drive_needs_sync,
        })
    }

    /// List drives belonging to the current agent.
    /// Falls back to the active drive if the agent resource has no `drives` property.
    pub async fn list_drives(&self) -> AtomicResult<Vec<DriveInfo>> {
        let agent = self.get_default_agent()?;
        let agent_resource = self.get_resource(&agent.subject).await?;

        let subjects = match agent_resource.get(urls::DRIVES) {
            Ok(Value::ResourceArray(arr)) => arr.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            _ => vec![],
        };

        // Fallback: active drive not in agent resource
        let subjects = if subjects.is_empty() {
            match self.get_active_drive() {
                Some(active) => vec![active],
                None => vec![],
            }
        } else {
            subjects
        };

        let mut drives = Vec::with_capacity(subjects.len());
        for subject in subjects {
            let name = match self.get_resource(&subject.as_str().into()).await {
                Ok(r) => r.get(urls::NAME).map(|v| v.to_string()).unwrap_or_default(),
                Err(_) => String::new(),
            };
            drives.push(DriveInfo { subject, name });
        }

        Ok(drives)
    }

    /// Every Drive this node stores.
    ///
    /// A full scan of the resource tree, deliberately. The query indexes would
    /// be faster, but an index that is stale or partial answers "fewer drives
    /// than you have" — and the caller (owner-mode enrollment) would then
    /// silently lock the owner out of their own data. Paying O(store) once at
    /// boot for a certain answer is the right trade; do not "optimize" this into
    /// a query without changing what a wrong answer costs.
    pub async fn drive_subjects(&self) -> Vec<String> {
        use crate::storelike::Storelike;

        self.all_resources(false)
            .filter(|resource| {
                matches!(
                    resource.get(crate::urls::IS_A),
                    Ok(Value::ResourceArray(classes))
                        if classes.iter().any(|class| class.to_string() == crate::urls::DRIVE)
                )
            })
            .map(|resource| resource.get_subject().to_string())
            .collect()
    }

    /// Cheap local-presence check (no network fetch): is this subject's resource
    /// already stored locally? Used by managed-node replication to skip drives it
    /// already hosts before resolving/pulling them from a peer.
    pub fn has_resource_locally(&self, subject: &str) -> bool {
        self.kv
            .contains_key(Tree::Resources, subject.as_bytes())
            .unwrap_or(false)
    }

    /// Per-drive storage usage (resource count, Loro snapshot bytes, blob
    /// bytes) for the given `drive_subjects` — the Sync page's usage display and
    /// a managed node's control-plane usage report. A managed node passes its
    /// allowlisted (hosted) drives — these belong to enrolled users, not the
    /// node's own agent.
    ///
    /// Cost is O(the drives' resources), not O(store): it resolves each drive's
    /// subjects and point-looks-up their propvals/snapshots. Blobs are
    /// content-addressed and counted once — a blob shared across drives is
    /// attributed to whichever drive's resource is visited first.
    pub async fn per_drive_usage(
        &self,
        drive_subjects: &[String],
    ) -> AtomicResult<Vec<DriveUsage>> {
        use std::collections::{HashMap, HashSet};

        if drive_subjects.is_empty() {
            return Ok(vec![]);
        }

        // Map every resource subject (pure id) → its drive, and seed a row per drive.
        let mut subject_to_drive: HashMap<String, String> = HashMap::new();
        let mut usage: HashMap<String, DriveUsage> = HashMap::new();
        for drive_subject in drive_subjects {
            // Best-effort display name from the drive resource.
            let name = match self.get_resource(&drive_subject.as_str().into()).await {
                Ok(r) => r.get(urls::NAME).ok().map(|v| v.to_string()),
                Err(_) => None,
            };
            usage.insert(
                drive_subject.clone(),
                DriveUsage {
                    drive_subject: drive_subject.clone(),
                    name,
                    resource_count: 0,
                    blob_bytes: 0,
                    loro_bytes: 0,
                },
            );
            let ds: crate::Subject = drive_subject.as_str().into();
            // The drive root resource itself is part of the drive;
            // collect_drive_subjects only walks its children.
            subject_to_drive.insert(ds.pure_id(), drive_subject.clone());
            for subject in crate::sync::engine::collect_drive_subjects(self, &ds).await {
                subject_to_drive.insert(subject, drive_subject.clone());
            }
        }

        // Walk only the drives' own subjects, with point lookups. Scanning every
        // resource and every Loro snapshot in the store to filter down to one
        // drive makes this O(store) rather than O(drive) — measured at ~4s for a
        // 43-resource drive on a multi-GB store, and it is paid on every Sync
        // page load.
        let mut seen_blobs: HashSet<[u8; 32]> = HashSet::new();

        for (subject, drive) in &subject_to_drive {
            let Some(row) = usage.get_mut(drive) else {
                continue;
            };

            if let Ok(Some(snapshot)) = self.kv.get(Tree::LoroSnapshots, subject.as_bytes()) {
                row.loro_bytes += snapshot.len() as u64;
            }

            // Propvals only — the materialized state carries `blob`, and a Loro
            // decode per resource would put the cost right back.
            let Ok(propvals) = self.get_propvals(subject) else {
                continue;
            };

            row.resource_count += 1;

            let Some(blob_val) = propvals.get(urls::BLOB) else {
                continue;
            };
            let blob_did = blob_val.to_string();
            let blob_subject = crate::Subject::from_raw(&blob_did, None);
            let Some(hash_hex) = blob_subject.blob_hash_hex() else {
                continue;
            };
            let Ok(hash_bytes) = hex::decode(hash_hex) else {
                continue;
            };
            if hash_bytes.len() != 32 {
                continue;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            if !seen_blobs.insert(hash) {
                continue;
            }
            if let Ok(Some(bytes)) = self.kv.get(Tree::Blobs, &hash) {
                row.blob_bytes += bytes.len() as u64;
            }
        }

        Ok(usage.into_values().collect())
    }

    /// Get children of a resource, optionally filtered by class.
    pub async fn get_children(
        &self,
        parent: &str,
        class_filter: Option<&str>,
    ) -> AtomicResult<Vec<Resource>> {
        let mut result = Vec::new();

        for resource in self.all_resources(false) {
            if let Ok(p) = resource.get(urls::PARENT) {
                if p.to_string() != parent {
                    continue;
                }
            } else {
                continue;
            }

            if let Some(class) = class_filter {
                if let Ok(is_a) = resource.get(urls::IS_A) {
                    if !is_a.to_string().contains(class) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            result.push(resource);
        }

        Ok(result)
    }

    /// Full onboarding: create an agent and a private drive in one call.
    /// The agent's secret will contain the drive DID for DHT discovery.
    /// Returns (agent, drive_subject).
    pub async fn setup(&self, agent_name: &str) -> AtomicResult<(crate::agents::Agent, String)> {
        let mut agent = self.create_agent(Some(agent_name)).await?;
        self.set_default_agent(agent.clone());
        let drive = self.ensure_private_drive().await?;
        // `create_drive` — which this used to call — set the active drive as
        // part of creating one. `ensure_private_drive` deliberately does not:
        // materializing a home is not the same act as switching to it. Setup IS
        // that act, so it records it here; without this every later call fails
        // with "No drive set. Call setup() first."
        self.set_active_drive(&drive)?;

        if let Ok(mut personal) = self.get_resource(&drive.as_str().into()).await {
            personal.set_unsafe(
                urls::NAME.into(),
                Value::String(format!("{}'s Drive", agent_name)),
            )?;
            self.add_resource_opts(&personal, false, true, true).await?;
        }

        // Set initial_drive so the secret contains the drive DID.
        // This lets other devices find this drive via DHT when restoring from secret.
        agent.initial_drive = Some(drive.as_str().into());
        self.set_default_agent(agent.clone());
        // Re-save the agent resource so `drives` and `personalDrive` are persisted.
        self.add_resource_opts(&agent.to_resource()?, false, true, true)
            .await?;

        Ok((agent, drive))
    }
    // ── High-level SDK helpers ─────────────────────────────────────────

    pub async fn resolve_request_target(
        &self,
        subject: &Subject,
        host: &str,
        subject_string: &str,
        origin: &str,
    ) -> AtomicResult<ResolvedTarget> {
        let full_subject = format!("{}{}", origin.trim_end_matches('/'), subject_string);
        match self
            .map_request_subject(subject, host, subject_string)
            .await
        {
            Ok(mapped_subject) => {
                let alias_subject = if mapped_subject != *subject {
                    Some(full_subject)
                } else {
                    None
                };
                Ok(ResolvedTarget {
                    subject: mapped_subject,
                    alias_subject,
                })
            }
            Err(e) => {
                // Drive-routing failed (e.g. ULID subject not found via shortname traversal).
                // Fall back to a direct DB lookup for the full HTTP URL before giving up.
                let direct = Subject::from_raw(&full_subject, None);
                if self.get_resource(&direct).await.is_ok() {
                    Ok(ResolvedTarget {
                        subject: direct,
                        alias_subject: None,
                    })
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn map_request_subject(
        &self,
        subject: &Subject,
        host: &str,
        subject_string: &str,
    ) -> AtomicResult<Subject> {
        if Self::should_bypass_drive_routing(subject, subject_string) {
            return Ok(subject.clone());
        }

        let Some(drive_did) = self.get_drive_did(host).await? else {
            return Ok(subject.clone());
        };

        if self.get_resource(&drive_did).await.is_err() {
            return Ok(subject.clone());
        }

        if subject_string == "/" {
            return Ok(drive_did);
        }

        let resolved = self
            .get_resource_at_path(&drive_did, subject_string)
            .await
            .map_err(|e| {
                AtomicError::not_found(format!(
                    "Path '{}' not found in drive {}: {}",
                    subject_string, drive_did, e
                ))
            })?;

        Ok(resolved.set_drive_hint(drive_did.as_str().to_string()))
    }

    fn should_bypass_drive_routing(subject: &Subject, subject_string: &str) -> bool {
        subject.is_did()
            || subject_string.starts_with("/did")
            || subject_string.starts_with("/bind-drive")
            || subject_string.starts_with("/search")
            || subject_string.starts_with("/upload")
            || subject_string.starts_with("/export")
            || subject_string.starts_with("/download")
            || subject_string.starts_with("/invites")
            || subject_string.starts_with("/commit")
            || subject_string.starts_with("/path")
            || subject_string.starts_with("/query")
    }

    /// Where a pre-DID server stored the Agent that `did:ad:agent:{pubkey}`
    /// now identifies. `None` for anything that isn't an Agent DID.
    ///
    /// The inverse of [crate::agents::migrate_legacy_agent_subject]. The
    /// pubkey is standard base64 and contains `/` and `+`, so the whole
    /// remainder is carried across untouched.
    fn legacy_agent_subject(subject: &Subject) -> Option<Subject> {
        let pubkey = subject
            .as_str()
            .strip_prefix(crate::subject::DID_AD_AGENT_PREFIX)?;

        if pubkey.is_empty() {
            return None;
        }

        Some(Subject::new_local(&format!("/agents/{pubkey}"), None))
    }

    pub async fn fetch_resource_with_did_fallback(
        &self,
        subject: &Subject,
        origin: &str,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        if subject.is_blob_did() {
            if let Some(hash) = subject.blob_hash_hex() {
                let target = format!("{}/download/files/{}", origin.trim_end_matches('/'), hash);
                return Ok(ResourceResponse::Redirect(target));
            }
        }

        let store = self.clone_with_url(origin.to_string());

        // A user from before the DID migration signs in as
        // `did:ad:agent:{pubkey}`, but their Agent resource is still stored
        // where the old server put it — `internal:/agents/{pubkey}` (the
        // localized form of `https://server/agents/{pubkey}`). Nothing links
        // the two.
        //
        // Resolving an Agent DID does not fail when there is no stored
        // resource: it synthesizes a minimal Agent from the key. So the user
        // isn't met with an error — they're met with an account that looks
        // brand new. Their name is gone, and because the Agent carries
        // `drives`, so is every drive they own, which is what empties the
        // sidebar.
        //
        // Same key, same identity, so serve the stored resource under the DID
        // that asked for it. Gated on the DID having nothing of its own, which
        // makes it self-healing: it applies only to identities that predate the
        // migration, and stops the moment a real Agent exists at the DID.
        // Read-only — the legacy resource is left exactly as it is.
        if !self.has_stored_resource(subject) {
            if let Some(legacy) = Self::legacy_agent_subject(subject) {
                if self.has_stored_resource(&legacy) {
                    let mut response = store
                        .get_resource_extended(&legacy, false, for_agent)
                        .await?;
                    // Answer under the subject that was requested, so the
                    // client caches it against the DID rather than
                    // re-introducing the legacy spelling.
                    response.set_subject(subject.clone());

                    return Ok(response);
                }
            }
        }

        store.get_resource_extended(subject, false, for_agent).await
    }

    pub fn add_class_extender(&self, class_extender: ClassExtender) -> AtomicResult<()> {
        // At registration, not at match time: a class that can never match is a
        // property of the extender, so say it once on load rather than on every
        // commit that failed to match it.
        class_extender.warn_about_unmatchable_classes();

        let mut extenders = self
            .class_extenders
            .write()
            .map_err(|e| format!("Failed to write to class extenders: {}", e))?;

        if let Some(id) = &class_extender.id {
            extenders.retain(|e| e.id.as_ref() != Some(id));
        }

        extenders.push(class_extender);
        Ok(())
    }

    pub fn get_class_extenders_on_drive(&self, drive_subject: &str) -> Vec<ClassExtender> {
        let Ok(extenders) = self.class_extenders.read() else {
            return Vec::new();
        };

        extenders
            .iter()
            .filter(
                |e| matches!(&e.scope, ClassExtenderScope::Drive(scope) if scope == drive_subject),
            )
            .cloned()
            .collect()
    }

    pub fn remove_class_extender(&self, id: &str) -> AtomicResult<()> {
        let mut extenders = self
            .class_extenders
            .write()
            .map_err(|e| format!("Failed to write to class extenders: {}", e))?;
        extenders.retain(|e| e.id.as_deref() != Some(id));
        Ok(())
    }

    pub fn add_endpoint(&mut self, endpoint: Endpoint) -> AtomicResult<()> {
        self.endpoints.push(endpoint);
        Ok(())
    }

    pub fn get_endpoints(&self) -> &Vec<Endpoint> {
        &self.endpoints
    }

    /// Maps a drive hint (short ID) to a full Drive DID.
    pub fn add_drive_mapping(&self, host: &str, drive_did: &Value) -> AtomicResult<()> {
        let did_str = match drive_did {
            Value::AtomicUrl(s) => s.to_string(),
            Value::ResourceArray(arr) => {
                if let Some(first) = arr.first() {
                    first.to_string()
                } else {
                    return Err("Drive DID array is empty".into());
                }
            }
            _ => drive_did.to_string(),
        };

        self.kv
            .insert(Tree::DriveMapping, host.as_bytes(), did_str.as_bytes())?;
        tracing::info!("Added drive mapping: {} -> {}", host, did_str);
        Ok(())
    }

    /// Removes the drive mapping for a given host.
    pub fn remove_drive_mapping(&self, host: &str) -> AtomicResult<()> {
        self.kv.remove(Tree::DriveMapping, host.as_bytes())?;
        tracing::info!("Removed drive mapping for host: {}", host);
        Ok(())
    }

    /// Where a drive is replicated to, and who authorized it.
    ///
    /// This is **server-local config, and must stay out of the drive**. A
    /// drive's sync set is its root plus every child (`collect_drive_subjects`),
    /// so a target stored inside the drive would be pushed to the target itself
    /// — and the receiving server, running this same code, would read it and
    /// start replicating onward to hosts it was never meant to contact.
    pub fn get_replication_targets(&self, drive: &str) -> AtomicResult<Vec<ReplicationTarget>> {
        let Some(bytes) = self
            .kv
            .get(Tree::PluginMeta, replication_key(drive).as_bytes())?
        else {
            return Ok(vec![]);
        };

        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Corrupt replication targets for {drive}: {e}").into())
    }

    /// Record a replication target for a drive. Idempotent: re-adding the same
    /// target updates who authorized it rather than duplicating it.
    pub fn add_replication_target(
        &self,
        drive: &str,
        target: &ReplicationTarget,
    ) -> AtomicResult<()> {
        let mut targets = self.get_replication_targets(drive)?;
        targets.retain(|t| t.url != target.url);
        targets.push(target.clone());

        let bytes = serde_json::to_vec(&targets)
            .map_err(|e| format!("Could not encode replication targets: {e}"))?;
        self.kv
            .insert(Tree::PluginMeta, replication_key(drive).as_bytes(), &bytes)?;

        Ok(())
    }

    /// Every drive that has at least one replication target, for the boot-time
    /// reconcile.
    pub fn get_all_replication_targets(
        &self,
    ) -> AtomicResult<Vec<(String, Vec<ReplicationTarget>)>> {
        let mut out = Vec::new();

        for (key, value) in self
            .kv
            .scan_prefix(Tree::PluginMeta, REPLICATION_PREFIX.as_bytes())
            .flatten()
        {
            let Ok(key) = std::str::from_utf8(&key) else {
                continue;
            };
            let Some(drive) = key.strip_prefix(REPLICATION_PREFIX) else {
                continue;
            };
            if let Ok(targets) = serde_json::from_slice::<Vec<ReplicationTarget>>(&value) {
                out.push((drive.to_string(), targets));
            }
        }

        Ok(out)
    }

    /// Returns the full Drive DID for a given host (domain/subdomain).
    pub async fn get_drive_did(&self, host: &str) -> AtomicResult<Option<Subject>> {
        if let Some(did_bin) = self.kv.get(Tree::DriveMapping, host.as_bytes())? {
            let did_str = std::str::from_utf8(&did_bin)
                .map_err(|e| format!("Failed to parse DID from database: {}", e))?;
            return Ok(Some(Subject::from_raw(did_str, None)));
        }

        Ok(None)
    }

    /// Resolves a path (e.g. "/blog/my-post") relative to a Drive DID.
    /// 1. First, it tries to find a resource in the Drive that has this exact string in its `PATH` property.
    /// 2. If not found, it traverses the hierarchy recursively using the PARENT property and shortnames.
    pub async fn get_resource_at_path(
        &self,
        drive_did: &Subject,
        path: &str,
    ) -> AtomicResult<Subject> {
        if path == "/" || path.is_empty() {
            return Ok(drive_did.clone());
        }

        // Strategy 1: Direct PATH lookup (flat routing)
        // Find any resource where parent is the drive and path matches the full path string.
        let mut query_path = Query::new_prop_val(urls::PATH, path);
        query_path.limit = Some(1);
        if let Ok(result) = self.query(&query_path).await {
            for resource in result.resources {
                // Verify the resource belongs to this drive
                // (In a multi-tenant world, we want to make sure we don't return someone else's resource)
                if let Ok(parent) = resource.get(urls::PARENT) {
                    if parent.to_string() == *drive_did {
                        return Ok(resource.get_subject().clone());
                    }
                }
            }
        }

        // Strategy 2: Recursive SHORTNAME traversal (hierarchical routing)
        let mut current_subject = drive_did.clone();
        let segments = path.trim_start_matches('/').split('/');

        for segment in segments {
            if segment.is_empty() {
                continue;
            }

            let mut query = Query::new_prop_val(urls::PARENT, current_subject.as_str());
            query.limit = Some(1000); // Reasonable limit for children

            let result = self.query(&query).await?;
            let mut found = None;

            for resource in result.resources {
                if let Ok(sn) = resource.get(urls::SHORTNAME) {
                    if sn.to_string() == segment {
                        found = Some(resource.get_subject().clone());
                        break;
                    }
                }
            }

            current_subject = found.ok_or_else(|| {
                format!(
                    "Could not find segment '{}' in {} (path: {})",
                    segment, current_subject, path
                )
            })?;
        }

        Ok(current_subject)
    }
    #[instrument(level = "trace", skip_all)]
    fn add_atom_to_index(
        &self,
        atom: &Atom,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        for index_atom in atom.to_indexable_atoms() {
            add_atom_to_valpropsub_index(&index_atom, transaction)?;
            add_atom_to_prop_val_sub_index(&index_atom, transaction)?;
            // Also update the query index to keep collections performant
            check_if_atom_matches_watched_query_filters(
                self,
                &index_atom,
                atom,
                false,
                resource,
                transaction,
            )
            .map_err(|e| format!("Failed to check_if_atom_matches_watched_collections. {}", e))?;
        }
        Ok(())
    }

    /// Index the propvals the server derives for a resource rather than
    /// reading them off the commit.
    ///
    /// `createdAt` / `createdBy` / `parent` / `drive` can all reach a resource
    /// without ever being atoms of its commit: `validate_and_build_response`
    /// stamps `drive` from the parent via `set_unsafe`, and
    /// `materialize_genesis_metadata` fills the rest in from the inline
    /// certificate. Both mutate `resource_new` — which is what gets stored —
    /// but neither touches `add_atoms`, and `apply_commit` indexes `add_atoms`.
    /// So these landed in the resource projection and never in the index.
    ///
    /// `drive` is the one that bites, because nothing else ever sets it: its
    /// index held only the rare resource whose commit named it explicitly. A
    /// drive-scoped filtered query then estimates that constraint as the
    /// cheapest candidate source (one entry), verifies just that one resource,
    /// and files an empty member list — which `query_complex` then caches for
    /// good, since it rebuilds only for filters that are not yet watched.
    ///
    /// Runs on every commit, not just the creating one: the values are
    /// immutable, so re-indexing is idempotent, and it lets a resource written
    /// before this existed heal on its next edit instead of waiting for a full
    /// index rebuild.
    fn index_genesis_derived_atoms(
        &self,
        commit_atoms: &[Atom],
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        const DERIVED_PROPS: [&str; 4] = [
            urls::CREATED_AT,
            urls::CREATED_BY,
            urls::PARENT,
            urls::DRIVE_PROP,
        ];

        for property in DERIVED_PROPS {
            // The commit set it itself — already indexed above.
            if commit_atoms.iter().any(|atom| atom.property == property) {
                continue;
            }

            let Ok(value) = resource.get(property) else {
                continue;
            };

            let atom = Atom::new(
                resource.get_subject().clone(),
                property.into(),
                value.clone(),
            );
            self.add_atom_to_index(&atom, resource, transaction)?;
        }

        Ok(())
    }

    fn add_resource_tx(
        &self,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        let subject = self.normalize_subject(resource.get_subject());
        let subject_str = subject.pure_id();
        let propvals = resource.get_propvals();

        // Persist DID routing hint if available
        if let Subject::Did {
            drive_hint: Some(hint),
            ..
        } = &subject
        {
            transaction.push(Operation {
                tree: Tree::DidMapping,
                method: Method::Insert,
                key: subject_str.as_bytes().to_vec(),
                val: Some(hint.as_bytes().to_vec()),
            });
        }

        // The `loroUpdate` propval is the resource's CRDT snapshot — it
        // belongs in `Tree::LoroSnapshots`, not
        // duplicated inside the resource blob, which is now a pure derived
        // projection. Commit resources are the exception: a commit's
        // `loroUpdate` is its signed payload and must stay in the blob.
        let resource_bin = if subject.is_commit_did() {
            encode_propvals(propvals)?
        } else {
            let mut projection = propvals.clone();
            projection.remove(crate::urls::LORO_UPDATE);
            encode_propvals(&projection)?
        };

        transaction.push(Operation {
            tree: Tree::Resources,
            method: Method::Insert,
            key: subject_str.as_bytes().to_vec(),
            val: Some(resource_bin),
        });
        Ok(())
    }

    #[instrument(skip_all)]
    fn all_index_atoms(&self, include_external: bool) -> IndexIterator {
        Box::new(
            self.all_resources(include_external)
                .flat_map(|resource| {
                    let index_atoms: Vec<IndexAtom> = resource
                        .to_atoms()
                        .iter()
                        .flat_map(|atom| atom.to_indexable_atoms())
                        .collect();
                    index_atoms
                })
                .map(Ok),
        )
    }

    /// Constructs the value index from all resources in the store. Could take a while.
    pub fn build_index(&self, include_external: bool) -> AtomicResult<()> {
        tracing::info!("Building index (this could take a few minutes for larger databases)");
        for (count, r) in self.all_resources(include_external).enumerate() {
            let mut transaction = Transaction::new();
            for atom in r.to_atoms_iter() {
                self.add_atom_to_index(&atom, &r, &mut transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", atom, e))?;
            }
            crate::search::index_resource(self, &r, &mut transaction)?;
            self.apply_transaction(&mut transaction)
                .map_err(|e| format!("Failed to commit transaction. {}", e))?;

            if count % 1000 == 0 {
                tracing::info!("Building index, applied transaction: {}", count);
            }

            if count % 10000 == 0 {
                tracing::info!("Building index, flushing to disk");
                self.kv.flush()?;
            }
        }

        tracing::info!("Building index finished!");
        Ok(())
    }

    /// Ranked full-text search over the local KV index.
    pub fn search_hits(
        &self,
        query: &str,
        opts: &crate::client::search::SearchOpts,
    ) -> AtomicResult<Vec<crate::search::SearchHit>> {
        crate::search::query(self, query, opts)
    }

    /// Sets a function that is called whenever a [Commit::apply] is called.
    /// This can be used to listen to events.
    pub fn set_handle_commit(&mut self, on_commit: HandleCommit) {
        self.on_commit = Some(Arc::new(on_commit));
    }

    /// Subscribe to all DB events (changes, deletions).
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<DbEvent> {
        self.db_events.subscribe()
    }

    /// Presence arriving from peers. See [`EphemeralEvent`].
    pub fn subscribe_ephemeral(&self) -> tokio::sync::broadcast::Receiver<EphemeralEvent> {
        self.ephemeral_events.subscribe()
    }

    /// Publish presence received from a peer. Send failure means nobody is
    /// listening (no websocket clients on this node) — expected, not an error.
    pub fn publish_ephemeral(&self, event: EphemeralEvent) {
        let _ = self.ephemeral_events.send(event);
    }

    /// Finds resource by Subject, return PropVals HashMap
    #[instrument(skip_all)]
    fn get_propvals(&self, subject: &str) -> AtomicResult<PropVals> {
        match self.kv.get(Tree::Resources, subject.as_bytes())? {
            Some(binpropval) => {
                let propval: PropVals = decode_propvals(&binpropval)?;
                Ok(propval)
            }
            None => Err(AtomicError::not_found(format!(
                "Resource {} not found",
                subject
            ))),
        }
    }

    /// A resource built only from its last-committed materialized propvals,
    /// **skipping the Loro snapshot re-decode** that [`Storelike::get_resource`]
    /// performs. That decode decompresses a resource's full CRDT history and can
    /// cost tens of milliseconds each — fine for a single fetch, ruinous when a
    /// directory listing reads hundreds of resources just to project their names
    /// and sizes. The propvals are the materialized state after the last commit,
    /// which is exactly what a read-only listing needs; do not use this where
    /// CRDT-authoritative state matters. Subject normalization (incl. the DID
    /// drive hint) matches `get_resource`, so ids/subjects stay consistent.
    pub fn get_resource_shallow(&self, subject: &Subject) -> AtomicResult<Resource> {
        let normalized = self.normalize_subject(subject);
        let subject_str = normalized.pure_id();
        let propvals = self.get_propvals(&subject_str)?;

        let mut res_subject = normalized.clone();
        if let Subject::Did {
            drive_hint: None, ..
        } = &res_subject
        {
            if let Ok(Some(hint_bin)) = self.kv.get(Tree::DidMapping, subject_str.as_bytes()) {
                if let Ok(hint) = std::str::from_utf8(&hint_bin) {
                    res_subject = res_subject.set_drive_hint(hint.to_string());
                }
            }
        }

        Ok(Resource::from_propvals(propvals, res_subject))
    }

    /// Removes all values from the indexes.
    pub fn clear_index(&self) -> AtomicResult<()> {
        self.kv.clear_tree(Tree::ValPropSub)?;
        self.kv.clear_tree(Tree::PropValSub)?;
        self.kv.clear_tree(Tree::QueryMembers)?;
        self.kv.clear_tree(Tree::WatchedQueries)?;
        Ok(())
    }

    /// Reset the watched-query registry (`Tree::WatchedQueries` + the
    /// in-memory `watched_queries_by_drive` map). Called on server
    /// startup: every restart drops every WS connection, so any
    /// previously-registered filter is now an orphan with no live
    /// subscriber. Without this, e2e suites leak filters across runs
    /// (each test's drive is unique, so each filter is unique), and
    /// `check_if_atom_matches_watched_query_filters` iterates a growing
    /// pile of dead entries on every commit — observed to reach 13k+
    /// filters, slowing rapid-save tests past their timeout. Active
    /// subscribers re-register their filters on reconnect, so the
    /// map repopulates organically without surprising anyone.
    pub fn clear_watched_queries(&self) -> AtomicResult<()> {
        self.kv.clear_tree(Tree::WatchedQueries)?;
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            map.clear();
        }
        Ok(())
    }

    /// Flushes the current state to disk.
    pub fn flush(&self) -> AtomicResult<()> {
        self.kv.flush()
    }

    /// Removes the DB and all content from disk.
    /// WARNING: This is irreversible.
    #[cfg(feature = "db-sled")]
    pub fn clear_all_danger(self) -> AtomicResult<()> {
        let path = self.path.clone();
        drop(self);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    fn map_kv_item_to_resource(
        subject_bytes: &[u8],
        resource_bin: &[u8],
        include_external: bool,
        base_domain: Option<&str>,
    ) -> Option<Resource> {
        let subject: String = String::from_utf8_lossy(subject_bytes).to_string();

        let subject_obj = Subject::from_raw(&subject, base_domain);

        if !include_external && !subject_obj.is_local() {
            return None;
        }

        let propvals: PropVals = decode_propvals(resource_bin)
            .unwrap_or_else(|e| panic!("{}. {}", corrupt_db_message(&subject), e));

        Some(Resource::from_propvals(propvals, subject_obj))
    }

    pub fn get_plugin_meta(&self, key: &PluginMetaKey) -> AtomicResult<Option<PluginMeta>> {
        let Some(plugin_meta_bin) = self.kv.get(Tree::PluginMeta, &key.encode()?)? else {
            return Ok(None);
        };
        let plugin_meta = PluginMeta::from_bytes(&plugin_meta_bin)?;

        Ok(Some(plugin_meta))
    }

    pub fn set_plugin_meta(
        &self,
        key: &PluginMetaKey,
        plugin_meta: &PluginMeta,
    ) -> AtomicResult<()> {
        self.kv
            .insert(Tree::PluginMeta, &key.encode()?, &plugin_meta.encode()?)?;
        Ok(())
    }

    pub fn delete_plugin_meta(&self, key: &PluginMetaKey) -> AtomicResult<()> {
        self.kv.remove(Tree::PluginMeta, &key.encode()?)?;
        Ok(())
    }

    fn get_index_iterator_for_query(&self, q: &Query) -> IndexIterator {
        match (&q.property, q.value.as_ref()) {
            (Some(prop), val) => find_in_prop_val_sub_index(self, prop, val),
            (None, None) => self.all_index_atoms(q.include_external),
            (None, Some(val)) => find_in_val_prop_sub_index(self, val, None),
        }
    }

    /// Bounded cardinality estimate for a `(property, value?)` prefix in the
    /// PropValSub index. Scans at most `cap` entries — enough to rank
    /// constraints by selectivity without paying for exact counts.
    fn estimate_prop_val_count(&self, prop: &str, val: Option<&Value>, cap: usize) -> usize {
        let mut prefix: Vec<u8> = [prop.as_bytes(), &[query_index::SEPARATION_BIT]].concat();
        if let Some(value) = val {
            prefix.extend(value.to_sortable_string().as_bytes());
            prefix.extend([query_index::SEPARATION_BIT]);
        }
        self.kv
            .scan_prefix(Tree::PropValSub, &prefix)
            .take(cap)
            .count()
    }

    /// Picks the candidate iterator for building a [QueryFilter]'s member
    /// index: the most selective property-bearing constraint by a scan-capped
    /// cardinality estimate. Every candidate is verified against the full
    /// filter afterwards, so any constraint's index entries are a valid
    /// starting set — the estimate only decides how few resources get row-
    /// checked. Constraints with non-equality operators can't be point-
    /// scanned; they contribute a whole-property scan as their candidate set.
    fn plan_candidate_iterator(&self, q: &Query, q_filter: &QueryFilter) -> IndexIterator {
        const PLANNER_SCAN_CAP: usize = 512;

        let mut best: Option<(usize, &crate::storelike::PropVal)> = None;
        for constraint in &q_filter.filters {
            let Some(prop) = &constraint.property else {
                continue;
            };
            let scan_val = match (constraint.operator, &constraint.value) {
                (crate::storelike::FilterOperator::Equal, Some(v)) => Some(v),
                _ => None,
            };
            let estimate = self.estimate_prop_val_count(prop, scan_val, PLANNER_SCAN_CAP);
            if best.is_none_or(|(current, _)| estimate < current) {
                best = Some((estimate, constraint));
            }
        }

        match best {
            Some((_, constraint)) => {
                let prop = constraint
                    .property
                    .as_ref()
                    .expect("planner only ranks property-bearing constraints");
                let val = match constraint.operator {
                    crate::storelike::FilterOperator::Equal => constraint.value.as_ref(),
                    _ => None,
                };
                find_in_prop_val_sub_index(self, prop, val)
            }
            // No property-bearing constraint (value-only filters): fall back
            // to the query's own iterator (value index or full scan).
            None => self.get_index_iterator_for_query(q),
        }
    }

    /// Register a filter to be watched. Persists to `Tree::WatchedQueries`
    /// (idempotent — same filter encodes to the same bytes) and pushes into
    /// the in-memory `watched_queries_by_drive` map. The KV `contains_key`
    /// short-circuit keeps the in-memory Vec from growing on duplicate
    /// `watch()` calls (e.g. when a client reconnects and re-watches a
    /// filter that's already persisted).
    pub(crate) fn register_watched_query(
        &self,
        filter: query_index::QueryFilter,
    ) -> AtomicResult<()> {
        let filter_bytes = filter.encode()?;
        // Skip if already persisted — avoids growing the in-memory Vec on
        // re-watches. The KV is authoritative for "what filters exist"; the
        // in-memory map is just a decoded mirror.
        if self
            .kv
            .contains_key(crate::db::trees::Tree::WatchedQueries, &filter_bytes)
            .unwrap_or(false)
        {
            return Ok(());
        }
        self.kv
            .insert(crate::db::trees::Tree::WatchedQueries, &filter_bytes, b"")?;
        let drive_key = filter.drive.as_str().to_string();
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            map.entry(drive_key).or_default().insert(Arc::new(filter));
        }
        Ok(())
    }

    /// Rebuild the in-memory watched-queries map from `Tree::WatchedQueries`.
    /// Called once at Db open (after KV/migrations are ready) so the map is
    /// authoritative on first commit. Subsequent `register_watched_query`
    /// calls keep both stores in sync.
    pub(crate) fn populate_watched_queries_cache(&self) -> AtomicResult<()> {
        let mut new_map: HashMap<String, DriveFilters> = HashMap::new();
        for entry in self.kv.iter_tree(crate::db::trees::Tree::WatchedQueries) {
            let (k, _v) = match entry {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("populate_watched_queries_cache: skipping bad entry: {e}");
                    continue;
                }
            };
            let qf = match query_index::QueryFilter::from_bytes(&k) {
                Ok(qf) => qf,
                Err(e) => {
                    tracing::warn!(
                        "populate_watched_queries_cache: skipping undecodable entry ({} bytes): {e}",
                        k.len()
                    );
                    continue;
                }
            };
            let drive_key = qf.drive.as_str().to_string();
            new_map.entry(drive_key).or_default().insert(Arc::new(qf));
        }
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            *map = new_map;
        }
        Ok(())
    }

    /// The watched filters a changed atom in `drive_key` with `property` must
    /// be checked against: the drive's filters that reference that property
    /// (constraint or `sort_by`) plus its value-only filters. Returns
    /// cheap-cloned `Arc`s; iterating doesn't hold the map lock.
    pub(crate) fn watched_queries_for_atom(
        &self,
        drive_key: &str,
        property: &str,
    ) -> Vec<Arc<query_index::QueryFilter>> {
        self.watched_queries_by_drive
            .read()
            .ok()
            .and_then(|m| m.get(drive_key).map(|df| df.for_property(property)))
            .unwrap_or_default()
    }

    /// Property-routed filters across every drive. Used for DID-subject atoms
    /// whose drive prefix can't be derived (their `drive_prefix_from_subject`
    /// returns the subject itself, which won't match an HTTP-drive filter's
    /// bucket).
    pub(crate) fn all_watched_queries_for_property(
        &self,
        property: &str,
    ) -> Vec<Arc<query_index::QueryFilter>> {
        self.watched_queries_by_drive
            .read()
            .map(|m| {
                m.values()
                    .flat_map(|df| df.for_property(property))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Apply made changes to the store.
    /// After a successful KV apply, scans the transaction for writes to
    /// `Tree::QueryMembers` and broadcasts a `DbEvent::QueryMembershipChanged`
    /// for each one. Subscribers (e.g. `CommitMonitor`'s listener task) use
    /// these to push live `QUERY_UPDATE` notifications without re-deriving
    /// membership from the raw atom stream.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn apply_transaction(&self, transaction: &mut Transaction) -> AtomicResult<()> {
        self.apply_transaction_with_source(transaction, None)
    }

    fn apply_transaction_with_source(
        &self,
        transaction: &mut Transaction,
        source_id: Option<&str>,
    ) -> AtomicResult<()> {
        self.kv.apply_batch(transaction)?;

        for op in transaction.iter() {
            if op.tree != Tree::QueryMembers {
                continue;
            }
            // Op key layout: `query_id(16B) || sort_key || 0x00 0x00 || subject`.
            let Some((query_id, subject)) = query_index::parse_members_key_id_subject(&op.key)
            else {
                continue;
            };
            let added = matches!(op.method, crate::db::trees::Method::Insert);
            let _ = self.db_events.send(DbEvent::QueryMembershipChanged {
                query_id,
                subject,
                added,
                source_id: source_id.map(str::to_string),
            });
        }
        Ok(())
    }

    /// Resolve one query-index hit against the materialized row and the
    /// requesting agent's rights, without decoding any Loro snapshot.
    ///
    /// Returns `None` when the member must be hidden (auth-denied or
    /// unresolvable), `Some(None)` when it's included subjects-only, and
    /// `Some(Some(resource))` when the query asked for nested bodies.
    ///
    /// Bodies are built from the row plus the resource's *raw* snapshot bytes
    /// attached as `loroUpdate` — byte-for-byte what the old full-decode path
    /// serialized, since the row **is** the snapshot's materialization (see
    /// planning/index-performance.md, finding 3). Subjects without a row
    /// (endpoints, never-stored externals, defensive invariant breaks) fall
    /// back to the full `get_resource_extended` path.
    pub(crate) async fn resolve_query_member(
        &self,
        subject: &Subject,
        q: &Query,
        rights_cache: &std::sync::Mutex<RightsCache>,
    ) -> Option<Option<Resource>> {
        let mut resource = match self.get_resource_shallow(subject) {
            Ok(resource) => resource,
            Err(_) => {
                // No materialized row — take the slow, complete path.
                return match self
                    .get_resource_extended(subject, true, &q.for_agent)
                    .await
                {
                    Ok(response) => {
                        if q.include_nested {
                            Some(Some(response.to_single()))
                        } else {
                            Some(None)
                        }
                    }
                    Err(_) => None,
                };
            }
        };

        if q.for_agent != ForAgent::Sudo
            && crate::hierarchy::check_rights_cached(
                self,
                &resource,
                &q.for_agent,
                crate::hierarchy::Right::Read,
                Some(rights_cache),
            )
            .await
            .is_err()
        {
            return None;
        }

        if !q.include_nested {
            return Some(None);
        }

        // Commit rows keep their `loroUpdate` payload in the row itself;
        // everything else gets the stored snapshot attached undecoded.
        if !resource.get_subject().is_commit_did() {
            let pure_id = resource.get_subject().pure_id();
            if let Ok(Some(snapshot)) = self.kv.get(Tree::LoroSnapshots, pure_id.as_bytes()) {
                resource
                    .insert_propval_raw(crate::urls::LORO_UPDATE.into(), Value::LoroDoc(snapshot));
            }
        }

        // Same `incomplete` marking as `get_resource_extended(skip_dynamic)`:
        // tells clients the member may have dynamic properties that a direct
        // GET would compute.
        let extenders = match self.class_extenders.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return None,
        };
        for extender in extenders.iter() {
            if !extender.can_extend(&resource) {
                continue;
            }
            match extender.resource_has_extender(&resource) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => return None,
            }
            match extender.check_scope(&resource, self, None).await {
                Ok((true, _)) => {
                    resource
                        .insert_propval_raw(crate::urls::INCOMPLETE.into(), Value::Boolean(true));
                    break;
                }
                Ok((false, _)) => continue,
                Err(_) => return None,
            }
        }

        Some(Some(resource))
    }

    async fn query_basic(&self, q: &Query) -> AtomicResult<QueryResult> {
        let mut subjects: Vec<Subject> = vec![];
        let mut resources: Vec<Resource> = vec![];
        let mut total_count = 0;
        let rights_cache = std::sync::Mutex::new(RightsCache::default());

        let atoms = self.get_index_iterator_for_query(q);

        for (i, atom_res) in atoms.enumerate() {
            let atom = atom_res?;
            if !q.include_external && !atom.subject.is_local() {
                continue;
            }

            total_count += 1;

            if q.offset > i {
                continue;
            }

            if q.limit.is_none() || subjects.len() < q.limit.unwrap() {
                // Sudo without nested bodies needs no per-member work at all.
                if q.for_agent == ForAgent::Sudo && !q.include_nested {
                    subjects.push(atom.subject.clone());
                    continue;
                }

                match self
                    .resolve_query_member(&atom.subject, q, &rights_cache)
                    .await
                {
                    Some(body) => {
                        subjects.push(atom.subject.clone());
                        if let Some(resource) = body {
                            resources.push(resource);
                        }
                    }
                    None => {
                        // The index has an entry for this subject but the
                        // requesting agent can't resolve it — auth-filtered,
                        // destroyed-with-stale-index, or otherwise invisible.
                        // Roll back the count bump so it doesn't outrun the
                        // returned subjects and produce a
                        // `totalMembers: N, members: []` drift. We only do
                        // this for in-page hits; entries past the limit stay
                        // counted blindly (issue #286).
                        total_count -= 1;
                    }
                }
            }
        }

        Ok(QueryResult {
            subjects,
            resources,
            aggregates: Vec::new(),
            count: total_count,
        })
    }

    /// Computes a query's aggregates over every row it matches.
    ///
    /// Re-runs the same filter unpaged and reads each row's value locally: the
    /// whole point is that the numbers travel instead of the rows. Values come
    /// from the materialized row (`get_resource_shallow`) — the same source the
    /// filters are matched against, so a total can never disagree with the set
    /// it claims to summarize.
    /// Every row the query matches, unpaged and in order.
    ///
    /// Subjects, not a count: these are the rows that actually resolved for this
    /// agent. `QueryResult::count` deliberately counts raw index hits (including
    /// unauthorized and stale-index entries, see issue #286), so a `count`
    /// aggregate can legitimately come out lower than `totalMembers` — it counts
    /// what the reader can see, which is the only number a sum over the same rows
    /// can agree with.
    ///
    /// Shared by the paging path and the aggregation pass, so a total can never
    /// summarize a different set than the rows on screen.
    async fn matching_subjects(&self, q: &Query) -> AtomicResult<Vec<Subject>> {
        // The same query, unpaged. `sort_by` is kept so this takes the exact
        // same index path as the paged query — a different path could disagree
        // about which rows match.
        let scan = Query {
            property: q.property.clone(),
            value: q.value.clone(),
            filters: q.filters.clone(),
            limit: None,
            offset: 0,
            start_val: q.start_val.clone(),
            end_val: q.end_val.clone(),
            sort_by: q.sort_by.clone(),
            sort_desc: q.sort_desc,
            include_external: q.include_external,
            // Bodies are never needed here; values are read straight off the
            // local row.
            include_nested: false,
            for_agent: q.for_agent.clone(),
            drive: q.drive.clone(),
            aggregation: None,
            expression_filters: Vec::new(),
        };

        let subjects = if requires_query_index(&scan) {
            self.query_complex(&scan).await?.subjects
        } else {
            self.query_basic(&scan).await?.subjects
        };

        if q.expression_filters.is_empty() {
            return Ok(subjects);
        }

        Ok(subjects
            .into_iter()
            .filter(|subject| {
                let Ok(resource) = self.get_resource_shallow(subject) else {
                    // Nothing to evaluate against: a row we can't read can't be
                    // shown to satisfy a constraint.
                    return false;
                };

                q.expression_filters
                    .iter()
                    .all(|filter| filter.matches(&resource))
            })
            .collect())
    }

    /// The paged answer to a query with a constraint on a computed value.
    ///
    /// The index can't narrow by such a value, so the whole matching set is
    /// evaluated and *then* paged — which also makes `count` the number of rows
    /// that really matched, rather than the index's hit count.
    async fn query_with_expression_filters(&self, q: &Query) -> AtomicResult<QueryResult> {
        let matching = self.matching_subjects(q).await?;
        let count = matching.len();

        let page: Vec<Subject> = matching
            .into_iter()
            .skip(q.offset)
            .take(q.limit.unwrap_or(usize::MAX))
            .collect();

        let resources = if q.include_nested {
            page.iter()
                .filter_map(|subject| self.get_resource_shallow(subject).ok())
                .collect()
        } else {
            Vec::new()
        };

        Ok(QueryResult {
            subjects: page,
            resources,
            aggregates: Vec::new(),
            count,
        })
    }

    async fn compute_aggregation(
        &self,
        q: &Query,
        aggregation: &crate::aggregate::Aggregation,
    ) -> AtomicResult<Vec<crate::aggregate::AggregateOutcome>> {
        use crate::aggregate::{
            Accumulator, AggregateGroup, AggregateOutcome, DEFAULT_GROUP_LIMIT,
        };
        use std::collections::HashMap;

        let subjects = self.matching_subjects(q).await?;

        let mut totals: Vec<Accumulator> =
            vec![Accumulator::default(); aggregation.aggregates.len()];
        let mut per_group: Vec<HashMap<String, Accumulator>> =
            vec![HashMap::new(); aggregation.aggregates.len()];

        // One instant for the whole pass: a `daysSince` evaluated per row against
        // a moving clock could put two rows of the same day in different buckets.
        let now_ms = aggregation.now_ms.unwrap_or_else(crate::utils::now);

        for subject in subjects {
            let Ok(resource) = self.get_resource_shallow(&subject) else {
                continue;
            };

            let group = aggregation.group_by.as_ref().map(|grouping| {
                crate::aggregate::group_key(&resource, grouping).unwrap_or_default()
            });

            for (index, aggregate) in aggregation.aggregates.iter().enumerate() {
                // A computed value stands in for a stored one: `Some(None)` means
                // "this row has nothing to contribute", which is exactly how a
                // missing property already reads below.
                let computed = aggregate
                    .expression
                    .as_ref()
                    .map(|expression| expression.evaluate(&resource, now_ms));

                let stored = if computed.is_some() {
                    None
                } else {
                    aggregate
                        .property
                        .as_ref()
                        .map(|property| resource.get(property).ok())
                };

                // `count` counts rows: every matching row when it names no
                // property, only the rows that HAVE the property when it does
                // (so "count of Paid date" answers "how many are paid"). The
                // other functions need a number, and a row without one simply
                // doesn't contribute — it must not land in `count` either, or a
                // sum would report a denominator it never added up.
                let accumulate = |acc: &mut Accumulator| {
                    if aggregate.function == crate::aggregate::AggregateFunction::Count {
                        if !matches!(stored, Some(None)) && !matches!(computed, Some(None)) {
                            acc.count_row();
                        }

                        return;
                    }

                    let number = match &computed {
                        Some(value) => *value,
                        None => stored.flatten().and_then(crate::aggregate::value_as_number),
                    };

                    if let Some(number) = number {
                        acc.add(number);
                    }
                };

                accumulate(&mut totals[index]);

                if let Some(group) = &group {
                    accumulate(per_group[index].entry(group.clone()).or_default());
                }
            }
        }

        let mut outcomes = Vec::with_capacity(aggregation.aggregates.len());

        for (index, aggregate) in aggregation.aggregates.iter().enumerate() {
            let mut groups: Vec<AggregateGroup> = per_group[index]
                .iter()
                .map(|(key, acc)| AggregateGroup {
                    key: key.clone(),
                    value: acc.finish(aggregate.function),
                    count: acc.count,
                })
                .collect();

            // Day and month buckets read chronologically; anything else reads
            // biggest-first, which is what a breakdown is usually scanned for.
            match aggregation.group_by.as_ref().map(|g| g.granularity) {
                Some(crate::aggregate::GroupGranularity::Exact) | None => {
                    groups.sort_by(|a, b| {
                        b.value
                            .unwrap_or(f64::MIN)
                            .partial_cmp(&a.value.unwrap_or(f64::MIN))
                            .unwrap_or(std::cmp::Ordering::Equal)
                            .then_with(|| a.key.cmp(&b.key))
                    });
                }
                _ => groups.sort_by(|a, b| a.key.cmp(&b.key)),
            }

            let limit = aggregation
                .group_by
                .as_ref()
                .and_then(|g| g.limit)
                .unwrap_or(DEFAULT_GROUP_LIMIT);
            let groups_truncated = groups.len() > limit;
            groups.truncate(limit);

            outcomes.push(AggregateOutcome {
                id: aggregate.id.clone(),
                property: aggregate.property.clone(),
                function: aggregate.function,
                value: totals[index].finish(aggregate.function),
                count: totals[index].count,
                groups,
                groups_truncated,
            });
        }

        Ok(outcomes)
    }

    async fn query_complex(&self, q: &Query) -> AtomicResult<QueryResult> {
        let q_filter = QueryFilter::try_from_query(q)?;
        let (mut subjects, mut resources, mut total_count) =
            query_sorted_indexed(self, q, &q_filter).await?;

        // Rebuild whenever the filter is not watched, whatever the index
        // currently holds.
        //
        // This used to also require `total_count == 0`. But "not watched" means
        // nothing has been maintaining this index — so however many entries it
        // happens to hold, they are not evidence that it is complete. A partial
        // one (a build that stopped short, entries left by a filter that was
        // once watched) is non-zero, so the rebuild never fired and the query
        // kept returning a number that was wrong and entirely plausible. Empty
        // was treated as suspicious and partial as authoritative, which is
        // backwards: partial is the state that looks fine.
        if !q_filter.is_watched(self) {
            info!(filter = ?q_filter, "Building query index");
            crate::metrics::query_indexed();
            let atoms = self.plan_candidate_iterator(q, &q_filter);
            q_filter.watch(self)?;

            let mut transaction = Transaction::new();

            // Drop whatever was there first, so the rebuild is authoritative
            // rather than merged into a set of unknown provenance — otherwise
            // a stale member for a resource that no longer matches survives a
            // rebuild that was supposed to correct exactly that.
            let id = query_index::query_id(&q_filter)?;
            for kv in self.kv.scan_prefix(Tree::QueryMembers, &id) {
                let (key, _) = kv?;
                transaction.push(Operation {
                    tree: Tree::QueryMembers,
                    method: Method::Delete,
                    key,
                    val: None,
                });
            }
            // Every candidate is verified against ALL of the filter's
            // constraints on its materialized row (no Loro decode), so the
            // member index only holds true AND-matches — including for
            // non-equality operators, whose candidate sets are supersets.
            for atom in atoms.flatten() {
                let Ok(resource) = self.get_resource_shallow(&atom.subject) else {
                    // No row to verify against (external/never-stored) —
                    // don't index what we can't confirm.
                    continue;
                };
                if !query_index::resource_matches_filter(&resource, &q_filter) {
                    continue;
                }
                let prop = query_index::index_key_property(&q_filter, &atom);
                let sort_key = query_index::sort_key_for(&resource, prop);
                update_indexed_member(
                    &q_filter,
                    atom.subject.as_str(),
                    &sort_key,
                    false,
                    &mut transaction,
                )?;
            }
            self.apply_transaction(&mut transaction)?;

            // Query through the new indexes.
            (subjects, resources, total_count) = query_sorted_indexed(self, q, &q_filter).await?;
        }

        Ok(QueryResult {
            subjects,
            resources,
            aggregates: Vec::new(),
            count: total_count,
        })
    }

    #[instrument(skip_all)]
    fn remove_atom_from_index(
        &self,
        atom: &Atom,
        resource: &Resource,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        for index_atom in atom.to_indexable_atoms() {
            transaction.push(Operation::remove_atom_from_reference_index(&index_atom));
            transaction.push(Operation::remove_atom_from_prop_val_sub_index(&index_atom));

            check_if_atom_matches_watched_query_filters(
                self,
                &index_atom,
                atom,
                true,
                resource,
                transaction,
            )
            .map_err(|e| format!("Checking atom went wrong: {}", e))?;
        }
        Ok(())
    }

    /// Recursively removes a resource and its children from the database.
    /// `removed` collects the `pure_id()` of every deleted subject so the
    /// caller can tombstone them after the transaction is applied.
    /// `inherited_drive` is the drive of the resource whose cascade brought us
    /// here. A child that carries no `drive` of its own — anything created
    /// before the server stamped it — is still in its parent's drive, and the
    /// removal has to name one or it reaches no subscriber.
    async fn recursive_remove(
        &self,
        subject: &Subject,
        transaction: &mut Transaction,
        removed: &mut Vec<String>,
        inherited_drive: Option<Subject>,
    ) -> AtomicResult<()> {
        // Key by `pure_id()` — that is how resources and Loro snapshots are
        // stored (`add_resource_tx`, `apply_commit`). Looking up by the raw
        // `to_string()` (which may carry `?drive=` params) would miss the
        // row entirely for DID subjects with a drive hint.
        let subject_str = subject.pure_id();
        if let Ok(found) = self.get_propvals(&subject_str) {
            let resource = Resource::from_propvals(found, subject.clone());
            transaction.push(Operation::remove_resource(&subject_str));
            // Remove the Loro snapshot in the same transaction. Without this
            // the snapshot is orphaned in `Tree::LoroSnapshots` and leaks
            // forever — only the WS/Iroh DESTROY path cleaned it before.
            transaction.push(Operation::remove_loro_snapshot(&subject_str));
            removed.push(subject_str.clone());
            let drive = resource.get_drive().or(inherited_drive);
            let mut children = resource.get_children(self).await?;
            for child in children.iter_mut() {
                // Notify subscribers so clients evict the cascade-deleted
                // child from their cache. The signed destroy commit only
                // fires DbEvent::Destroyed for the top-level subject; without
                // this, children remain in WASM-DB / store and the UI keeps
                // rendering them.
                let _ = self.db_events.send(DbEvent::Destroyed {
                    subject: child.get_subject().without_params(),
                    drive: child.get_drive().or_else(|| drive.clone()),
                    source_id: None,
                    from_commit: false,
                    commit_json: None,
                });
                // Because the function is async we need to box it to use recursion.
                Box::pin(self.recursive_remove(
                    child.get_subject(),
                    transaction,
                    removed,
                    drive.clone(),
                ))
                .await?;
            }
            for (prop, val) in resource.get_propvals() {
                let remove_atom = crate::Atom::new(subject.clone(), prop.clone(), val.clone());
                self.remove_atom_from_index(&remove_atom, &resource, transaction)?;
            }
            crate::search::unindex_subject(self, &subject_str, transaction)?;
        } else {
            return Err(format!(
                "Resource {} could not be deleted, because it was not found in the store.",
                subject
            )
            .into());
        }
        Ok(())
    }

    fn is_endpoint(&self, url: &url::Url) -> bool {
        self.endpoints.iter().any(|e| e.path == url.path())
    }

    #[tracing::instrument(skip_all)]
    async fn call_endpoint(
        &self,
        subject: &str,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        // For internal endpoint resolution, we use the store's base domain if set.
        let origin = self
            .get_base_domain()
            .unwrap_or_else(|| "http://localhost".to_string());
        let resolved = Subject::from(subject).resolve(&origin);
        let url = url::Url::parse(&resolved)?;

        // Check if the subject matches one of the endpoints
        for endpoint in self.endpoints.iter() {
            if url.path() == endpoint.path {
                // An endpoint whose required query keys are absent returns itself,
                // which clients render as a form to fill in. Handling it here (and
                // not in each handler) keeps handlers to the case they exist for:
                // the request that actually carries what they need.
                let missing_required = endpoint.form_when_missing.iter().any(|key| {
                    !url.query_pairs()
                        .any(|(k, v)| k == key.as_str() && !v.is_empty())
                });

                // Not all Endpoints have a handle function.
                // If there is none, return the endpoint plainly.
                let response = if missing_required {
                    endpoint.to_resource_response(self, subject).await?
                } else if let Some(handle) = endpoint.handle.as_ref() {
                    // Call the handle function for the endpoint, if it exists.
                    let context: HandleGetContext = HandleGetContext {
                        subject: url,
                        store: self,
                        for_agent,
                    };
                    (handle)(context).await.map_err(|mut e| {
                        e.message = format!(
                            "Error handling {} Endpoint: {}",
                            endpoint.shortname, e.message
                        );
                        e
                    })?
                } else {
                    endpoint.to_resource_response(self, subject).await?
                };

                // Extended resources must always return the requested subject as their own subject,
                // EXCEPT when the handler returned a resource with its own canonical subject
                // (e.g. the /did proxy endpoint returns DID resources that must keep their DID as @id).
                match response {
                    ResourceResponse::Resource(mut resource) => {
                        if !matches!(resource.get_subject(), Subject::Did { .. }) {
                            resource.set_subject(subject.into());
                        }
                        return Ok(resource.into());
                    }
                    ResourceResponse::ResourceWithReferenced(mut resource, references) => {
                        if !matches!(resource.get_subject(), Subject::Did { .. }) {
                            resource.set_subject(subject.into());
                        }
                        return Ok(ResourceResponse::ResourceWithReferenced(
                            resource, references,
                        ));
                    }
                    ResourceResponse::Redirect(target) => {
                        return Ok(ResourceResponse::Redirect(target));
                    }
                }
            }
        }

        Err(format!("No endpoint found for {}", subject).into())
    }
}

// Drop is handled by SledStore's own Drop impl which flushes on drop.
// No explicit Drop needed for Db since Arc<dyn KvStore> handles cleanup.

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Storelike for Db {
    fn normalize_subject(&self, subject: &Subject) -> Subject {
        Subject::from_raw(subject.as_str(), self.get_base_domain().as_deref())
    }

    fn sync_policy(&self) -> Arc<dyn crate::sync::policy::SyncPolicy> {
        // The installed policy (managed) or the permissive default. Reads the
        // field directly to avoid resolving against the inherent method of the
        // same name.
        self.sync_policy
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| Arc::new(crate::sync::policy::OpenPolicy))
    }

    fn get_active_drive(&self) -> Option<String> {
        self.get_active_drive()
    }

    fn set_active_drive(&self, drive: &str) -> AtomicResult<()> {
        self.set_active_drive(drive)
    }

    fn clear_tombstone(&self, subject: &str) {
        crate::sync::tombstones::clear_tombstone(self, subject)
    }

    fn clear_default_agent(&self) {
        self.clear_default_agent()
    }

    /// Adds Atoms to the store.
    /// Will replace existing Atoms that share Subject / Property combination.
    /// Validates datatypes and required props presence.
    #[instrument(skip_all)]
    async fn add_atoms(&self, atoms: Vec<Atom>) -> AtomicResult<()> {
        // Start with a nested HashMap, containing only strings.
        let mut map: HashMap<Subject, Resource> = HashMap::new();
        for atom in atoms {
            match map.get_mut(&atom.subject) {
                // Resource exists in map
                Some(resource) => {
                    resource
                        .set_string(atom.property.clone(), &atom.value.to_string(), self)
                        .await
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                }
                // Resource does not exist
                None => {
                    let mut resource = Resource::new(atom.subject.to_string());
                    resource
                        .set_string(atom.property.clone(), &atom.value.to_string(), self)
                        .await
                        .map_err(|e| format!("Failed adding attom {}. {}", atom, e))?;
                    map.insert(atom.subject, resource);
                }
            }
        }
        for (_subject, resource) in map.iter() {
            self.add_resource(resource).await?
        }
        self.kv.flush()?;
        Ok(())
    }

    /// Maps a host (domain/subdomain) to a Drive DID.
    fn add_drive_mapping(&self, host: &str, drive_did: &Value) -> AtomicResult<()> {
        self.add_drive_mapping(host, drive_did)
    }

    /// Removes the drive mapping for a given host.
    fn remove_drive_mapping(&self, host: &str) -> AtomicResult<()> {
        self.remove_drive_mapping(host)
    }

    /// Returns the base domain of the store, e.g. "https://atomicdata.dev".
    fn get_base_domain(&self) -> Option<String> {
        self.base_domain.clone()
    }

    fn set_base_url(&self, _url: &str) {
        // Since Db is mostly immutable and cloned per-request in multi-tenant mode,
        // setting base_url on the original instance might not be what's intended
        // in all cases, but for CLI usage it is.
        // However, we don't have a Mutex for base_domain in Db.
        // Let's just say it's not supported for Db yet if it's not a clone.
        // Actually, for CLI it's usually just initialized once.
        tracing::warn!(
            "set_base_url called on Db, but it is not supported to change it after initialization. Use clone_with_url instead."
        );
    }

    #[instrument(skip_all)]
    async fn add_resource_opts(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
    ) -> AtomicResult<()> {
        // This only works if no external functions rely on using add_resource for atom-like operations!
        // However, add_atom uses set_propvals, which skips the validation.
        let subject = self.normalize_subject(resource.get_subject());
        let subject_str = subject.pure_id();
        let existing = self.get_propvals(&subject_str).ok();
        if !overwrite_existing && existing.is_some() {
            return Err(format!(
                "Failed to add: '{}', already exists, should not be overwritten.",
                resource.get_subject()
            )
            .into());
        }
        if check_required_props {
            resource.check_required_props(self).await?;
        }
        // Build a single transaction for index updates + resource persistence
        let mut transaction = Transaction::new();

        if update_index {
            // Persist DID routing hint if available
            if let Subject::Did {
                drive_hint: Some(hint),
                ..
            } = &subject
            {
                transaction.push(Operation {
                    tree: Tree::DidMapping,
                    method: Method::Insert,
                    key: subject_str.as_bytes().to_vec(),
                    val: Some(hint.as_bytes().to_vec()),
                });
            }

            if let Some(pv) = existing {
                let subject = resource.get_subject();
                // Evict against the state that is going away, not the one
                // replacing it. Whether an entry belongs in a watched query's
                // member list — and under which sort key it was filed — are
                // facts about the old values. Handing over the new resource
                // asks instead whether the *new* values still match, and a row
                // edited out of a filtered view answers no, so the entry that
                // needs deleting is the one deletion is skipped for. The row
                // then stays listed in that view until the index is rebuilt.
                let old = Resource::from_propvals(pv.clone(), subject.clone());
                for (prop, val) in pv.iter() {
                    let remove_atom = crate::Atom::new(subject.clone(), prop.into(), val.clone());
                    self.remove_atom_from_index(&remove_atom, &old, &mut transaction)
                        .map_err(|e| {
                            format!("Failed to remove atom from index {}. {}", remove_atom, e)
                        })?;
                }
            }
            for a in resource.to_atoms() {
                self.add_atom_to_index(&a, resource, &mut transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", a, e))?;
            }
            crate::search::index_resource(self, resource, &mut transaction)?;
        }
        // The snapshot in `Tree::LoroSnapshots` is the authoritative CRDT
        // state. Derive and
        // persist it here UNCONDITIONALLY for every CRDT resource — in the
        // same transaction as the `Tree::Resources` write — so the invariant
        // holds that every resource blob is paired with a current snapshot.
        // (The old code only wrote the snapshot when the propvals lacked a
        // `loroUpdate`, so any resource that had been through `apply_state_doc`
        // — i.e. every sync import — had its snapshot write silently skipped.)
        // The `loroUpdate` propval is stripped from the `Tree::Resources`
        // blob: that blob is a pure derived projection, not a second home for
        // the CRDT state. Commits are native (immutable, not CRDT) — they get
        // no snapshot and keep their `loroUpdate` payload in the blob.
        let mut propvals = resource.get_propvals().clone();
        if !subject.is_commit_did() {
            let snapshot = resource.build_state_doc()?.export_snapshot();
            propvals.remove(crate::urls::LORO_UPDATE);
            transaction.push(Operation {
                tree: Tree::LoroSnapshots,
                method: Method::Insert,
                key: subject_str.as_bytes().to_vec(),
                val: Some(snapshot),
            });
        }

        // Persist the resource data in the same transaction
        let resource_bin = encode_propvals(&propvals)?;
        transaction.push(Operation {
            tree: Tree::Resources,
            method: Method::Insert,
            key: subject_str.as_bytes().to_vec(),
            val: Some(resource_bin),
        });
        self.apply_transaction(&mut transaction)?;
        let _ = self.db_events.send(DbEvent::Changed {
            subject: resource.get_subject().without_params(),
            delta: None,
            // Attributed here, while the importing write is still on the stack:
            // the live push loop uses it to avoid sending an update straight
            // back to the peer it came from.
            source_id: crate::sync::ws_apply::current_import_source(),
            is_new: false,
            from_commit: false,
        });
        Ok(())
    }

    /// Apply a single signed Commit to the Db.
    /// Creates, edits or destroys a resource.
    /// Allows for control over which validations should be performed.
    /// Returns the generated Commit, the old Resource and the new Resource.
    #[tracing::instrument(skip_all)]
    async fn apply_commit(
        &self,
        commit: Commit,
        opts: &CommitOpts,
    ) -> AtomicResult<CommitResponse> {
        let store = self;

        // Persisting a commit is a read-modify-write: `validate_and_build_response`
        // reads the resource's stored Loro snapshot, applies this commit's ops to
        // it, and the transaction below writes the result back as a *replace*. A
        // peer update landing in that window would be overwritten and lost, so the
        // whole span is exclusive per subject. See `subject_lock` for why this is
        // a lock rather than a merge, and for the no-reentrancy invariant.
        let subject_guard = store.subject_locks.lock(&commit.subject.pure_id()).await;

        // A signed destroy is durable (tombstone envelope, re-sent by bulk
        // sync). If this exact commit is already stored here and the subject
        // exists again, the subject was recreated after the destroy and this
        // is a replay, not a delete. Local presence only — a commit DID must
        // never be resolved over the network.
        if commit.destroy.unwrap_or(false) && opts.validate_rights {
            if let Some(sig) = commit.signature.as_ref() {
                let commit_id = format!("did:ad:commit:{sig}");
                if store.has_resource_locally(&commit_id)
                    && store.has_resource_locally(&commit.subject.pure_id())
                {
                    return Err(format!(
                        "Destroy commit for {} was already applied here; refusing replay",
                        commit.subject
                    )
                    .into());
                }
            }
        }

        let commit_response = commit.validate_and_build_response(opts, store).await?;

        let mut transaction = Transaction::new();

        let mut root_subject: Option<String> = None;

        // BEFORE APPLY COMMIT HANDLERS
        let resource_before = commit_response
            .resource_new
            .as_ref()
            .or(commit_response.resource_old.as_ref());

        if let Some(resource) = resource_before {
            let extenders = self
                .class_extenders
                .read()
                .map_err(|e| format!("Failed to read class extenders: {}", e))?
                .clone();
            for extender in extenders.iter() {
                if extender.resource_has_extender(resource)? {
                    if !extender.can_extend(resource) {
                        // A plugin may not extend a plugin. Silently skipping
                        // read as "the hook did not run" with no way to tell
                        // this apart from a class mismatch.
                        tracing::debug!(
                            resource = %resource.get_subject(),
                            "class extender skipped: a plugin cannot extend another plugin"
                        );
                        continue;
                    }

                    let (is_in_scope, cached_root) =
                        extender.check_scope(resource, self, root_subject).await?;

                    root_subject = cached_root;

                    if !is_in_scope {
                        continue;
                    }

                    let Some(handler) = extender.before_commit.as_ref() else {
                        continue;
                    };

                    let fut = (handler)(CommitExtenderContext {
                        store,
                        commit: &commit_response.commit,
                        resource,
                        is_new: commit_response.resource_old.is_none(),
                        changed_props: &commit_response.changed_props,
                    });
                    fut.await?;
                }
            }
        }

        // Commits are signed envelopes, not a queryable class. Keep genesis
        // and rights/parent/destroy; drop ordinary content certificates.
        if commit_response.auth_impact().is_critical() {
            store.add_resource_tx(&commit_response.commit_resource, &mut transaction)?;
            for atom in commit_response.commit_resource.to_atoms() {
                store.add_atom_to_index(
                    &atom,
                    &commit_response.commit_resource,
                    &mut transaction,
                )?;
            }
        }

        // The signed envelope itself lives in `Tree::Envelopes`, keyed by the
        // resource it is about, in the same transaction as the state it
        // signs. This is what lets any node that holds the resource say who
        // signed it, independent of the commit rows above.
        crate::envelopes::record_ops(store, &commit_response, &mut transaction)?;

        match (&commit_response.resource_old, &commit_response.resource_new) {
            (None, None) => {
                if !commit_response.commit.destroy.unwrap_or(false) {
                    return Err("Neither an old nor a new resource is returned from the commit - something went wrong.".into());
                }
            }
            (Some(_old), None) => {
                let normalized_commit_subject =
                    self.normalize_subject(&commit_response.commit.subject.clone());
                assert_eq!(
                    _old.get_subject().to_string(),
                    normalized_commit_subject.to_string()
                );
                assert!(&commit_response
                    .commit
                    .destroy
                    .expect("Resource was removed but `commit.destroy` was not set!"));
                let subject: Subject = commit_response.commit.subject.clone();
                // `remove_resource` records the tombstone; the signed destroy
                // is the envelope row `record_ops` queued above, which is what
                // `SYNC_DIFF.removeCommits` carries.
                self.remove_resource(&subject).await?;
            }
            _ => {}
        };

        if let Some(new) = &commit_response.resource_new {
            self.add_resource_tx(new, &mut transaction)?;

            // Persist the Loro snapshot so VV-based sync can find it.
            // Use pure_id() (strips query params/drive hints) for a canonical key.
            if let Some(snapshot) = new.materialized_state() {
                transaction.push(trees::Operation {
                    tree: trees::Tree::LoroSnapshots,
                    method: trees::Method::Insert,
                    key: new.get_subject().pure_id().as_bytes().to_vec(),
                    val: Some(snapshot),
                });
            }
        }

        if opts.update_index {
            if let Some(old) = &commit_response.resource_old {
                for atom in &commit_response.remove_atoms {
                    store
                        .remove_atom_from_index(atom, old, &mut transaction)
                        .map_err(|e| format!("Error removing atom from index: {e}  Atom: {e}"))?
                }
            }
            if let Some(new) = &commit_response.resource_new {
                for atom in &commit_response.add_atoms {
                    store
                        .add_atom_to_index(atom, new, &mut transaction)
                        .map_err(|e| format!("Error adding atom to index: {e}  Atom: {e}"))?
                }

                store.index_genesis_derived_atoms(
                    &commit_response.add_atoms,
                    new,
                    &mut transaction,
                )?;
                crate::search::index_resource(store, new, &mut transaction)?;
            }
            if commit_response.resource_new.is_none() {
                if let Some(old) = &commit_response.resource_old {
                    crate::search::unindex_subject(
                        store,
                        &old.get_subject().pure_id(),
                        &mut transaction,
                    )?;
                }
            }
        }

        store.apply_transaction_with_source(
            &mut transaction,
            commit_response.source_id.as_deref(),
        )?;

        // Notify subscribers
        let subject = commit_response.commit.subject.without_params();
        let is_destroy = commit_response.commit.destroy.unwrap_or(false);
        let event = if is_destroy {
            // The signed destroy itself, so a peer transport can forward it
            // as a `COMMIT` frame. Serialisation failure is not fatal for the
            // local apply; the event just carries no commit and the destroy
            // reaches peers on the next bulk reconcile instead.
            let commit_json = commit_response.commit_resource.to_json_ad(None).ok();
            DbEvent::Destroyed {
                subject,
                drive: commit_response
                    .resource_old
                    .as_ref()
                    .and_then(|old| old.get_drive()),
                source_id: commit_response.source_id.clone(),
                from_commit: true,
                commit_json,
            }
        } else {
            DbEvent::Changed {
                subject,
                delta: commit_response.commit.loro_update.clone(),
                source_id: commit_response.source_id.clone(),
                is_new: commit_response.resource_old.is_none(),
                from_commit: true,
            }
        };
        let _ = store.db_events.send(event);

        store.handle_commit(&commit_response);

        // The read-modify-write this lock protects (read snapshot, apply ops,
        // write back the transaction above) is done. Release it before running
        // AFTER APPLY COMMIT HANDLERS: an `after_commit` extender is allowed to
        // issue its own follow-up commit to the same subject (see
        // `atomic_plugin::commit` / `server/src/plugins/wasm.rs`'s `commit`
        // host function), which re-enters `apply_commit` and tries to lock the
        // same subject again. Holding the guard across that call would be the
        // exact self-reentrancy `subject_lock` warns against and deadlocks the
        // request forever, since nothing else can ever release a lock this
        // task already holds.
        drop(subject_guard);

        // AFTER APPLY COMMIT HANDLERS
        // Commit has been checked and saved.
        // Here you can add side-effects, such as creating new Commits.
        let resource_after = commit_response
            .resource_new
            .as_ref()
            .or(commit_response.resource_old.as_ref());

        if let Some(resource) = resource_after {
            let extenders = self
                .class_extenders
                .read()
                .map_err(|e| format!("Failed to read class extenders: {}", e))?
                .clone();
            for extender in extenders.iter() {
                if extender.resource_has_extender(resource)? {
                    if !extender.can_extend(resource) {
                        continue;
                    }

                    let (is_in_scope, cached_root) =
                        extender.check_scope(resource, self, root_subject).await?;

                    root_subject = cached_root;

                    if !is_in_scope {
                        continue;
                    }

                    use crate::class_extender::CommitExtenderContext;

                    let Some(handler) = extender.after_commit.as_ref() else {
                        continue;
                    };

                    let fut = (handler)(CommitExtenderContext {
                        store,
                        commit: &commit_response.commit,
                        resource,
                        is_new: commit_response.resource_old.is_none(),
                        changed_props: &commit_response.changed_props,
                    });
                    fut.await?;
                }
            }
        }
        Ok(commit_response)
    }

    fn get_default_agent(&self) -> AtomicResult<crate::agents::Agent> {
        match self.default_agent.lock().unwrap().to_owned() {
            Some(agent) => Ok(agent),
            None => {
                Err("No agent set. Call db.setup() or db.load_agent_from_secret() first.".into())
            }
        }
    }

    #[instrument(skip_all)]
    async fn get_value(&self, subject: &str, property: &str) -> AtomicResult<Value> {
        self.get_resource(&subject.into())
            .await
            .and_then(|r| r.get(property).cloned())
    }

    #[instrument(skip_all)]
    async fn get_resource(&self, subject: &Subject) -> AtomicResult<Resource> {
        let normalized = self.normalize_subject(subject);
        let subject_str = normalized.pure_id();
        if let Ok(propvals) = self.get_propvals(&subject_str) {
            let mut res_subject = normalized.clone();

            // If it's a DID and we don't have a hint in the requested subject,
            // check if we have one persisted in the did_mapping tree.
            if let Subject::Did {
                drive_hint: None, ..
            } = &res_subject
            {
                if let Ok(Some(hint_bin)) = self.kv.get(Tree::DidMapping, subject_str.as_bytes()) {
                    if let Ok(hint) = std::str::from_utf8(&hint_bin) {
                        res_subject = res_subject.set_drive_hint(hint.to_string());
                    }
                }
            }

            let mut resource = Resource::from_propvals(propvals, res_subject);
            // Authoritative merged CRDT state (full oplog) lives in LoroSnapshots.
            // Propvals may carry a smaller incremental `loroUpdate` from the last commit.
            if let Ok(Some(snapshot)) = self.kv.get(
                crate::db::trees::Tree::LoroSnapshots,
                subject_str.as_bytes(),
            ) {
                if let Ok(doc) = crate::loro::AtomicLoroDoc::from_snapshot(&snapshot) {
                    // We already hold the exact bytes `doc` was just imported
                    // from — reuse them instead of having `apply_state_doc`
                    // re-export an equivalent snapshot. This is the hot path
                    // for every resource read (including once per member of
                    // a collection query), so the saved export is per-read,
                    // not one-off.
                    let _ = resource.apply_state_doc_with_snapshot(doc, snapshot);
                }
            }
            Ok(resource)
        } else {
            // Resolve the subject to a full URL for network operations
            let origin = self
                .get_base_domain()
                .unwrap_or_else(|| "http://localhost".to_string());
            let resolved_url = normalized.resolve(&origin);

            // If the resource is not found, it might be an endpoint.
            // This is checking if the subject matches one of the endpoints
            if let Ok(url) = url::Url::parse(&resolved_url) {
                if self.is_endpoint(&url) {
                    let agent_opt = self.get_default_agent().ok();
                    let for_agent = if let Some(agent) = &agent_opt {
                        ForAgent::from(agent)
                    } else {
                        ForAgent::Public
                    };
                    return Ok(self
                        .call_endpoint(&resolved_url, &for_agent)
                        .await?
                        .to_single());
                }
            }
            let resolved_url = normalized.resolve(&origin);

            if normalized.is_did() || normalized.path().starts_with("/did") {
                // If it's an agent DID and not found locally, return a minimal resource
                // instead of an error. This is important for "just-in-time" agent registration.
                if normalized.is_agent_did() || normalized.path().starts_with("/did:ad:agent:") {
                    let lookup = if normalized.path().starts_with('/') {
                        &normalized.path()[1..]
                    } else {
                        &normalized.path()
                    };
                    if let Some(pubkey) = lookup.strip_prefix("did:ad:agent:") {
                        if let Ok(agent) = crate::agents::Agent::new_from_public_key(pubkey) {
                            if let Ok(resource) = agent.to_resource() {
                                return Ok(resource);
                            }
                        }
                    }
                }

                if normalized.is_did() || resolved_url.starts_with("/did:") {
                    return Err(AtomicError::not_found(format!(
                        "DID Resource {} not found locally",
                        resolved_url
                    )));
                }

                return self
                    .handle_not_found(
                        &resolved_url,
                        format!("Resource {} not found locally", resolved_url).into(),
                        self.get_default_agent().ok().as_ref(),
                    )
                    .await;
            }

            // Only attempt a network fetch for external subjects.
            // Fetching a local URL would cause the server to request itself,
            // creating an infinite loop.
            //
            // `is_local()` alone is not enough: the canonical atomicdata.dev
            // vocabulary is deliberately kept `External` even on its own host
            // (see `Subject::CANONICAL_VOCABULARY_PREFIXES`), so on
            // atomicdata.dev a miss for `/properties/*` would fall through to a
            // network fetch of this very server. Anything served from our own
            // authority is ours whether or not it is `Internal`, so compare
            // authorities too — and ignore the scheme, since a store migrated
            // as `https://` must not self-fetch when served over `http://`.
            let base_domain = self.get_base_domain();
            let resolved_subject_obj = Subject::from_raw(&resolved_url, base_domain.as_deref());
            let is_own_authority = base_domain
                .as_deref()
                .map(|base| {
                    let strip = |s: &str| {
                        s.trim_start_matches("https://")
                            .trim_start_matches("http://")
                            .trim_end_matches('/')
                            .to_string()
                    };
                    let base_authority = strip(base);
                    let resolved = strip(&resolved_url);
                    resolved == base_authority
                        || resolved.starts_with(&format!("{}/", base_authority))
                })
                .unwrap_or(false);

            if resolved_subject_obj.is_local() || is_own_authority {
                return self
                    .handle_not_found(
                        &resolved_url,
                        "Not found in DB".into(),
                        self.get_default_agent().ok().as_ref(),
                    )
                    .await;
            }

            if let Ok(resource) = self
                .fetch_resource(&resolved_url, self.get_default_agent().ok().as_ref())
                .await
            {
                // If the resource is external, it's not present in the store.
                // However, we did fetch it (because the user probably requested it).
                // So we should add it to the store.
                // Note that this logic is also in `Store`'s `get_resource`, but it's slightly different there.
                // We should probably unify this.
                // Also, this might cause issues if we want to get a resource but NOT save it.
                self.add_resource_opts(&resource, false, false, true)
                    .await?;
                Ok(resource)
            } else {
                self.handle_not_found(
                    &resolved_url,
                    "Not found in DB".into(),
                    self.get_default_agent().ok().as_ref(),
                )
                .await
            }
        }
    }

    fn has_stored_resource(&self, subject: &Subject) -> bool {
        let normalized = self.normalize_subject(subject);
        self.get_propvals(&normalized.pure_id()).is_ok()
    }

    fn get_defaults_fingerprint(&self) -> AtomicResult<Option<String>> {
        Ok(self
            .kv
            .get(Tree::PluginMeta, DEFAULTS_FINGERPRINT_KEY)?
            .and_then(|v| String::from_utf8(v).ok()))
    }

    fn set_defaults_fingerprint(&self, fingerprint: &str) -> AtomicResult<()> {
        // Folds into the open bootstrap batch, so the fingerprint is only
        // persisted together with the seed it describes.
        self.kv.insert(
            Tree::PluginMeta,
            DEFAULTS_FINGERPRINT_KEY,
            fingerprint.as_bytes(),
        )
    }

    #[instrument(skip_all)]
    async fn get_resource_extended(
        &self,
        subject: &Subject,
        skip_dynamic: bool,
        for_agent: &ForAgent,
    ) -> AtomicResult<ResourceResponse> {
        let subject_without_params = subject.without_params();

        // Get the inner URL for endpoint checking and extender context
        let inner_url = match subject {
            Subject::Internal { url, .. } => url,
            Subject::External(u) => u,
            Subject::Did { url, .. } => url,
        };

        // Check if the subject matches one of the endpoints, if so, call the endpoint.
        let is_endpoint = self.is_endpoint(inner_url);

        if is_endpoint {
            return self.call_endpoint(subject.as_str(), for_agent).await;
        }

        async move {
            let mut resource = self.get_resource(&subject_without_params).await?;

            let _explanation = crate::hierarchy::check_read(self, &resource, for_agent).await?;

            let mut root_subject: Option<String> = None;

            let extenders = self
                .class_extenders
                .read()
                .map_err(|e| format!("Failed to read class extenders: {}", e))?
                .clone();
            for extender in extenders.iter() {
                if !extender.can_extend(&resource) {
                    continue;
                }

                if extender.resource_has_extender(&resource)? {
                    let (is_in_scope, cached_root) =
                        extender.check_scope(&resource, self, root_subject).await?;

                    root_subject = cached_root;

                    if !is_in_scope {
                        continue;
                    }

                    if skip_dynamic {
                        // This lets clients know that the resource may have dynamic properties that are currently not included
                        resource
                            .set(
                                crate::urls::INCOMPLETE.into(),
                                crate::Value::Boolean(true),
                                self,
                            )
                            .await?;

                        return Ok(resource.into());
                    }

                    if let Some(handler) = extender.on_resource_get.as_ref() {
                        let fut = (handler)(GetExtenderContext {
                            store: self,
                            url: inner_url,
                            db_resource: &mut resource,
                            for_agent,
                        });
                        let resource_response = fut.await?;

                        // TODO: Check if we actually need this
                        // make sure the actual subject matches the one requested - It should not be changed in the logic above
                        match resource_response {
                            ResourceResponse::Resource(mut resource) => {
                                resource.set_subject(subject.to_string());
                                return Ok(resource.into());
                            }
                            ResourceResponse::ResourceWithReferenced(mut resource, referenced) => {
                                resource.set_subject(subject.to_string());

                                return Ok(ResourceResponse::ResourceWithReferenced(
                                    resource, referenced,
                                ));
                            }
                            ResourceResponse::Redirect(target) => {
                                return Ok(ResourceResponse::Redirect(target));
                            }
                        }
                    }
                }
            }

            resource.set_subject(subject.to_string());

            Ok(resource.into())
        }
        .await
    }

    fn handle_commit(&self, commit_response: &CommitResponse) {
        if let Some(fun) = &self.on_commit {
            fun(commit_response);
        }
    }

    /// Search the Store, returns the matching subjects.
    /// The second returned vector should be filled if query.include_resources is true.
    /// Tries `query_cache`, which you should implement yourself.
    #[instrument(skip_all)]
    async fn query(&self, q: &Query) -> AtomicResult<QueryResult> {
        // A constraint on a computed value can't come from the index, so it is
        // applied to the set the index narrows to — which means paging has to
        // happen after it, not in it.
        let mut result = if !q.expression_filters.is_empty() {
            self.query_with_expression_filters(q).await?
        } else if requires_query_index(q) {
            self.query_complex(q).await?
        } else {
            self.query_basic(q).await?
        };

        // Aggregates run over the whole matching set, so they need their own
        // pass — the one above is limited to the requested page. Only when
        // asked: a query without aggregates pays nothing for this.
        if let Some(aggregation) = &q.aggregation {
            if !aggregation.is_empty() {
                result.aggregates = self.compute_aggregation(q, aggregation).await?;
            }
        }

        Ok(result)
    }

    async fn search(
        &self,
        query_str: &str,
        opts: crate::client::search::SearchOpts,
    ) -> AtomicResult<Vec<Resource>> {
        let hits = crate::search::query(self, query_str, &opts)?;
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits {
            match self.get_resource(&hit.subject).await {
                Ok(r) => out.push(r),
                Err(_) => out.push(Resource::new(hit.subject.to_string())),
            }
        }
        Ok(out)
    }

    #[instrument(skip_all)]
    fn all_resources(
        &self,
        include_external: bool,
    ) -> Box<dyn std::iter::Iterator<Item = Resource> + Send> {
        let base_domain = self.base_domain.clone();
        let result = self.kv.iter_tree(Tree::Resources).filter_map(move |item| {
            let (subject_bytes, resource_bin) = item.expect(DB_CORRUPT_MSG);
            Db::map_kv_item_to_resource(
                &subject_bytes,
                &resource_bin,
                include_external,
                base_domain.as_deref(),
            )
        });

        Box::new(result)
    }

    async fn post_resource(
        &self,
        subject: &str,
        body: Vec<u8>,
        for_agent: &ForAgent,
    ) -> AtomicResult<Resource> {
        let endpoints = self.endpoints.iter().filter(|e| e.handle_post.is_some());
        let subj_url = url::Url::try_from(subject)?;
        for e in endpoints {
            if let Some(fun) = &e.handle_post {
                if subj_url.path() == e.path {
                    let handle_post_context = crate::endpoints::HandlePostContext {
                        store: self,
                        body: body.clone(),
                        for_agent,
                        subject: subj_url.clone(),
                    };
                    let mut resource = fun(handle_post_context).await?.to_single();
                    resource.set_subject(subject.into());

                    return Ok(resource);
                }
            }
        }
        // If we get Class Handlers with POST, this is where the code goes
        // let mut r = self.get_resource(subject)?;
        // for class in r.get_classes(self)? {
        //     match class.subject.as_str() {
        //         urls::IMPORTER => {
        //             let query_params = url::Url::try_from(subject)?;
        //             return crate::plugins::importer::construct_importer(
        //                 self,
        //                 query_params.query_pairs(),
        //                 &mut r,
        //                 for_agent,
        //                 Some(body),
        //             );
        //         }
        //         _ => {}
        //     }
        // }
        Err(
            AtomicError::method_not_allowed("Cannot post here - no Endpoint Post handler found")
                .set_subject(subject),
        )
    }

    async fn populate(&self) -> AtomicResult<()> {
        crate::populate::bootstrap(self).await.map(|_| ())
    }

    #[instrument(skip_all)]
    async fn remove_resource(&self, subject: &Subject) -> AtomicResult<()> {
        let mut transaction = Transaction::new();
        let mut removed = Vec::new();
        self.recursive_remove(subject, &mut transaction, &mut removed, None)
            .await?;
        self.apply_transaction(&mut transaction)?;
        // Tombstone every removed subject so bulk sync (Iroh / WS `SYNC`)
        // does not resurrect them from a peer that still holds a stale copy.
        for s in &removed {
            crate::sync::tombstones::record_tombstone(self, s);
        }
        // TODO: deletion sync — should create a signed destroy commit
        // and push it through the normal commit pipeline, not a raw DESTROY frame.
        Ok(())
    }

    fn set_default_agent(&self, agent: crate::agents::Agent) {
        self.default_agent.lock().unwrap().replace(agent);
    }

    fn begin_batch(&self) {
        self.kv.begin_batch();
    }

    fn commit_batch(&self) -> AtomicResult<()> {
        self.kv.commit_batch()
    }
}

fn corrupt_db_message(subject: &str) -> String {
    format!(
        "Could not deserialize item {} from database. DB is possibly corrupt, could be due to an update or a lack of migrations. Restore to a previous version, export your data and import your data again.",
        subject
    )
}

const DB_CORRUPT_MSG: &str = "Could not deserialize item from database. DB is possibly corrupt, could be due to an update or a lack of migrations. Restore to a previous version, export your data and import your data again.";

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("base_domain", &self.base_domain)
            .finish()
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::*;
    use crate::{test_utils::setup_test_env, urls, Resource, Storelike, Value};

    #[tokio::test]
    async fn resolves_root_to_drive_subject() {
        let store = Db::init_temp("resolver_root").await.unwrap();
        setup_test_env(&store).await.unwrap();

        let resolved = store
            .resolve_request_target(
                &Subject::from_raw("/", None),
                "localhost",
                "/",
                "http://localhost",
            )
            .await
            .unwrap();

        assert_eq!(
            resolved.alias_subject,
            Some("http://localhost/".to_string())
        );
        assert!(matches!(resolved.subject, Subject::Did { .. }));
    }

    #[tokio::test]
    async fn resolves_drive_relative_paths_to_canonical_did() {
        let store = Db::init_temp("resolver_path").await.unwrap();
        setup_test_env(&store).await.unwrap();

        let drive_did = store.get_drive_did("localhost").await.unwrap().unwrap();
        let mut resource = Resource::new("did:ad:test-child".into());
        resource
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive_did.clone()))
            .unwrap();
        resource
            .set_unsafe(urls::SHORTNAME.into(), Value::Slug("about".into()))
            .unwrap();
        resource
            .set_unsafe(urls::NAME.into(), Value::String("About".into()))
            .unwrap();
        store
            .add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();

        let resolved = store
            .resolve_request_target(
                &Subject::from_raw("/about", None),
                "localhost",
                "/about",
                "http://localhost",
            )
            .await
            .unwrap();

        assert_eq!(
            resolved.alias_subject,
            Some("http://localhost/about".to_string())
        );
        assert_eq!(
            resolved.subject.as_str(),
            "did:ad:test-child?drive=".to_string() + drive_did.as_str()
        );
    }
}

#[cfg(test)]
mod pending_blob_request_ttl_tests {
    use super::*;

    /// F4 follow-up: a `BLOB_REQUEST` the server issued but the peer never
    /// answers must not sit in `pending_blob_requests` forever — that's an
    /// unbounded leak, one entry per missing blob a peer never delivers.
    /// `note_pending_blob_request` lazily prunes anything older than
    /// `PENDING_BLOB_REQUEST_TTL` on every insert; this reaches the private
    /// map directly to backdate an entry past the TTL without an actual
    /// 300s sleep, then drives the prune through the public API.
    #[tokio::test]
    async fn stale_entry_is_pruned_on_next_insert() {
        let db = Db::init_temp("pending_blob_ttl_prune").await.unwrap();

        let stale_hash = [1u8; 32];
        let backdated = std::time::Instant::now()
            .checked_sub(PENDING_BLOB_REQUEST_TTL + std::time::Duration::from_secs(1))
            .expect("test host must have been up longer than the TTL");
        db.pending_blob_requests.write().unwrap().insert(
            stale_hash,
            ("https://example.com/old-drive".into(), backdated),
        );

        // Insert a second, fresh entry — this is what triggers the prune.
        let fresh_hash = [2u8; 32];
        db.note_pending_blob_request(fresh_hash, "https://example.com/new-drive".into());

        assert!(
            db.take_pending_blob_request(&stale_hash).is_none(),
            "an entry older than the TTL must be pruned, not returned"
        );
        assert_eq!(
            db.take_pending_blob_request(&fresh_hash),
            Some("https://example.com/new-drive".to_string()),
            "a fresh entry inserted in the same call must survive its own prune"
        );
    }

    /// Sanity check for the inverse: a request answered promptly (the
    /// normal case) is unaffected by the TTL machinery.
    #[tokio::test]
    async fn fresh_entry_survives_take() {
        let db = Db::init_temp("pending_blob_ttl_fresh").await.unwrap();

        let hash = [3u8; 32];
        db.note_pending_blob_request(hash, "https://example.com/drive".into());

        assert_eq!(
            db.take_pending_blob_request(&hash),
            Some("https://example.com/drive".to_string())
        );
    }
}

#[cfg(test)]
mod private_drive_tests {
    use super::*;
    use crate::Storelike;

    #[tokio::test]
    async fn setup_uses_the_derived_private_drive_did() {
        let store = Db::init_temp("private_drive_setup").await.unwrap();
        let (_agent, drive) = store.setup("Alice").await.unwrap();
        let expected = store.private_drive_subject().unwrap();
        assert_eq!(drive, expected);
        assert_eq!(store.ensure_private_drive().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn extra_drive_is_listed_on_the_private_drive() {
        let store = Db::init_temp("private_drive_list").await.unwrap();
        let (_agent, personal) = store.setup("Alice").await.unwrap();
        let extra = store.create_drive("Project").await.unwrap();
        assert_ne!(extra, personal);

        let listed = store
            .get_resource(&personal.as_str().into())
            .await
            .unwrap()
            .get(urls::DRIVES)
            .unwrap()
            .to_subjects(None)
            .unwrap();
        assert!(
            listed.iter().any(|s| s == &extra),
            "private drive should list {extra}, got {listed:?}"
        );
    }
}
