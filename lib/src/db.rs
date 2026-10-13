//! Persistent, ACID compliant, threadsafe to-disk store.
//! Powered by redb (sled only to migrate old stores).

mod ai_chat_migration;
#[cfg(test)]
mod ai_chat_migration_test;
pub mod app_agent;
pub mod blob_backend;
mod canonical_scheme;
mod chat_migration;
#[cfg(test)]
mod chat_migration_test;
#[cfg(all(feature = "db", not(target_arch = "wasm32")))]
pub mod compaction;
mod compressed_kv;
mod encoding;
pub mod encrypted_backend;
mod index_keys;
pub mod kv_store;
#[cfg(feature = "db-sled")]
mod migrations;
#[cfg(all(feature = "db", target_arch = "wasm32"))]
pub mod opfs_backend;
pub mod plugin_meta;
pub mod plugin_release;
pub mod plugin_schedule;
pub mod plugin_secret;
pub mod plugin_trigger;
pub(crate) mod prop_val_sub_index;
mod query_index;
pub mod redb_store;
pub mod website;
/// The set of drives [`Db::migrate_messages_step`] may write chat log pages
/// for, from the drives' subjects in any spelling.
pub fn chat_migration_drive_set(drives: Vec<String>) -> std::collections::HashSet<String> {
    drives.iter().map(|d| chat_migration::id_body(d)).collect()
}
// `PropVal` is half of `QueryFilter`'s public surface: without it a caller
// outside this crate can read `filters` but cannot build one.
pub use query_index::{drive_prefix_from_subject, query_id, PropVal, QueryFilter};
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
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
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
        app_agent::{AppAgent, AppAgentInfo, AppAgentKey, AppAgentState},
        encoding::{decode_propvals, encode_propvals},
        plugin_meta::{PluginMeta, PluginMetaKey},
        plugin_schedule::{PluginSchedule, PluginScheduleKey},
        plugin_secret::{PluginSecret, PluginSecretInfo, PluginSecretKey},
        plugin_trigger::{PluginTrigger, PluginTriggerKey},
        query_index::requires_query_index,
        val_prop_sub_index::find_in_val_prop_sub_index,
    },
    endpoints::{Endpoint, HandleGetContext},
    errors::{AtomicError, AtomicErrorType, AtomicResult},
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

/// A subject `Db::recursive_remove` queued for deletion, kept until its
/// transaction has been applied so the caller can tombstone and announce it.
#[derive(Debug, Clone)]
struct RemovedSubject {
    /// The subject without query params, as [`DbEvent::Destroyed`] names it.
    subject: Subject,
    /// See [`DbEvent::Destroyed::drive`]: read before the resource was gone.
    drive: Option<Subject>,
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

/// One resource's share of a drive's storage, for the "where does space go"
/// view. `blob_bytes` is attributed to the first resource that references a
/// blob, so shared bytes are counted once, as in [`DriveUsage`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResourceUsage {
    pub subject: String,
    pub name: Option<String>,
    pub parent: Option<String>,
    pub is_a: Option<String>,
    pub loro_bytes: u64,
    pub blob_bytes: u64,
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

/// What [`Db::sync_drive_mappings`] changed in the host → Drive mapping table.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DriveMappingSync {
    /// Hosts that had no mapping before.
    pub added: Vec<String>,
    /// Hosts that pointed at a different Drive before.
    pub updated: Vec<String>,
    /// Hosts an earlier reconcile installed and that the desired set no longer
    /// names.
    pub removed: Vec<String>,
}

impl DriveMappingSync {
    /// Whether anything actually changed, so a caller polling on a timer can
    /// log real edits instead of one line per poll.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.updated.is_empty() && self.removed.is_empty()
    }
}

/// `Tree::PluginMeta` key holding the hosts whose Drive mapping was installed
/// by [`Db::sync_drive_mappings`].
///
/// Removal is scoped to this set rather than to everything in
/// `Tree::DriveMapping`, because that table also holds bindings made by hand
/// through `/bind-drive` plus the `localhost` / `127.0.0.1` entries every store
/// gets at setup. A reconcile that treated its input as authoritative for the
/// whole table would delete those the first time it ran.
const MANAGED_ALIAS_HOSTS_KEY: &[u8] = b"managed_drive_alias_hosts";

/// Normalizes a host into a `Tree::DriveMapping` key.
///
/// Hostnames are case-insensitive (RFC 4343), but the `Host` header comes back
/// in whatever case the client sent, and `/bind-drive` derives its key from a
/// parsed URL (which the `url` crate has already lowercased). Storing and
/// looking up lowercased is what makes `ACME.example.com` resolve the Drive
/// that `acme.example.com` was bound to, instead of silently missing the
/// mapping and falling through to the store root.
fn drive_mapping_key(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

const REPLICATION_PREFIX: &str = "replication:";

/// `Tree::PluginMeta` key holding the fingerprint of the built-in defaults
/// last seeded into this store. See `populate::bootstrap`.
const DEFAULTS_FINGERPRINT_KEY: &[u8] = b"defaults_fingerprint";

fn replication_key(drive: &str) -> String {
    format!("{REPLICATION_PREFIX}{drive}")
}

/// Upper bound on the `PropValSub` entries the planner counts per constraint
/// when ranking them, and on what the first-build cross-check will walk.
const PLANNER_SCAN_CAP: usize = 512;

/// What [`Db::check_query_index`] found when it compared a query's member
/// index with a scan of the store.
#[derive(Debug, Clone)]
pub struct QueryIndexReport {
    /// The filter whose index was checked.
    pub filter: query_index::QueryFilter,
    /// Whether the filter is watched (its index is maintained on commit).
    pub watched: bool,
    /// Members the index holds.
    pub indexed: usize,
    /// Resources in the store that match the filter.
    pub expected: usize,
    /// Matching subjects the index does not list.
    pub missing: Vec<String>,
    /// Indexed subjects that no longer match (or no longer exist).
    pub stale: Vec<String>,
}

impl QueryIndexReport {
    pub fn is_consistent(&self) -> bool {
        self.missing.is_empty() && self.stale.is_empty()
    }
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

/// Crash data-loss bound for file-backed stores: one fsync per interval,
/// amortised across every commit in the window. See `Db::spawn_durable_flush`.
#[cfg(not(target_arch = "wasm32"))]
pub const DURABLE_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

type PendingBlobRequests = HashMap<[u8; 32], (String, web_time::Instant)>;

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
    /// Optional remote file storage. Configure before sharing this Db.
    pub blob_backend: Option<Arc<dyn blob_backend::BlobBackend>>,
    default_agent: Arc<Mutex<Option<crate::agents::Agent>>>,
    /// The key this node wraps stored secrets with, set once at startup.
    ///
    /// Held here rather than passed to each call so it cannot be forgotten at
    /// one of them: a secret written in the clear because a caller did not
    /// know about encryption is indistinguishable, on disk, from one nobody
    /// meant to protect.
    node_key: Arc<std::sync::OnceLock<[u8; crate::vault::keys::KEK_LEN]>>,
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
    /// The drive root each watched filter's `drive` resolves to, keyed by the
    /// filter's `drive` string. For a `did:` query, `QueryFilter::drive` is
    /// the queried subject (a table, a folder), not the drive it lives in;
    /// its stored `drive` stamp names the root. Resolved when a filter is
    /// registered and looked up per DID atom on the commit path, so that a
    /// DID resource stamped into another drive never enters this drive's
    /// members (security audit C17). `None` records that the subject could
    /// not be resolved here, in which case the filter is not drive-checked.
    filter_drive_roots: Arc<RwLock<HashMap<String, Option<Subject>>>>,
    /// Serialises writers that read-modify-write the same subject's state, so
    /// a commit and a sync apply cannot replace each other's snapshot. Per
    /// store, not global — see [`crate::subject_lock`].
    pub(crate) subject_locks: crate::subject_lock::SubjectLocks,
    plugin_locks: crate::subject_lock::SubjectLocks,
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
    pending_blob_requests: Arc<RwLock<PendingBlobRequests>>,
    /// How often the full-decode vs propvals-only fetch paths ran. Shared
    /// across clones; used by tests to pin query-path cost to call counts
    /// rather than wall clock (snapshots in a fresh store are too small
    /// to show the difference). See `planning/slow-collection-queries.md`.
    fetch_counters: Arc<FetchCounters>,
    /// Lenses by the properties they touch (see [`crate::lens`]). Rebuilt from
    /// the stored Lens resources when the Db opens, swapped for a new index
    /// when a Lens commit applies. Readers clone the inner `Arc`.
    lenses: Arc<RwLock<Arc<crate::lens::LensIndex>>>,
    /// Lens subjects that are stored but not active yet, because the property
    /// they write is not in this store (it may sync later).
    pending_lenses: Arc<RwLock<Vec<String>>>,
    /// External subjects the remote answered 404/410 for this session. A
    /// definitive "not found" is asked once: without this, every parse or
    /// serialize that meets an unknown property fetched it again. Maps the
    /// subject to when the entry expires, so a resource published later is
    /// found again after `REMOTE_NOT_FOUND_TTL`.
    remote_not_found: Arc<Mutex<HashMap<String, web_time::Instant>>>,
}

#[derive(Default)]
struct FetchCounters {
    get_resource: AtomicUsize,
    get_resource_shallow: AtomicUsize,
}

fn default_fetch_counters() -> Arc<FetchCounters> {
    Arc::new(FetchCounters::default())
}

/// How long an unanswered `BLOB_REQUEST` stays in `pending_blob_requests`
/// before lazy pruning drops it. Generous relative to a realistic peer
/// round trip (seconds) — this bounds a slow leak from peers that vanish
/// mid-sync, not a normal-latency budget.
const PENDING_BLOB_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a remote 404/410 is remembered before the subject is asked for again.
const REMOTE_NOT_FOUND_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The default (permissive) sync policy reference used by every `Db` until a
/// managed node installs one.
fn default_sync_policy() -> Arc<RwLock<Arc<dyn crate::sync::policy::SyncPolicy>>> {
    Arc::new(RwLock::new(Arc::new(crate::sync::policy::OpenPolicy)))
}

impl Db {
    fn is_remote_not_found(&self, subject: &str) -> bool {
        let Ok(mut map) = self.remote_not_found.lock() else {
            return false;
        };
        match map.get(subject) {
            Some(expires) if web_time::Instant::now() < *expires => true,
            Some(_) => {
                map.remove(subject);
                false
            }
            None => false,
        }
    }

    fn remember_remote_not_found(&self, subject: &str) {
        if let Ok(mut map) = self.remote_not_found.lock() {
            map.insert(
                subject.to_string(),
                web_time::Instant::now() + REMOTE_NOT_FOUND_TTL,
            );
        }
    }

    /// A `Db` over `kv` with every other field at its default. Not usable
    /// until [`Db::open`] has run.
    fn from_kv(path: std::path::PathBuf, kv: Arc<dyn KvStore>, base_domain: Option<String>) -> Db {
        Db {
            path,
            blob_backend: None,
            kv: Arc::new(compressed_kv::CompressedKv::new(kv)),
            default_agent: Arc::new(Mutex::new(None)),
            node_key: Arc::new(std::sync::OnceLock::new()),
            endpoints: vec![],
            class_extenders: Arc::new(RwLock::new(vec![])),
            on_commit: None,
            db_events: tokio::sync::broadcast::channel(64).0,
            ephemeral_events: tokio::sync::broadcast::channel(32).0,
            watched_queries_by_drive: Arc::new(RwLock::new(HashMap::new())),
            filter_drive_roots: Arc::new(RwLock::new(HashMap::new())),
            subject_locks: Default::default(),
            plugin_locks: Default::default(),
            base_domain,
            sync_policy: default_sync_policy(),
            envelope_retention: Arc::new(RwLock::new(Default::default())),
            pending_blob_requests: Arc::new(RwLock::new(HashMap::new())),
            fetch_counters: default_fetch_counters(),
            lenses: Default::default(),
            pending_lenses: Default::default(),
            remote_not_found: Default::default(),
        }
    }

    /// The steps every backend runs once its KV is ready.
    async fn open(self) -> AtomicResult<Db> {
        self.add_class_extender(crate::collections::get_collection_class_extender())?;

        // Load persisted watched-queries (if any) into the in-memory map
        // before bootstrap, so any filter-matching commits during bootstrap
        // see the right state.
        self.migrate_canonical_scheme_if_needed()?;
        // The browser runs this in slices it can show progress for
        // (`ClientDb.migrateIndexKeysStep`); everywhere else it is done here.
        #[cfg(not(target_arch = "wasm32"))]
        self.migrate_index_keys()?;
        #[cfg(target_arch = "wasm32")]
        if self.kv.iter_tree(Tree::Resources).next().is_none() {
            self.migrate_index_keys_step(1)?;
        }
        self.populate_watched_queries_cache()?;

        // Runs on every open, but only writes when the embedded defaults
        // (`lib/defaults/*.json` + base models) changed since this store was
        // last seeded: `bootstrap` compares a fingerprint of them against the
        // one stored in `Tree::PluginMeta` and adds what is missing.
        crate::populate::bootstrap(&self)
            .await
            .map_err(|e| format!("Failed to populate base models. {}", e))?;
        // Old chat messages become entries in chat log pages. The browser runs
        // this in slices it can show progress for
        // (`ClientDb.migrateMessagesStep`); everywhere else it is done here,
        // after the watched queries are loaded so the new pages are indexed.
        #[cfg(not(target_arch = "wasm32"))]
        self.migrate_messages().await?;
        #[cfg(not(target_arch = "wasm32"))]
        self.migrate_ai_chats().await?;
        crate::search::maybe_rebuild_search_index(&self)?;
        self.load_lenses().await;
        Ok(self)
    }

    /// The active lenses. Cheap: clones an `Arc`.
    pub fn lenses(&self) -> Arc<crate::lens::LensIndex> {
        self.lenses
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn update_lenses(&self, change: impl FnOnce(&mut crate::lens::LensIndex)) {
        if let Ok(mut guard) = self.lenses.write() {
            let mut next = (**guard).clone();
            change(&mut next);
            *guard = Arc::new(next);
        }
    }

    /// Rebuild the lens index from the stored Lens resources.
    async fn load_lenses(&self) {
        let class = Value::AtomicUrl(urls::LENS.into());
        let subjects: Vec<Subject> = find_in_prop_val_sub_index(self, urls::IS_A, Some(&class))
            .flatten()
            .map(|atom| atom.subject)
            .collect();
        for subject in subjects {
            if let Ok(lens) = Storelike::get_resource(self, &subject).await {
                self.register_lens(&lens).await;
            }
        }
    }

    /// Make a stored Lens active. Returns the entry when it is. A lens whose
    /// target property is not in the store yet is remembered and retried when
    /// a Property is created ([`Self::retry_pending_lenses`]). Never fails a
    /// commit: an inactive lens is just not applied.
    pub async fn register_lens(&self, lens: &Resource) -> Option<crate::lens::LensEntry> {
        let subject = crate::identifiers::canonicalize_scheme(&lens.get_subject().pure_id());
        match crate::lens::build_entry(self, lens).await {
            Ok(entry) => {
                if let Ok(mut pending) = self.pending_lenses.write() {
                    pending.retain(|p| p != &subject);
                }
                self.update_lenses(|index| index.insert(entry.clone()));
                Some(entry)
            }
            Err(e) => {
                tracing::debug!(lens = %subject, error = %e, "Lens is not active");
                if let Ok(mut pending) = self.pending_lenses.write() {
                    if !pending.contains(&subject) {
                        pending.push(subject);
                    }
                }
                None
            }
        }
    }

    /// Call after a resource landed in the store. A Lens becomes active (and
    /// its resources are backfilled); a new Property may let a waiting Lens
    /// become active.
    pub(crate) async fn note_lens_related(&self, resource: &Resource) {
        let subject = resource.get_subject().pure_id();
        if crate::identifiers::is_lens_id(&subject) {
            if let Some(entry) = self.register_lens(resource).await {
                self.backfill_lens(&entry).await;
            }
        } else if crate::identifiers::is_prop_id(&subject)
            && self
                .pending_lenses
                .read()
                .map(|p| !p.is_empty())
                .unwrap_or(false)
        {
            self.retry_pending_lenses().await;
        }
    }

    /// Stop applying a lens (it was destroyed).
    pub fn unregister_lens(&self, subject: &str) {
        let subject = crate::identifiers::canonicalize_scheme(subject);
        if let Ok(mut pending) = self.pending_lenses.write() {
            pending.retain(|p| p != &subject);
        }
        self.update_lenses(|index| index.remove(&subject));
    }

    /// Try the lenses that were waiting for a property, now that one arrived.
    async fn retry_pending_lenses(&self) {
        let pending: Vec<String> = self
            .pending_lenses
            .read()
            .map(|p| p.clone())
            .unwrap_or_default();
        for subject in pending {
            let Ok(lens) = Storelike::get_resource(self, &subject.as_str().into()).await else {
                continue;
            };
            if let Some(entry) = self.register_lens(&lens).await {
                self.backfill_lens(&entry).await;
            }
        }
    }

    /// Re-materialize the stored resources that hold a property of this lens,
    /// so the value index and search see the derived values. Reads already
    /// apply lenses; this only brings the stored projection and the indexes
    /// in line. Derived values are not commits: nothing is broadcast.
    pub async fn backfill_lens(&self, entry: &crate::lens::LensEntry) {
        let mut subjects: Vec<Subject> = Vec::new();
        let mut seen = HashSet::new();
        for prop in [&entry.from, &entry.to] {
            for atom in find_in_prop_val_sub_index(self, prop, None).flatten() {
                if seen.insert(atom.subject.to_string()) {
                    subjects.push(atom.subject);
                }
            }
        }
        for subject in subjects {
            let _guard = self.subject_locks.lock(&subject.pure_id()).await;
            let Ok(resource) = Storelike::get_resource(self, &subject).await else {
                continue;
            };
            let snapshot = self.get_loro_snapshot_bytes(&subject.pure_id());
            let mut transaction = Transaction::new();
            let built = self
                .build_projection_tx(&resource, false, true, true, snapshot, &mut transaction)
                .await;
            match built.and_then(|()| self.apply_transaction(&mut transaction)) {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(%subject, error = %e, "Could not backfill lens");
                }
            }
        }
    }

    /// Persist already-admitted replica state, including independently created
    /// duplicate import identities. Keep both subjects available for review;
    /// authoring paths must still enforce identity uniqueness.
    pub async fn persist_replicated_resource(&self, resource: &Resource) -> AtomicResult<()> {
        self.persist_replicated(resource, None).await
    }

    /// [`Self::persist_replicated_resource`] with the CRDT snapshot the caller
    /// already holds. The row, its snapshot and its index entries land in one
    /// transaction, and the stored snapshot keeps the caller's history instead
    /// of a doc re-seeded from the propvals (which would carry a fresh peer id
    /// and merge badly with the real one).
    pub async fn persist_replicated_resource_with_snapshot(
        &self,
        resource: &Resource,
        snapshot: Vec<u8>,
    ) -> AtomicResult<()> {
        self.persist_replicated(resource, Some(snapshot)).await
    }

    /// [`Self::persist_replicated_resource_with_snapshot`] for many resources in
    /// one write. Each resource costs the same index entries as on its own, but
    /// they share one commit, so a page the batch touches repeatedly (a
    /// parent's member list, the name index) is written once instead of once
    /// per resource. A large first sync is bound by that cost.
    ///
    /// A resource named twice keeps its last entry. One with an import
    /// identity goes through the single-resource path, which serialises on the
    /// identity lock and flushes.
    pub async fn persist_replicated_resources(
        &self,
        entries: Vec<(Resource, Option<Vec<u8>>)>,
    ) -> AtomicResult<()> {
        self.persist_replicated_resources_opts(entries, false).await
    }

    /// [`Self::persist_replicated_resources`] for a bulk pull: with
    /// `defer_search` the full-text entries (most of the index writes) are left
    /// out and each resource is filed for [`crate::search::index_pending`].
    pub async fn persist_replicated_resources_opts(
        &self,
        entries: Vec<(Resource, Option<Vec<u8>>)>,
        defer_search: bool,
    ) -> AtomicResult<()> {
        let mut last: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, (resource, _)) in entries.iter().enumerate() {
            last.insert(self.normalize_subject(resource.get_subject()).pure_id(), i);
        }
        let mut transaction = Transaction::new();
        let mut batched: Vec<&Resource> = Vec::new();
        for (i, (resource, snapshot)) in entries.iter().enumerate() {
            let key = self.normalize_subject(resource.get_subject()).pure_id();
            if last.get(&key) != Some(&i) {
                continue;
            }
            if crate::import_identity::identity(resource).is_some() {
                self.persist_replicated(resource, snapshot.clone()).await?;
                continue;
            }
            let before = transaction.len();
            self.build_projection_tx(
                resource,
                false,
                true,
                true,
                snapshot.clone(),
                &mut transaction,
            )
            .await?;
            if defer_search {
                let mut added = transaction.split_off(before);
                added.retain(|op| !crate::search::is_search_op(op));
                transaction.extend(added);
                transaction.push(crate::search::pending_marker(&key));
            }
            batched.push(resource);
        }
        if batched.is_empty() {
            return Ok(());
        }
        self.apply_transaction(&mut transaction)?;
        for resource in batched {
            self.note_lens_related(resource).await;
            let _ = self.db_events.send(DbEvent::Changed {
                subject: resource.get_subject().without_params(),
                delta: None,
                source_id: crate::sync::ws_apply::current_import_source(),
                is_new: false,
                from_commit: false,
            });
        }
        Ok(())
    }

    async fn persist_replicated(
        &self,
        resource: &Resource,
        snapshot: Option<Vec<u8>>,
    ) -> AtomicResult<()> {
        // Review validation holds this same identity lock while reading all
        // copies. Replica changes must not land halfway through that review.
        let _identity_guard = if let Some((parent, id)) = crate::import_identity::identity(resource)
        {
            Some(
                self.subject_locks
                    .lock(&format!(
                        "import-identity:{}",
                        serde_json::to_string(&(parent.pure_id(), &id))?
                    ))
                    .await,
            )
        } else {
            None
        };
        self.persist_resource_projection(resource, false, true, true, snapshot)
            .await
    }

    async fn persist_resource_projection(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
        snapshot: Option<Vec<u8>>,
    ) -> AtomicResult<()> {
        let mut transaction = Transaction::new();
        self.build_projection_tx(
            resource,
            check_required_props,
            update_index,
            overwrite_existing,
            snapshot,
            &mut transaction,
        )
        .await?;
        self.apply_transaction(&mut transaction)?;
        if crate::import_identity::identity(resource).is_some() {
            self.flush()?;
        }
        self.note_lens_related(resource).await;
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

    /// Everything [`Self::persist_resource_projection`] writes for one
    /// resource, appended to `transaction` instead of applied: the index
    /// entries, the Loro snapshot and the row.
    async fn build_projection_tx(
        &self,
        resource: &Resource,
        check_required_props: bool,
        update_index: bool,
        overwrite_existing: bool,
        snapshot: Option<Vec<u8>>,
        transaction: &mut Transaction,
    ) -> AtomicResult<()> {
        // This only works if no external functions rely on using add_resource for atom-like operations!
        // However, add_atom uses set_propvals, which skips the validation.
        let subject = self.normalize_subject(resource.get_subject());
        let subject_str = subject.pure_id();
        // Lenses derive values the doc does not hold; the stored row and the
        // indexes carry them like real ones. Only a resource that holds a lens
        // property is copied.
        let lenses = self.lenses();
        let derived_resource;
        let resource = if !lenses.is_empty()
            && resource
                .get_propvals()
                .keys()
                .any(|prop| lenses.touches(prop))
        {
            let mut copy = resource.clone();
            copy.apply_lenses(&lenses);
            derived_resource = copy;
            &derived_resource
        } else {
            resource
        };
        let existing = self
            .get_propvals_canonical(&subject_str)
            .ok()
            .map(|(_, pv)| pv);
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
        if update_index {
            // Every atom is removed and filed again, not only the changed
            // ones. Identical re-puts from a tab are already skipped before
            // they reach here (`Store.persistState`).
            //
            // Evict against the state that is going away, not the one
            // replacing it. Whether an entry belongs in a watched query's
            // member list, and under which sort key it was filed, are facts
            // about the old values: asking the new resource instead makes a
            // row edited out of a filtered view skip the one delete it needs.
            if let Some(pv) = existing {
                let old = Resource::from_propvals(pv, resource.get_subject().clone());
                for atom in old.to_atoms() {
                    self.remove_atom_from_index(&atom, &old, transaction)
                        .map_err(|e| format!("Failed to remove atom from index {}. {}", atom, e))?;
                }
            }
            for atom in resource.to_atoms() {
                self.add_atom_to_index(&atom, resource, transaction)
                    .map_err(|e| format!("Failed to add atom to index {}. {}", atom, e))?;
            }
            crate::search::index_resource(self, resource, transaction)?;
        }
        // The snapshot in `Tree::LoroSnapshots` is the authoritative CRDT
        // state. Store it for every CRDT resource in the same transaction as
        // the `Tree::Resources` row, so every row is paired with a current
        // snapshot. Commits are native (immutable, not CRDT): they get no
        // snapshot and keep their `loroUpdate` payload in the row.
        if !subject.is_commit_did() {
            let snapshot = match snapshot {
                Some(snapshot) => snapshot,
                None => resource.build_state_doc()?.export_snapshot(),
            };
            transaction.push(Operation {
                tree: Tree::LoroSnapshots,
                method: Method::Insert,
                key: subject_str.as_bytes().to_vec(),
                val: Some(snapshot),
            });
        }
        // The row (a projection without `loroUpdate`), its DID routing hint
        // and the removal of other identifier spellings: the same write a
        // commit makes.
        self.add_resource_tx(resource, transaction)?;
        Ok(())
    }

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
            let now = web_time::Instant::now();
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
            .map_err(|e| format!("Error during migration of database: {:?}", e))?;

        Db::from_kv(path.into(), Arc::new(sled_store), base_domain)
            .open()
            .await
    }

    /// Creates a Db backed by redb with an in-memory backend.
    /// Useful for WASM targets where redb provides proper B-tree indexing.
    /// Can be upgraded to OPFS persistence in the future.
    pub async fn init_redb(base_domain: Option<String>) -> AtomicResult<Db> {
        let redb_store = redb_store::RedbStore::new_memory()?;
        Db::from_kv(std::path::PathBuf::new(), Arc::new(redb_store), base_domain)
            .open()
            .await
    }

    /// Creates a Db backed by redb with file-based persistent storage.
    /// Works on all native targets (not WASM — use init_redb_opfs for that).
    ///
    /// Runs the default [`compaction::CompactionPolicy`] on the file before
    /// serving it; `init_redb_file_with_policy` takes another.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub async fn init_redb_file(
        path: &std::path::Path,
        base_domain: Option<String>,
        uploads_path: &std::path::Path,
    ) -> AtomicResult<Db> {
        Self::init_redb_file_with_policy(
            path,
            base_domain,
            uploads_path,
            &compaction::CompactionPolicy::default(),
        )
        .await
    }

    /// `init_redb_file` with an explicit startup compaction policy. The
    /// file's size and open duration are logged either way; with the policy
    /// enabled the reclaimable space is measured and, past both thresholds,
    /// compacted before any table is read. A compaction failure (including
    /// redb refusing because of a live transaction) is logged and the store
    /// opens as it was; it never fails startup.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub async fn init_redb_file_with_policy(
        path: &std::path::Path,
        base_domain: Option<String>,
        uploads_path: &std::path::Path,
        policy: &compaction::CompactionPolicy,
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

        let (redb_store, compaction) =
            redb_store::RedbStore::new_file_with_policy(&redb_path, policy)?;

        let store = Db::from_kv(path.to_path_buf(), Arc::new(redb_store), base_domain);

        // Bookkeeping only: the compaction itself already happened, and
        // failing to note it must not refuse the start.
        if let Ok(record) = compaction {
            if let Err(e) = store.record_compaction(&record) {
                tracing::warn!("Could not record the startup compaction: {e}");
            }
        }

        let store = store.open().await?;
        store.spawn_durable_flush(DURABLE_FLUSH_INTERVAL);
        Ok(store)
    }

    /// Persist the outcome of a startup compaction so `last_compaction`
    /// can report it after the log line is gone. Durable at once: the
    /// compaction it describes already cost seconds, a 100 ms flush
    /// window is nothing next to it.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    fn record_compaction(&self, record: &compaction::CompactionRecord) -> AtomicResult<()> {
        let bytes = serde_json::to_vec(record)
            .map_err(|e| format!("Could not serialize the compaction record: {e}"))?;
        self.kv
            .insert(trees::Tree::PluginMeta, compaction::RECORD_KEY, &bytes)?;
        self.kv.flush()
    }

    /// The most recent automatic startup compaction of this store's file,
    /// if one ever ran. `None` on a store that was never compacted at
    /// startup, and on the in-memory, OPFS and sled backends.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
    pub fn last_compaction(&self) -> Option<compaction::CompactionRecord> {
        let bytes = self
            .kv
            .get(trees::Tree::PluginMeta, compaction::RECORD_KEY)
            .ok()
            .flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Make `Durability::None` commits durable on a fixed cadence.
    ///
    /// Every redb write skips the fsync for throughput and only becomes
    /// durable at the next `flush`. This thread is that flush. It belongs to
    /// the library, not the host, so that no binding can open a file store
    /// and forget it: the Flutter app did exactly that and lost every edit
    /// since the last drive switch on an app kill. The tick is cheap when
    /// idle (`RedbStore::flush` returns early unless something was written)
    /// and blocks on fsync when not, hence a dedicated OS thread rather than
    /// a tokio task. It holds only a `Weak` to the store and exits once the
    /// last `Db` clone is dropped.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn spawn_durable_flush(&self, interval: std::time::Duration) {
        let kv: std::sync::Weak<dyn KvStore> = Arc::downgrade(&self.kv);
        std::thread::Builder::new()
            .name("durable-flush".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                let Some(kv) = kv.upgrade() else { break };
                if let Err(e) = kv.flush() {
                    tracing::warn!("periodic durable flush failed: {e}");
                }
            })
            .expect("spawn durable-flush thread");
    }

    #[cfg(all(feature = "db", feature = "db-sled", not(target_arch = "wasm32")))]
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
                                    crate::identifiers::blob_subject(&hash_hex).into(),
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
            for item in sled_store.iter_tree(tree) {
                let (key, val) = item?;
                redb_store.insert(tree, &key, &val)?;
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
    #[cfg(all(feature = "db", target_arch = "wasm32"))]
    pub async fn init_redb_opfs(
        base_domain: Option<String>,
        filename: &str,
        encryption_key: Option<&[u8; 32]>,
    ) -> AtomicResult<Db> {
        let redb_store = redb_store::RedbStore::new_opfs(filename, encryption_key).await?;
        Db::from_kv(std::path::PathBuf::new(), Arc::new(redb_store), base_domain)
            .open()
            .await
    }

    /// Creates a clone of the store with a different base_domain.
    /// This is useful for multi-tenant applications.
    /// Cloning is very cheap, as it only clones Arc pointers.
    pub fn clone_with_url(&self, base_domain: String) -> Db {
        let mut clone = self.clone();
        clone.base_domain = Some(base_domain);
        clone
    }

    /// Create a temporary Db backed by ReDB. Useful for testing.
    #[cfg(all(feature = "db", not(target_arch = "wasm32")))]
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

        // Keep legacy Agent.drives entries, then include the private home where
        // create_drive records new drives. Read both during the migration.
        let mut subjects = match agent_resource.get(urls::DRIVES) {
            Ok(Value::ResourceArray(arr)) => arr.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            _ => vec![],
        };
        if let Ok(personal) = self.private_drive_subject() {
            if let Ok(home) = self.get_resource(&personal.as_str().into()).await {
                if !subjects.contains(&personal) {
                    subjects.push(personal);
                }
                if let Ok(Value::ResourceArray(listed)) = home.get(urls::DRIVES) {
                    for subject in listed {
                        let subject = subject.to_string();
                        if !subjects.contains(&subject) {
                            subjects.push(subject);
                        }
                    }
                }
            }
        }
        if let Some(active) = self.get_active_drive() {
            if !subjects.contains(&active) {
                subjects.push(active);
            }
        }

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
        let key = crate::identifiers::canonicalize_scheme(subject);
        self.kv
            .contains_key(Tree::Resources, key.as_bytes())
            .unwrap_or(false)
    }

    /// Rewrite `did:ad:` resource / snapshot / mapping keys to `atomic:` on
    /// open. Idempotent; see [`canonical_scheme::migrate_if_needed`].
    fn migrate_canonical_scheme_if_needed(&self) -> AtomicResult<()> {
        canonical_scheme::migrate_if_needed(self)
    }

    /// The stored Loro snapshot of `subject`, under whichever spelling the
    /// caller used: normalized to the `pure_id` key writers store it under.
    pub fn get_loro_snapshot(&self, subject: &Subject) -> Option<Vec<u8>> {
        self.get_loro_snapshot_bytes(&self.normalize_subject(subject).pure_id())
    }

    pub(crate) fn get_loro_snapshot_bytes(&self, subject: &str) -> Option<Vec<u8>> {
        let key = crate::identifiers::canonicalize_scheme(subject);
        self.kv
            .get(Tree::LoroSnapshots, key.as_bytes())
            .ok()
            .flatten()
    }

    fn get_did_mapping_hint(&self, subject: &str) -> Option<String> {
        let key = crate::identifiers::canonicalize_scheme(subject);
        let bin = self.kv.get(Tree::DidMapping, key.as_bytes()).ok()??;
        std::str::from_utf8(&bin).ok().map(str::to_string)
    }

    /// Per-drive storage usage (resource count, Loro snapshot bytes, blob
    /// bytes) for the given `drive_subjects` — the Sync page's usage display and
    /// a managed node's control-plane usage report. A managed node passes its
    /// allowlisted (hosted) drives — these belong to enrolled users, not the
    /// node's own agent.
    ///
    /// Cost is O(the drives' resources), not O(store): it resolves each drive's
    /// subjects and point-looks-up their propvals/snapshots. Blobs are
    /// content-addressed and counted once per drive. Each drive pays its own
    /// logical quota usage even when another owner's drive shares the same
    /// physical object. These counters must not be used as bucket-size totals.
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
        let mut seen_blobs: HashSet<(&str, [u8; 32])> = HashSet::new();
        // Share metadata lookups, not quota attribution, across drives.
        let mut blob_sizes: HashMap<[u8; 32], Option<u64>> = HashMap::new();

        for (subject, drive) in &subject_to_drive {
            let Some(row) = usage.get_mut(drive) else {
                continue;
            };

            if let Some(snapshot) = self.get_loro_snapshot_bytes(subject) {
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
            if !seen_blobs.insert((drive.as_str(), hash)) {
                continue;
            }
            let size = match blob_sizes.get(&hash) {
                Some(size) => *size,
                None => {
                    let size = self.blob_size(&hash).await?;
                    blob_sizes.insert(hash, size);
                    size
                }
            };
            if let Some(size) = size {
                row.blob_bytes += size;
            }
        }

        Ok(usage.into_values().collect())
    }

    /// Per-resource storage of one drive: Loro snapshot bytes (history) and the
    /// blob bytes of attached files. Same accounting as [`Db::per_drive_usage`],
    /// kept per resource so a client can draw a size map of the drive.
    pub async fn drive_usage_breakdown(
        &self,
        drive_subject: &str,
    ) -> AtomicResult<Vec<ResourceUsage>> {
        use std::collections::HashSet;

        let ds: crate::Subject = drive_subject.into();
        let mut subjects: Vec<String> = crate::sync::engine::collect_drive_subjects(self, &ds)
            .await
            .into_iter()
            .collect();
        subjects.sort();

        let mut seen_blobs: HashSet<[u8; 32]> = HashSet::new();
        let mut rows = Vec::new();

        for subject in subjects {
            let Ok(propvals) = self.get_propvals(&subject) else {
                continue;
            };
            let loro_bytes = self
                .get_loro_snapshot_bytes(&subject)
                .map(|s| s.len() as u64)
                .unwrap_or(0);

            let mut blob_bytes = 0;
            if let Some(blob_val) = propvals.get(urls::BLOB) {
                let blob_subject = crate::Subject::from_raw(&blob_val.to_string(), None);
                if let Some(hash_bytes) = blob_subject
                    .blob_hash_hex()
                    .and_then(|h| hex::decode(h).ok())
                    .filter(|b| b.len() == 32)
                {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&hash_bytes);
                    if seen_blobs.insert(hash) {
                        blob_bytes = self.blob_size(&hash).await?.unwrap_or(0);
                    }
                }
            }

            let text = |prop: &str| propvals.get(prop).map(|v| v.to_string());
            rows.push(ResourceUsage {
                name: text(urls::NAME).or_else(|| text(urls::FILENAME)),
                parent: text(urls::PARENT),
                is_a: text(urls::IS_A).and_then(|c| c.split(',').next().map(str::to_string)),
                subject,
                loro_bytes,
                blob_bytes,
            });
        }

        Ok(rows)
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
                if crate::identifiers::canonicalize_scheme(&p.to_string())
                    != crate::identifiers::canonicalize_scheme(parent)
                {
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

        // A host bound to a Drive serves that Drive or nothing. Falling through
        // to the store root here is what let a vanity host whose Drive has not
        // synced yet — or was migrated to another node — quietly serve the
        // node's *own* root Drive under a customer's hostname. On a
        // multi-tenant node that is one tenant's domain answering with another
        // namespace's content, so it is a 404 instead.
        if self.get_resource(&drive_did).await.is_err() {
            return Err(AtomicError::not_found(format!(
                "Host '{host}' is bound to drive {drive_did}, which this server does not have."
            )));
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
            || crate::identifiers::is_identifier_resolution_path(subject_string)
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
        let pubkey = subject.agent_public_key()?;

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

    /// Runs one extender's `after_commit` for a commit that is already
    /// persisted. The caller logs an error and moves on to the next extender;
    /// see the AFTER APPLY COMMIT HANDLERS block in `apply_commit`.
    async fn run_after_commit_extender(
        &self,
        extender: &ClassExtender,
        resource: &Resource,
        commit_response: &CommitResponse,
        root_subject: &mut Option<String>,
    ) -> AtomicResult<()> {
        let Some(handler) = extender.after_commit.as_ref() else {
            return Ok(());
        };
        if !extender.resource_has_extender(resource)? || !extender.can_extend(resource) {
            return Ok(());
        }

        let (is_in_scope, cached_root) = extender
            .check_scope(resource, self, root_subject.take())
            .await?;
        *root_subject = cached_root;
        if !is_in_scope {
            return Ok(());
        }

        (handler)(crate::class_extender::CommitExtenderContext {
            store: self,
            commit: &commit_response.commit,
            resource,
            is_new: commit_response.resource_old.is_none(),
            changed_props: &commit_response.changed_props,
        })
        .await
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

    /// Whether an extender of this id is registered right now.
    pub fn has_class_extender(&self, id: &str) -> bool {
        let Ok(extenders) = self.class_extenders.read() else {
            return false;
        };
        extenders.iter().any(|e| e.id.as_deref() == Some(id))
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

        let key = drive_mapping_key(host);
        self.kv
            .insert(Tree::DriveMapping, key.as_bytes(), did_str.as_bytes())?;
        tracing::info!("Added drive mapping: {} -> {}", key, did_str);
        Ok(())
    }

    /// Removes the drive mapping for a given host.
    pub fn remove_drive_mapping(&self, host: &str) -> AtomicResult<()> {
        let key = drive_mapping_key(host);
        self.kv.remove(Tree::DriveMapping, key.as_bytes())?;
        tracing::info!("Removed drive mapping for host: {}", key);
        Ok(())
    }

    /// Every host → Drive mapping in this store, sorted by host.
    pub fn list_drive_mappings(&self) -> AtomicResult<Vec<(String, String)>> {
        let mut out = Vec::new();

        for (key, value) in self.kv.scan_prefix(Tree::DriveMapping, b"").flatten() {
            let (Ok(host), Ok(did)) = (std::str::from_utf8(&key), std::str::from_utf8(&value))
            else {
                continue;
            };
            // `RedbStore::flush` parks its sentinel in this tree, so any open
            // that ran a flush (the index-key migration does) holds one.
            if host == "__flush_sentinel__" {
                continue;
            }
            out.push((host.to_string(), did.to_string()));
        }

        out.sort();
        Ok(out)
    }

    /// The hosts [`Self::sync_drive_mappings`] installed on its last run.
    pub fn managed_alias_hosts(&self) -> AtomicResult<Vec<String>> {
        let Some(bytes) = self.kv.get(Tree::PluginMeta, MANAGED_ALIAS_HOSTS_KEY)? else {
            return Ok(Vec::new());
        };

        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Corrupt managed alias host list: {e}").into())
    }

    /// Reconciles the host → Drive mappings this server installs on behalf of a
    /// control plane against `desired`, reporting what changed.
    ///
    /// Idempotent, so a managed node can call it on every policy poll: a host
    /// already pointing at the right Drive is left untouched. Hosts a previous
    /// run installed that `desired` no longer names are removed, which is what
    /// makes a released vanity name stop resolving without anyone touching the
    /// box. Ownership is tracked in [`MANAGED_ALIAS_HOSTS_KEY`], so a mapping
    /// made by hand through `/bind-drive` is never removed by a reconcile that
    /// does not name it.
    ///
    /// A host the control plane *does* name is taken over even if something
    /// else bound it first: the control plane owns the namespace it hands out,
    /// and a stale local binding shadowing an issued name is the failure this
    /// is meant to correct.
    pub fn sync_drive_mappings(
        &self,
        desired: &[(String, String)],
    ) -> AtomicResult<DriveMappingSync> {
        let mut report = DriveMappingSync::default();
        let mut managed: Vec<String> = Vec::with_capacity(desired.len());

        for (host, drive_did) in desired {
            let key = drive_mapping_key(host);
            // An empty host would claim the zero-length key and match no
            // request; an empty DID would point a live hostname at nothing.
            // Either is a bug upstream, and neither is worth writing.
            if key.is_empty() || drive_did.trim().is_empty() {
                tracing::warn!("Skipping drive mapping with an empty host or drive: {key:?}");
                continue;
            }

            let current = self
                .kv
                .get(Tree::DriveMapping, key.as_bytes())?
                .and_then(|bytes| String::from_utf8(bytes).ok());

            match current {
                Some(current) if current == *drive_did => {}
                Some(_) => {
                    self.kv
                        .insert(Tree::DriveMapping, key.as_bytes(), drive_did.as_bytes())?;
                    report.updated.push(key.clone());
                }
                None => {
                    self.kv
                        .insert(Tree::DriveMapping, key.as_bytes(), drive_did.as_bytes())?;
                    report.added.push(key.clone());
                }
            }

            if !managed.contains(&key) {
                managed.push(key);
            }
        }

        for host in self.managed_alias_hosts()? {
            if managed.contains(&host) {
                continue;
            }
            if self.kv.get(Tree::DriveMapping, host.as_bytes())?.is_some() {
                self.kv.remove(Tree::DriveMapping, host.as_bytes())?;
                report.removed.push(host);
            }
        }

        managed.sort();
        let bytes = serde_json::to_vec(&managed)
            .map_err(|e| format!("Could not encode managed alias hosts: {e}"))?;
        self.kv
            .insert(Tree::PluginMeta, MANAGED_ALIAS_HOSTS_KEY, &bytes)?;

        if !report.is_empty() {
            tracing::info!(
                "Drive mappings reconciled: {} added, {} updated, {} removed",
                report.added.len(),
                report.updated.len(),
                report.removed.len()
            );
        }

        Ok(report)
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

    /// Whether `host` (no port) has a Drive mapping in this store: bound by
    /// hand through `/bind-drive`, or installed by a control plane through
    /// [`Self::sync_drive_mappings`]. Either way the server answers for it.
    pub fn has_drive_mapping(&self, host: &str) -> bool {
        let key = drive_mapping_key(host);
        !key.is_empty() && matches!(self.kv.get(Tree::DriveMapping, key.as_bytes()), Ok(Some(_)))
    }

    /// Returns the full Drive DID for a given host (domain/subdomain).
    pub async fn get_drive_did(&self, host: &str) -> AtomicResult<Option<Subject>> {
        let key = drive_mapping_key(host);
        if let Some(did_bin) = self.kv.get(Tree::DriveMapping, key.as_bytes())? {
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
        for mut index_atom in atom.to_indexable_atoms() {
            // Index by resource identity, even when an older peer sent the
            // same subject using the legacy identifier scheme.
            index_atom.subject = index_atom.subject.pure_id().into();
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
        let mut propvals = resource.get_propvals().clone();
        canonical_scheme::canonicalize_propvals(&mut propvals);

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
            encode_propvals(&propvals)?
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

    /// Removes `subject` and its children in one transaction and tombstones
    /// them, returning what was removed so the caller can announce it once it
    /// has decided how: `remove_resource` sends a plain `DbEvent::Destroyed`
    /// for each, `apply_commit` wraps the destroyed subject in its signed
    /// destroy commit and announces only the children this way.
    async fn remove_applied(&self, subject: &Subject) -> AtomicResult<Vec<RemovedSubject>> {
        let mut transaction = Transaction::new();
        let mut removed = Vec::new();
        self.recursive_remove(subject, &mut transaction, &mut removed, None)
            .await?;
        self.apply_transaction(&mut transaction)?;
        // Tombstone every removed subject so bulk sync (Iroh / WS `SYNC`)
        // does not resurrect them from a peer that still holds a stale copy.
        // Only after the apply succeeded: a tombstone for a resource that is
        // still present would suppress it forever.
        for r in &removed {
            crate::sync::tombstones::record_tombstone(self, &r.subject.pure_id());
        }
        Ok(removed)
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
    pub(crate) fn get_propvals(&self, subject: &str) -> AtomicResult<PropVals> {
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

    /// The stored row of `subject`, and the key it is stored under: the
    /// `atomic:` spelling. Opening a store rewrites every `did:ad:` key
    /// (`canonical_scheme::migrate_if_needed`) and every write keys by
    /// [`Subject::pure_id`], so a legacy spelling only needs normalizing.
    fn get_propvals_canonical(&self, subject: &str) -> AtomicResult<(String, PropVals)> {
        let key = crate::identifiers::canonicalize_scheme(subject);
        let propvals = self.get_propvals(&key)?;
        Ok((key, propvals))
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
        self.fetch_counters
            .get_resource_shallow
            .fetch_add(1, Ordering::Relaxed);
        let normalized = self.normalize_subject(subject);
        let (subject_str, propvals) = self.get_propvals_canonical(&normalized.pure_id())?;

        let mut res_subject = normalized.clone();
        if let Subject::Did {
            drive_hint: None, ..
        } = &res_subject
        {
            if let Some(hint) = self.get_did_mapping_hint(&subject_str) {
                res_subject = res_subject.set_drive_hint(hint);
            }
        }

        Ok(Resource::from_propvals(propvals, res_subject))
    }

    /// Zero the fetch counters. Tests call this after fixture setup so the
    /// subsequent query's counts aren't mixed with bootstrap / save traffic.
    pub fn reset_fetch_counters(&self) {
        self.fetch_counters.get_resource.store(0, Ordering::Relaxed);
        self.fetch_counters
            .get_resource_shallow
            .store(0, Ordering::Relaxed);
    }

    /// Full-decode [`Storelike::get_resource`] calls since the last reset.
    pub fn get_resource_call_count(&self) -> usize {
        self.fetch_counters.get_resource.load(Ordering::Relaxed)
    }

    /// Propvals-only [`Db::get_resource_shallow`] calls since the last reset.
    pub fn get_resource_shallow_call_count(&self) -> usize {
        self.fetch_counters
            .get_resource_shallow
            .load(Ordering::Relaxed)
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

    /// Stores a secret, replacing any of the same name.
    ///
    /// There is deliberately no `get_plugin_secret` returning a value. The only
    /// reader is [`Db::use_plugin_secret`], which hands the value to a closure
    /// and never out of it, so no endpoint can serve one by accident.
    /// Sets the key stored secrets are wrapped with. Once per process.
    ///
    /// Silently ignored if already set: a second call would mean two parts of
    /// the process disagree about which key opens the store, and the loser
    /// would write secrets the winner cannot read.
    pub fn set_node_key(&self, key: [u8; crate::vault::keys::KEK_LEN]) {
        let _ = self.node_key.set(key);
    }

    /// A 32-byte key for one purpose, derived from the node key, or `None`
    /// when this node has no key. The node key itself never leaves the store;
    /// what comes out is bound to `context` (say what it is for, and version
    /// it), so a key made for signing tokens cannot open a wrapped secret.
    pub fn derive_node_key(&self, context: &str) -> Option<[u8; 32]> {
        self.node_key
            .get()
            .map(|key| blake3::derive_key(context, key))
    }

    /// Wraps a secret for storage, or passes it through when no key is set.
    ///
    /// Passing through is what lets a store predating the node key still be
    /// read and written. It is not a fallback anyone should rely on, which is
    /// why `has_node_key` exists for callers that must know.
    fn wrap_secret(&self, value: &str) -> AtomicResult<String> {
        let Some(key) = self.node_key.get() else {
            return Ok(value.to_string());
        };

        crate::vault::secret_envelope::SecretEnvelope::create(
            value.as_bytes(),
            &[crate::vault::secret_envelope::NewWrapper::NodeKey { kek: *key }],
        )?
        .to_json()
    }

    /// Opens a stored secret, tolerating one written before there was a key.
    fn unwrap_secret(&self, stored: &str) -> AtomicResult<String> {
        let Ok(envelope) = crate::vault::secret_envelope::SecretEnvelope::from_json(stored) else {
            // Written before this node had a key. Readable, and rewritten
            // wrapped the next time it is set.
            return Ok(stored.to_string());
        };

        let Some(key) = self.node_key.get() else {
            return Err("this secret is wrapped, but this node has no key to open it".into());
        };

        let opened = envelope.unwrap_secret(&crate::vault::secret_envelope::Unlock::Kek(*key))?;

        String::from_utf8(opened).map_err(|_| "a stored secret was not text".into())
    }

    /// Whether stored secrets are wrapped at all.
    pub fn has_node_key(&self) -> bool {
        self.node_key.get().is_some()
    }

    pub fn set_plugin_secret(
        &self,
        key: &PluginSecretKey,
        secret: &PluginSecret,
    ) -> AtomicResult<()> {
        PluginSecretKey::validate_name(&key.name)?;

        let mut stored = secret.clone();
        stored.value = self.wrap_secret(&secret.value)?;

        self.kv
            .insert(Tree::PluginSecret, &key.encode()?, &stored.encode()?)?;
        Ok(())
    }

    /// Runs `f` with the secret's value if it exists and allows `origin`.
    ///
    /// Records the use before returning, so "used 0 times in 90 days" is a
    /// question the UI can answer when someone is deciding whether to revoke.
    pub fn use_plugin_secret<T>(
        &self,
        key: &PluginSecretKey,
        origin: &str,
        at: i64,
        f: impl FnOnce(&str) -> T,
    ) -> AtomicResult<Option<T>> {
        let encoded_key = key.encode()?;

        let Some(bin) = self.kv.get(Tree::PluginSecret, &encoded_key)? else {
            return Ok(None);
        };

        let mut secret = PluginSecret::from_bytes(&bin)?;

        if !secret.allows(origin) {
            return Ok(None);
        }

        // References are one hop, same drive, and restricted by BOTH origin lists.
        // Rotating/revoking the connection affects every bound plugin immediately.
        let resolved = if let Some(target) = &secret.connection {
            if target.drive != key.drive {
                return Err("cross-drive credential reference".into());
            }
            let Some(bytes) = self.kv.get(Tree::PluginSecret, &target.encode()?)? else {
                return Ok(None);
            };
            let shared = PluginSecret::from_bytes(&bytes)?;
            if shared.connection.is_some() || !shared.allows(origin) {
                return Ok(None);
            }
            self.unwrap_secret(&shared.value)?
        } else {
            self.unwrap_secret(&secret.value)?
        };
        let out = f(&resolved);

        secret.record_use(at);
        self.kv
            .insert(Tree::PluginSecret, &encoded_key, &secret.encode()?)?;

        Ok(Some(out))
    }

    /// What may be said about a secret: never its value.
    pub fn get_plugin_secret_info(
        &self,
        key: &PluginSecretKey,
    ) -> AtomicResult<Option<PluginSecretInfo>> {
        let Some(bin) = self.kv.get(Tree::PluginSecret, &key.encode()?)? else {
            return Ok(None);
        };

        Ok(Some(PluginSecretInfo::of(
            &key.name,
            &PluginSecret::from_bytes(&bin)?,
        )))
    }

    /// Describes every secret a plugin has. Never their values.
    /// Records the key an app signs with, wrapped like every other secret.
    pub fn set_app_agent(&self, key: &AppAgentKey, agent: &AppAgent) -> AtomicResult<()> {
        let mut stored = agent.clone();
        stored.secret = self.wrap_secret(&agent.secret)?;
        stored.revoked = false;

        self.kv
            .insert(Tree::AppAgent, &key.encode()?, &stored.encode()?)?;
        Ok(())
    }

    /// Which DID an app writes as, without opening its key.
    pub fn get_app_agent_info(&self, key: &AppAgentKey) -> AtomicResult<Option<AppAgentInfo>> {
        Ok(match self.get_app_agent_state(key)? {
            AppAgentState::Active(info) => Some(info),
            _ => None,
        })
    }

    /// Read identity and lifecycle atomically, so revocation cannot look legacy
    /// between separate existence and status probes.
    pub fn get_app_agent_state(&self, key: &AppAgentKey) -> AtomicResult<AppAgentState> {
        let Some(bin) = self.kv.get(Tree::AppAgent, &key.encode()?)? else {
            return Ok(AppAgentState::Legacy);
        };
        let stored = AppAgent::from_bytes(&bin)?;
        Ok(if stored.revoked {
            AppAgentState::Revoked
        } else {
            AppAgentState::Active(stored.info())
        })
    }

    /// Runs `f` with the app's signing agent.
    ///
    /// A closure rather than a return value, for the same reason
    /// `use_plugin_secret` is one: nothing that hands a private key back to a
    /// caller can promise where it goes next.
    pub fn with_app_agent<T>(
        &self,
        key: &AppAgentKey,
        f: impl FnOnce(&crate::agents::Agent) -> T,
    ) -> AtomicResult<Option<T>> {
        let Some(bin) = self.kv.get(Tree::AppAgent, &key.encode()?)? else {
            return Ok(None);
        };

        let stored = AppAgent::from_bytes(&bin)?;
        if stored.revoked {
            return Ok(None);
        }
        let secret = self.unwrap_secret(&stored.secret)?;
        let agent = crate::agents::Agent::from_secret(&secret)?;

        Ok(Some(f(&agent)))
    }

    pub fn delete_app_agent(&self, key: &AppAgentKey) -> AtomicResult<()> {
        // Replace the encrypted key and state in one KV write. Keep no secret,
        // but remember that this installation must not use the legacy signer.
        let mut tombstone = AppAgent::new(String::new(), String::new(), 0);
        tombstone.revoked = true;
        self.kv
            .insert(Tree::AppAgent, &key.encode()?, &tombstone.encode()?)?;
        self.flush()?;
        Ok(())
    }

    pub fn app_agent_was_revoked(&self, key: &AppAgentKey) -> AtomicResult<bool> {
        Ok(matches!(
            self.get_app_agent_state(key)?,
            AppAgentState::Revoked
        ))
    }

    /// Secrets this node could not open with nobody present.
    ///
    /// A secret wrapped only by a user's credential has no unattended path —
    /// that is the trade for the server not being able to read it, not a gap.
    /// So arming a schedule or a trigger has to ask this first, while the
    /// person is there to be told, rather than discovering it at 3am and
    /// leaving an error nobody reads until the week is out.
    pub fn plugin_secrets_needing_a_person(
        &self,
        drive: &str,
        plugin: &str,
    ) -> AtomicResult<Vec<String>> {
        let prefix = PluginSecretKey::plugin_prefix(drive, plugin);
        let mut blocked = Vec::new();

        for entry in self.kv.scan_prefix(Tree::PluginSecret, &prefix) {
            let (key, value) = entry?;
            let stored = PluginSecret::from_bytes(&value)?;

            // Anything this node can already open is fine, wrapped or not:
            // a secret from before there was a key reads as plaintext.
            if self.unwrap_secret(&stored.value).is_err() {
                blocked.push(PluginSecretKey::name_from_key(&key)?);
            }
        }

        blocked.sort();

        Ok(blocked)
    }

    pub fn list_plugin_secrets(
        &self,
        drive: &str,
        plugin: &str,
    ) -> AtomicResult<Vec<PluginSecretInfo>> {
        let prefix = PluginSecretKey::plugin_prefix(drive, plugin);
        let mut out = Vec::new();

        for entry in self.kv.scan_prefix(Tree::PluginSecret, &prefix) {
            let (key, value) = entry?;
            let name = PluginSecretKey::name_from_key(&key)?;
            out.push(PluginSecretInfo::of(
                &name,
                &PluginSecret::from_bytes(&value)?,
            ));
        }

        out.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(out)
    }

    pub fn delete_plugin_secret(&self, key: &PluginSecretKey) -> AtomicResult<()> {
        self.kv.remove(Tree::PluginSecret, &key.encode()?)?;
        Ok(())
    }

    pub fn set_plugin_schedule(
        &self,
        key: &PluginScheduleKey,
        schedule: &PluginSchedule,
    ) -> AtomicResult<()> {
        self.kv
            .insert(Tree::PluginSchedule, &key.encode()?, &schedule.encode()?)?;
        Ok(())
    }

    pub fn get_plugin_schedule(
        &self,
        key: &PluginScheduleKey,
    ) -> AtomicResult<Option<PluginSchedule>> {
        let Some(bin) = self.kv.get(Tree::PluginSchedule, &key.encode()?)? else {
            return Ok(None);
        };

        Ok(Some(PluginSchedule::from_bytes(&bin)?))
    }

    pub fn delete_plugin_schedule(&self, key: &PluginScheduleKey) -> AtomicResult<()> {
        self.kv.remove(Tree::PluginSchedule, &key.encode()?)?;
        Ok(())
    }

    /// Every schedule due at `now`.
    ///
    /// A whole-tree scan on purpose: one entry per scheduled plugin is a very
    /// small set, and an index keyed by due-time would have to be rewritten on
    /// every run for no gain at this size.
    pub fn due_plugin_schedules(
        &self,
        now: i64,
    ) -> AtomicResult<Vec<(PluginScheduleKey, PluginSchedule)>> {
        let mut due = Vec::new();

        for entry in self.kv.iter_tree(Tree::PluginSchedule) {
            let (key, value) = entry?;
            let schedule = PluginSchedule::from_bytes(&value)?;

            if schedule.is_due(now) {
                due.push((PluginScheduleKey::from_bytes(&key)?, schedule));
            }
        }

        Ok(due)
    }

    /// Exclusion scoped to this database and plugin operation namespace.
    pub async fn lock_plugin(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.plugin_locks.lock(key).await
    }

    pub fn set_plugin_trigger(
        &self,
        key: &PluginTriggerKey,
        trigger: &PluginTrigger,
    ) -> AtomicResult<()> {
        // The store only fires membership events for queries it watches, so
        // registering the filter is part of storing the trigger rather than a
        // separate step someone can forget — a trigger that was never watched
        // would sit there looking armed and never fire.
        trigger.query.watch(self)?;

        self.kv
            .insert(Tree::PluginTrigger, &key.encode()?, &trigger.encode()?)?;
        Ok(())
    }

    pub fn get_plugin_trigger(
        &self,
        key: &PluginTriggerKey,
    ) -> AtomicResult<Option<PluginTrigger>> {
        let Some(bin) = self.kv.get(Tree::PluginTrigger, &key.encode()?)? else {
            return Ok(None);
        };

        Ok(Some(PluginTrigger::from_bytes(&bin)?))
    }

    pub fn delete_plugin_trigger(&self, key: &PluginTriggerKey) -> AtomicResult<()> {
        // The watched query stays. Another plugin — or a live `SUBSCRIBE_QUERY`
        // — may be watching the same filter, and unwatching one that is still
        // in use would silently stop delivering to it.
        self.kv.remove(Tree::PluginTrigger, &key.encode()?)?;
        Ok(())
    }

    /// Every trigger whose query is the one that just changed.
    ///
    /// A whole-tree scan, for the same reason `due_plugin_schedules` is one:
    /// there is one entry per triggered plugin, which is a very small set. An
    /// index keyed by query id would be another thing to keep in step for no
    /// gain at this size.
    pub fn plugin_triggers_for_query(
        &self,
        query_id: &[u8],
    ) -> AtomicResult<Vec<(PluginTriggerKey, PluginTrigger)>> {
        let mut found = Vec::new();

        for entry in self.kv.iter_tree(Tree::PluginTrigger) {
            let (key, value) = entry?;
            let trigger = PluginTrigger::from_bytes(&value)?;

            if crate::db::query_index::query_id(&trigger.query)?.as_slice() == query_id {
                found.push((PluginTriggerKey::from_bytes(&key)?, trigger));
            }
        }

        Ok(found)
    }

    /// Re-registers every stored trigger's query as watched.
    ///
    /// Called at startup: watched queries live in the store, but a trigger
    /// written by a version that did not watch — or one whose watch entry was
    /// lost — would otherwise never fire again, and nothing would say so.
    pub fn watch_plugin_trigger_queries(&self) -> AtomicResult<usize> {
        let mut watched = 0;

        for entry in self.kv.iter_tree(Tree::PluginTrigger) {
            let (_, value) = entry?;
            PluginTrigger::from_bytes(&value)?.query.watch(self)?;
            watched += 1;
        }

        Ok(watched)
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
        let mut prefix: Vec<u8> = [
            &query_index::property_key_part(prop)[..],
            &[query_index::SEPARATION_BIT],
        ]
        .concat();
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
    ///
    /// Also returns the position of the chosen constraint in
    /// `q_filter.filters`, so the build can cross-check its result against
    /// the constraints it did not scan (see `cross_check_first_build`).
    fn plan_candidate_iterator(
        &self,
        q: &Query,
        q_filter: &QueryFilter,
    ) -> (IndexIterator, Option<usize>) {
        let mut best: Option<(usize, usize, &crate::storelike::PropVal)> = None;
        for (position, constraint) in q_filter.filters.iter().enumerate() {
            let Some(prop) = &constraint.property else {
                continue;
            };
            let scan_val = match (constraint.operator, &constraint.value) {
                (crate::storelike::FilterOperator::Equal, Some(v)) => Some(v),
                _ => None,
            };
            let estimate = self.estimate_prop_val_count(prop, scan_val, PLANNER_SCAN_CAP);
            if best.is_none_or(|(current, _, _)| estimate < current) {
                best = Some((estimate, position, constraint));
            }
        }

        match best {
            Some((_, position, constraint)) => {
                let prop = constraint
                    .property
                    .as_ref()
                    .expect("planner only ranks property-bearing constraints");
                let val = match constraint.operator {
                    crate::storelike::FilterOperator::Equal => constraint.value.as_ref(),
                    _ => None,
                };
                (find_in_prop_val_sub_index(self, prop, val), Some(position))
            }
            // No property-bearing constraint (value-only filters): fall back
            // to the query's own iterator (value index or full scan).
            None => (self.get_index_iterator_for_query(q), None),
        }
    }

    /// The members a first build missed, found by walking the small
    /// equality constraints the planner did *not* scan.
    ///
    /// The planner trusts that any one constraint's `PropValSub` entries are a
    /// superset of the members. That held only as long as every encoding of a
    /// value produced the same index key; when one did not, the cheapest
    /// constraint had fewer candidates than rows, the build filed a partial
    /// member list, and the filter was watched — so the partial list was
    /// trusted for good and every count it produced looked plausible
    /// (planning/silent-failures.md). This walks each other equality
    /// constraint whose entries fit under the planner's scan cap (so at most
    /// `PLANNER_SCAN_CAP` extra key reads per constraint, once per first
    /// build), and returns every matching resource that is not in `built`.
    /// Constraints beyond the cap are not walked here; the full comparison is
    /// [`Db::check_query_index`].
    fn cross_check_first_build(
        &self,
        q_filter: &QueryFilter,
        chosen: Option<usize>,
        built: &HashSet<String>,
    ) -> Vec<Resource> {
        let mut missing = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (position, constraint) in q_filter.filters.iter().enumerate() {
            if Some(position) == chosen {
                continue;
            }
            let (Some(prop), Some(val)) = (&constraint.property, &constraint.value) else {
                continue;
            };
            if constraint.operator != crate::storelike::FilterOperator::Equal {
                continue;
            }
            if self.estimate_prop_val_count(prop, Some(val), PLANNER_SCAN_CAP) >= PLANNER_SCAN_CAP {
                continue;
            }
            for atom in find_in_prop_val_sub_index(self, prop, Some(val)).flatten() {
                let subject = atom.subject.as_str().to_string();
                if built.contains(&subject) || !seen.insert(subject) {
                    continue;
                }
                let Ok(resource) = self.get_resource_shallow(&atom.subject) else {
                    continue;
                };
                if query_index::resource_matches_filter(&resource, q_filter)
                    && self.filter_accepts_resource_drive(q_filter, &resource)
                {
                    missing.push(resource);
                }
            }
        }
        missing
    }

    /// Compare a query's member index with the resources it claims to index.
    ///
    /// Walks every stored resource, applies the query's filter to it the way
    /// the index maintenance does (`resource_matches_filter` plus the drive
    /// check), and reports which matching subjects the index lacks and which
    /// indexed subjects no longer match. Reading a row set out of the index
    /// is fast because it trusts the index; this is the check that trust is
    /// deserved. It is a full scan, so it is for tests, diagnostics and
    /// one-off repairs, not for the query path.
    pub fn check_query_index(&self, q: &Query) -> AtomicResult<QueryIndexReport> {
        let q_filter = QueryFilter::try_from_query(q)?;
        let id = query_index::query_id(&q_filter)?;
        // Index keys hold the subject as the writer spelled it; rows come
        // back under the store's normalized spelling. Compare one form.
        let base_domain = self.get_base_domain();
        let canonical = |s: &str| Subject::from_raw(s, base_domain.as_deref()).pure_id();

        let mut indexed: HashSet<String> = HashSet::new();
        for kv in self.kv.scan_prefix(Tree::QueryMembers, &id) {
            let (key, _) = kv?;
            let (_id, _sort, subject) = query_index::parse_members_key(&key)?;
            indexed.insert(canonical(subject));
        }

        let mut expected: HashSet<String> = HashSet::new();
        for resource in self.all_resources(true) {
            if query_index::resource_matches_filter(&resource, &q_filter)
                && self.filter_accepts_resource_drive(&q_filter, &resource)
            {
                expected.insert(canonical(resource.get_subject().as_str()));
            }
        }

        let mut missing: Vec<String> = expected.difference(&indexed).cloned().collect();
        let mut stale: Vec<String> = indexed.difference(&expected).cloned().collect();
        missing.sort();
        stale.sort();
        Ok(QueryIndexReport {
            watched: q_filter.is_watched(self),
            filter: q_filter,
            indexed: indexed.len(),
            expected: expected.len(),
            missing,
            stale,
        })
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
        // Before the persisted short-circuit: a client re-watching after the
        // queried subject arrived here gets its drive root resolved now.
        self.cache_filter_drive_root(&filter.drive);
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
            self.cache_filter_drive_root(&qf.drive);
            let drive_key = qf.drive.as_str().to_string();
            new_map.entry(drive_key).or_default().insert(Arc::new(qf));
        }
        if let Ok(mut map) = self.watched_queries_by_drive.write() {
            *map = new_map;
        }
        Ok(())
    }

    /// Resolve the drive root a filter's `drive` subject lives in and remember
    /// it. A subject that is not stored here (an `https://host` prefix, a DID
    /// that has not arrived yet) records `None`; the next `watch()` retries.
    fn cache_filter_drive_root(&self, drive: &Subject) {
        let key = drive.as_str().to_string();
        let known = self
            .filter_drive_roots
            .read()
            .ok()
            .and_then(|m| m.get(&key).cloned());
        if matches!(known, Some(Some(_))) {
            return;
        }
        let root = self
            .get_resource_shallow(drive)
            .ok()
            .and_then(|resource| resource.get_drive());
        if let Ok(mut map) = self.filter_drive_roots.write() {
            map.insert(key, root);
        }
    }

    /// The drive root a watched filter was resolved to, if known.
    pub(crate) fn filter_drive_root(&self, filter: &query_index::QueryFilter) -> Option<Subject> {
        self.filter_drive_roots
            .read()
            .ok()
            .and_then(|m| m.get(filter.drive.as_str()).cloned().flatten())
    }

    /// Whether a resource may be a member of `filter` as far as drive scope
    /// goes. HTTP and `internal:` subjects are already routed to their drive
    /// by prefix. A DID subject has no prefix, so the only evidence is its
    /// `drive` stamp: when both it and the filter's root are known, they
    /// must agree. A row without a stamp, or a filter whose root could not be
    /// resolved, is not excluded — a missing stamp is not proof of a leak,
    /// and read rights still apply at query time.
    pub(crate) fn filter_accepts_resource_drive(
        &self,
        filter: &query_index::QueryFilter,
        resource: &Resource,
    ) -> bool {
        if !crate::identifiers::is_atomic_identifier(resource.get_subject().as_str()) {
            return true;
        }
        match (resource.get_drive(), self.filter_drive_root(filter)) {
            (Some(stamp), Some(root)) => stamp.pure_id() == root.pure_id(),
            _ => true,
        }
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
        // Persist delivery before publishing the wake-up. A crashed or lagging
        // subscriber can replay the queue; it is never the owner of the event.
        // A sorted member moving positions has a delete and insert in this
        // batch, which is not a membership edge.
        let mut edges = std::collections::BTreeMap::new();
        for op in transaction
            .iter()
            .filter(|op| op.tree == Tree::QueryMembers)
        {
            if let Some((query, subject)) = query_index::parse_members_key_id_subject(&op.key) {
                let delta = edges.entry((query, subject)).or_insert(0i32);
                *delta += if matches!(op.method, Method::Insert) {
                    1
                } else {
                    -1
                };
            }
        }
        for ((query, subject), delta) in edges {
            if delta == 0 {
                continue;
            }
            let edge = plugin_trigger::Edge::of(delta > 0);
            for (key, trigger) in self.plugin_triggers_for_query(&query)? {
                if !trigger.wants(edge) {
                    continue;
                }
                let event = plugin_trigger::QueuedEvent {
                    id: format!(
                        "{:020}-{}",
                        crate::utils::now(),
                        crate::utils::random_string(24)
                    ),
                    key,
                    subject: subject.clone(),
                    edge,
                    at: crate::utils::now(),
                    verdict: None,
                    waiting_for_review: false,
                    authorization: None,
                };
                transaction.push(Operation {
                    tree: Tree::PluginMeta,
                    method: Method::Insert,
                    key: format!("plugin-event/v1/{}", event.id).into_bytes(),
                    val: Some(serde_json::to_vec(&event)?),
                });
            }
        }
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
            if let Some(snapshot) = self.get_loro_snapshot_bytes(&pure_id) {
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
        // An extender that cannot decide whether it applies is skipped, not
        // treated as a reason to hide the row. The row exists and the reader
        // may see it; the only thing at stake here is the `incomplete`
        // marker. Returning `None` from here used to drop every row whose
        // `isA` the built-in collection extender could not parse, silently,
        // from every collection listing and count (planning/silent-failures.md,
        // "A query index silently disagreed with the data it indexes").
        for extender in extenders.iter() {
            if !extender.can_extend(&resource) {
                continue;
            }
            match extender.resource_has_extender(&resource) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(
                        subject = %resource.get_subject(),
                        extender = extender.id.as_deref().unwrap_or("<unnamed>"),
                        "query member listed without its extender check: {e}"
                    );
                    continue;
                }
            }
            match extender.check_scope(&resource, self, None).await {
                Ok((true, _)) => {
                    resource
                        .insert_propval_raw(crate::urls::INCOMPLETE.into(), Value::Boolean(true));
                    break;
                }
                Ok((false, _)) => continue,
                Err(e) => {
                    tracing::warn!(
                        subject = %resource.get_subject(),
                        extender = extender.id.as_deref().unwrap_or("<unnamed>"),
                        "query member listed without its extender scope check: {e}"
                    );
                    continue;
                }
            }
        }

        Some(Some(resource))
    }

    async fn query_basic(&self, q: &Query) -> AtomicResult<QueryResult> {
        let mut subjects: Vec<Subject> = vec![];
        let mut resources: Vec<Resource> = vec![];
        let mut total_count = 0;
        let mut seen = HashSet::new();
        let rights_cache = std::sync::Mutex::new(RightsCache::default());
        let base_domain = self.get_base_domain();

        let atoms = self.get_index_iterator_for_query(q);

        for atom_res in atoms {
            let atom = atom_res?;
            if !q.include_external && !atom.subject.is_local() {
                continue;
            }
            let identity = atom.subject.pure_id();
            if !seen.insert(identity.clone()) {
                continue;
            }
            let subject = Subject::from_raw(&identity, base_domain.as_deref());
            let index = seen.len() - 1;

            total_count += 1;

            if q.offset > index {
                continue;
            }

            // Denied members do not grow `subjects`, so we keep resolving
            // until the page is full of *authorized* hits — a private streak
            // must not hide a later readable row.
            if q.limit.is_none() || subjects.len() < q.limit.unwrap() {
                // Sudo without nested bodies needs no per-member work at all.
                if q.for_agent == ForAgent::Sudo && !q.include_nested {
                    subjects.push(subject);
                    continue;
                }

                match self.resolve_query_member(&subject, q, &rights_cache).await {
                    Some(body) => {
                        subjects.push(subject);
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
            let (atoms, chosen) = self.plan_candidate_iterator(q, &q_filter);
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
            let mut built: HashSet<String> = HashSet::new();
            for atom in atoms.flatten() {
                let Ok(resource) = self.get_resource_shallow(&atom.subject) else {
                    // No row to verify against (external/never-stored) —
                    // don't index what we can't confirm.
                    continue;
                };
                if !query_index::resource_matches_filter(&resource, &q_filter)
                    || !self.filter_accepts_resource_drive(&q_filter, &resource)
                {
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
                built.insert(atom.subject.as_str().to_string());
            }
            // A member the scanned constraint's index does not know about is
            // a member the filter would have listed forever without. Say so,
            // and file it.
            let missed = self.cross_check_first_build(&q_filter, chosen, &built);
            if !missed.is_empty() {
                let subjects: Vec<String> = missed
                    .iter()
                    .map(|r| r.get_subject().as_str().to_string())
                    .collect();
                tracing::warn!(
                    filter = ?q_filter,
                    missing = ?subjects,
                    "query index build missed members its candidate index did not list; added"
                );
                for resource in &missed {
                    // The cross-check only walks property-bearing
                    // constraints, so the filter always has a key property.
                    let prop = query_index::filter_key_property(&q_filter)
                        .cloned()
                        .unwrap_or_default();
                    let sort_key = query_index::sort_key_for(resource, &prop);
                    update_indexed_member(
                        &q_filter,
                        resource.get_subject().as_str(),
                        &sort_key,
                        false,
                        &mut transaction,
                    )?;
                }
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
        for mut index_atom in atom.to_stored_index_atoms() {
            index_atom.subject = index_atom.subject.pure_id().into();
            for op in Operation::remove_atom_from_legacy_indexes(&index_atom) {
                transaction.push(op);
            }
            if atom.property == urls::GENESIS {
                continue;
            }
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
    /// `removed` collects every deleted subject so the caller can tombstone
    /// and announce them after the transaction is applied — nothing is sent on
    /// `db_events` from here, since the removal has not happened yet.
    /// `inherited_drive` is the drive of the resource whose cascade brought us
    /// here. A child that carries no `drive` of its own — anything created
    /// before the server stamped it — is still in its parent's drive, and the
    /// removal has to name one or it reaches no subscriber.
    async fn recursive_remove(
        &self,
        subject: &Subject,
        transaction: &mut Transaction,
        removed: &mut Vec<RemovedSubject>,
        inherited_drive: Option<Subject>,
    ) -> AtomicResult<()> {
        // Key by `pure_id()` — that is how resources and Loro snapshots are
        // stored (`add_resource_tx`, `apply_commit`). Looking up by the raw
        // `to_string()` (which may carry `?drive=` params) would miss the
        // row entirely for DID subjects with a drive hint.
        let subject_str = subject.pure_id();
        if let Ok((found_key, found)) = self.get_propvals_canonical(&subject_str) {
            let resource = Resource::from_propvals(found, subject.clone());
            transaction.push(Operation::remove_resource(&found_key));
            transaction.push(Operation::remove_loro_snapshot(&found_key));
            // Read the drive now, while the resource still exists: a listener
            // reacting to the removal cannot look it up any more.
            let drive = resource.get_drive().or(inherited_drive);
            removed.push(RemovedSubject {
                subject: subject.without_params(),
                drive: drive.clone(),
            });
            let mut children = resource.get_children(self).await?;
            for child in children.iter_mut() {
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
            crate::search::unindex_subject(self, &found_key, transaction)?;
        } else {
            return Err(format!(
                "Resource {} could not be deleted, because it was not found in the store.",
                subject
            )
            .into());
        }
        Ok(())
    }

    /// Announces subjects `recursive_remove` collected, once the transaction
    /// holding their removal has been applied. Any earlier and a listener
    /// (the WS fan-out in `atomic-server`'s `CommitMonitor`, a peer
    /// transport) would tell clients about a deletion that can still fail or
    /// roll back, and hear of a child before the parent whose destroy caused
    /// it. Removals no commit authorises carry no `commit_json`, so they are
    /// not propagated live to peers; see [`DbEvent::Destroyed`].
    fn emit_destroyed<'a>(&self, removed: impl IntoIterator<Item = &'a RemovedSubject>) {
        for r in removed {
            let _ = self.db_events.send(DbEvent::Destroyed {
                subject: r.subject.clone(),
                drive: r.drive.clone(),
                source_id: None,
                from_commit: false,
                commit_json: None,
            });
        }
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
        for resource in map.values() {
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
        let _import_guard = if let Some((parent, id)) = crate::import_identity::identity(resource) {
            let guard = self
                .subject_locks
                .lock(&format!(
                    "import-identity:{}",
                    serde_json::to_string(&(parent.pure_id(), &id))?
                ))
                .await;
            if let Some(found) = crate::import_identity::find_existing(self, &parent, &id).await? {
                if Subject::from(found).pure_id() != resource.get_subject().pure_id() {
                    return Err("Import identity already exists; preview again instead of creating a duplicate".into());
                }
            }
            Some(guard)
        } else {
            None
        };
        self.persist_resource_projection(
            resource,
            check_required_props,
            update_index,
            overwrite_existing,
            None,
        )
        .await
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
                let commit_id = crate::identifiers::commit_subject(sig);
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

        if let Some(old) = &commit_response.resource_old {
            if old.get(crate::urls::IMPORT_RESOLUTION).is_ok() {
                let same_identity = commit_response.resource_new.as_ref().is_some_and(|new| {
                    crate::import_identity::identity(old) == crate::import_identity::identity(new)
                });
                if !same_identity {
                    return Err(
                        "A reviewed primary record must retain its identity and history".into(),
                    );
                }
            }
        }
        let import_guard = if let Some(new) = &commit_response.resource_new {
            crate::import_identity::validate_baseline(commit_response.resource_old.as_ref(), new)?;
            crate::import_identity::validate_reference_review(
                commit_response.resource_old.as_ref(),
                new,
            )?;
            if let Some((parent, id)) = crate::import_identity::identity(new) {
                let guard = self
                    .subject_locks
                    .lock(&format!(
                        "import-identity:{}",
                        serde_json::to_string(&(parent.pure_id(), &id))?
                    ))
                    .await;
                if let Some(found) = crate::import_identity::validate_candidate(
                    self,
                    commit_response.resource_old.as_ref(),
                    new,
                )
                .await?
                {
                    if Subject::from(found).pure_id() != new.get_subject().pure_id() {
                        return Err("Import identity already exists; preview again instead of creating a duplicate".into());
                    }
                }
                Some(guard)
            } else {
                None
            }
        } else {
            None
        };
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
            // A creation's commit is found by its id (it names the resource),
            // so its atoms stay out of the indexes: five rows and about
            // 0.5 KB for every new resource that no query asks for. Later
            // critical commits (rights, parent, destroy) stay queryable by
            // the subject they are about.
            if !commit_response.creates_resource() {
                for atom in commit_response.commit_resource.to_atoms() {
                    store.add_atom_to_index(
                        &atom,
                        &commit_response.commit_resource,
                        &mut transaction,
                    )?;
                }
            }
        }

        // The signed envelope itself lives in `Tree::Envelopes`, keyed by the
        // resource it is about, in the same transaction as the state it
        // signs. This is what lets any node that holds the resource say who
        // signed it, independent of the commit rows above.
        crate::envelopes::record_ops(store, &commit_response, &mut transaction)?;

        // Every subject a destroy removes below (the resource and its
        // cascade-deleted children). Tombstoned and announced once the
        // transaction has landed; empty for anything but a destroy.
        let mut removed: Vec<RemovedSubject> = Vec::new();

        match (&commit_response.resource_old, &commit_response.resource_new) {
            (None, None) if !commit_response.commit.destroy.unwrap_or(false) => {
                return Err("Neither an old nor a new resource is returned from the commit - something went wrong.".into());
            }
            (None, None) => {}
            (Some(old), None) => {
                let normalized_commit_subject =
                    self.normalize_subject(&commit_response.commit.subject);
                if old.get_subject().as_str() != normalized_commit_subject.as_str() {
                    return Err(format!(
                        "Commit for {} removed a different resource ({}) - refusing to apply.",
                        normalized_commit_subject,
                        old.get_subject()
                    )
                    .into());
                }
                if !commit_response.commit.destroy.unwrap_or(false) {
                    return Err(format!(
                        "Resource {} was removed but `commit.destroy` was not set.",
                        normalized_commit_subject
                    )
                    .into());
                }
                let subject: Subject = commit_response.commit.subject.clone();
                // Queue the removal (resource, Loro snapshot, index and search
                // rows, cascaded children) into the same transaction as the
                // envelope row `record_ops` queued above, so the signed
                // destroy — what `SYNC_DIFF.removeCommits` carries — lands
                // with the deletion it signs, or not at all. Tombstones and
                // the children's `Destroyed` events follow the apply below.
                self.recursive_remove(&subject, &mut transaction, &mut removed, None)
                    .await?;
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

        // A destroy's `recursive_remove` above already queued the index and
        // search removals for every stored atom of the subject (and its
        // children); queuing them again here would only duplicate the same
        // deletes and re-run the watched-query checks.
        let removal_queued = !removed.is_empty();

        if opts.update_index {
            if let Some(old) = &commit_response.resource_old {
                if !removal_queued {
                    for atom in &commit_response.remove_atoms {
                        store
                            .remove_atom_from_index(atom, old, &mut transaction)
                            .map_err(|e| {
                                format!("Error removing atom from index: {e}  Atom: {e}")
                            })?
                    }
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
                if let Some(old) = &commit_response.resource_old {
                    if !removal_queued {
                        query_index::refile_sort_order_entries(store, old, new, &mut transaction)?;
                    }
                }
                crate::search::index_resource(store, new, &mut transaction)?;
            }
            if commit_response.resource_new.is_none() && !removal_queued {
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

        // An import receipt may be the only evidence available when retrying
        // after a process kill. Persist identity, snapshot and index before ACK.
        if [&commit_response.resource_new, &commit_response.resource_old]
            .into_iter()
            .filter_map(|r| r.as_ref())
            .any(|r| {
                crate::import_identity::identity(r).is_some()
                    || r.get(crate::urls::IMPORT_REFERENCE_REVIEW).is_ok()
            })
        {
            store.flush()?;
        }

        // Tombstone every subject the destroy removed, so bulk sync (Iroh /
        // WS `SYNC`) does not resurrect them from a peer that still holds a
        // stale copy. Only after the transaction above succeeded: a tombstone
        // for a resource that is still present would suppress it forever.
        for r in &removed {
            crate::sync::tombstones::record_tombstone(store, &r.subject.pure_id());
        }

        // Announce the cascade-deleted children now that the removal has
        // landed. The destroyed subject itself is announced below, wrapped in
        // the signed destroy commit, so it is left out here.
        let top_level = commit_response.commit.subject.pure_id();
        store.emit_destroyed(removed.iter().filter(|r| r.subject.pure_id() != top_level));

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
                delta: commit_response.fanout_delta().map(<[u8]>::to_vec),
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
        drop(import_guard);
        drop(subject_guard);

        // A Lens starts (or, destroyed, stops) applying. Not part of the
        // commit: it cannot fail it.
        if is_destroy {
            if crate::identifiers::is_lens_id(&top_level) {
                store.unregister_lens(&top_level);
            }
        } else if let Some(new) = &commit_response.resource_new {
            store.note_lens_related(new).await;
        }

        // AFTER APPLY COMMIT HANDLERS
        // Commit has been checked and saved.
        // Here you can add side-effects, such as creating new Commits.
        //
        // Nothing below may fail the commit: it is already persisted, so an
        // error here would tell the client a saved change failed, and it would
        // retry or show an error for data that did change (#1848). Each
        // extender's failure is logged and the next extender still runs.
        let resource_after = commit_response
            .resource_new
            .as_ref()
            .or(commit_response.resource_old.as_ref());

        if let Some(resource) = resource_after {
            // A poisoned lock still holds a usable list; a panic elsewhere is
            // no reason to skip every after-commit side effect.
            let extenders = match self.class_extenders.read() {
                Ok(extenders) => extenders.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            for extender in extenders.iter() {
                let result = self
                    .run_after_commit_extender(
                        extender,
                        resource,
                        &commit_response,
                        &mut root_subject,
                    )
                    .await;
                if let Err(e) = result {
                    tracing::error!(
                        extender = extender.id.as_deref().unwrap_or("<anonymous>"),
                        plugin = extender.subject.as_deref(),
                        subject = %commit_response.commit.subject,
                        commit = %commit_response.commit_resource.get_subject(),
                        error = %e,
                        "after_commit extender failed; the commit is saved and still succeeds"
                    );
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
        self.fetch_counters
            .get_resource
            .fetch_add(1, Ordering::Relaxed);
        let normalized = self.normalize_subject(subject);
        let subject_str = normalized.pure_id();
        if let Ok((subject_str, propvals)) = self.get_propvals_canonical(&subject_str) {
            let mut res_subject = normalized.clone();

            // If it's a DID and we don't have a hint in the requested subject,
            // check if we have one persisted in the did_mapping tree.
            if let Subject::Did {
                drive_hint: None, ..
            } = &res_subject
            {
                if let Some(hint) = self.get_did_mapping_hint(&subject_str) {
                    res_subject = res_subject.set_drive_hint(hint);
                }
            }

            let mut resource = Resource::from_propvals(propvals, res_subject);
            // Authoritative merged CRDT state (full oplog) lives in LoroSnapshots.
            // Propvals may carry a smaller incremental `loroUpdate` from the last commit.
            if let Some(snapshot) = self.get_loro_snapshot_bytes(&subject_str) {
                // A snapshot that cannot be read or applied is not fatal: the
                // read falls back to the (possibly stale) propval projection
                // stored beside it. It is still worth a warning, because a
                // silent fallback would hide corruption behind stale data.
                match crate::loro::AtomicLoroDoc::from_snapshot(&snapshot) {
                    // We already hold the exact bytes `doc` was just imported
                    // from — reuse them instead of having `apply_state_doc`
                    // re-export an equivalent snapshot. This is the hot path
                    // for every resource read (including once per member of
                    // a collection query), so the saved export is per-read,
                    // not one-off.
                    Ok(doc) => {
                        let lenses = self.lenses();
                        let lenses = (!lenses.is_empty()).then_some(&*lenses);
                        if let Err(e) = resource.apply_state_doc_with_lenses(doc, snapshot, lenses)
                        {
                            tracing::warn!(
                                subject = %subject_str,
                                error = %e,
                                "Failed to apply stored Loro snapshot; serving the stored propvals instead"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(
                        subject = %subject_str,
                        error = %e,
                        "Failed to read stored Loro snapshot; serving the stored propvals instead"
                    ),
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
            let path = normalized.path();

            if normalized.is_did() || crate::identifiers::is_identifier_resolution_path(&path) {
                // If it's an agent identifier and not found locally, return a minimal resource
                // instead of an error. This is important for "just-in-time" agent registration.
                if normalized.is_agent_did()
                    || crate::identifiers::is_agent_id(path.trim_start_matches('/'))
                {
                    let lookup = path.strip_prefix('/').unwrap_or(&path);
                    if let Some(pubkey) = crate::identifiers::agent_public_key(lookup) {
                        // The same key has been spelled padded, unpadded,
                        // standard and URL-safe. A profile stored under another
                        // spelling is this agent: serve it, rather than
                        // synthesizing an empty twin beside it.
                        for spelling in crate::identifiers::agent_pubkey_spellings(pubkey)
                            .into_iter()
                            .skip(1)
                        {
                            let alias = Subject::from_raw(
                                &crate::identifiers::agent_subject(&spelling),
                                self.get_base_domain().as_deref(),
                            );
                            if self.has_stored_resource(&alias) {
                                let mut found = self.get_resource(&alias).await?;
                                found.set_subject(normalized.to_string());
                                return Ok(found);
                            }
                            let legacy_did = Subject::from_raw(
                                &format!("{}{}", crate::identifiers::DID_AD_AGENT_PREFIX, spelling),
                                self.get_base_domain().as_deref(),
                            );
                            if self.has_stored_resource(&legacy_did) {
                                let mut found = self.get_resource(&legacy_did).await?;
                                found.set_subject(normalized.to_string());
                                return Ok(found);
                            }
                        }
                        if let Ok(agent) = crate::agents::Agent::new_from_public_key(pubkey) {
                            if let Ok(mut resource) = agent.to_resource() {
                                // A lookup is not creation of an agent. There is
                                // no known creation date or signed history yet.
                                // Seed the same fallback ops on every read and
                                // device, otherwise a refresh replaces the cached
                                // profile with new ops and grows its vault backup.
                                resource.remove_propval(crate::urls::CREATED_AT)?;
                                let doc = crate::loro::AtomicLoroDoc::new();
                                doc.set_peer_id(0)?;
                                let ordered: std::collections::BTreeMap<_, _> =
                                    resource.get_propvals().iter().collect();
                                for (property, value) in ordered {
                                    doc.set_property(property, value)?;
                                }
                                doc.doc()
                                    .commit_with(loro::CommitOptions::new().timestamp(0));
                                resource.apply_state_doc(doc)?;
                                return Ok(resource);
                            }
                        }
                    }
                }

                if normalized.is_did()
                    || crate::identifiers::is_identifier_path_form(&resolved_url)
                    || crate::identifiers::is_atomic_identifier(&resolved_url)
                {
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

            if self.is_remote_not_found(&resolved_url) {
                return Err(AtomicError::not_found(format!(
                    "{} was not found on its server earlier this session",
                    resolved_url
                )));
            }

            match self
                .fetch_resource(&resolved_url, self.get_default_agent().ok().as_ref())
                .await
            {
                Ok(resource) => {
                    // If the resource is external, it's not present in the store.
                    // However, we did fetch it (because the user probably requested it).
                    // So we should add it to the store.
                    // Note that this logic is also in `Store`'s `get_resource`, but it's slightly different there.
                    // We should probably unify this.
                    // Also, this might cause issues if we want to get a resource but NOT save it.
                    self.add_resource_opts(&resource, false, false, true)
                        .await?;
                    Ok(resource)
                }
                Err(e) => {
                    // The failed fetch is the answer. The default
                    // `handle_not_found` would fetch the same URL a second time.
                    if e.error_type == AtomicErrorType::NotFoundError {
                        self.remember_remote_not_found(&resolved_url);
                    }
                    Err(e)
                }
            }
        }
    }

    async fn get_resource_shallow(&self, subject: &Subject) -> AtomicResult<Resource> {
        Db::get_resource_shallow(self, subject)
    }

    fn has_stored_resource(&self, subject: &Subject) -> bool {
        let normalized = self.normalize_subject(subject);
        self.get_propvals(&normalized.pure_id()).is_ok()
    }

    fn lens_index(&self) -> Option<Arc<crate::lens::LensIndex>> {
        let lenses = self.lenses();
        (!lenses.is_empty()).then_some(lenses)
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

            // Response shaping below (`incomplete`, class extenders) writes
            // dynamic propvals through `Resource::set`, which also records each
            // write as a Loro op on the doc `get_resource` decoded from the
            // stored snapshot; serialization would then re-export that doc as
            // the served `loroUpdate`. Those ops are never persisted, so a
            // client that seeds its doc from the response builds every later
            // delta on ops this store does not have, and `apply_commit` parks
            // them as pending ("Commit's Loro update depends on ops the server
            // does not have"). Observed as the form builder's Publish never
            // reaching visitors: the Form extender's `form-submission-summary`
            // op poisoned every doc hydrated from an HTTP GET. Whatever the
            // extender does to the doc, the response carries the persisted
            // snapshot.
            let persisted_snapshot = match resource.get(crate::urls::LORO_UPDATE) {
                Ok(crate::Value::LoroDoc(bytes)) => Some(bytes.clone()),
                _ => None,
            };
            let served_id = resource.get_subject().pure_id();
            let serve_persisted = |shaped: &mut Resource| {
                if let Some(snapshot) = &persisted_snapshot {
                    if shaped.get_subject().pure_id() == served_id {
                        shaped.restore_persisted_state(snapshot.clone());
                    }
                }
            };

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
                        serve_persisted(&mut resource);

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
                                serve_persisted(&mut resource);
                                resource.set_subject(subject.to_string());
                                return Ok(resource.into());
                            }
                            ResourceResponse::ResourceWithReferenced(mut resource, referenced) => {
                                serve_persisted(&mut resource);
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
        let removed = self.remove_applied(subject).await?;
        // Only now, with the removal on disk: a listener that hears of it
        // earlier evicts a resource the store may still hold.
        self.emit_destroyed(&removed);
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
            "atomic:test-child?drive=".to_string() + drive_did.as_str()
        );
    }

    /// The vanity-subdomain hazard: a host is bound to a Drive this node does
    /// not hold (not synced yet, or migrated away). Serving the store root
    /// instead would answer a customer's hostname with another namespace's
    /// content, so the request must fail.
    #[tokio::test]
    async fn a_bound_host_whose_drive_is_missing_does_not_serve_the_store_root() {
        let store = Db::init_temp("resolver_missing_drive").await.unwrap();
        setup_test_env(&store).await.unwrap();
        let root_drive = store.get_drive_did("localhost").await.unwrap().unwrap();

        store
            .add_drive_mapping(
                "acme.example.com",
                &Value::AtomicUrl("did:ad:not-on-this-node".into()),
            )
            .unwrap();

        for path in ["/", "/about"] {
            let resolved = store
                .resolve_request_target(
                    &Subject::from_raw(path, None),
                    "acme.example.com",
                    path,
                    "https://acme.example.com",
                )
                .await;

            let Err(err) = resolved else {
                panic!("{path} on a bound host with a missing drive must not resolve");
            };
            assert!(
                !format!("{err}").contains(root_drive.as_str()),
                "must not leak the root drive: {err}"
            );
        }

        // The node's own hostname is unaffected: it has no mapping, so it
        // keeps serving its root as before.
        assert!(store
            .resolve_request_target(
                &Subject::from_raw("/", None),
                "node1.example.com",
                "/",
                "https://node1.example.com",
            )
            .await
            .is_ok());
    }
}

#[cfg(test)]
mod drive_mapping_tests {
    use super::*;
    use crate::{test_utils::setup_test_env, Value};

    fn desired(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(h, d)| (h.to_string(), d.to_string()))
            .collect()
    }

    /// The reconcile a managed node runs on every policy poll: new names are
    /// installed, a repointed name follows its Drive, and a released name
    /// stops resolving. All three without an operator touching the box.
    #[tokio::test]
    async fn reconcile_adds_updates_and_removes() {
        let store = Db::init_temp("drive_mapping_reconcile").await.unwrap();

        let report = store
            .sync_drive_mappings(&desired(&[
                ("acme.example.com", "did:ad:acme"),
                ("blog.example.com", "did:ad:blog"),
            ]))
            .unwrap();
        assert_eq!(report.added, vec!["acme.example.com", "blog.example.com"]);
        assert!(report.updated.is_empty());
        assert!(report.removed.is_empty());

        // `acme` is repointed at another Drive (a migration), `blog` is
        // released, and `docs` is new.
        let report = store
            .sync_drive_mappings(&desired(&[
                ("acme.example.com", "did:ad:acme-moved"),
                ("docs.example.com", "did:ad:docs"),
            ]))
            .unwrap();
        assert_eq!(report.added, vec!["docs.example.com"]);
        assert_eq!(report.updated, vec!["acme.example.com"]);
        assert_eq!(report.removed, vec!["blog.example.com"]);

        assert_eq!(
            store
                .get_drive_did("acme.example.com")
                .await
                .unwrap()
                .unwrap()
                .as_str(),
            "did:ad:acme-moved"
        );
        assert!(store
            .get_drive_did("blog.example.com")
            .await
            .unwrap()
            .is_none());
    }

    /// Polled on a timer, so an unchanged policy must be a no-op rather than a
    /// write per tick.
    #[tokio::test]
    async fn reconcile_is_idempotent() {
        let store = Db::init_temp("drive_mapping_idempotent").await.unwrap();
        let want = desired(&[("acme.example.com", "did:ad:acme")]);

        assert_eq!(
            store.sync_drive_mappings(&want).unwrap().added,
            vec!["acme.example.com"]
        );
        for _ in 0..3 {
            assert!(store.sync_drive_mappings(&want).unwrap().is_empty());
        }
    }

    /// The reconcile owns only what it installed. `setup_test_env` binds
    /// `localhost` and `127.0.0.1`, and an operator may have bound a host by
    /// hand through `/bind-drive`; treating the control plane's list as
    /// authoritative for the whole table would delete all of those on the
    /// first poll.
    #[tokio::test]
    async fn reconcile_leaves_bindings_it_did_not_install_alone() {
        let store = Db::init_temp("drive_mapping_scope").await.unwrap();
        setup_test_env(&store).await.unwrap();
        let local_drive = store.get_drive_did("localhost").await.unwrap().unwrap();

        store
            .add_drive_mapping(
                "hand-bound.example.com",
                &Value::AtomicUrl("did:ad:hand-bound".into()),
            )
            .unwrap();

        let report = store
            .sync_drive_mappings(&desired(&[("acme.example.com", "did:ad:acme")]))
            .unwrap();
        assert!(report.removed.is_empty());

        // Both survive a reconcile that names neither.
        assert_eq!(
            store.get_drive_did("localhost").await.unwrap().unwrap(),
            local_drive
        );
        assert!(store
            .get_drive_did("hand-bound.example.com")
            .await
            .unwrap()
            .is_some());
    }

    /// A vanity name the control plane routed here is a host this server
    /// answers for, whatever suffix it sits under; a released one is not.
    #[tokio::test]
    async fn mapped_hosts_are_served_here() {
        let store = Db::init_temp("drive_mapping_served").await.unwrap();
        assert!(!store.has_drive_mapping("ontola.atomic.place"));

        store
            .sync_drive_mappings(&desired(&[("ontola.atomic.place", "did:ad:ontola")]))
            .unwrap();
        assert!(store.has_drive_mapping("ontola.atomic.place"));
        assert!(store.has_drive_mapping("Ontola.Atomic.Place"));
        assert!(!store.has_drive_mapping("evil.atomic.place"));
        assert!(!store.has_drive_mapping(""));

        store.sync_drive_mappings(&desired(&[])).unwrap();
        assert!(!store.has_drive_mapping("ontola.atomic.place"));
    }

    /// Hostnames are case-insensitive, but the `Host` header is echoed in
    /// whatever case the client sent. Without normalization a request for
    /// `ACME.example.com` misses the mapping and falls through to the store
    /// root.
    #[tokio::test]
    async fn mapping_keys_are_case_insensitive() {
        let store = Db::init_temp("drive_mapping_case").await.unwrap();

        store
            .sync_drive_mappings(&desired(&[("ACME.Example.COM", "did:ad:acme")]))
            .unwrap();

        for spelling in ["acme.example.com", "ACME.EXAMPLE.COM", "Acme.Example.Com"] {
            assert_eq!(
                store
                    .get_drive_did(spelling)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("{spelling} should resolve"))
                    .as_str(),
                "did:ad:acme",
            );
        }

        assert_eq!(
            store.list_drive_mappings().unwrap(),
            vec![("acme.example.com".to_string(), "did:ad:acme".to_string())]
        );
    }

    /// A host with no Drive, or a Drive with no host, is a bug upstream. Both
    /// are skipped rather than written: the empty key would match no request,
    /// and an empty Drive would point a live hostname at nothing.
    #[tokio::test]
    async fn reconcile_skips_empty_hosts_and_drives() {
        let store = Db::init_temp("drive_mapping_empty").await.unwrap();

        let report = store
            .sync_drive_mappings(&desired(&[
                ("", "did:ad:nohost"),
                ("nodrive.example.com", "   "),
                ("good.example.com", "did:ad:good"),
            ]))
            .unwrap();

        assert_eq!(report.added, vec!["good.example.com"]);
        assert_eq!(
            store.list_drive_mappings().unwrap(),
            vec![("good.example.com".to_string(), "did:ad:good".to_string())]
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
        let backdated = web_time::Instant::now()
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
        store.set_active_drive(&personal).unwrap();
        let drives = store.list_drives().await.unwrap();
        assert_eq!(drives.len(), 2);
        assert!(drives.iter().any(|d| d.subject == personal));
        assert!(drives
            .iter()
            .any(|d| d.subject == extra && d.name == "Project"));
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod remote_not_found_tests {
    use super::*;
    use crate::Storelike;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves `status` to every request and counts them.
    fn serve(status: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
            }
        });
        (url, hits)
    }

    #[tokio::test]
    async fn a_404_property_is_fetched_once() {
        let db = Db::init_temp("remote_not_found_404").await.unwrap();
        let (server, hits) = serve("404 Not Found");
        let property = format!("{server}/properties/demo/speaker");

        for _ in 0..3 {
            assert!(db.get_property(&property).await.is_err());
        }

        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_404_is_fetched_again() {
        let db = Db::init_temp("remote_not_found_expiry").await.unwrap();
        let (server, hits) = serve("404 Not Found");
        let property = format!("{server}/properties/demo/speaker");

        assert!(db.get_property(&property).await.is_err());
        assert!(db.get_property(&property).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Backdate the entry: it expires now.
        db.remote_not_found
            .lock()
            .unwrap()
            .insert(property.clone(), web_time::Instant::now());

        assert!(db.get_property(&property).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_server_error_is_retried() {
        let db = Db::init_temp("remote_not_found_500").await.unwrap();
        let (server, hits) = serve("500 Internal Server Error");
        let property = format!("{server}/properties/demo/speaker");

        for _ in 0..2 {
            assert!(db.get_property(&property).await.is_err());
        }

        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
