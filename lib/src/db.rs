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
mod config;
mod drives;
mod extenders;
mod index;
mod lenses;
mod open;
mod plugins;
mod query;
mod replicate;
mod resources;
mod routing;
#[cfg(feature = "db-sled")]
pub mod sled_store;
mod storelike_impl;
#[cfg(test)]
pub mod test;
#[cfg(test)]
mod tests_drive_mapping;
#[cfg(test)]
mod tests_pending_blob_request_ttl;
#[cfg(test)]
mod tests_private_drive;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests_remote_not_found;
#[cfg(test)]
mod tests_resolver;
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

// Drop is handled by SledStore's own Drop impl which flushes on drop.
// No explicit Drop needed for Db since Arc<dyn KvStore> handles cleanup.

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
