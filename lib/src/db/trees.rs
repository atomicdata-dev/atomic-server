use crate::atoms::IndexAtom;

use super::{
    prop_val_sub_index::{propvalsub_key, propvalsub_legacy_key},
    val_prop_sub_index::{valpropsub_key, valpropsub_legacy_key},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tree {
    /// Full resources, Key: Subject, Value: [Propvals](crate::resources::PropVals)
    Resources,
    /// Stores the members of Collections, easily sortable.
    QueryMembers,
    /// A list of all the Collections currently being used. Is used to update `query_index`.
    WatchedQueries,
    /// Index sorted by {Property}-{Value}-{Subject}.
    /// Used for queries where the property is known.
    PropValSub,
    /// Reference index, used for queries where the value (or one of the values, in case of an array) is known but the subject is not.
    /// Index sorted by {Value}-{Property}-{Subject}.
    ValPropSub,
    /// Stores metadata about installed plugins.
    PluginMeta,
    PluginSecret,
    PluginSchedule,
    PluginTrigger,
    AppAgent,
    /// Maps Drive Hints (short IDs) to full Drive DIDs.
    DriveMapping,
    /// Maps DID pure IDs to their best known routing hint (e.g. drive DID).
    DidMapping,
    /// Stores Loro CRDT snapshots as raw bytes, keyed by resource subject.
    /// Kept separate from Resources because binary data doesn't round-trip through JSON-AD.
    LoroSnapshots,
    /// Content-addressed storage for binary files, keyed by BLAKE3 hash.
    Blobs,
    /// Full-text search postings: `field_id || token || 0x00 || doc_id (8 bytes)` → tf (varint).
    SearchPostings,
    /// Per-document FTS row, keyed by doc id (first 8 bytes of blake3 of the
    /// subject): subject, drive and parent ids, field lengths and the tokens
    /// a delete needs to drop the matching postings.
    SearchDocs,
    /// Trigram → term map for 1-edit candidate generation on longer tokens.
    SearchTrigrams,
    /// Signed commit envelopes kept per resource (the audit floor, F6/F7 in
    /// `planning/completed/commit-retention-floor-decision.md`). Key:
    /// `pure_id || 0x00 || createdAt (u64 BE) || 0x00 || signature`, value: the
    /// commit's JSON-AD exactly as accepted. Not a resource, not indexed, so
    /// it never shows up in queries or `all_resources`. See `crate::envelopes`.
    Envelopes,
    /// The durable outbox: subjects with local writes a hub has not
    /// acknowledged, per signing agent. Key `agent_pure_id || 0x00 ||
    /// subject_pure_id`, value a JSON [`crate::sync::outbox::OutboxEntry`].
    /// See `crate::sync::outbox`.
    Outbox,
}

const RESOURCES: &str = "resources_v3";
const VALPROPSUB: &str = "reference_index_v1";
// v3: QueryFilter key encoding changed to [drive_len][drive_bytes][msgpack rest]
// so the per-atom matching loop can scan_prefix to just the relevant drive's
// watched queries instead of decoding every entry.
// v4: QueryFilter `property`/`value` replaced by `filters: Vec<PropVal>` (AND
// multi-property filtering), which changes the msgpack `rest` encoding.
// Old entries are unreadable with the new decoder — leaving them stranded under
// their old tree name is fine; they're pure caches and rebuild on next query.
// v6: key layout `query_id(16B blake3) || typed sort key || 0x00 0x00 ||
// subject` — compact ids instead of the full serialized filter, and
// order-preserving typed sort keys (numbers finally sort numerically, #287).
const QUERY_MEMBERS: &str = "members_index_v6";
const PROPVALSUB: &str = "prop_val_sub_index";
const QUERIES_WATCHED: &str = "watched_queries_v5";
const PLUGIN_META: &str = "plugin_meta";
const PLUGIN_SECRET: &str = "plugin_secret";
const PLUGIN_SCHEDULE: &str = "plugin_schedule";
const PLUGIN_TRIGGER: &str = "plugin_trigger";
const APP_AGENT: &str = "app_agent";
const DRIVE_MAPPING: &str = "drive_mapping";
const DID_MAPPING: &str = "did_mapping";
const LORO_SNAPSHOTS: &str = "loro_snapshots";
const BLOBS: &str = "blobs";
const SEARCH_POSTINGS: &str = "search_postings_v2";
const SEARCH_DOCS: &str = "search_docs_v2";
const SEARCH_TRIGRAMS: &str = "search_trigrams_v2";
const ENVELOPES: &str = "envelopes_v1";
const OUTBOX: &str = "outbox_v1";

impl Tree {
    /// Every tree, in the order backends create them.
    pub const ALL: [Tree; 19] = [
        Tree::Resources,
        Tree::WatchedQueries,
        Tree::PropValSub,
        Tree::ValPropSub,
        Tree::QueryMembers,
        Tree::PluginMeta,
        Tree::PluginSecret,
        Tree::PluginSchedule,
        Tree::PluginTrigger,
        Tree::AppAgent,
        Tree::DriveMapping,
        Tree::DidMapping,
        Tree::LoroSnapshots,
        Tree::Blobs,
        Tree::SearchPostings,
        Tree::SearchDocs,
        Tree::SearchTrigrams,
        Tree::Envelopes,
        Tree::Outbox,
    ];

    /// The on-disk name of this tree. Every backend (sled tree, redb table)
    /// uses this one name, so bumping a version suffix here is all it takes
    /// to strand old-layout entries.
    pub const fn name(self) -> &'static str {
        match self {
            Tree::Resources => RESOURCES,
            Tree::WatchedQueries => QUERIES_WATCHED,
            Tree::PropValSub => PROPVALSUB,
            Tree::ValPropSub => VALPROPSUB,
            Tree::QueryMembers => QUERY_MEMBERS,
            Tree::PluginMeta => PLUGIN_META,
            Tree::PluginSecret => PLUGIN_SECRET,
            Tree::PluginSchedule => PLUGIN_SCHEDULE,
            Tree::PluginTrigger => PLUGIN_TRIGGER,
            Tree::AppAgent => APP_AGENT,
            Tree::DriveMapping => DRIVE_MAPPING,
            Tree::DidMapping => DID_MAPPING,
            Tree::LoroSnapshots => LORO_SNAPSHOTS,
            Tree::Blobs => BLOBS,
            Tree::SearchPostings => SEARCH_POSTINGS,
            Tree::SearchDocs => SEARCH_DOCS,
            Tree::SearchTrigrams => SEARCH_TRIGRAMS,
            Tree::Envelopes => ENVELOPES,
            Tree::Outbox => OUTBOX,
        }
    }
}

impl std::fmt::Display for Tree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl AsRef<[u8]> for Tree {
    fn as_ref(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

#[derive(Debug, Clone)]
pub enum Method {
    Insert,
    Delete,
}

/// A single operation to be executed on the database.
#[derive(Debug, Clone)]
pub struct Operation {
    pub tree: Tree,
    pub method: Method,
    pub key: Vec<u8>,
    pub val: Option<Vec<u8>>,
}

impl Operation {
    pub fn remove_atom_from_reference_index(index_atom: &IndexAtom) -> Self {
        Operation {
            tree: Tree::ValPropSub,
            method: Method::Delete,
            key: valpropsub_key(index_atom),
            val: None,
        }
    }
    pub fn remove_atom_from_prop_val_sub_index(index_atom: &IndexAtom) -> Self {
        Operation {
            tree: Tree::PropValSub,
            method: Method::Delete,
            key: propvalsub_key(index_atom),
            val: None,
        }
    }

    /// Deletes of the keys an older store wrote for this atom (a sort part that
    /// repeats the reference value), so its rows go when the atom does.
    pub fn remove_atom_from_legacy_indexes(index_atom: &IndexAtom) -> [Self; 2] {
        [
            Operation {
                tree: Tree::ValPropSub,
                method: Method::Delete,
                key: valpropsub_legacy_key(index_atom),
                val: None,
            },
            Operation {
                tree: Tree::PropValSub,
                method: Method::Delete,
                key: propvalsub_legacy_key(index_atom),
                val: None,
            },
        ]
    }

    pub fn remove_resource(subject: &str) -> Self {
        Operation {
            tree: Tree::Resources,
            method: Method::Delete,
            key: subject.as_bytes().to_vec(),
            val: None,
        }
    }

    /// Remove a resource's Loro snapshot. `pure_id` must be the
    /// [`crate::Subject::pure_id`] form — that is the key snapshots are
    /// written under (see `apply_commit` / `add_resource_opts`).
    pub fn remove_loro_snapshot(pure_id: &str) -> Self {
        Operation {
            tree: Tree::LoroSnapshots,
            method: Method::Delete,
            key: pure_id.as_bytes().to_vec(),
            val: None,
        }
    }
}

/// A set of [Operation]s that should be executed atomically by the database.
pub type Transaction = Vec<Operation>;
