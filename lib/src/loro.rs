//! Loro CRDT integration for Atomic Data.
//!
//! Each Atomic Resource can be backed by a LoroDoc. Properties become named containers
//! within the document. Commits carry Loro binary updates instead of (or in addition to)
//! set/remove/push deltas. The server imports the update, derives add/remove atoms from
//! the diff events, and updates indexes — the read path (JSON-AD) stays unchanged.

use crate::errors::{AtomicError, AtomicResult};
use crate::values::Value;
use crate::Atom;
use loro::{ExportMode, LoroDoc, VersionVector};
use std::ops::ControlFlow;

/// Origin prefix for writes that the undo button should ignore (touches to
/// `dateEdited`, sync-bookkeeping, etc.). Tag a commit with an origin starting
/// with this prefix via [`AtomicLoroDoc::set_next_commit_origin`] and the
/// configured UndoManager will skip it. Kept as a public constant so callers
/// match the same prefix the manager filters on.
pub const SYS_ORIGIN_PREFIX: &str = "sys:";

/// Opaque identifier for a specific version of a resource.
/// Internally wraps Loro's Frontiers.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VersionID(Vec<u8>);

impl VersionID {
    pub fn from_frontiers(f: &loro::Frontiers) -> Self {
        Self(f.encode())
    }

    pub fn to_frontiers(&self) -> AtomicResult<loro::Frontiers> {
        loro::Frontiers::decode(&self.0)
            .map_err(|e| format!("Failed to decode VersionID: {e}").into())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Metadata about a specific historical version (change) in the Loro oplog.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VersionMetadata {
    /// Opaque version identifier (encoded Loro Frontiers).
    pub id: VersionID,
    /// Unix timestamp in seconds (0 if not recorded). Same unit as Loro `ChangeMeta::timestamp`.
    pub timestamp: i64,
    /// The peer that authored this change (Loro PeerID as string).
    pub peer_id: String,
    /// Lamport timestamp — establishes causal order across peers.
    pub lamport: u64,
    /// Number of operations in this change.
    pub len: usize,
    /// Optional commit message attached to the change.
    pub message: Option<String>,
}

/// The founding (genesis) change of a resource's oplog — the source of its
/// creation metadata. See [`AtomicLoroDoc::genesis_change`].
#[derive(Clone, Debug)]
pub struct GenesisChange {
    /// Change timestamp normalised to Unix **milliseconds** (0 if unrecorded).
    pub timestamp: i64,
    /// Lamport timestamp — used to tie-break changes sharing a timestamp.
    pub lamport: u64,
    /// Commit message attached to the change. The client writes the signing
    /// agent's subject here at genesis, so it carries `createdBy`.
    pub message: Option<String>,
}

/// Coerce a Loro change timestamp to Unix **milliseconds**. Loro's own
/// auto-recording uses seconds, but we stamp commits with millisecond
/// precision (Loro orders changes by lamport, not timestamp, so a finer
/// timestamp is safe). Values already in milliseconds (≥ 1e12, i.e. any time
/// after 2001 in ms) pass through; second-resolution values are scaled up. A
/// single oplog can carry both conventions (legacy snapshots, mixed peers),
/// so always normalise before comparing or materialising.
pub fn normalize_change_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp >= 1_000_000_000_000 {
        timestamp
    } else {
        timestamp * 1000
    }
}

/// Wraps a LoroDoc for an Atomic Resource, providing helpers to convert between
/// Atomic Data property/value pairs and Loro containers.
pub struct AtomicLoroDoc {
    doc: LoroDoc,
    /// Lazily initialized undo manager. Only created when undo/redo is needed.
    undo_manager: std::sync::Mutex<Option<loro::UndoManager>>,
}

impl std::fmt::Debug for AtomicLoroDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicLoroDoc")
            .field("peer_id", &self.doc.peer_id())
            .finish()
    }
}

/// The result of applying a Loro update to a document.
/// Contains the atom-level diff needed to update indexes.
pub struct LoroDiff {
    pub add_atoms: Vec<Atom>,
    pub remove_atoms: Vec<Atom>,
}

impl AtomicLoroDoc {
    /// Create a new empty LoroDoc for a resource.
    pub fn new() -> Self {
        let doc = LoroDoc::new();
        // Enable timestamps for history scrubbing
        doc.set_record_timestamp(true);
        Self {
            doc,
            undo_manager: std::sync::Mutex::new(None),
        }
    }

    /// Create from an existing snapshot (e.g. loaded from the database).
    pub fn from_snapshot(snapshot: &[u8]) -> AtomicResult<Self> {
        let doc = LoroDoc::new();
        doc.set_record_timestamp(true);
        doc.import(snapshot)
            .map_err(|e| format!("Failed to import Loro snapshot: {e}"))?;
        Ok(Self {
            doc,
            undo_manager: std::sync::Mutex::new(None),
        })
    }

    /// Set the peer ID for subsequent operations. Mainly useful for tests that
    /// need a deterministic LWW tiebreak between concurrent peers.
    pub fn set_peer_id(&self, peer: u64) -> AtomicResult<()> {
        self.doc
            .set_peer_id(peer)
            .map_err(|e| format!("Failed to set Loro peer ID: {e}").into())
    }

    /// Import a binary update (from a commit's loroUpdate field).
    pub fn import_update(&self, update: &[u8]) -> AtomicResult<()> {
        self.doc
            .import(update)
            .map_err(|e| format!("Failed to import Loro update: {e}"))?;
        Ok(())
    }

    /// Export a snapshot of the full document state.
    pub fn export_snapshot(&self) -> Vec<u8> {
        self.doc.export(ExportMode::Snapshot).unwrap()
    }

    /// Export only the updates since a given version.
    pub fn export_updates_since(&self, version: &VersionVector) -> Vec<u8> {
        self.doc.export(ExportMode::updates(version)).unwrap()
    }

    /// Returns the current version of the document.
    pub fn current_version(&self) -> VersionID {
        VersionID::from_frontiers(&self.doc.state_frontiers())
    }

    /// An independent document, as this one was at `version`.
    ///
    /// Prefer this over [Self::checkout] for reads: the receiver keeps its
    /// place, so time-travelling does not strand whoever else is holding it.
    pub fn fork_at(&self, version: &VersionID) -> AtomicResult<Self> {
        let frontiers = version.to_frontiers()?;
        let doc = self
            .doc
            .fork_at(&frontiers)
            .map_err(|e| AtomicError::other_error(format!("Loro fork error: {e}")))?;
        doc.set_record_timestamp(true);

        Ok(Self {
            doc,
            undo_manager: std::sync::Mutex::new(None),
        })
    }

    /// Moves the document to a historical version.
    /// The doc enters a "detached" read-only state.
    pub fn checkout(&self, version: &VersionID) -> AtomicResult<()> {
        let f = version.to_frontiers()?;
        self.doc
            .checkout(&f)
            .map_err(|e| format!("Loro checkout error: {e}").into())
    }

    /// Returns the document to the latest version and enables editing.
    pub fn attach(&self) -> AtomicResult<()> {
        self.doc.checkout_to_latest();
        Ok(())
    }

    /// Returns a list of all historical versions (changes) in the document,
    /// sorted by timestamp descending (newest first).
    ///
    /// Each entry represents a change made by a peer, with its version ID,
    /// timestamp, peer ID, and operation count.
    pub fn get_history(&self) -> Vec<VersionMetadata> {
        let mut history = Vec::new();
        let frontier_ids: Vec<loro::ID> = self.doc.oplog_frontiers().iter().collect();

        if frontier_ids.is_empty() {
            return history;
        }

        let _ = self
            .doc
            .travel_change_ancestors(&frontier_ids, &mut |change| {
                // A change is identified by its *first* op, but a version means
                // the state that change produced — so the id has to point at its
                // last op. Pointing at the first op reads the change as only
                // partly applied: for the oldest change, that is an almost empty
                // document.
                let last_op = loro::ID::new(
                    change.id.peer,
                    change.id.counter + change.len.saturating_sub(1) as i32,
                );
                let id = VersionID::from_frontiers(&loro::Frontiers::from_id(last_op));
                history.push(VersionMetadata {
                    id,
                    timestamp: change.timestamp,
                    peer_id: change.id.peer.to_string(),
                    lamport: change.lamport as u64,
                    len: change.len,
                    message: change.message.map(|m| m.to_string()),
                });
                ControlFlow::Continue(())
            });

        // travel_change_ancestors yields in reverse lamport order (newest first),
        // but sort explicitly by timestamp for consistent output. Timestamps are
        // whole seconds, so edits made in quick succession share one — lamport
        // breaks the tie, being the causal order the timestamp only approximates.
        history.sort_by(|a, b| {
            b.timestamp
                .cmp(&a.timestamp)
                .then(b.lamport.cmp(&a.lamport))
        });
        history
    }

    /// The founding (genesis) change in the oplog: the causally-first change,
    /// i.e. the one with the lowest Lamport timestamp. Creation metadata
    /// (`createdAt` from its timestamp, `createdBy` from its commit message) is
    /// derived from it — the change travels inside the resource's own Loro doc,
    /// so no commit resource is needed. Returns `None` for an empty oplog.
    ///
    /// Selection is by **Lamport, not wall-clock timestamp**: server-authored
    /// follow-up changes (e.g. setting `lastCommit` after apply) carry a
    /// second-resolution timestamp that can sort *before* the client's
    /// millisecond-precise genesis within the same second, which would
    /// mis-pick a later, message-less change as the genesis. Lamport is the
    /// causal order — the founding change is always the minimum.
    pub fn genesis_change(&self) -> Option<GenesisChange> {
        let frontier_ids: Vec<loro::ID> = self.doc.oplog_frontiers().iter().collect();

        if frontier_ids.is_empty() {
            return None;
        }

        let mut genesis: Option<GenesisChange> = None;

        let _ = self
            .doc
            .travel_change_ancestors(&frontier_ids, &mut |change| {
                // Select by Lamport (causal order); the founding change is the
                // minimum. timestamp is kept only for `createdAt`, normalised to
                // ms.
                let timestamp = normalize_change_timestamp_ms(change.timestamp);
                let lamport = change.lamport as u64;
                let is_earlier = match &genesis {
                    None => true,
                    Some(g) => lamport < g.lamport,
                };

                if is_earlier {
                    genesis = Some(GenesisChange {
                        timestamp,
                        lamport,
                        message: change.message.map(|m| m.to_string()),
                    });
                }

                ControlFlow::Continue(())
            });

        genesis
    }

    /// Returns the properties at a specific historical version without
    /// mutating the document's checkout state. Creates a fork of the doc
    /// at the requested version and reads all properties.
    pub fn get_properties_at(
        &self,
        version: &VersionID,
    ) -> AtomicResult<std::collections::HashMap<String, loro::LoroValue>> {
        let frontiers = version.to_frontiers()?;
        let fork = self
            .doc
            .fork_at(&frontiers)
            .map_err(|err| AtomicError::other_error(err.to_string()))?;
        let root = fork.get_map("properties");
        let mut result = std::collections::HashMap::new();
        root.for_each(|key: &str, value: loro::ValueOrContainer| {
            result.insert(key.to_string(), value.get_deep_value());
        });
        Ok(result)
    }

    /// Get the oplog version vector as a serializable map (peer_id → counter).
    pub fn oplog_vv_map(&self) -> std::collections::HashMap<String, i32> {
        self.doc
            .oplog_vv()
            .iter()
            .map(|(peer_id, counter)| (peer_id.to_string(), *counter))
            .collect()
    }

    /// Extract the version vector from a snapshot blob WITHOUT importing /
    /// reconstructing the document.
    ///
    /// For a full `ExportMode::Snapshot` blob (how we persist Loro state),
    /// `ImportBlobMetadata::partial_end_vv` is the complete oplog version
    /// vector — i.e. identical to `from_snapshot(..).oplog_vv_map()` — but this
    /// only parses the blob header instead of rebuilding the whole CRDT doc.
    /// `getAllVersionVectors` calls this once per resource at sync time, so on a
    /// large drive the difference is hundreds of ms of avoided work.
    pub fn vv_map_from_snapshot(
        snapshot: &[u8],
    ) -> AtomicResult<std::collections::HashMap<String, i32>> {
        let meta = LoroDoc::decode_import_blob_meta(snapshot, false)
            .map_err(|e| format!("Failed to decode Loro blob meta: {e}"))?;
        Ok(meta
            .partial_end_vv
            .iter()
            .map(|(peer_id, counter)| (peer_id.to_string(), *counter))
            .collect())
    }

    /// Messages of the changes this doc holds inside `[start, end)` per peer,
    /// i.e. the changes an update with that blob range introduced. Reading
    /// them here, from a doc that already has the update's dependencies,
    /// is what makes it work for a delta: importing a delta into an empty
    /// doc leaves it pending (missing deps) and shows no changes at all.
    pub fn change_messages_in(&self, start: &VersionVector, end: &VersionVector) -> Vec<String> {
        let mut messages = Vec::new();
        let frontier_ids: Vec<loro::ID> = self.doc.oplog_frontiers().iter().collect();
        if frontier_ids.is_empty() {
            return messages;
        }
        let _ = self
            .doc
            .travel_change_ancestors(&frontier_ids, &mut |change| {
                let peer = change.id.peer;
                let from = start.get(&peer).copied().unwrap_or(0);
                let to = end.get(&peer).copied().unwrap_or(0);
                let change_end = change.id.counter + change.len as i32;
                // Overlap with [from, to): a change is one commit boundary,
                // so any overlap means this update carried it.
                if change.id.counter < to && change_end > from {
                    if let Some(message) = change.message.as_ref() {
                        let message = message.to_string();
                        if !messages.contains(&message) {
                            messages.push(message);
                        }
                    }
                }
                ControlFlow::Continue(())
            });
        messages
    }

    /// The `[start, end)` version range an update or snapshot blob covers.
    pub fn update_range(update: &[u8]) -> AtomicResult<(VersionVector, VersionVector)> {
        let meta = LoroDoc::decode_import_blob_meta(update, false)
            .map_err(|e| format!("Failed to decode Loro blob meta: {e}"))?;
        Ok((meta.partial_start_vv, meta.partial_end_vv))
    }

    /// Get the raw oplog version vector.
    pub fn oplog_vv(&self) -> VersionVector {
        self.doc.oplog_vv()
    }

    /// Encode the version vector to bytes (for hashing).
    pub fn oplog_vv_bytes(&self) -> Vec<u8> {
        self.doc.oplog_vv().encode()
    }

    /// Build a VersionVector from a map of peer_id_string → counter.
    pub fn vv_from_map(map: &std::collections::HashMap<String, i32>) -> VersionVector {
        map.iter()
            .filter_map(|(peer_str, &counter)| {
                peer_str.parse::<u64>().ok().map(|pid| (pid, counter))
            })
            .collect()
    }

    /// Get a reference to the inner LoroDoc.
    pub fn doc(&self) -> &LoroDoc {
        &self.doc
    }

    /// Set a property on the root map of the document.
    /// This is the Loro equivalent of a `set` in a commit.
    pub fn set_property(&self, property: &str, value: &Value) -> AtomicResult<()> {
        let root = self.doc.get_map("properties");
        // Record a datatype tag in a sibling `datatypes` map so
        // materialization need not guess the
        // `Value` variant from the bare primitive. Covers reference/shape
        // cases (ref strings, lists, nested objects) and the cosmetic
        // string-likes (`Markdown`/`Slug`/`Uri`/`Date`/`Timestamp`) — see
        // [`datatype_tag`]. Plain `String` stays untagged as the default.
        if let Some(tag) = datatype_tag(value) {
            self.doc
                .get_map("datatypes")
                .insert(property, tag)
                .map_err(|e| format!("Loro datatype tag error: {e}"))?;
        }
        match value {
            Value::String(s) | Value::Markdown(s) | Value::Slug(s) | Value::Date(s) => {
                root.insert(property, s.as_str())
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
            Value::Integer(i) | Value::Timestamp(i) => {
                root.insert(property, *i)
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
            Value::Float(f) => {
                root.insert(property, *f)
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
            Value::Boolean(b) => {
                root.insert(property, *b)
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
            Value::AtomicUrl(subject) => {
                root.insert(property, subject.to_string().as_str())
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
            Value::Uri(s) => {
                root.insert(property, s.as_str())
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
            Value::ResourceArray(arr) => {
                // Use native LoroList for arrays — enables per-element CRDT merge.
                let list = root
                    .insert_container(property, loro::LoroList::new())
                    .map_err(|e| format!("Loro insert_container error: {e}"))?;

                for item in arr {
                    list.push(item.to_string())
                        .map_err(|e| format!("Loro list push error: {e}"))?;
                }
            }
            Value::Json(json_val) => match json_val {
                serde_json::Value::Object(_) => {
                    let map = root
                        .insert_container(property, loro::LoroMap::new())
                        .map_err(|e| format!("Loro insert_container error: {e}"))?;
                    json_value_to_loro_map(json_val, &map)?;
                }
                serde_json::Value::Array(arr) => {
                    let list = root
                        .insert_container(property, loro::LoroList::new())
                        .map_err(|e| format!("Loro insert_container error: {e}"))?;
                    for item in arr {
                        json_value_to_loro_list_item(item, &list)?;
                    }
                }
                serde_json::Value::String(s) => {
                    root.insert(property, s.as_str())
                        .map_err(|e| format!("Loro set error: {e}"))?;
                }
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        root.insert(property, i)
                            .map_err(|e| format!("Loro set error: {e}"))?;
                    } else if let Some(f) = n.as_f64() {
                        root.insert(property, f)
                            .map_err(|e| format!("Loro set error: {e}"))?;
                    }
                }
                serde_json::Value::Bool(b) => {
                    root.insert(property, *b)
                        .map_err(|e| format!("Loro set error: {e}"))?;
                }
                serde_json::Value::Null => {
                    root.insert(property, loro::LoroValue::Null)
                        .map_err(|e| format!("Loro set error: {e}"))?;
                }
            },
            Value::LocalizedText(translations) => {
                // Native LoroMap keyed by language tag — each language is its
                // own LWW register, so concurrent edits to different
                // languages merge cleanly.
                let map = root
                    .insert_container(property, loro::LoroMap::new())
                    .map_err(|e| format!("Loro insert_container error: {e}"))?;
                for (tag, s) in translations {
                    map.insert(tag, s.as_str())
                        .map_err(|e| format!("Loro map insert error: {e}"))?;
                }
            }
            _ => {
                // For other complex types, serialize the display string.
                root.insert(property, value.to_string().as_str())
                    .map_err(|e| format!("Loro set error: {e}"))?;
            }
        }
        Ok(())
    }

    /// Push a JSON item to a property's LoroList.
    /// Creates the list if it doesn't exist. Does NOT replace existing items.
    pub fn push_to_loro_list(&self, property: &str, item: &serde_json::Value) -> AtomicResult<()> {
        let root = self.doc.get_map("properties");

        // Get or create the LoroList for this property
        let list = match root.get(property) {
            Some(loro::ValueOrContainer::Container(c)) => c
                .into_list()
                .map_err(|_| format!("{property} is not a list"))?,
            _ => root
                .insert_container(property, loro::LoroList::new())
                .map_err(|e| format!("Loro insert_container error: {e}"))?,
        };

        json_value_to_loro_list_item(item, &list)?;
        Ok(())
    }

    /// Clear all items from a property's LoroList.
    pub fn clear_loro_list(&self, property: &str) -> AtomicResult<()> {
        let root = self.doc.get_map("properties");
        if let Some(loro::ValueOrContainer::Container(c)) = root.get(property) {
            if let Ok(list) = c.into_list() {
                let len = list.len();
                if len > 0 {
                    list.delete(0, len)
                        .map_err(|e| format!("Loro list delete error: {e}"))?;
                }
            }
        }
        Ok(())
    }

    /// Insert a JSON item at a specific index in a property's LoroList.
    pub fn insert_into_loro_list(
        &self,
        property: &str,
        index: usize,
        item: &serde_json::Value,
    ) -> AtomicResult<()> {
        let root = self.doc.get_map("properties");
        match root.get(property) {
            Some(loro::ValueOrContainer::Container(c)) => {
                let list = c
                    .into_list()
                    .map_err(|_| format!("{property} is not a list"))?;
                if index > list.len() {
                    return Err(format!(
                        "Index {index} out of bounds for {property} (len {})",
                        list.len()
                    )
                    .into());
                }
                insert_json_value_into_loro_list(item, &list, index)?;
                Ok(())
            }
            _ => Err(format!("{property} is not a list container").into()),
        }
    }

    /// Delete an item at a specific index from a property's LoroList.
    pub fn delete_from_loro_list(&self, property: &str, index: usize) -> AtomicResult<()> {
        let root = self.doc.get_map("properties");
        match root.get(property) {
            Some(loro::ValueOrContainer::Container(c)) => {
                let list = c
                    .into_list()
                    .map_err(|_| format!("{property} is not a list"))?;
                if index >= list.len() {
                    return Err(format!(
                        "Index {index} out of bounds for {property} (len {})",
                        list.len()
                    )
                    .into());
                }
                list.delete(index, 1)
                    .map_err(|e| format!("Loro list delete error: {e}"))?;
                Ok(())
            }
            _ => Err(format!("{property} is not a list container").into()),
        }
    }

    /// Ensure the UndoManager is initialized. Call before mutations that
    /// should be undoable. Subsequent calls are no-ops.
    pub fn ensure_undo_manager(&self) {
        let mut guard = self.undo_manager.lock().unwrap();
        if guard.is_none() {
            let mut um = loro::UndoManager::new(&self.doc);
            um.set_max_undo_steps(200);
            // Each top-level operation (push_stroke, delete_stroke) is its own
            // undo step — don't merge based on time.
            um.set_merge_interval(0);
            // Skip system-managed writes (e.g. `dateEdited` touches, sync
            // bookkeeping) so they never form their own undo group. Without
            // this, drawing a stroke + touching `dateEdited` would take two
            // undo taps to revert: the first reverts the date tick and looks
            // like a no-op to the user, the second finally removes the stroke.
            // Match by prefix so callers can scope it (`sys:date_edited`, etc.).
            um.add_exclude_origin_prefix(SYS_ORIGIN_PREFIX);
            *guard = Some(um);
        }
    }

    /// Tag the next [`Self::commit`] with an origin so the UndoManager can
    /// classify it. Use [`SYS_ORIGIN_PREFIX`]-prefixed origins for writes
    /// that should not be reachable by the user's undo button.
    pub fn set_next_commit_origin(&self, origin: &str) {
        self.doc.set_next_commit_origin(origin);
    }

    /// Commit the pending transaction with an explicit origin. Equivalent
    /// to [`Self::set_next_commit_origin`] followed by [`Self::commit`],
    /// but uses Loro's `commit_with(CommitOptions)` so the origin is bound
    /// to *this* commit even if other code paths drove an auto-commit in
    /// between.
    pub fn commit_with_origin(&self, origin: &str) {
        self.doc
            .commit_with(loro::CommitOptions::new().origin(origin));
    }

    /// Finalize pending Loro edits so they enter the oplog (required for undo + sync export).
    pub fn commit(&self) {
        self.doc.commit();
    }

    /// Commit the pending edits as a change carrying `message`.
    ///
    /// The message also keeps this change separate: Loro merges adjacent
    /// changes by the same peer within the same second, so edits committed
    /// without one collapse into a single change — and a single version, since
    /// [crate::history] reads changes. Clients tag every edit for this reason.
    pub fn commit_with_message(&self, message: &str) {
        self.doc
            .commit_with(loro::CommitOptions::new().commit_msg(message));
    }

    /// Record a checkpoint so that subsequent operations form a new undo group.
    pub fn checkpoint(&self) -> AtomicResult<()> {
        self.ensure_undo_manager();
        let mut guard = self.undo_manager.lock().unwrap();
        if let Some(um) = guard.as_mut() {
            um.record_new_checkpoint()
                .map_err(|e| format!("Loro checkpoint error: {e}"))?;
        }
        Ok(())
    }

    /// Undo the last local operation. Returns true if something was undone.
    pub fn undo(&self) -> AtomicResult<bool> {
        self.ensure_undo_manager();
        let mut guard = self.undo_manager.lock().unwrap();
        match guard.as_mut() {
            Some(um) if um.can_undo() => um
                .undo()
                .map_err(|e| format!("Loro undo error: {e}").into()),
            _ => Ok(false),
        }
    }

    /// Redo the last undone operation. Returns true if something was redone.
    pub fn redo(&self) -> AtomicResult<bool> {
        self.ensure_undo_manager();
        let mut guard = self.undo_manager.lock().unwrap();
        match guard.as_mut() {
            Some(um) if um.can_redo() => um
                .redo()
                .map_err(|e| format!("Loro redo error: {e}").into()),
            _ => Ok(false),
        }
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        self.undo_manager
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|um| um.can_undo()))
            .unwrap_or(false)
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        self.undo_manager
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|um| um.can_redo()))
            .unwrap_or(false)
    }

    /// Remove a property from the root map.
    pub fn remove_property(&self, property: &str) -> AtomicResult<()> {
        let root = self.doc.get_map("properties");
        root.delete(property)
            .map_err(|e| format!("Loro remove error: {e}"))?;
        Ok(())
    }

    /// Get a string property from the root map.
    pub fn get_string_property(&self, property: &str) -> Option<String> {
        let root = self.doc.get_map("properties");
        root.get(property)
            .and_then(|v| v.into_value().ok())
            .and_then(|v| match v {
                loro::LoroValue::String(s) => Some(s.to_string()),
                _ => None,
            })
    }

    /// Get an integer property from the root map.
    pub fn get_integer_property(&self, property: &str) -> Option<i64> {
        let root = self.doc.get_map("properties");
        root.get(property)
            .and_then(|v| v.into_value().ok())
            .and_then(|v| match v {
                loro::LoroValue::I64(i) => Some(i),
                _ => None,
            })
    }

    /// Extract plain text from a Document-v2 body for search indexing.
    ///
    /// Reads the loro-prosemirror `doc` root map first, then falls back to a
    /// top-level `documentContent` text container.
    pub fn extract_document_plain_text(&self) -> String {
        let doc = self.doc();

        if let Some(pm_map) = doc.try_get_map("doc") {
            let deep = pm_map.get_deep_value();
            let json = loro_value_to_json(&deep);
            let text = extract_text_from_prosemirror_json(&json);
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return collapse_whitespace(trimmed);
            }
        }

        if let Some(text_container) = doc.try_get_text("documentContent") {
            let trimmed = text_container.to_string().trim().to_string();
            if !trimmed.is_empty() {
                return collapse_whitespace(&trimmed);
            }
        }

        String::new()
    }

    /// Get all properties from the root map as a HashMap of LoroValues.
    pub fn get_all_properties(&self) -> std::collections::HashMap<String, loro::LoroValue> {
        let root = self.doc.get_map("properties");
        let mut result = std::collections::HashMap::new();
        root.for_each(|key, value| {
            match value.into_value() {
                Ok(v) => {
                    result.insert(key.to_string(), v);
                }
                Err(container) => {
                    // Container types (LoroList, LoroMap, etc.) — get their deep value.
                    result.insert(key.to_string(), container.get_deep_value());
                }
            }
        });
        result
    }

    /// Read the sibling `datatypes` map: `property_url → datatype tag`.
    /// Only load-bearing properties (reference strings, lists, nested
    /// objects) have an entry — see [`datatype_tag`]. Used by
    /// materialization to recover the exact `Value` variant without guessing.
    pub fn get_all_datatypes(&self) -> std::collections::HashMap<String, String> {
        let root = self.doc.get_map("datatypes");
        let mut result = std::collections::HashMap::new();
        root.for_each(|key, value| {
            if let Ok(loro::LoroValue::String(s)) = value.into_value() {
                result.insert(key.to_string(), s.to_string());
            }
        });
        result
    }

    /// Import an update and compute the diff as add/remove atoms.
    /// Compares the properties map before and after the import.
    pub fn import_update_with_diff(&self, update: &[u8], subject: &str) -> AtomicResult<LoroDiff> {
        let before = self.get_all_properties();
        self.import_update(update)?;
        let after = self.get_all_properties();
        // Tags are per-property and stable; one read after the import covers
        // both the before and after value of every property.
        let datatypes = self.get_all_datatypes();
        let tag_of = |key: &str| datatypes.get(key).map(String::as_str);

        let mut add_atoms = Vec::new();
        let mut remove_atoms = Vec::new();

        // Check for added/changed properties
        for (key, new_val) in &after {
            match before.get(key) {
                Some(old_val) if old_val != new_val => {
                    // Changed: remove old, add new
                    if let Some(old_v) = loro_value_to_atomic_value_tagged(old_val, tag_of(key)) {
                        remove_atoms.push(Atom::new(subject.into(), key.clone(), old_v));
                    }
                    if let Some(new_v) = loro_value_to_atomic_value_tagged(new_val, tag_of(key)) {
                        add_atoms.push(Atom::new(subject.into(), key.clone(), new_v));
                    }
                }
                None => {
                    // Added
                    if let Some(new_v) = loro_value_to_atomic_value_tagged(new_val, tag_of(key)) {
                        add_atoms.push(Atom::new(subject.into(), key.clone(), new_v));
                    }
                }
                _ => {} // Unchanged
            }
        }

        // Check for removed properties
        for (key, old_val) in &before {
            if !after.contains_key(key) {
                if let Some(old_v) = loro_value_to_atomic_value_tagged(old_val, tag_of(key)) {
                    remove_atoms.push(Atom::new(subject.into(), key.clone(), old_v));
                }
            }
        }

        Ok(LoroDiff {
            add_atoms,
            remove_atoms,
        })
    }
}

/// The `datatypes`-map tag for a `Value`, or `None` for values whose Loro
/// primitive already pins the variant (`Integer`/`Float`/`Boolean`) or which
/// is a plain `String` (the untagged default).
///
/// Two groups are tagged:
/// - **Reference / shape** (`atomicUrl`, `resourceArray`, `json`, `resource`):
///   genuinely *cannot* be recovered from the Loro primitive — a `String` may
///   be a ref or plain text, a `List` may hold subjects or JSON.
/// - **Cosmetic string-likes** (`markdown`, `slug`, `uri`, `date`) and
///   `timestamp`: collapse to the same primitive as `String`/`Integer`, but at
///   least one consumer (vector / search text extraction) branches on the
///   variant, so we preserve them rather than guess. Plain `String` stays
///   untagged as the default.
pub fn datatype_tag(value: &Value) -> Option<&'static str> {
    match value {
        Value::AtomicUrl(_) => Some("atomicUrl"),
        Value::ResourceArray(_) => Some("resourceArray"),
        Value::Json(_) => Some("json"),
        Value::LocalizedText(_) => Some("localizedText"),
        Value::NestedResource(_) => Some("resource"),
        Value::Markdown(_) => Some("markdown"),
        Value::Slug(_) => Some("slug"),
        Value::Uri(_) => Some("uri"),
        Value::Date(_) => Some("date"),
        Value::Timestamp(_) => Some("timestamp"),
        _ => None,
    }
}

/// Materialize a Loro value, using the `datatypes` tag when present.
/// Falls back to [`loro_value_to_atomic_value`]'s heuristics for untagged
/// values — legacy snapshots and docs written by clients that do not yet
/// emit the `datatypes` map.
pub fn loro_value_to_atomic_value_tagged(lv: &loro::LoroValue, tag: Option<&str>) -> Option<Value> {
    if let Some(tag) = tag {
        if let Some(v) = atomic_value_from_tag(lv, tag) {
            return Some(v);
        }
        // Tag present but the primitive shape did not match it — fall
        // through to the heuristic rather than dropping the value.
    }
    loro_value_to_atomic_value(lv)
}

/// Reconstruct the exact `Value` variant from a primitive plus its tag.
/// Returns `None` if the tag and primitive shape disagree (caller falls back).
fn atomic_value_from_tag(lv: &loro::LoroValue, tag: &str) -> Option<Value> {
    match (tag, lv) {
        ("atomicUrl", loro::LoroValue::String(s)) => Some(Value::AtomicUrl(s.to_string().into())),
        ("json", lv) => {
            if let loro::LoroValue::String(s) = lv {
                if let Ok(parsed) = serde_json::from_str(s.as_ref()) {
                    return Some(Value::Json(parsed));
                }
            }
            Some(Value::Json(loro_value_to_json(lv)))
        }
        ("resource", loro::LoroValue::String(s)) => {
            serde_json::from_str::<std::collections::HashMap<String, Value>>(s.as_ref())
                .ok()
                .map(|obj| Value::NestedResource(crate::values::SubResource::Nested(obj)))
        }
        ("localizedText", lv) => {
            // Written as a native LoroMap by current clients; tolerate a
            // JSON-stringified object from older writers (same as `json`).
            if let loro::LoroValue::String(s) = lv {
                let parsed = serde_json::from_str::<serde_json::Value>(s.as_ref()).ok()?;
                return Value::localized_text_from_json(&parsed).ok();
            }
            let json = loro_value_to_json(lv);
            Value::localized_text_from_json(&json).ok()
        }
        ("resourceArray", loro::LoroValue::List(items)) => {
            let subjects: Vec<crate::values::SubResource> = items
                .iter()
                .filter_map(|item| match item {
                    loro::LoroValue::String(s) => Some(s.to_string().into()),
                    _ => None,
                })
                .collect();
            Some(Value::ResourceArray(subjects))
        }
        // Cosmetic string-likes: same primitive as a plain String, recovered
        // to their variant via the tag.
        ("markdown", loro::LoroValue::String(s)) => Some(Value::Markdown(s.to_string())),
        ("slug", loro::LoroValue::String(s)) => Some(Value::Slug(s.to_string())),
        ("uri", loro::LoroValue::String(s)) => Some(Value::Uri(s.to_string())),
        ("date", loro::LoroValue::String(s)) => Some(Value::Date(s.to_string())),
        ("timestamp", loro::LoroValue::I64(i)) => Some(Value::Timestamp(*i)),
        _ => None,
    }
}

/// Convert a Loro value to an Atomic Data Value.
pub fn loro_value_to_atomic_value(lv: &loro::LoroValue) -> Option<Value> {
    match lv {
        loro::LoroValue::String(s) => {
            let s = s.to_string();

            // Legacy: try to detect JSON-encoded arrays from older Loro docs
            if s.starts_with('[') {
                if let Ok(arr) = serde_json::from_str::<Vec<String>>(&s) {
                    let subjects: Vec<crate::values::SubResource> =
                        arr.into_iter().map(|v| v.into()).collect();
                    return Some(Value::ResourceArray(subjects));
                }
            }

            // Legacy: try to detect JSON-encoded objects from older Loro docs
            if s.starts_with('{') {
                if let Ok(obj) =
                    serde_json::from_str::<std::collections::HashMap<String, Value>>(&s)
                {
                    return Some(Value::NestedResource(crate::values::SubResource::Nested(
                        obj,
                    )));
                }
            }

            // Loro stores URLs/DIDs as plain strings. Restore them as
            // AtomicUrl so downstream consumers (extenders, validators)
            // that pattern-match on `Value::AtomicUrl` see them correctly.
            // Without this, e.g. plugin extender's `resource.get(parent)`
            // returns `Value::String` and rejects the commit.
            if s.starts_with("did:") || s.starts_with("http://") || s.starts_with("https://") {
                return Some(Value::AtomicUrl(s.into()));
            }

            // Untagged fallback only: tagged docs recover Slug/Markdown/Uri/Date
            // via `atomic_value_from_tag` (#1217). A bare untagged
            // string (legacy snapshot / pre-tag write) collapses to String.
            Some(Value::String(s))
        }
        loro::LoroValue::I64(i) => Some(Value::Integer(*i)),
        loro::LoroValue::Double(f) => Some(Value::Float(*f)),
        loro::LoroValue::Bool(b) => Some(Value::Boolean(*b)),
        loro::LoroValue::Null => None,
        loro::LoroValue::List(items) => {
            if items.is_empty() {
                // Empty list: the property is set, just has no elements yet.
                // Default to ResourceArray since that's by far the more common
                // shape and required-but-empty array props (e.g.
                // SelectProperty.allowsOnly during dialog creation) need to
                // round-trip into propvals so check_required_props sees them.
                return Some(Value::ResourceArray(vec![]));
            }

            // Check the first item to determine list type:
            // - Map / primitive JSON items → Json (native LoroList elements)
            // - String items → ResourceArray or legacy Json
            match &items[0] {
                loro::LoroValue::Map(_) => {
                    // Native LoroMaps → Json
                    let json_items: Vec<serde_json::Value> =
                        items.iter().map(loro_value_to_json).collect();
                    Some(Value::Json(serde_json::Value::Array(json_items)))
                }
                loro::LoroValue::I64(_)
                | loro::LoroValue::Double(_)
                | loro::LoroValue::Bool(_)
                | loro::LoroValue::Null
                | loro::LoroValue::List(_) => {
                    let json_items: Vec<serde_json::Value> =
                        items.iter().map(loro_value_to_json).collect();
                    Some(Value::Json(serde_json::Value::Array(json_items)))
                }
                loro::LoroValue::String(first_s) => {
                    let first = first_s.to_string();
                    let trimmed = first.trim_start();
                    if trimmed.starts_with('{') || trimmed.starts_with('[') {
                        // Legacy: JSON strings in list → Json
                        let json_items: Vec<serde_json::Value> = items
                            .iter()
                            .filter_map(|item| match item {
                                loro::LoroValue::String(s) => serde_json::from_str(s.as_ref()).ok(),
                                _ => None,
                            })
                            .collect();
                        if json_items.is_empty() {
                            None
                        } else {
                            Some(Value::Json(serde_json::Value::Array(json_items)))
                        }
                    } else {
                        // ResourceArray: plain URL strings
                        let subjects: Vec<crate::values::SubResource> = items
                            .iter()
                            .filter_map(|item| match item {
                                loro::LoroValue::String(s) => Some(s.to_string().into()),
                                _ => None,
                            })
                            .collect();
                        if subjects.is_empty() {
                            None
                        } else {
                            Some(Value::ResourceArray(subjects))
                        }
                    }
                }
                _ => None,
            }
        }
        loro::LoroValue::Map(m) => {
            // Single map → JSON object
            Some(Value::Json(loro_value_to_json(&loro::LoroValue::Map(
                m.clone(),
            ))))
        }
        _ => None,
    }
}

/// Write a serde_json::Value into a LoroMap. Handles nested objects and arrays.
fn json_value_to_loro_map(json: &serde_json::Value, map: &loro::LoroMap) -> AtomicResult<()> {
    if let serde_json::Value::Object(obj) = json {
        for (key, val) in obj {
            match val {
                serde_json::Value::String(s) => {
                    map.insert(key, s.as_str())
                        .map_err(|e| format!("Loro map insert error: {e}"))?;
                }
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        map.insert(key, i)
                            .map_err(|e| format!("Loro map insert error: {e}"))?;
                    } else if let Some(f) = n.as_f64() {
                        map.insert(key, f)
                            .map_err(|e| format!("Loro map insert error: {e}"))?;
                    }
                }
                serde_json::Value::Bool(b) => {
                    map.insert(key, *b)
                        .map_err(|e| format!("Loro map insert error: {e}"))?;
                }
                serde_json::Value::Array(arr) => {
                    let list = map
                        .insert_container(key, loro::LoroList::new())
                        .map_err(|e| format!("Loro insert_container error: {e}"))?;
                    for item in arr {
                        json_value_to_loro_list_item(item, &list)?;
                    }
                }
                serde_json::Value::Object(_) => {
                    let nested = map
                        .insert_container(key, loro::LoroMap::new())
                        .map_err(|e| format!("Loro insert_container error: {e}"))?;
                    json_value_to_loro_map(val, &nested)?;
                }
                serde_json::Value::Null => {}
            }
        }
    }
    Ok(())
}

/// Push a JSON value into a LoroList.
fn json_value_to_loro_list_item(
    json: &serde_json::Value,
    list: &loro::LoroList,
) -> AtomicResult<()> {
    match json {
        serde_json::Value::String(s) => {
            list.push(s.as_str())
                .map_err(|e| format!("Loro list push error: {e}"))?;
        }
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                list.push(f)
                    .map_err(|e| format!("Loro list push error: {e}"))?;
            }
        }
        serde_json::Value::Bool(b) => {
            list.push(*b)
                .map_err(|e| format!("Loro list push error: {e}"))?;
        }
        serde_json::Value::Array(arr) => {
            let nested = list
                .push_container(loro::LoroList::new())
                .map_err(|e| format!("Loro push_container error: {e}"))?;
            for item in arr {
                json_value_to_loro_list_item(item, &nested)?;
            }
        }
        serde_json::Value::Object(_) => {
            let nested = list
                .push_container(loro::LoroMap::new())
                .map_err(|e| format!("Loro push_container error: {e}"))?;
            json_value_to_loro_map(json, &nested)?;
        }
        serde_json::Value::Null => {}
    }
    Ok(())
}

/// Insert a JSON value into a LoroList at a specific index.
fn insert_json_value_into_loro_list(
    json: &serde_json::Value,
    list: &loro::LoroList,
    index: usize,
) -> AtomicResult<()> {
    match json {
        serde_json::Value::String(s) => {
            list.insert(index, s.as_str())
                .map_err(|e| format!("Loro list insert error: {e}"))?;
        }
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                list.insert(index, f)
                    .map_err(|e| format!("Loro list insert error: {e}"))?;
            }
        }
        serde_json::Value::Bool(b) => {
            list.insert(index, *b)
                .map_err(|e| format!("Loro list insert error: {e}"))?;
        }
        serde_json::Value::Array(arr) => {
            let nested = list
                .insert_container(index, loro::LoroList::new())
                .map_err(|e| format!("Loro insert_container error: {e}"))?;
            for item in arr {
                json_value_to_loro_list_item(item, &nested)?;
            }
        }
        serde_json::Value::Object(_) => {
            let nested = list
                .insert_container(index, loro::LoroMap::new())
                .map_err(|e| format!("Loro insert_container error: {e}"))?;
            json_value_to_loro_map(json, &nested)?;
        }
        serde_json::Value::Null => {}
    }
    Ok(())
}

impl Default for AtomicLoroDoc {
    fn default() -> Self {
        Self::new()
    }
}

/// Best-effort plain text from a loro-prosemirror or ProseMirror JSON tree.
fn extract_text_from_prosemirror_json(node: &serde_json::Value) -> String {
    match node {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => {
            let parts: Vec<String> = arr
                .iter()
                .map(extract_text_from_prosemirror_json)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            parts.join(" ")
        }
        serde_json::Value::Object(obj) => {
            if let Some(serde_json::Value::String(text)) = obj.get("text") {
                return text.clone();
            }

            if let Some(content) = obj.get("content").and_then(|c| c.as_array()) {
                let joined: String = content
                    .iter()
                    .map(extract_text_from_prosemirror_json)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("");
                let node_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
                let is_block =
                    !node_type.is_empty() && node_type != "text" && node_type != "hardBreak";
                if is_block && !joined.is_empty() {
                    return format!("{joined}\n");
                }
                return joined;
            }

            if let Some(children) = obj.get("children").and_then(|c| c.as_array()) {
                let parts: Vec<String> = children
                    .iter()
                    .map(extract_text_from_prosemirror_json)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let node_name = obj
                    .get("nodeName")
                    .or_else(|| obj.get("type"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let is_block = matches!(
                    node_name,
                    "paragraph" | "heading" | "doc" | "blockquote" | "listItem" | "codeBlock"
                );
                return parts.join(if is_block { " " } else { "" });
            }

            String::new()
        }
        _ => String::new(),
    }
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Convert a LoroValue back to serde_json::Value.
fn loro_value_to_json(lv: &loro::LoroValue) -> serde_json::Value {
    match lv {
        loro::LoroValue::String(s) => serde_json::Value::String(s.to_string()),
        loro::LoroValue::I64(i) => serde_json::json!(*i),
        loro::LoroValue::Double(f) => serde_json::json!(*f),
        loro::LoroValue::Bool(b) => serde_json::Value::Bool(*b),
        loro::LoroValue::Null => serde_json::Value::Null,
        loro::LoroValue::List(items) => {
            serde_json::Value::Array(items.iter().map(loro_value_to_json).collect())
        }
        loro::LoroValue::Map(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.to_string(), loro_value_to_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Storelike;

    fn get_doc_property(doc: &AtomicLoroDoc, prop: &str) -> Option<Value> {
        let props = doc.get_all_properties();
        let datatypes = doc.get_all_datatypes();
        let val = props.get(prop)?;
        let tag = datatypes.get(prop).map(|s| s.as_str());
        loro_value_to_atomic_value_tagged(val, tag)
    }

    /// Documents WHY `content` must be `recommends`, not `requires`, on the
    /// ai-message class (`lib/defaults/ai.json`): an EMPTY Loro array container
    /// is dropped from the genesis snapshot entirely (Loro does not persist an
    /// op-less container), so a genesis that seeds `content: []` materializes
    /// WITHOUT `content`. A DID resource can't carry real `content` at genesis
    /// either — the subject is derived from the genesis signature, but the parts
    /// are children whose `parent` is that subject. So `content` is structurally
    /// absent from every ai-message genesis; requiring it made creation fail on
    /// every retry ("content missing. Is required in class ai-message" — the
    /// ingest loop). Bytes are the verbatim `loroUpdate` from a rejected commit.
    #[test]
    fn empty_required_array_is_dropped_from_genesis() {
        use base64::Engine;
        const CONTENT: &str = "https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/property/content";
        const ISA: &str = "https://atomicdata.dev/properties/isA";
        let b64 = "bG9ybwAAAAAAAAAAAAAAALmxW4oAA8UBAABMT1JPAAQiTRhgQIKUAQAA8AgBrZ/h/bqn945qDAAMAGod3TuvuE+tAAEA8AEHAAcBEAGtT7ivO90dagEBFADwCAAJAaD+9aENAAEAEAMEAQAABgQAAQAACgD/GwikASVodHRwczovL2F0b21pY2RhdGEuZGV2L3Byb3BlcnRpZXMvaXNBKCYAD39wYXJlbnQ/KQAE9AswMWp0anh0c2E5c3l4bWZjYTJ6eDVnY25tamoAdnkvcm9sZQp4ABAJjAD/G3R5cGVzABoBBAgJAAIBAAQEAAgEAAQCBQADAgIOCwIOAQCNAgkBBwEFQnkAH/9iY2xhc3MvYWktbWVzc2FnZQVdZGlkOmFkOmZTckl5STgwWnYxYlJXeG5KTE5fYjZTZElSdEJjemRpeEVValFxODlqSFBlODIzODBXbk5jejA1eE1aUUpBRG9iZ0hnSFNEOS11d3BjMWFKMWZ6UURBBT9rAQQPHAEI8gB0YWcvYXNzaXN0YW50BQmkAfcDVXJsBQ1yZXNvdXJjZUFycmF5GgBWAAIAdnYiApAOAAALAB0CAwAAAAAArXuYDQEAAAAFAAAAAgBmcgECAHZ2cMoZlqwBAAC8AQAATE9STwAEIk0YYECCdgEAAP9tAQIBAApwcm9wZXJ0aWVzAQEEQmh0dHBzOi8vYXRvbWljZGF0YS5kZXYvMDFqdGp4dHNhOXN5eG1mY2Eyeng1Z2NubWovY2xhc3MvYWktbWVzc2FnZQGtT7ivO90dagEDAgEAAgECAgEAAAsAgAlkYXRhdHlwZXMAAQADP2kAHwOpAIJ5L3JvbGUECaIAT1VybCVLAAQDMAD/CGllcy9pc0EEDXJlc291cmNlQXJyYXkoNQAPZ3BhcmVudGkAFQDbAKcABAAFAAYADACAPwEP1wAyHz+YAAQPgQEI33RhZy9hc3Npc3RhbnQNARPvBwGtn+H9uqf3jmoAAihzAAQHQAEDCwH3T11kaWQ6YWQ6ZlNySXlJODBadjFiUld4bkpMTl9iNlNkSVJ0QmN6ZGl4RVVqUXE4OWpIUGU4MjM4MFduTmN6MDV4TVpRSkFEb2JnSGdIU0Q5LXV3cGMxYUoxZnpRREFfAdADAAAAAgAAaQA/AQMAAAAAAMRY9EsBAAAABQAAAA0AAa1PuK873R1qAAAAAAEMAIAKcHJvcGVydGllc2zom/mOAQAAAAAAAA==";
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");

        let doc = AtomicLoroDoc::new();
        doc.import_update(&bytes).expect("import genesis snapshot");
        let props = doc.get_all_properties();

        // The non-empty array (isA) round-trips...
        assert!(
            props.contains_key(ISA),
            "isA (non-empty array) should survive"
        );
        // ...but the empty `content` array is gone — not just skipped by
        // `for_each`, it is absent from the doc's `properties` map entirely.
        assert!(
            !props.contains_key(CONTENT),
            "empty `content` is dropped from the genesis — hence it must not be \
             `requires` on ai-message",
        );
        assert!(
            doc.doc().get_map("properties").get(CONTENT).is_none(),
            "the empty content container is not persisted in the snapshot at all",
        );
    }

    #[test]
    fn genesis_change_is_earliest_and_carries_message() {
        let doc = AtomicLoroDoc::new();

        // Genesis: one change tagged with the signing agent's subject, stamped
        // with millisecond precision (as the client does at sign time).
        doc.set_property(
            "https://atomicdata.dev/properties/description",
            &Value::String("hello".into()),
        )
        .unwrap();
        doc.doc().commit_with(
            loro::CommitOptions::new()
                .timestamp(1_700_000_000_123)
                .commit_msg("https://atomicdata.dev/agents/alice"),
        );

        // A later edit with a newer timestamp must NOT become the genesis.
        doc.set_property(
            "https://atomicdata.dev/properties/description",
            &Value::String("edited".into()),
        )
        .unwrap();
        doc.doc()
            .commit_with(loro::CommitOptions::new().timestamp(1_700_000_009_999));

        let genesis = doc.genesis_change().expect("doc has changes");
        assert_eq!(
            genesis.timestamp, 1_700_000_000_123,
            "genesis is the earliest change, ms precision preserved",
        );
        assert_eq!(
            genesis.message.as_deref(),
            Some("https://atomicdata.dev/agents/alice"),
            "genesis carries the agent subject from its commit message",
        );
    }

    #[test]
    fn genesis_change_picks_lowest_lamport_not_earliest_timestamp() {
        // A genesis followed by a later edit whose (second-resolution) timestamp
        // is numerically *smaller* than the ms-precise genesis — mimicking the
        // server's post-apply `lastCommit` change. Timestamp-based selection
        // would mis-pick the later, message-less edit; Lamport (causal order)
        // correctly keeps the genesis, which was committed first.
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/description",
            &Value::String("hello".into()),
        )
        .unwrap();
        doc.doc().commit_with(
            loro::CommitOptions::new()
                .timestamp(1_700_000_000_000)
                .commit_msg("https://atomicdata.dev/agents/alice"),
        );

        doc.set_property(
            "https://atomicdata.dev/properties/description",
            &Value::String("edited".into()),
        )
        .unwrap();
        doc.doc()
            .commit_with(loro::CommitOptions::new().timestamp(1_700_000_001));

        let genesis = doc.genesis_change().expect("doc has changes");
        assert_eq!(
            genesis.message.as_deref(),
            Some("https://atomicdata.dev/agents/alice"),
            "genesis (lowest lamport) wins over the later, smaller-timestamp edit",
        );
        assert_eq!(genesis.timestamp, 1_700_000_000_000);
    }

    #[test]
    fn genesis_change_none_for_empty_doc() {
        let doc = AtomicLoroDoc::new();
        assert!(doc.genesis_change().is_none());
    }

    #[test]
    fn materializes_created_at_and_created_by_from_genesis() {
        let agent = "https://atomicdata.dev/agents/alice";

        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/description",
            &Value::String("hello".into()),
        )
        .unwrap();
        // Millisecond-precise genesis timestamp.
        doc.doc().commit_with(
            loro::CommitOptions::new()
                .timestamp(1_700_000_123_456)
                .commit_msg(agent),
        );

        // `apply_state_doc` runs the projection (materialize_propvals_from_loro_doc)
        // — the same chokepoint the index and JSON-AD reads use.
        let mut resource = crate::Resource::new("https://example.com/msg".into());
        resource.apply_state_doc(doc).unwrap();

        // createdAt: the genesis timestamp, preserved at millisecond precision.
        assert_eq!(
            resource
                .get(crate::urls::CREATED_AT)
                .unwrap()
                .to_int()
                .unwrap(),
            1_700_000_123_456,
        );
        // createdBy: the agent subject from the genesis change message.
        assert_eq!(
            resource.get(crate::urls::CREATED_BY).unwrap().to_string(),
            agent,
        );

        // Both must serialize when the resource is read in JSON-AD.
        let json = resource.to_json_ad(None).unwrap();
        assert!(
            json.contains(crate::urls::CREATED_AT),
            "createdAt serialized in JSON-AD: {json}",
        );
        assert!(
            json.contains(crate::urls::CREATED_BY) && json.contains(agent),
            "createdBy serialized in JSON-AD: {json}",
        );
    }

    #[test]
    fn create_doc_set_and_get_properties() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("Alice".into()),
        )
        .unwrap();
        doc.set_property("https://atomicdata.dev/properties/age", &Value::Integer(30))
            .unwrap();
        doc.set_property(
            "https://atomicdata.dev/properties/score",
            &Value::Float(9.5),
        )
        .unwrap();

        assert_eq!(
            doc.get_string_property("https://atomicdata.dev/properties/name"),
            Some("Alice".into())
        );
        assert_eq!(
            doc.get_integer_property("https://atomicdata.dev/properties/age"),
            Some(30)
        );
    }

    #[test]
    fn empty_resource_array_round_trips_through_loro() {
        // An empty ResourceArray must materialize back as an empty
        // ResourceArray (not be dropped). Required-but-empty array properties
        // — e.g. SelectProperty.allowsOnly while a creation dialog is open —
        // depend on this so check_required_props sees the property as set.
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/allowsOnly",
            &Value::ResourceArray(vec![]),
        )
        .unwrap();

        let props = doc.get_all_properties();
        let lv = props
            .get("https://atomicdata.dev/properties/allowsOnly")
            .expect("empty array key must be present in the Loro doc");
        let av = loro_value_to_atomic_value(lv)
            .expect("empty list must materialize into a Value, not None");
        match av {
            Value::ResourceArray(arr) => assert!(arr.is_empty()),
            other => panic!("expected empty ResourceArray, got {other:?}"),
        }
    }

    #[test]
    fn untagged_numeric_loro_list_materializes_as_json() {
        // Column widths are stored as a native numeric LoroList. If the
        // datatype tag is absent (e.g. the Property was not cached client-side
        // when signing), the untagged fallback still needs to keep the value.
        let lv = loro::LoroValue::List(
            vec![loro::LoroValue::I64(300), loro::LoroValue::I64(214)].into(),
        );

        let av = loro_value_to_atomic_value(&lv)
            .expect("numeric list must materialize into a Value, not None");

        match av {
            Value::Json(json) => assert_eq!(json, serde_json::json!([300, 214])),
            other => panic!("expected Json array, got {other:?}"),
        }
    }

    #[test]
    fn datatype_tags_preserve_load_bearing_variants() {
        // Load-bearing variants survive a snapshot round-trip exactly, via
        // the sibling `datatypes` map —
        // not via the lossy heuristics.
        let p = |n: &str| format!("https://atomicdata.dev/properties/{n}");
        let doc = AtomicLoroDoc::new();
        doc.set_property(&p("ref"), &Value::AtomicUrl("did:ad:target".into()))
            .unwrap();
        doc.set_property(
            &p("refs"),
            &Value::ResourceArray(vec!["did:ad:x".into(), "did:ad:y".into()]),
        )
        .unwrap();
        doc.set_property(&p("emptyRefs"), &Value::ResourceArray(vec![]))
            .unwrap();
        doc.set_property(&p("strokes"), &Value::Json(serde_json::json!([{"x": 1}])))
            .unwrap();
        doc.set_property(&p("text"), &Value::String("plain".into()))
            .unwrap();
        // Cosmetic string-likes: same primitive as String, but
        // their variant must survive — at least vector/search text extraction
        // branches on `Value::Markdown`.
        doc.set_property(&p("desc"), &Value::Markdown("# Hi".into()))
            .unwrap();
        doc.set_property(&p("handle"), &Value::Slug("my-slug".into()))
            .unwrap();
        doc.set_property(&p("link"), &Value::Uri("mailto:a@b.c".into()))
            .unwrap();
        doc.set_property(&p("day"), &Value::Date("2026-06-16".into()))
            .unwrap();
        doc.set_property(&p("ts"), &Value::Timestamp(1_700_000_000_000))
            .unwrap();
        let translations: std::collections::BTreeMap<String, String> = [
            ("en".to_string(), "Fast sync".to_string()),
            ("nl".to_string(), "Snelle synchronisatie".to_string()),
        ]
        .into();
        doc.set_property(&p("tagline"), &Value::LocalizedText(translations))
            .unwrap();

        // Round-trip through a snapshot, as sync / persistence does.
        let doc2 = AtomicLoroDoc::from_snapshot(&doc.export_snapshot()).unwrap();
        let props = doc2.get_all_properties();
        let tags = doc2.get_all_datatypes();
        let mat = |n: &str| {
            let key = p(n);
            loro_value_to_atomic_value_tagged(
                props.get(&key).expect("property present"),
                tags.get(&key).map(String::as_str),
            )
        };

        assert!(
            matches!(mat("ref"), Some(Value::AtomicUrl(_))),
            "tagged reference must materialize as AtomicUrl"
        );
        match mat("refs") {
            Some(Value::ResourceArray(a)) => assert_eq!(a.len(), 2),
            other => panic!("expected ResourceArray, got {other:?}"),
        }
        match mat("emptyRefs") {
            // The tag pins the shape even when the list is empty — the
            // heuristic alone cannot tell an empty ResourceArray from Json.
            Some(Value::ResourceArray(a)) => assert!(a.is_empty()),
            other => panic!("expected empty ResourceArray, got {other:?}"),
        }
        match mat("strokes") {
            Some(Value::Json(serde_json::Value::Array(a))) => assert_eq!(a.len(), 1),
            other => panic!("expected Json array, got {other:?}"),
        }
        // Plain text carries no tag and stays string-like.
        assert!(matches!(mat("text"), Some(Value::String(_))));
        // Cosmetic string-likes recover their exact variant via the tag.
        assert!(matches!(mat("desc"), Some(Value::Markdown(s)) if s == "# Hi"));
        assert!(matches!(mat("handle"), Some(Value::Slug(s)) if s == "my-slug"));
        assert!(matches!(mat("link"), Some(Value::Uri(s)) if s == "mailto:a@b.c"));
        assert!(matches!(mat("day"), Some(Value::Date(s)) if s == "2026-06-16"));
        assert!(matches!(
            mat("ts"),
            Some(Value::Timestamp(1_700_000_000_000))
        ));
        // A LoroMap without a tag would materialize as Json; the tag pins it.
        match mat("tagline") {
            Some(Value::LocalizedText(m)) => {
                assert_eq!(
                    m.get("nl").map(String::as_str),
                    Some("Snelle synchronisatie")
                );
                assert_eq!(m.len(), 2);
            }
            other => panic!("expected LocalizedText, got {other:?}"),
        }
        // Scalars and plain strings get no `datatypes` entry — the map is sparse.
        assert!(!tags.contains_key(&p("text")));
        assert!(tags.contains_key(&p("ref")));
        assert_eq!(tags.get(&p("desc")).map(String::as_str), Some("markdown"));
        assert_eq!(
            tags.get(&p("tagline")).map(String::as_str),
            Some("localizedText")
        );
    }

    #[test]
    fn snapshot_roundtrip() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("Bob".into()),
        )
        .unwrap();

        let snapshot = doc.export_snapshot();
        let doc2 = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();

        assert_eq!(
            doc2.get_string_property("https://atomicdata.dev/properties/name"),
            Some("Bob".into())
        );
    }

    #[test]
    fn vv_from_snapshot_matches_full_import() {
        // The fast path (`vv_map_from_snapshot`, header-only) must produce the
        // exact same version vector as the slow path (`from_snapshot` +
        // `oplog_vv_map`, full doc rebuild) that the sync protocol relies on.
        let doc = AtomicLoroDoc::new();
        for (k, v) in [("name", "Bob"), ("description", "hi"), ("name", "Bobby")] {
            doc.set_property(
                &format!("https://atomicdata.dev/properties/{k}"),
                &Value::String(v.into()),
            )
            .unwrap();
        }

        let snapshot = doc.export_snapshot();

        let fast = AtomicLoroDoc::vv_map_from_snapshot(&snapshot).unwrap();
        let slow = AtomicLoroDoc::from_snapshot(&snapshot)
            .unwrap()
            .oplog_vv_map();

        assert_eq!(fast, slow, "header-decoded VV must match full-import VV");
        assert!(!fast.is_empty(), "a non-trivial doc should have a VV");
    }

    #[test]
    fn vv_from_snapshot_matches_after_multi_peer_merge() {
        // Two peers with concurrent histories, merged both ways — the version
        // vector now carries multiple peer entries. This is the case where a
        // *partial* header VV could in principle omit a peer, so it's the
        // important one: the header-decoded VV must still exactly match the
        // full-import VV the sync protocol would otherwise compute.
        let doc_a = AtomicLoroDoc::new();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("A".into()),
            )
            .unwrap();

        // doc_b starts from doc_a's snapshot but is a distinct peer.
        let doc_b = AtomicLoroDoc::from_snapshot(&doc_a.export_snapshot()).unwrap();

        // Concurrent edits on each peer.
        let va = doc_a.doc().oplog_vv();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::String("from A".into()),
            )
            .unwrap();
        let vb = doc_b.doc().oplog_vv();
        doc_b
            .set_property(
                "https://atomicdata.dev/properties/shortname",
                &Value::String("fromb".into()),
            )
            .unwrap();

        // Merge both directions so doc_a holds a genuinely multi-peer oplog.
        doc_a
            .import_update(&doc_b.export_updates_since(&vb))
            .unwrap();
        doc_b
            .import_update(&doc_a.export_updates_since(&va))
            .unwrap();

        let snapshot = doc_a.export_snapshot();
        let fast = AtomicLoroDoc::vv_map_from_snapshot(&snapshot).unwrap();
        let slow = AtomicLoroDoc::from_snapshot(&snapshot)
            .unwrap()
            .oplog_vv_map();

        assert_eq!(fast, slow, "multi-peer merged VV mismatch");
        assert!(
            fast.len() >= 2,
            "expected a >=2-peer version vector, got {fast:?}"
        );
    }

    #[test]
    fn incremental_update_sync() {
        let doc_a = AtomicLoroDoc::new();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("Alice".into()),
            )
            .unwrap();

        // Sync doc_a -> doc_b via snapshot
        let snapshot = doc_a.export_snapshot();
        let doc_b = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();

        // Now doc_a makes a new change
        let version_before = doc_a.doc().oplog_vv();
        doc_a
            .set_property("https://atomicdata.dev/properties/age", &Value::Integer(25))
            .unwrap();

        // Export only the delta
        let update = doc_a.export_updates_since(&version_before);

        // Apply delta to doc_b
        doc_b.import_update(&update).unwrap();

        // doc_b now has both properties
        assert_eq!(
            doc_b.get_string_property("https://atomicdata.dev/properties/name"),
            Some("Alice".into())
        );
        assert_eq!(
            doc_b.get_integer_property("https://atomicdata.dev/properties/age"),
            Some(25)
        );
    }

    #[test]
    fn concurrent_edits_merge_automatically() {
        // Two peers start from the same state
        let doc_a = AtomicLoroDoc::new();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("Original Name".into()),
            )
            .unwrap();
        let snapshot = doc_a.export_snapshot();
        let doc_b = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();

        let version_a = doc_a.doc().oplog_vv();
        let version_b = doc_b.doc().oplog_vv();

        // Peer A changes name
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("From A".into()),
            )
            .unwrap();
        // Peer A adds a property
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::String("Desc from A".into()),
            )
            .unwrap();

        // Peer B changes a different property concurrently
        doc_b
            .set_property("https://atomicdata.dev/properties/age", &Value::Integer(42))
            .unwrap();

        // Exchange updates — this is the core of the sync protocol
        let update_a = doc_a.export_updates_since(&version_a);
        let update_b = doc_b.export_updates_since(&version_b);

        doc_a.import_update(&update_b).unwrap();
        doc_b.import_update(&update_a).unwrap();

        // Both docs converge to the same state
        assert_eq!(
            doc_a.get_string_property("https://atomicdata.dev/properties/name"),
            doc_b.get_string_property("https://atomicdata.dev/properties/name"),
        );
        assert_eq!(
            doc_a.get_integer_property("https://atomicdata.dev/properties/age"),
            Some(42)
        );
        assert_eq!(
            doc_a.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Desc from A".into())
        );
        // Both docs have the same state
        assert_eq!(
            doc_b.get_integer_property("https://atomicdata.dev/properties/age"),
            Some(42)
        );
        assert_eq!(
            doc_b.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Desc from A".into())
        );
    }

    #[test]
    fn remove_property_works() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("Alice".into()),
        )
        .unwrap();
        assert!(doc
            .get_string_property("https://atomicdata.dev/properties/name")
            .is_some());

        doc.remove_property("https://atomicdata.dev/properties/name")
            .unwrap();
        assert!(doc
            .get_string_property("https://atomicdata.dev/properties/name")
            .is_none());
    }

    #[test]
    fn rich_text_collaboration() {
        // Loro's Text type — this would replace Yjs for rich text
        let doc_a = LoroDoc::new();
        let text_a = doc_a.get_text("description");
        text_a.insert(0, "Hello World").unwrap();

        let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
        let doc_b = LoroDoc::new();
        doc_b.import(&snapshot).unwrap();

        let text_b = doc_b.get_text("description");
        assert_eq!(text_b.to_string(), "Hello World");

        // Concurrent edits to the same text
        let v_a = doc_a.oplog_vv();
        let v_b = doc_b.oplog_vv();

        text_a.insert(5, " Beautiful").unwrap();
        // "Hello Beautiful World"
        text_b.insert(11, "!").unwrap();
        // "Hello World!"

        let update_a = doc_a.export(ExportMode::updates(&v_a)).unwrap();
        let update_b = doc_b.export(ExportMode::updates(&v_b)).unwrap();

        doc_a.import(&update_b).unwrap();
        doc_b.import(&update_a).unwrap();

        // Both converge — the exact merge result depends on Loro's CRDT semantics,
        // but both docs will have the same string.
        assert_eq!(text_a.to_string(), text_b.to_string());
        // Both insertions are preserved
        assert!(text_a.to_string().contains("Beautiful"));
        assert!(text_a.to_string().contains("!"));
    }

    #[test]
    fn loro_update_in_commit_flow() {
        // Simulates the commit flow:
        // 1. Client creates a LoroDoc, makes changes
        // 2. Client exports update as binary, base64-encodes it, puts in commit
        // 3. Server receives commit, decodes update, imports into its LoroDoc

        // === Client side ===
        let client_doc = AtomicLoroDoc::new();
        client_doc
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("New Resource".into()),
            )
            .unwrap();
        client_doc
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::Markdown("Hello".into()),
            )
            .unwrap();

        // Client exports update bytes
        let update_bytes = client_doc.export_snapshot();
        // In a real commit, this would be base64-encoded into the commit body
        use base64::Engine;
        let base64_update = base64::engine::general_purpose::STANDARD.encode(&update_bytes);

        // === Server side ===
        // Server decodes the base64 update from the commit
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&base64_update)
            .unwrap();

        // Server has an existing (or new) LoroDoc for this resource
        let server_doc = AtomicLoroDoc::new();
        server_doc.import_update(&decoded).unwrap();

        // Server can now read the materialized state for JSON-AD
        assert_eq!(
            server_doc.get_string_property("https://atomicdata.dev/properties/name"),
            Some("New Resource".into())
        );
        assert_eq!(
            server_doc.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Hello".into())
        );

        // Server persists the snapshot for future merges
        let server_snapshot = server_doc.export_snapshot();
        assert!(!server_snapshot.is_empty());
    }

    #[test]
    fn movable_list_for_kanban() {
        // MovableList is perfect for kanban columns where items get reordered
        let doc = LoroDoc::new();
        let list = doc.get_movable_list("kanban_column");

        list.push("task-1").unwrap();
        list.push("task-2").unwrap();
        list.push("task-3").unwrap();

        // Move task-3 to the front
        list.mov(2, 0).unwrap();

        let items: Vec<String> = (0..list.len())
            .map(|i| {
                list.get(i)
                    .unwrap()
                    .into_value()
                    .unwrap()
                    .as_string()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(items, vec!["task-3", "task-1", "task-2"]);
    }

    #[test]
    fn tree_for_hierarchy() {
        // Loro's Tree type maps well to Atomic Data's parent-child hierarchy
        let doc = LoroDoc::new();
        let tree = doc.get_tree("hierarchy");

        let root = tree.create(loro::TreeParentId::Root).unwrap();
        let child1 = tree.create(loro::TreeParentId::Node(root)).unwrap();
        let child2 = tree.create(loro::TreeParentId::Node(root)).unwrap();

        // Move child2 under child1
        tree.mov(child2, loro::TreeParentId::Node(child1)).unwrap();

        // Verify structure
        let root_children = tree.children(loro::TreeParentId::Root).unwrap();
        assert_eq!(root_children.len(), 1); // only root node
        let child1_children = tree.children(loro::TreeParentId::Node(child1)).unwrap();
        assert_eq!(child1_children.len(), 1); // child2 is now under child1
    }

    // === Integration tests: loroUpdate through the commit pipeline ===

    #[tokio::test]
    async fn loro_update_commit_through_store() {
        // Full pipeline: create LoroDoc → export update → build CommitBuilder with
        // loroUpdate → sign → apply_commit → verify resource has materialized propvals
        let store = crate::Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        let agent = store.create_agent(Some("loro_test")).await.unwrap();
        let subject = "https://localhost/loro_test_resource";

        // Client-side: create a LoroDoc with properties
        let client_doc = AtomicLoroDoc::new();
        client_doc
            .set_property(
                crate::urls::DESCRIPTION,
                &Value::String("Hello from Loro".into()),
            )
            .unwrap();
        client_doc
            .set_property(crate::urls::SHORTNAME, &Value::String("loro-test".into()))
            .unwrap();
        client_doc
            .set_property(
                crate::urls::IS_A,
                &Value::ResourceArray(vec![crate::urls::CLASS.into()]),
            )
            .unwrap();

        // Export the update
        let update = client_doc.export_snapshot();

        // Build a commit with the loro update
        let mut builder = crate::commit::CommitBuilder::new(subject.into());
        builder.set_loro_update(update);

        let resource = crate::Resource::new(subject.into());
        let commit = builder.sign(&agent, &store, &resource).await.unwrap();

        // Apply the commit
        let opts = crate::commit::CommitOpts {
            validate_schema: false,
            validate_signature: true,
            validate_timestamp: true,
            validate_rights: false,
            validate_loro_causality: false,
            update_index: false,
            validate_for_agent: None,
            source_id: None,
        };
        let response = store.apply_commit(commit, &opts).await.unwrap();

        // Verify the resource now has the materialized properties from Loro
        let new_resource = response.resource_new.unwrap();
        assert_eq!(
            new_resource
                .get(crate::urls::DESCRIPTION)
                .unwrap()
                .to_string(),
            "Hello from Loro"
        );
        assert_eq!(
            new_resource
                .get(crate::urls::SHORTNAME)
                .unwrap()
                .to_string(),
            "loro-test"
        );

        // Verify the Loro snapshot was persisted on the resource
        let loro_snap = new_resource.get(crate::urls::LORO_UPDATE);
        assert!(loro_snap.is_ok(), "Resource should have a LoroDoc snapshot");
    }

    #[tokio::test]
    async fn loro_update_concurrent_merge() {
        // Two clients make concurrent edits via loroUpdate, both applied to the same resource.
        // The second commit should merge with the first without conflict.
        let store = crate::Store::init().await.unwrap();
        store.set_base_url("http://localhost:9883");
        store.populate().await.unwrap();
        let agent = store.create_agent(Some("loro_merge")).await.unwrap();
        let subject = "https://localhost/loro_merge_resource";

        let opts = crate::commit::CommitOpts {
            validate_schema: false,
            validate_signature: true,
            validate_timestamp: true,
            validate_rights: false,
            validate_loro_causality: false,
            update_index: false,
            validate_for_agent: None,
            source_id: None,
        };

        // Client A sets name
        let doc_a = AtomicLoroDoc::new();
        doc_a
            .set_property(crate::urls::SHORTNAME, &Value::String("from-a".into()))
            .unwrap();
        let update_a = doc_a.export_snapshot();

        let mut builder_a = crate::commit::CommitBuilder::new(subject.into());
        builder_a.set_loro_update(update_a);
        let resource = crate::Resource::new(subject.into());
        let commit_a = builder_a.sign(&agent, &store, &resource).await.unwrap();
        store.apply_commit(commit_a, &opts).await.unwrap();

        // Client B starts from same empty state, sets description
        let doc_b = AtomicLoroDoc::new();
        doc_b
            .set_property(crate::urls::DESCRIPTION, &Value::String("from-b".into()))
            .unwrap();
        let update_b = doc_b.export_snapshot();

        let mut builder_b = crate::commit::CommitBuilder::new(subject.into());
        builder_b.set_loro_update(update_b);
        let resource_after_a = store.get_resource(&subject.into()).await.unwrap();
        let commit_b = builder_b
            .sign(&agent, &store, &resource_after_a)
            .await
            .unwrap();
        let response_b = store.apply_commit(commit_b, &opts).await.unwrap();

        // After both commits, the resource should have BOTH properties
        let final_resource = response_b.resource_new.unwrap();
        assert_eq!(
            final_resource
                .get(crate::urls::SHORTNAME)
                .unwrap()
                .to_string(),
            "from-a"
        );
        assert_eq!(
            final_resource
                .get(crate::urls::DESCRIPTION)
                .unwrap()
                .to_string(),
            "from-b"
        );
    }

    #[test]
    fn import_update_with_diff_generates_atoms() {
        let doc = AtomicLoroDoc::new();
        doc.set_property("https://example.com/name", &Value::String("Alice".into()))
            .unwrap();

        let subject = "https://example.com/resource1";

        // Now apply an update that changes name and adds age
        let doc2 = AtomicLoroDoc::from_snapshot(&doc.export_snapshot()).unwrap();
        let version_before = doc2.doc().oplog_vv();
        doc2.set_property("https://example.com/name", &Value::String("Bob".into()))
            .unwrap();
        doc2.set_property("https://example.com/age", &Value::Integer(30))
            .unwrap();
        let update = doc2.export_updates_since(&version_before);

        // Apply the delta update to the original doc
        let diff = doc.import_update_with_diff(&update, subject).unwrap();

        // Should have: remove old name "Alice", add new name "Bob", add age 30
        assert_eq!(diff.remove_atoms.len(), 1);
        assert_eq!(diff.remove_atoms[0].value.to_string(), "Alice");

        assert_eq!(diff.add_atoms.len(), 2);
        let added_values: Vec<String> =
            diff.add_atoms.iter().map(|a| a.value.to_string()).collect();
        assert!(added_values.contains(&"Bob".to_string()));
        assert!(added_values.contains(&"30".to_string()));
    }

    #[test]
    fn deterministic_serialization_with_loro_update() {
        // Verify that a commit with loroUpdate serializes deterministically
        let doc = AtomicLoroDoc::new();
        doc.set_property("https://example.com/name", &Value::String("test".into()))
            .unwrap();
        let update = doc.export_snapshot();

        let commit = crate::commit::Commit {
            subject: "https://localhost/test".into(),
            created_at: 1700000000,
            signer: "https://localhost/agent".into(),
            loro_update: Some(update.clone()),
            destroy: None,
            previous_commit: None,
            is_genesis: None,
            signature: None,
            url: None,
        };

        // Serialize twice — must produce identical output
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let store = rt.block_on(async { crate::Store::init().await.unwrap() });
        let s1 = rt
            .block_on(commit.serialize_deterministically_json_ad(&store))
            .unwrap();
        let s2 = rt
            .block_on(commit.serialize_deterministically_json_ad(&store))
            .unwrap();
        assert_eq!(s1, s2);

        // Must contain the loroUpdate key
        assert!(s1.contains("loroUpdate"));
    }

    /// Simulate a client storing arrays as JSON strings (like the JS client does)
    /// and verify the server materializes them back to ResourceArray.
    #[test]
    fn client_json_stringified_arrays_materialize_as_resource_array() {
        // Client side: stores write/read as JSON.stringify(["did:ad:agent:abc"])
        let client_doc = AtomicLoroDoc::new();
        let root = client_doc.doc().get_map("properties");

        // This is what the JS client does:
        // map.set(prop, JSON.stringify(value))
        root.insert(
            "https://atomicdata.dev/properties/write",
            r#"["did:ad:agent:abc"]"#,
        )
        .unwrap();
        root.insert(
            "https://atomicdata.dev/properties/read",
            r#"["did:ad:agent:abc"]"#,
        )
        .unwrap();
        root.insert("https://atomicdata.dev/properties/name", "Test Drive")
            .unwrap();

        // Export as snapshot (simulates the loroUpdate in a commit)
        let snapshot = client_doc.export_snapshot();

        // Server side: import the snapshot and materialize
        let server_doc = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();
        let props = server_doc.get_all_properties();

        // Materialize using the same function the server uses
        let write_val = loro_value_to_atomic_value(
            props
                .get("https://atomicdata.dev/properties/write")
                .unwrap(),
        );
        let read_val = loro_value_to_atomic_value(
            props.get("https://atomicdata.dev/properties/read").unwrap(),
        );
        let name_val = loro_value_to_atomic_value(
            props.get("https://atomicdata.dev/properties/name").unwrap(),
        );

        // write/read must be ResourceArray, not String
        match write_val.unwrap() {
            Value::ResourceArray(arr) => {
                assert_eq!(arr.len(), 1);
                assert_eq!(arr[0].to_string(), "did:ad:agent:abc");
            }
            other => panic!("Expected ResourceArray for write, got {:?}", other),
        }

        match read_val.unwrap() {
            Value::ResourceArray(arr) => {
                assert_eq!(arr.len(), 1);
                assert_eq!(arr[0].to_string(), "did:ad:agent:abc");
            }
            other => panic!("Expected ResourceArray for read, got {:?}", other),
        }

        match name_val.unwrap() {
            Value::String(s) => assert_eq!(s, "Test Drive"),
            other => panic!("Expected String for name, got {:?}", other),
        }
    }

    #[test]
    fn native_loro_list_arrays_round_trip() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/write",
            &Value::ResourceArray(vec!["did:ad:agent:alice".into(), "did:ad:agent:bob".into()]),
        )
        .unwrap();
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("Test".into()),
        )
        .unwrap();

        // Export and reimport (simulates network round-trip)
        let snapshot = doc.export_snapshot();
        let doc2 = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();
        let props = doc2.get_all_properties();

        // write should materialize as ResourceArray from LoroList
        let write_val = loro_value_to_atomic_value(
            props
                .get("https://atomicdata.dev/properties/write")
                .unwrap(),
        );
        match write_val.unwrap() {
            Value::ResourceArray(arr) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0].to_string(), "did:ad:agent:alice");
                assert_eq!(arr[1].to_string(), "did:ad:agent:bob");
            }
            other => panic!("Expected ResourceArray, got {:?}", other),
        }

        // name should still be a plain string
        let name_val = loro_value_to_atomic_value(
            props.get("https://atomicdata.dev/properties/name").unwrap(),
        );
        assert_eq!(name_val.unwrap().to_string(), "Test");
    }

    // --- Sync protocol tests ---

    /// Simulate two peers (client and server) with the same drive.
    /// Both start with the same state, then each makes independent edits.
    /// After exchanging VVs and deltas, both should converge to the same state.
    #[test]
    fn sync_two_peers_converge() {
        // Peer A: "client"
        let doc_a = AtomicLoroDoc::new();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("Original Name".into()),
            )
            .unwrap();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::String("Shared doc".into()),
            )
            .unwrap();

        // Peer B: "server" — starts with same state via snapshot
        let snapshot = doc_a.export_snapshot();
        let doc_b = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();

        // Both should have identical VVs
        let vv_a_initial = doc_a.oplog_vv_map();
        let vv_b_initial = doc_b.oplog_vv_map();
        assert_eq!(vv_a_initial, vv_b_initial);

        // Peer A edits name (offline)
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("Name from Client".into()),
            )
            .unwrap();

        // Peer B edits description (independently)
        doc_b
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::String("Description from Server".into()),
            )
            .unwrap();

        // VVs should now differ
        let vv_a = doc_a.oplog_vv_map();
        let vv_b = doc_b.oplog_vv_map();
        assert_ne!(vv_a, vv_b);

        // Sync: A sends delta to B (from B's version)
        let vv_b_loro = AtomicLoroDoc::vv_from_map(&vv_b);
        let delta_a_to_b = doc_a.export_updates_since(&vv_b_loro);
        assert!(!delta_a_to_b.is_empty());

        // Sync: B sends delta to A (from A's version)
        let vv_a_loro = AtomicLoroDoc::vv_from_map(&vv_a);
        let delta_b_to_a = doc_b.export_updates_since(&vv_a_loro);
        assert!(!delta_b_to_a.is_empty());

        // Both import the other's delta
        doc_a.import_update(&delta_b_to_a).unwrap();
        doc_b.import_update(&delta_a_to_b).unwrap();

        // Both should now have the same state
        assert_eq!(
            doc_a.get_string_property("https://atomicdata.dev/properties/name"),
            Some("Name from Client".into())
        );
        assert_eq!(
            doc_a.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Description from Server".into())
        );
        assert_eq!(
            doc_b.get_string_property("https://atomicdata.dev/properties/name"),
            Some("Name from Client".into())
        );
        assert_eq!(
            doc_b.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Description from Server".into())
        );

        // VVs should match after sync
        assert_eq!(doc_a.oplog_vv_map(), doc_b.oplog_vv_map());
    }

    /// Test VV comparison: detect which peer is ahead for a resource.
    #[test]
    fn vv_comparison_detects_ahead_behind() {
        let doc_a = AtomicLoroDoc::new();
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("V1".into()),
            )
            .unwrap();

        // B starts from A's state
        let snapshot = doc_a.export_snapshot();
        let doc_b = AtomicLoroDoc::from_snapshot(&snapshot).unwrap();

        // A makes more edits — A is now ahead
        doc_a
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("V2 from A".into()),
            )
            .unwrap();

        let vv_a = doc_a.oplog_vv_map();
        let vv_b = doc_b.oplog_vv_map();

        // A should be ahead: for at least one peer, A's counter > B's counter
        let a_ahead = vv_a
            .iter()
            .any(|(peer, &counter)| counter > *vv_b.get(peer).unwrap_or(&0));
        let b_ahead = vv_b
            .iter()
            .any(|(peer, &counter)| counter > *vv_a.get(peer).unwrap_or(&0));

        assert!(a_ahead, "A should be ahead of B");
        assert!(!b_ahead, "B should not be ahead of A");
    }

    /// Simulate a full drive sync scenario with multiple resources:
    /// - Client has 3 resources (drive, table, readme)
    /// - Server has 2 resources (drive, table) with a different version of table
    /// - After sync, both should have all 3 resources with merged state
    #[test]
    fn drive_sync_multiple_resources() {
        // --- Setup: shared initial state ---
        let drive_doc = AtomicLoroDoc::new();
        drive_doc
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("My Drive".into()),
            )
            .unwrap();

        let table_doc = AtomicLoroDoc::new();
        table_doc
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("Tasks".into()),
            )
            .unwrap();

        // Server gets initial snapshots
        let server_drive = AtomicLoroDoc::from_snapshot(&drive_doc.export_snapshot()).unwrap();
        let server_table = AtomicLoroDoc::from_snapshot(&table_doc.export_snapshot()).unwrap();

        // --- Client creates a new resource (readme) that server doesn't have ---
        let client_readme = AtomicLoroDoc::new();
        client_readme
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("README".into()),
            )
            .unwrap();
        client_readme
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::String("Read this first".into()),
            )
            .unwrap();

        // --- Server edits table independently ---
        server_table
            .set_property(
                "https://atomicdata.dev/properties/description",
                &Value::String("Server-side task list".into()),
            )
            .unwrap();

        // --- Client edits table independently ---
        table_doc
            .set_property(
                "https://atomicdata.dev/properties/name",
                &Value::String("My Tasks".into()),
            )
            .unwrap();

        // --- Collect VVs (simulating the SYNC_VV exchange) ---
        let client_vvs: std::collections::HashMap<String, std::collections::HashMap<String, i32>> =
            [
                ("did:ad:drive".to_string(), drive_doc.oplog_vv_map()),
                ("did:ad:table".to_string(), table_doc.oplog_vv_map()),
                ("did:ad:readme".to_string(), client_readme.oplog_vv_map()),
            ]
            .into();

        let server_vvs: std::collections::HashMap<String, std::collections::HashMap<String, i32>> =
            [
                ("did:ad:drive".to_string(), server_drive.oplog_vv_map()),
                ("did:ad:table".to_string(), server_table.oplog_vv_map()),
            ]
            .into();

        // --- Compute diff ---
        let mut client_ahead: Vec<String> = Vec::new();
        let mut server_ahead: Vec<String> = Vec::new();
        let mut client_only: Vec<String> = Vec::new();

        for (subject, client_vv) in &client_vvs {
            if let Some(server_vv) = server_vvs.get(subject) {
                let c_ahead = client_vv
                    .iter()
                    .any(|(p, &c)| c > *server_vv.get(p).unwrap_or(&0));
                let s_ahead = server_vv
                    .iter()
                    .any(|(p, &c)| c > *client_vv.get(p).unwrap_or(&0));
                if c_ahead {
                    client_ahead.push(subject.clone());
                }
                if s_ahead {
                    server_ahead.push(subject.clone());
                }
            } else {
                client_only.push(subject.clone());
            }
        }

        // drive: identical (no edits on either side since initial sync)
        assert!(!client_ahead.contains(&"did:ad:drive".to_string()));
        assert!(!server_ahead.contains(&"did:ad:drive".to_string()));

        // table: both edited → both ahead
        assert!(client_ahead.contains(&"did:ad:table".to_string()));
        assert!(server_ahead.contains(&"did:ad:table".to_string()));

        // readme: client only
        assert!(client_only.contains(&"did:ad:readme".to_string()));

        // --- Exchange deltas ---

        // Server sends table delta to client
        let client_table_vv = AtomicLoroDoc::vv_from_map(client_vvs.get("did:ad:table").unwrap());
        let server_table_delta = server_table.export_updates_since(&client_table_vv);

        // Client sends table delta + readme snapshot to server
        let server_table_vv = AtomicLoroDoc::vv_from_map(server_vvs.get("did:ad:table").unwrap());
        let client_table_delta = table_doc.export_updates_since(&server_table_vv);
        let readme_snapshot = client_readme.export_snapshot();

        // Apply deltas
        table_doc.import_update(&server_table_delta).unwrap();
        server_table.import_update(&client_table_delta).unwrap();
        let server_readme = AtomicLoroDoc::from_snapshot(&readme_snapshot).unwrap();

        // --- Verify convergence ---

        // Table: both should have merged state
        assert_eq!(
            table_doc.get_string_property("https://atomicdata.dev/properties/name"),
            Some("My Tasks".into()) // client's edit
        );
        assert_eq!(
            table_doc.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Server-side task list".into()) // server's edit
        );
        assert_eq!(
            server_table.get_string_property("https://atomicdata.dev/properties/name"),
            Some("My Tasks".into())
        );
        assert_eq!(
            server_table.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Server-side task list".into())
        );

        // VVs should match for table
        assert_eq!(table_doc.oplog_vv_map(), server_table.oplog_vv_map());

        // Server should now have readme
        assert_eq!(
            server_readme.get_string_property("https://atomicdata.dev/properties/name"),
            Some("README".into())
        );
        assert_eq!(
            server_readme.get_string_property("https://atomicdata.dev/properties/description"),
            Some("Read this first".into())
        );
    }

    /// Test vv_from_map helper: roundtrip from map to VV and back.
    #[test]
    fn vv_map_roundtrip() {
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("test".into()),
        )
        .unwrap();

        let map = doc.oplog_vv_map();
        assert!(!map.is_empty());

        // Reconstruct VV from map
        let reconstructed = AtomicLoroDoc::vv_from_map(&map);

        // The reconstructed VV should produce a very small delta (just Loro overhead, no ops)
        let delta = doc.export_updates_since(&reconstructed);
        // Loro includes some header bytes even for empty updates.
        // A delta with actual content would be much larger than the snapshot.
        let snapshot = doc.export_snapshot();
        assert!(
            delta.len() < snapshot.len(),
            "Delta ({} bytes) should be smaller than snapshot ({} bytes)",
            delta.len(),
            snapshot.len()
        );
    }

    #[test]
    fn history_and_time_travel() {
        let doc = AtomicLoroDoc::new();

        // Make a first change with explicit timestamp
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("v1".into()),
        )
        .unwrap();
        doc.doc()
            .commit_with(loro::CommitOptions::new().timestamp(1000));
        let v1 = doc.current_version();

        // Make a second change with a different timestamp
        doc.set_property(
            "https://atomicdata.dev/properties/name",
            &Value::String("v2".into()),
        )
        .unwrap();
        doc.doc()
            .commit_with(loro::CommitOptions::new().timestamp(2000));
        let v2 = doc.current_version();

        // get_history should return at least 1 entry (Loro may merge same-peer changes)
        let history = doc.get_history();
        assert!(
            !history.is_empty(),
            "Expected at least 1 history entry, got 0"
        );

        // Each entry should have a non-zero lamport
        for entry in &history {
            assert!(!entry.peer_id.is_empty());
        }

        // get_properties_at(v1) should return "v1"
        let props_v1 = doc.get_properties_at(&v1).unwrap();
        let name_v1 = props_v1
            .get("https://atomicdata.dev/properties/name")
            .unwrap();
        assert_eq!(
            name_v1,
            &loro::LoroValue::String("v1".into()),
            "v1 should have name=v1"
        );

        // get_properties_at(v2) should return "v2"
        let props_v2 = doc.get_properties_at(&v2).unwrap();
        let name_v2 = props_v2
            .get("https://atomicdata.dev/properties/name")
            .unwrap();
        assert_eq!(
            name_v2,
            &loro::LoroValue::String("v2".into()),
            "v2 should have name=v2"
        );

        // checkout + attach cycle
        doc.checkout(&v1).unwrap();
        assert_eq!(
            doc.get_string_property("https://atomicdata.dev/properties/name"),
            Some("v1".into())
        );
        doc.attach().unwrap();
        assert_eq!(
            doc.get_string_property("https://atomicdata.dev/properties/name"),
            Some("v2".into())
        );
    }

    /// Test that two independent docs pushing to a JSON array/list merge correctly.
    /// This simulates two devices drawing strokes independently.
    #[test]
    fn json_array_concurrent_push_merges() {
        let stroke_prop = "https://atomicdata.dev/ontology/canvas/strokeData";

        // Create base doc with initial state
        let base = AtomicLoroDoc::new();
        base.set_property("name", &Value::String("Canvas".into()))
            .unwrap();
        base.set_property(
            stroke_prop,
            &Value::Json(serde_json::json!([{"color": 1, "path": [[0, 0]]}])),
        )
        .unwrap();
        base.doc().commit();
        let base_snapshot = base.export_snapshot();

        // Device A: fork from base, push stroke A
        let doc_a = AtomicLoroDoc::from_snapshot(&base_snapshot).unwrap();
        doc_a
            .push_to_loro_list(
                stroke_prop,
                &serde_json::json!({"color": 2, "path": [[10, 10]]}),
            )
            .unwrap();
        doc_a.doc().commit();
        let snapshot_a = doc_a.export_snapshot();

        // Device B: fork from same base, push stroke B
        let doc_b = AtomicLoroDoc::from_snapshot(&base_snapshot).unwrap();
        doc_b
            .push_to_loro_list(
                stroke_prop,
                &serde_json::json!({"color": 3, "path": [[20, 20]]}),
            )
            .unwrap();
        doc_b.doc().commit();
        let snapshot_b = doc_b.export_snapshot();

        // Merge: B imports A's snapshot
        doc_b.import_update(&snapshot_a).unwrap();
        let merged_val = get_doc_property(&doc_b, stroke_prop).unwrap();

        match merged_val {
            Value::Json(serde_json::Value::Array(arr)) => {
                println!("Merged array has {} items: {:?}", arr.len(), arr);
                // Should have 3 strokes: base + A + B
                assert_eq!(
                    arr.len(),
                    3,
                    "Expected 3 strokes after merge, got {}",
                    arr.len()
                );
                // All colors should be present
                let colors: Vec<i64> = arr.iter().map(|s| s["color"].as_i64().unwrap()).collect();
                assert!(colors.contains(&1), "Missing base stroke");
                assert!(colors.contains(&2), "Missing A's stroke");
                assert!(colors.contains(&3), "Missing B's stroke");
            }
            other => panic!("Expected Json array, got {:?}", other),
        }

        // Also verify A importing B works the same way
        doc_a.import_update(&snapshot_b).unwrap();
        let merged_a_val = get_doc_property(&doc_a, stroke_prop).unwrap();
        match merged_a_val {
            Value::Json(serde_json::Value::Array(arr)) => {
                assert_eq!(arr.len(), 3, "A should also have 3 strokes after merge");
            }
            _ => panic!("Expected Json array"),
        }

        println!("TEST PASSED: concurrent Json pushes merge correctly");
    }

    #[test]
    fn delete_from_json_array() {
        let prop = "https://atomicdata.dev/ontology/canvas/strokeData";
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            prop,
            &Value::Json(serde_json::json!([
                {"color": 1},
                {"color": 2},
                {"color": 3},
            ])),
        )
        .unwrap();
        doc.doc().commit();

        // Delete the middle item (index 1)
        doc.delete_from_loro_list(prop, 1).unwrap();
        doc.doc().commit();

        let val = get_doc_property(&doc, prop).unwrap();
        match val {
            Value::Json(serde_json::Value::Array(arr)) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0]["color"], 1);
                assert_eq!(arr[1]["color"], 3);
            }
            _ => panic!("Expected Json array"),
        }

        // Out of bounds should error
        assert!(doc.delete_from_loro_list(prop, 10).is_err());
    }

    #[test]
    fn undo_exports_updates_for_sync() {
        let prop = "https://atomicdata.dev/ontology/canvas/strokeData";
        let doc = AtomicLoroDoc::new();
        doc.set_property(prop, &Value::Json(serde_json::Value::Array(vec![])))
            .unwrap();
        doc.doc().commit();
        doc.ensure_undo_manager();

        let base_snapshot = doc.export_snapshot();
        let base = AtomicLoroDoc::from_snapshot(&base_snapshot).unwrap();

        doc.push_to_loro_list(prop, &serde_json::json!({"color": 1}))
            .unwrap();
        doc.doc().commit();
        doc.checkpoint().unwrap();
        doc.push_to_loro_list(prop, &serde_json::json!({"color": 2}))
            .unwrap();
        doc.doc().commit();
        doc.checkpoint().unwrap();

        assert!(doc.undo().unwrap());
        let update = doc.export_updates_since(&base.oplog_vv());
        assert!(
            !update.is_empty(),
            "undo must produce oplog updates that can be exported for peer sync"
        );
    }

    #[test]
    fn undo_redo_json_array() {
        let prop = "https://atomicdata.dev/ontology/canvas/strokeData";
        let doc = AtomicLoroDoc::new();
        doc.set_property(prop, &Value::Json(serde_json::Value::Array(vec![])))
            .unwrap();
        doc.doc().commit();

        // Initialize undo manager before making changes
        doc.ensure_undo_manager();

        // Push stroke 1
        doc.push_to_loro_list(prop, &serde_json::json!({"color": 1}))
            .unwrap();
        doc.doc().commit();
        doc.checkpoint().unwrap();

        // Push stroke 2
        doc.push_to_loro_list(prop, &serde_json::json!({"color": 2}))
            .unwrap();
        doc.doc().commit();
        doc.checkpoint().unwrap();

        // Should have 2 strokes
        let count = |d: &AtomicLoroDoc| -> usize {
            match get_doc_property(d, prop) {
                Some(Value::Json(serde_json::Value::Array(arr))) => arr.len(),
                _ => 0,
            }
        };
        assert_eq!(count(&doc), 2);

        // Undo stroke 2
        assert!(doc.undo().unwrap());
        assert_eq!(count(&doc), 1);

        // Undo stroke 1
        assert!(doc.undo().unwrap());
        assert_eq!(count(&doc), 0);

        // Redo stroke 1
        assert!(doc.redo().unwrap());
        assert_eq!(count(&doc), 1);

        // Redo stroke 2
        assert!(doc.redo().unwrap());
        assert_eq!(count(&doc), 2);
    }

    #[test]
    fn undo_delete_restores_item() {
        let prop = "https://atomicdata.dev/ontology/canvas/strokeData";
        let doc = AtomicLoroDoc::new();
        doc.set_property(
            prop,
            &Value::Json(serde_json::json!([
                {"color": 1},
                {"color": 2},
            ])),
        )
        .unwrap();
        doc.doc().commit();

        // Initialize undo manager
        doc.ensure_undo_manager();
        doc.checkpoint().unwrap();

        // Delete item at index 0
        doc.delete_from_loro_list(prop, 0).unwrap();
        doc.doc().commit();

        let val = get_doc_property(&doc, prop).unwrap();
        match &val {
            Value::Json(serde_json::Value::Array(arr)) => assert_eq!(arr.len(), 1),
            _ => panic!("Expected Json array"),
        }

        // Undo the delete — item should come back
        assert!(doc.undo().unwrap());
        let val = get_doc_property(&doc, prop).unwrap();
        match val {
            Value::Json(serde_json::Value::Array(arr)) => {
                assert_eq!(arr.len(), 2, "Undo should restore the deleted item");
            }
            _ => panic!("Expected Json array"),
        }
    }

    #[test]
    fn extract_document_plain_text_empty() {
        let doc = AtomicLoroDoc::new();
        assert_eq!(doc.extract_document_plain_text(), "");
    }

    #[test]
    fn extract_document_plain_text_document_content_container() {
        let doc = AtomicLoroDoc::new();
        doc.doc()
            .get_text("documentContent")
            .insert(0, "RTE body text")
            .unwrap();
        assert_eq!(doc.extract_document_plain_text(), "RTE body text");
    }

    #[test]
    fn extract_text_loro_prosemirror_node_name_children() {
        let json = serde_json::json!({
            "nodeName": "doc",
            "children": [
                {
                    "nodeName": "paragraph",
                    "children": ["Hello ", "world"]
                }
            ]
        });
        assert_eq!(
            super::extract_text_from_prosemirror_json(&json).trim(),
            "Hello world"
        );
    }

    #[test]
    fn extract_text_prosemirror_type_content() {
        let json = serde_json::json!({
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{ "type": "text", "text": "Line one" }]
                },
                {
                    "type": "paragraph",
                    "content": [{ "type": "text", "text": "Line two" }]
                }
            ]
        });
        let text = super::extract_text_from_prosemirror_json(&json);
        assert!(text.contains("Line one"));
        assert!(text.contains("Line two"));
    }

    #[test]
    fn extract_document_plain_text_prefers_doc_over_document_content() {
        let doc = AtomicLoroDoc::new();
        doc.doc()
            .get_text("documentContent")
            .insert(0, "legacy text")
            .unwrap();
        let pm = doc.doc().get_map("doc");
        pm.insert("nodeName", "doc").unwrap();
        let children = pm
            .insert_container("children", loro::LoroList::new())
            .unwrap();
        let para = children.insert_container(0, loro::LoroMap::new()).unwrap();
        para.insert("nodeName", "paragraph").unwrap();
        let para_children = para
            .insert_container("children", loro::LoroList::new())
            .unwrap();
        para_children.insert(0, "from doc map").unwrap();

        assert_eq!(doc.extract_document_plain_text(), "from doc map");
    }
}
