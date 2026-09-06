//! Backup and restore — Phases 1 and 2 of
//! `atomic-saas/planning/CLOUD_VAULT_ARCHITECTURE.md`.
//!
//! One pass produces one object. Usually a **delta pack**: the resources whose
//! Loro version vector moved since this lane's cursor, exported as updates
//! against that cursor. Periodically a **checkpoint**: every resource's whole
//! oplog, self-sufficient, the anchor a delta chain hangs off and the thing
//! that lets the control plane delete what came before it.
//!
//! The Phase 1 shape exported every resource's whole oplog on every pass, so a
//! drive's stored bytes tracked how often somebody pressed "Back up now" rather
//! than how much data they had — five backups of an unchanged drive cost five
//! copies of it. Now an unchanged drive costs nothing at all: a pass whose
//! version vectors all match the cursor produces no object.
//!
//! Restore is order-independent and idempotent within a group, and that is a
//! property of Loro rather than of this code: ops are deduplicated by
//! `(peerId, counter)`, so importing the same pack twice, or importing lanes
//! from several devices in any order, converges on the same state. That is what
//! makes per-device lanes safe without a shared manifest or compare-and-swap.
//!
//! What Loro does *not* make order-independent is a delete racing a create for
//! the same subject, because a tombstone is applied by this code and not by the
//! CRDT. [`plan_restore`] is where that ordering is decided.

use super::dek::DriveVaultKey;
use super::envelope::{self, ObjectKind};
use super::pack::{Pack, PackEntry};
use super::store::VaultObjectStore;
use crate::db::Db;
use crate::errors::AtomicResult;
use crate::loro::AtomicLoroDoc;
use crate::resources::Resource;
use crate::storelike::Storelike;
use crate::Subject;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// A resource's Loro oplog version vector, as peer-id string → counter.
///
/// The same shape `AtomicLoroDoc::oplog_vv_map` and the sync engine already
/// use, kept as a `BTreeMap` here so a serialized cursor is byte-stable.
pub type VersionVectorMap = BTreeMap<String, i32>;

/// Local record of what a lane has already backed up.
///
/// Not uploaded and not part of the format — purely this device's memory,
/// which is `CLOUD_VAULT_ARCHITECTURE.md` decision 2 holding: incremental
/// cursors live in each device's local `Db`, never in shared metadata, so no
/// uploaded object is ever O(resources).
///
/// It does two jobs. The cursors are what makes a pass incremental: a resource
/// whose version vector still matches its cursor has not changed since this
/// lane last shipped it, and costs nothing. And the cursor set is how a
/// deletion is *detected* — a subject that was in the cursor and is gone from
/// this walk was removed, and a backup that cannot express that would restore
/// data its owner deleted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LaneState {
    /// Subject `pure_id()` → the oplog version vector this lane has shipped.
    ///
    /// An absent subject, or an empty vector, means "ship the whole oplog" —
    /// which is what a brand-new resource and a freshly-upgraded device both
    /// need, and is always safe because it is a superset of what is missing.
    #[serde(default)]
    pub cursors: BTreeMap<String, VersionVectorMap>,
    /// Segments this lane has written since the last checkpoint it took part in.
    #[serde(default)]
    pub segments_since_checkpoint: u32,
    /// Sealed bytes written since then. Drives the "a checkpoint would pay for
    /// itself" half of [`CheckpointPolicy`].
    #[serde(default)]
    pub bytes_since_checkpoint: u64,
    /// Sealed size of the last checkpoint this device wrote, or 0 if it has
    /// never written one.
    #[serde(default)]
    pub last_checkpoint_bytes: u64,
    /// Lanes this device has provably imported, device pubkey → highest
    /// segment. A checkpoint may claim coverage for these, because importing a
    /// segment means holding its ops; it may not claim coverage for a lane it
    /// has only seen listed.
    #[serde(default)]
    pub imported_lanes: BTreeMap<String, u32>,
}

impl LaneState {
    /// Read what a pre-Phase-2 build wrote, or a fresh state.
    ///
    /// Phase 1 stored a bare `Vec<String>` of the subjects the last pack held.
    /// Those become cursors with no version vector — "ship everything" — so the
    /// first pass after an upgrade is a full export and every pass after it is
    /// incremental. The alternative would be inventing version vectors for
    /// history we never recorded, which would silently skip ops that were never
    /// backed up.
    fn decode(bytes: &[u8]) -> Self {
        if let Ok(state) = serde_json::from_slice::<LaneState>(bytes) {
            return state;
        }
        if let Ok(subjects) = serde_json::from_slice::<Vec<String>>(bytes) {
            return Self {
                cursors: subjects
                    .into_iter()
                    .map(|subject| (subject, VersionVectorMap::new()))
                    .collect(),
                ..Default::default()
            };
        }
        Self::default()
    }

    /// Subjects this lane believes it has backed up.
    fn known_subjects(&self) -> impl Iterator<Item = &String> {
        self.cursors.keys()
    }
}

fn lane_state_key(drive_pseudonym: &str, device_pubkey: &str) -> Vec<u8> {
    format!("vault-lane:{drive_pseudonym}:{device_pubkey}").into_bytes()
}

/// Where a not-yet-uploaded export parks its lane state.
///
/// Sealing and *storing* are two steps for a hosted vault: the client seals
/// locally and something else pushes the bytes at object storage afterwards.
/// Recording the lane as backed up at seal time would mean a failed upload
/// still advanced the cursor, and the next pass would export deltas against a
/// segment that does not exist in the vault — a hole no later pass would ever
/// fill. So the export writes here, and [`commit_lane_state`] promotes it once
/// the upload is confirmed.
fn pending_lane_state_key(drive_pseudonym: &str, device_pubkey: &str, segment: u32) -> Vec<u8> {
    format!("vault-lane-pending:{drive_pseudonym}:{device_pubkey}:{segment}").into_bytes()
}

pub fn read_lane_state(store: &Db, drive_pseudonym: &str, device_pubkey: &str) -> LaneState {
    store
        .kv
        .get(
            crate::db::trees::Tree::PluginMeta,
            &lane_state_key(drive_pseudonym, device_pubkey),
        )
        .ok()
        .flatten()
        .map(|bytes| LaneState::decode(&bytes))
        .unwrap_or_default()
}

fn write_lane_state(store: &Db, drive_pseudonym: &str, device_pubkey: &str, state: &LaneState) {
    if let Ok(bytes) = serde_json::to_vec(state) {
        let _ = store.kv.insert(
            crate::db::trees::Tree::PluginMeta,
            &lane_state_key(drive_pseudonym, device_pubkey),
            &bytes,
        );
    }
}

/// Promote a parked export to this lane's committed state.
///
/// Call once the segment is durably in the vault. Until then the previous
/// state stands, so a failed upload is retried against the same view of what
/// has been backed up rather than one that assumed success.
///
/// A no-op when nothing was parked for that segment, so a caller that
/// double-confirms does no harm.
pub fn commit_lane_state(
    store: &Db,
    drive_pseudonym: &str,
    device_pubkey: &str,
    segment: u32,
) -> AtomicResult<()> {
    let pending_key = pending_lane_state_key(drive_pseudonym, device_pubkey, segment);
    let Some(bytes) = store
        .kv
        .get(crate::db::trees::Tree::PluginMeta, &pending_key)
        .ok()
        .flatten()
    else {
        return Ok(());
    };

    let state: LaneState =
        serde_json::from_slice(&bytes).map_err(|e| format!("malformed pending lane state: {e}"))?;
    write_lane_state(store, drive_pseudonym, device_pubkey, &state);
    let _ = store
        .kv
        .remove(crate::db::trees::Tree::PluginMeta, &pending_key);
    Ok(())
}

/// Record that this device imported a lane up to `segment`.
///
/// This is what lets a later checkpoint claim coverage for somebody else's
/// lane: importing a segment means holding its ops, and coverage is a claim
/// the control plane acts on by *deleting* things. A lane this device has
/// merely seen in a listing is not covered, however sure we feel — the cost of
/// being wrong is the only copy of some history.
pub fn record_imported_lane(
    store: &Db,
    drive_pseudonym: &str,
    device_pubkey: &str,
    lane: &str,
    segment: u32,
) {
    let mut state = read_lane_state(store, drive_pseudonym, device_pubkey);
    let slot = state.imported_lanes.entry(lane.to_string()).or_insert(0);
    if segment <= *slot {
        return;
    }
    *slot = segment;
    write_lane_state(store, drive_pseudonym, device_pubkey, &state);
}

/// Every object for a drive, across every device lane.
///
/// Restore must span lanes: each device appends only to its own, so importing
/// one lane's prefix would silently drop every other device's history.
pub fn drive_prefix(drive_pseudonym: &str) -> String {
    format!("vault/{drive_pseudonym}/")
}

/// Where a device's lane objects live for a drive.
pub fn lane_prefix(drive_pseudonym: &str, device_pubkey: &str) -> String {
    format!("vault/{drive_pseudonym}/lanes/{device_pubkey}/")
}

/// The object key for one segment of one device's lane.
///
/// Zero-padded to six digits so lexical ordering matches numeric ordering —
/// both S3 listing and the filesystem store sort lexically, and `seg-10` must
/// not sort before `seg-2`.
pub fn segment_key(drive_pseudonym: &str, device_pubkey: &str, segment: u32) -> String {
    format!(
        "{}seg-{segment:06}.pack",
        lane_prefix(drive_pseudonym, device_pubkey)
    )
}

/// Where a drive's checkpoints live.
pub fn checkpoint_prefix(drive_pseudonym: &str) -> String {
    format!("vault/{drive_pseudonym}/checkpoints/")
}

/// The object key for one checkpoint.
///
/// Zero-padded for the same reason segments are, and it matters more here:
/// `checkpoints/` sorts before `lanes/`, so a listing hands a restore every
/// checkpoint before any segment, and `ckpt-10` ahead of `ckpt-2` would make it
/// pick the wrong anchor.
pub fn checkpoint_key(drive_pseudonym: &str, checkpoint_n: u64) -> String {
    format!(
        "{}ckpt-{checkpoint_n:06}.loro",
        checkpoint_prefix(drive_pseudonym)
    )
}

/// The segment number in a lane object key, if it is one.
pub fn parse_segment_key(object_key: &str) -> Option<(String, u32)> {
    let rest = object_key.split("/lanes/").nth(1)?;
    let (device, file) = rest.split_once('/')?;
    let number = file.strip_prefix("seg-")?.strip_suffix(".pack")?;
    Some((device.to_string(), number.parse().ok()?))
}

/// The checkpoint number in a checkpoint object key, if it is one.
pub fn parse_checkpoint_key(object_key: &str) -> Option<u64> {
    let file = object_key.split("/checkpoints/").nth(1)?;
    file.strip_prefix("ckpt-")?
        .strip_suffix(".loro")?
        .parse()
        .ok()
}

/// What kind of object a pass produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    /// A delta against this lane's cursor. Needs the checkpoint it hangs off.
    Pack,
    /// Every resource's whole oplog. Restores the drive on its own.
    Checkpoint,
}

/// When a pass should write a checkpoint instead of a delta.
///
/// Both thresholds bound something real. `max_segments` bounds *restore cost*:
/// a restore replays the anchor plus every delta after it, so an unbounded
/// chain is an unbounded restore, and a chain with one missing link is a
/// restore that comes up short. `bytes_ratio` bounds *stored size*: once the
/// deltas since the last checkpoint outweigh the checkpoint itself, taking a
/// new one and letting the control plane drop the chain is strictly cheaper.
///
/// An idle drive trips neither, which is the point — it writes nothing at all.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointPolicy {
    pub max_segments: u32,
    pub bytes_ratio: f64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            max_segments: 64,
            bytes_ratio: 1.0,
        }
    }
}

impl CheckpointPolicy {
    fn wants_checkpoint(&self, state: &LaneState, drive_has_checkpoint: bool) -> bool {
        // No anchor in the vault at all: this pass has to be one, or every
        // delta it writes hangs off nothing. Also the upgrade path — a lane
        // whose cursors came from Phase 1 has no version vectors, so this pass
        // is a full export regardless and may as well be published as the
        // anchor it already is.
        if !drive_has_checkpoint {
            return true;
        }
        if state.segments_since_checkpoint >= self.max_segments {
            return true;
        }
        state.last_checkpoint_bytes > 0
            && state.bytes_since_checkpoint as f64
                >= state.last_checkpoint_bytes as f64 * self.bytes_ratio
    }
}

/// Outcome of one backup pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    pub kind: SegmentKind,
    pub object_key: String,
    /// Resources whose history this object carries.
    pub resources: usize,
    /// Resources the walk found and skipped because their version vector still
    /// matched the cursor. The whole point of Phase 2, and worth surfacing: on
    /// a healthy incremental pass this is nearly the whole drive.
    pub unchanged: usize,
    pub tombstones: usize,
    pub sealed_bytes: usize,
    /// Checkpoints only — the lanes this object provably subsumes, which is
    /// what the control plane prunes against. Empty for a delta pack.
    pub coverage: BTreeMap<String, u32>,
}

/// Outcome of one restore pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreSummary {
    pub packs_read: usize,
    pub resources_restored: usize,
    pub tombstones_applied: usize,
    /// Objects the plan deliberately did not read because a checkpoint already
    /// subsumes them.
    pub objects_skipped: usize,
    /// Objects that would not open. Non-zero means part of this vault is
    /// corrupt or was written by something else — the rest was still restored,
    /// and a caller that reports "restored" without reporting this is lying.
    pub objects_unreadable: usize,
}

/// The agents named in a drive's `read` and `write` rights.
///
/// A drive walk never reaches them: an agent resource has no parent, it is
/// nobody's child. Yet the name typed on the first device lives there, and on
/// an origin without a node — the hosted app — nowhere else. Restored from a
/// pack that leaves it out, the drive opens fine and settings shows an empty
/// name: the account came back, the person did not. So the agents a drive
/// grants rights to travel with it.
///
/// Rights the drive cannot be read for are treated as no agents: a drive that
/// exports at all has already been read once, and a missing property is the
/// ordinary case for a drive nobody was ever invited to.
async fn drive_agent_subjects(store: &Db, drive: &Subject) -> Vec<String> {
    let Ok(resource) = store.get_resource(drive).await else {
        return Vec::new();
    };

    [crate::urls::READ, crate::urls::WRITE]
        .iter()
        .filter_map(|right| resource.get(right).ok())
        .filter_map(|value| value.to_subjects(None).ok())
        .flatten()
        .filter(|subject| Subject::from_raw(subject, None).is_agent_did())
        .collect()
}

/// This resource's current oplog version vector, read without rebuilding it.
///
/// `vv_map_from_snapshot` parses the stored blob's header instead of replaying
/// the whole CRDT document, which is what makes an incremental pass cheap: an
/// unchanged drive is a header read per resource rather than a doc build per
/// resource. `None` means we could not read it cheaply, and the caller falls
/// back to building the doc — never to assuming nothing changed.
fn cheap_version_vector(store: &Db, subject: &str) -> Option<VersionVectorMap> {
    let snapshot = store
        .kv
        .get(crate::db::trees::Tree::LoroSnapshots, subject.as_bytes())
        .ok()
        .flatten()?;
    let vv = AtomicLoroDoc::vv_map_from_snapshot(&snapshot).ok()?;
    Some(vv.into_iter().collect())
}

/// One resource's contribution to this pass.
enum Contribution {
    /// Ship these bytes and advance the cursor to this vector.
    Update(Vec<u8>, VersionVectorMap),
    /// Nothing moved since the cursor.
    Unchanged,
    /// The store could not produce it; leave the cursor alone.
    Unreadable,
}

async fn contribution(
    store: &Db,
    subject_str: &str,
    cursor: Option<&VersionVectorMap>,
    full: bool,
) -> Contribution {
    // The cheap path, and the one that carries the whole win: if this
    // resource's version vector still matches what the lane shipped, there is
    // nothing to export and no reason to build the document to find that out.
    if !full {
        if let Some(cursor) = cursor {
            if cheap_version_vector(store, subject_str).as_ref() == Some(cursor) {
                return Contribution::Unchanged;
            }
        }
    }

    let subject = Subject::from_raw(subject_str, None);

    // A subject the drive walk found but the store cannot produce is not
    // fatal: the walk reads an index, and a resource deleted between the two
    // is an ordinary race rather than a corrupt drive.
    let Ok(resource) = store.get_resource(&subject).await else {
        return Contribution::Unreadable;
    };
    let Ok(doc) = resource.build_state_doc() else {
        return Contribution::Unreadable;
    };

    // A checkpoint exports against an empty vector — the whole oplog, still a
    // stream of updates rather than a snapshot. A delta exports against the
    // cursor, so its size tracks the edit rather than the document.
    let since = match (full, cursor) {
        (false, Some(cursor)) => AtomicLoroDoc::vv_from_map(&cursor.clone().into_iter().collect()),
        _ => Default::default(),
    };
    let update = doc.export_updates_since(&since);
    let reached: VersionVectorMap = doc.oplog_vv_map().into_iter().collect();

    if update.is_empty() {
        // Empty against a real cursor means "nothing new"; empty against an
        // empty cursor means the resource has no history to ship at all. Both
        // are "contribute nothing", but only the first may advance a cursor —
        // and it advances to a vector we just read, not one we assumed.
        return Contribution::Unchanged;
    }

    Contribution::Update(update, reached)
}

/// Export one pass of a drive's history into `vault`.
///
/// Writes a **delta pack** at `segment`, or a **checkpoint** at `checkpoint_n`
/// when [`CheckpointPolicy`] says the chain needs a fresh anchor. The caller
/// does not choose: the policy lives here so every host that drives the vault
/// makes the same decision, which is decision 5 of the architecture doc
/// ("one implementation everywhere") applied to cadence rather than crypto.
///
/// `observed_lanes` is the control plane's `{device → newest segment}` map,
/// which a checkpoint records so a restore can tell which segments predate it.
/// Pass an empty map when it is unavailable; the checkpoint is still correct,
/// it simply orders every segment after itself.
///
/// Returns `None` when the drive has nothing to back up — which, unlike
/// Phase 1, is now the *normal* outcome for an idle device rather than a rare
/// one.
#[allow(clippy::too_many_arguments)]
pub async fn export_vault_segment(
    store: &Db,
    drive: &Subject,
    key: &DriveVaultKey,
    vault: &dyn VaultObjectStore,
    drive_pseudonym: &str,
    device_pubkey: &str,
    segment: u32,
    checkpoint_n: u64,
    drive_has_checkpoint: bool,
    observed_lanes: &BTreeMap<String, u32>,
    policy: CheckpointPolicy,
) -> AtomicResult<Option<BackupSummary>> {
    let mut state = read_lane_state(store, drive_pseudonym, device_pubkey);
    let full = policy.wants_checkpoint(&state, drive_has_checkpoint);

    let mut subjects: HashSet<String> =
        crate::sync::engine::collect_drive_subjects(store, drive).await;
    subjects.extend(drive_agent_subjects(store, drive).await);

    let mut entries = Vec::new();
    let mut cursors: BTreeMap<String, VersionVectorMap> = BTreeMap::new();
    let mut unchanged = 0usize;

    for subject_str in &subjects {
        match contribution(store, subject_str, state.cursors.get(subject_str), full).await {
            Contribution::Update(update, reached) => {
                entries.push(PackEntry {
                    subject: subject_str.clone(),
                    update,
                });
                cursors.insert(subject_str.clone(), reached);
            }
            Contribution::Unchanged => {
                unchanged += 1;
                // Carry the cursor forward unchanged. Dropping it would make
                // the next pass re-export the resource, and — worse — make it
                // look deleted to the tombstone check below.
                if let Some(existing) = state.cursors.get(subject_str) {
                    cursors.insert(subject_str.clone(), existing.clone());
                } else if let Some(current) = cheap_version_vector(store, subject_str) {
                    cursors.insert(subject_str.clone(), current);
                }
            }
            Contribution::Unreadable => {
                // Keep whatever the lane knew. A resource we failed to read is
                // not a resource that was deleted, and forgetting it here would
                // make the next pass claim a tombstone for it.
                if let Some(existing) = state.cursors.get(subject_str) {
                    cursors.insert(subject_str.clone(), existing.clone());
                }
            }
        }
    }

    // Stable order so two passes over the same change produce identical
    // plaintext. The sealed bytes still differ (fresh nonce per seal), but a
    // deterministic plaintext keeps the format debuggable and makes a
    // content-addressed layer possible later.
    entries.sort_by(|a, b| a.subject.cmp(&b.subject));

    // Anything this lane backed up before and cannot see now was deleted.
    // Without this the deletion is simply absent from the vault: the resource
    // still lives in an earlier segment's pack, and a restore brings it back.
    // Restoring data its owner deleted is the one failure a backup must not
    // have.
    //
    // Only subjects with a local tombstone are claimed. A subject that merely
    // vanished from the walk could be a transient read failure or an
    // authorization change, and a tombstone we invent would *delete real data*
    // on restore — far worse than carrying a stale resource for another cycle.
    let mut tombstones = Vec::new();
    let mut carried = Vec::new();
    for subject in state.known_subjects() {
        if cursors.contains_key(subject) {
            continue;
        }
        if crate::sync::tombstones::is_tombstoned(store, subject) {
            tombstones.push(subject.clone());
        } else {
            // Gone from the walk with no tombstone to explain it. Keep the
            // cursor rather than forgetting the subject: forgetting it means
            // this lane no longer knows it ever backed it up, so if the
            // resource is deleted later the deletion is never claimed and a
            // restore brings it back. Carrying a stale cursor costs a
            // re-export if the resource returns; forgetting costs a deletion
            // that never reaches the vault.
            carried.push(subject.clone());
        }
    }
    for subject in carried {
        if let Some(cursor) = state.cursors.get(&subject) {
            cursors.insert(subject, cursor.clone());
        }
    }

    let (pack, kind, object_key, coverage) = if full {
        // Coverage is a claim the control plane acts on by deleting, so it
        // names only lanes whose ops this device can show it holds: its own,
        // which it wrote, and any it has imported. Every other lane keeps its
        // full history until its own device publishes a checkpoint.
        let mut coverage = state.imported_lanes.clone();
        if segment > 1 {
            coverage.insert(device_pubkey.to_string(), segment - 1);
        }
        let observed = observed_lanes.clone();
        (
            Pack::checkpoint(entries, tombstones, coverage.clone(), observed),
            SegmentKind::Checkpoint,
            checkpoint_key(drive_pseudonym, checkpoint_n),
            coverage,
        )
    } else {
        (
            Pack::new(entries, tombstones),
            SegmentKind::Pack,
            segment_key(drive_pseudonym, device_pubkey, segment),
            BTreeMap::new(),
        )
    };

    if pack.is_empty() {
        return Ok(None);
    }

    let resources = pack.entries.len();
    let tombstone_count = pack.tombstones.len();
    let object_kind = match kind {
        SegmentKind::Pack => ObjectKind::Pack,
        SegmentKind::Checkpoint => ObjectKind::Checkpoint,
    };
    let sealed = envelope::seal(key, object_kind, &pack.encode()?)?;
    vault.put(&object_key, &sealed)?;

    state.cursors = cursors;
    match kind {
        SegmentKind::Checkpoint => {
            state.segments_since_checkpoint = 0;
            state.bytes_since_checkpoint = 0;
            state.last_checkpoint_bytes = sealed.len() as u64;
        }
        SegmentKind::Pack => {
            state.segments_since_checkpoint = state.segments_since_checkpoint.saturating_add(1);
            state.bytes_since_checkpoint = state
                .bytes_since_checkpoint
                .saturating_add(sealed.len() as u64);
        }
    }

    // Parked, not committed. `vault.put` above may be a staging buffer whose
    // real upload happens elsewhere and can still fail; only
    // `commit_lane_state` — called once the object is durably stored — makes
    // this lane's progress official. Getting this wrong matters more now than
    // it did in Phase 1: an advanced cursor whose segment never landed leaves
    // ops that no future delta will ever ship again.
    if let Ok(bytes) = serde_json::to_vec(&state) {
        let _ = store.kv.insert(
            crate::db::trees::Tree::PluginMeta,
            &pending_lane_state_key(drive_pseudonym, device_pubkey, segment),
            &bytes,
        );
    }

    Ok(Some(BackupSummary {
        kind,
        object_key,
        resources,
        unchanged,
        tombstones: tombstone_count,
        sealed_bytes: sealed.len(),
        coverage,
    }))
}

/// Which objects a restore reads, and in what order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorePlan {
    /// Object keys in application order.
    pub order: Vec<String>,
    /// Object keys a checkpoint already subsumes. Not read, not downloaded.
    pub skipped: Vec<String>,
}

/// Decide what to replay from what the vault holds.
///
/// Without an anchor this is just "everything, in key order" — Phase 1's
/// behaviour, and still correct for a vault written before checkpoints existed.
///
/// With one, the anchor splits the timeline in three, and the split is the
/// whole reason `observed` is recorded separately from `coverage`:
///
/// 1. **Before the anchor.** Older checkpoints, and lane segments at or below
///    the anchor's observed mark that it does not actually cover.
/// 2. **The anchor**, whose tombstones therefore win over everything in (1).
/// 3. **After the anchor.** Segments above the observed mark, and every
///    segment of a lane the anchor never saw — those are the ones that may
///    legitimately re-create something the anchor recorded as deleted.
///
/// Applying the anchor first instead would let an old segment from (1) put back
/// a resource the anchor knows was deleted. Applying it last would let it
/// delete a resource created after it. Loro makes the *updates* commute; the
/// tombstones are applied by this code, so this code has to order them.
pub fn plan_restore(
    keys: &[String],
    anchor: Option<&str>,
    coverage: &BTreeMap<String, u32>,
    observed: &BTreeMap<String, u32>,
) -> RestorePlan {
    let Some(anchor) = anchor else {
        let mut order = keys.to_vec();
        order.sort();
        return RestorePlan {
            order,
            skipped: Vec::new(),
        };
    };

    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut skipped = Vec::new();

    for object_key in keys {
        if object_key == anchor {
            continue;
        }
        match parse_segment_key(object_key) {
            Some((lane, segment)) => {
                // Covered means the anchor provably holds these ops. Reading
                // them again would be harmless but pointless, and the control
                // plane deletes them, so a restore must not need them.
                if coverage.get(&lane).is_some_and(|&c| segment <= c) {
                    skipped.push(object_key.clone());
                } else if observed.get(&lane).is_some_and(|&o| segment <= o) {
                    before.push(object_key.clone());
                } else {
                    // Either newer than the anchor, or from a lane the anchor
                    // never saw. Both belong after it: an unseen lane's history
                    // cannot be assumed older than a checkpoint that never
                    // mentioned it.
                    after.push(object_key.clone());
                }
            }
            // Another checkpoint. The anchor has the highest number, so any
            // other one predates it.
            None => before.push(object_key.clone()),
        }
    }

    before.sort();
    after.sort();
    skipped.sort();

    let mut order = before;
    order.push(anchor.to_string());
    order.extend(after);

    RestorePlan { order, skipped }
}

/// The anchor a restore should hang off: the highest-numbered checkpoint.
fn newest_checkpoint(keys: &[String]) -> Option<String> {
    keys.iter()
        .filter_map(|key| parse_checkpoint_key(key).map(|n| (n, key)))
        .max_by_key(|(n, _)| *n)
        .map(|(_, key)| key.clone())
}

/// Open the objects under `prefix` and merge them into `store`.
///
/// Safe to run against a populated store as well as an empty one: Loro merges
/// rather than overwrites, so a restore over a partially-synced device
/// converges instead of clobbering local edits.
///
/// `device_pubkey` is this device's lane, used only to record which other lanes
/// were imported — that is what lets a checkpoint this device publishes later
/// claim coverage for them. Pass `None` from a tool that is not a vault client
/// (a one-shot recovery command, say); the restore is identical, it simply
/// teaches this device nothing about what it now holds.
pub async fn import_vault_batch(
    store: &Db,
    key: &DriveVaultKey,
    vault: &dyn VaultObjectStore,
    prefix: &str,
    drive_pseudonym: Option<(&str, &str)>,
) -> AtomicResult<RestoreSummary> {
    let mut summary = RestoreSummary::default();

    // Sorted by the store contract, so segments replay in the order written.
    let keys = vault.list(prefix)?;

    // Read the anchor first — not to apply it first, but because its own
    // coverage and observed maps are what decide the order everything else is
    // applied in. It is the one object whose contents the plan depends on.
    let anchor = newest_checkpoint(&keys);
    let (mut coverage, mut observed) = (BTreeMap::new(), BTreeMap::new());
    let mut anchor_key = None;
    if let Some(candidate) = anchor {
        match vault
            .get(&candidate)
            .and_then(|sealed| envelope::open(key, &sealed))
        {
            Ok((_, plaintext)) => {
                let pack = Pack::decode(&plaintext)?;
                coverage = pack.coverage.clone();
                observed = pack.observed.clone();
                anchor_key = Some(candidate);
            }
            // An anchor we cannot open is not an anchor. Falling back to
            // replaying everything restores strictly more than skipping
            // objects on the word of a checkpoint we never read.
            Err(err) => {
                tracing::warn!(
                    "Cloud Vault restore: checkpoint {candidate} could not be opened ({err}); \
                     replaying every object instead"
                );
            }
        }
    }

    let plan = plan_restore(&keys, anchor_key.as_deref(), &coverage, &observed);
    summary.objects_skipped = plan.skipped.len();

    for object_key in &plan.order {
        let sealed = vault.get(object_key)?;

        // One unopenable object must not cost the user every other one. A
        // corrupt or foreign object is skipped and counted; the caller is
        // expected to surface the count rather than report a clean restore.
        //
        // The whole-vault case is different and is checked after the loop: if
        // *nothing* opened, this is the wrong key, not corruption, and a
        // successful-looking restore of an empty drive is the worst answer
        // available.
        let Ok((header, plaintext)) = envelope::open(key, &sealed) else {
            tracing::warn!("Cloud Vault restore: {object_key} could not be opened; skipping it");
            summary.objects_unreadable += 1;
            continue;
        };
        if !matches!(header.kind, ObjectKind::Pack | ObjectKind::Checkpoint) {
            continue;
        }
        let pack = Pack::decode(&plaintext)?;
        summary.packs_read += 1;

        for entry in pack.entries {
            let subject = Subject::from_raw(&entry.subject, None);

            // Merge into whatever is already here rather than replacing it.
            // An existing resource contributes its history; a missing one
            // starts from an empty doc.
            let mut resource = match store.get_resource(&subject).await {
                Ok(existing) => existing,
                Err(_) => Resource::new(entry.subject.clone()),
            };
            let doc = resource.build_state_doc()?;
            doc.import_update(&entry.update)?;
            resource.apply_state_doc(doc)?;

            // Validation off: a restore replays history that was already
            // validated when it was written. Re-imposing today's required-props
            // rules on old data would make a schema change retroactively
            // unrestorable, which is precisely when a backup matters most.
            store
                .add_resource_opts(&resource, false, true, true)
                .await?;

            // A subject this device had destroyed is being re-created by the
            // backup. Leaving the tombstone in place would keep `is_tombstoned`
            // suppressing it from every future bulk sync, so the restored
            // resource would exist locally and never reach another replica —
            // the same stale-invariant bug `clear_tombstone` exists for (F11).
            // Objects replay in plan order, so a later tombstone still wins.
            crate::sync::tombstones::clear_tombstone(store, &entry.subject);
            summary.resources_restored += 1;
        }

        for subject_str in pack.tombstones {
            // `remove_resource` rather than a bare `record_tombstone`: the
            // marker alone leaves the resource's data and index entries in
            // place, so an earlier segment's oplog would restore a deleted
            // resource and the tombstone would only stop it propagating. A
            // delete must actually delete. `remove_resource` recurses into
            // children and records tombstones for everything it removes.
            let subject = Subject::from_raw(&subject_str, None);
            match store.remove_resource(&subject).await {
                Ok(()) => {}
                // Already absent is the normal case when restoring into an
                // empty store: the tombstone still has to be recorded so a
                // later bulk sync does not pull the resource back from a peer.
                Err(_) => crate::sync::tombstones::record_tombstone(store, &subject_str),
            }
            summary.tombstones_applied += 1;
        }

        // Now this device provably holds that lane's ops up to here, so a
        // checkpoint it publishes later may cover them — which is what lets a
        // restored device clean up lanes belonging to a phone that is gone.
        if let (Some((pseudonym, device)), Some((lane, segment))) =
            (drive_pseudonym, parse_segment_key(object_key))
        {
            record_imported_lane(store, pseudonym, device, &lane, segment);
        }
    }

    // Nothing opened, but there was something to open: the key is wrong. Say so
    // rather than returning a summary that reads like a successful restore of a
    // drive that happens to be empty.
    if summary.packs_read == 0 && summary.objects_unreadable > 0 {
        return Err(format!(
            "could not decrypt any of the {} vault objects for this drive — wrong drive key",
            summary.objects_unreadable
        )
        .into());
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::store::MemoryVaultStore;

    const PSEUDONYM: &str = "testpseudonym";
    const DEVICE: &str = "testdevice";

    fn key() -> DriveVaultKey {
        DriveVaultKey::from_bytes([5u8; 32], 1)
    }

    #[test]
    fn segment_keys_sort_in_replay_order() {
        let mut keys = vec![
            segment_key(PSEUDONYM, DEVICE, 10),
            segment_key(PSEUDONYM, DEVICE, 2),
            segment_key(PSEUDONYM, DEVICE, 1),
        ];
        keys.sort();
        assert_eq!(
            keys,
            vec![
                segment_key(PSEUDONYM, DEVICE, 1),
                segment_key(PSEUDONYM, DEVICE, 2),
                segment_key(PSEUDONYM, DEVICE, 10),
            ],
            "lexical order must match segment order, or replay applies packs backwards"
        );
    }

    /// Golden vectors for the S3 key layout, shared with the control plane.
    ///
    /// The layout is implemented **twice**: here, and in atomic-saas's
    /// `build_object_key`, which decides the key a presigned URL points at.
    /// `planning/encrypted-vault-format.md` is the source of truth for both. A
    /// matching test lives in that repo
    /// (`object_keys_match_the_published_format_spec`) asserting these exact
    /// strings.
    ///
    /// Nothing at compile time couples the two — that repo is closed and this
    /// one is MIT, so no shared fixture crate is possible. If either side
    /// drifts, a client uploads to keys the control plane never issued and
    /// nothing notices until a restore comes up short. Changing a string here
    /// means changing it there and in the spec, in the same change.
    #[test]
    fn segment_key_matches_the_published_format() {
        let device = "0303030303030303030303030303030303030303030303030303030303030303";
        let key = segment_key("testpseudonym", device, 1);
        assert_eq!(
            key,
            "vault/testpseudonym/lanes/0303030303030303030303030303030303030303030303030303030303030303/seg-000001.pack",
            "atomic-saas build_object_key must produce this byte-for-byte"
        );

        // Six-digit zero padding is load-bearing: both S3 listing and the
        // filesystem store sort lexically, and seg-10 ordering before seg-2
        // would replay a lane's history backwards.
        assert!(
            key < segment_key("testpseudonym", device, 10),
            "lexical order must match segment order"
        );
    }

    #[test]
    fn segment_keys_live_under_the_device_lane() {
        let k = segment_key(PSEUDONYM, DEVICE, 1);
        assert_eq!(k, "vault/testpseudonym/lanes/testdevice/seg-000001.pack");
        assert!(k.starts_with(&lane_prefix(PSEUDONYM, DEVICE)));
    }

    /// Without an anchor the plan is Phase 1's: everything, in key order.
    #[test]
    fn a_vault_with_no_checkpoint_replays_everything() {
        let keys = vec![
            segment_key(PSEUDONYM, DEVICE, 2),
            segment_key(PSEUDONYM, DEVICE, 1),
        ];
        let plan = plan_restore(&keys, None, &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(
            plan.order,
            vec![
                segment_key(PSEUDONYM, DEVICE, 1),
                segment_key(PSEUDONYM, DEVICE, 2),
            ]
        );
        assert!(plan.skipped.is_empty());
    }

    /// The ordering rule the whole checkpoint design rests on.
    ///
    /// A segment the anchor *observed* predates it and must be applied first,
    /// or the anchor's tombstone is undone by an older segment that still holds
    /// the resource. A segment above the observed mark came after and must be
    /// applied last, or the anchor deletes something created since. A segment
    /// the anchor *covers* is not read at all — the control plane deletes those,
    /// so a restore must never need them.
    #[test]
    fn a_checkpoint_orders_the_segments_around_itself() {
        let other = "ff".repeat(32);
        let anchor = checkpoint_key(PSEUDONYM, 7);
        let keys = vec![
            checkpoint_key(PSEUDONYM, 3),
            anchor.clone(),
            segment_key(PSEUDONYM, DEVICE, 1),
            segment_key(PSEUDONYM, DEVICE, 4),
            segment_key(PSEUDONYM, DEVICE, 9),
            segment_key(PSEUDONYM, &other, 2),
        ];

        let plan = plan_restore(
            &keys,
            Some(&anchor),
            // Provably held through segment 1 of this device's lane.
            &BTreeMap::from([(DEVICE.to_string(), 1u32)]),
            // Seen up to segment 4 when it was published. Nothing was known
            // about the other device's lane at all.
            &BTreeMap::from([(DEVICE.to_string(), 4u32)]),
        );

        assert_eq!(
            plan.skipped,
            vec![segment_key(PSEUDONYM, DEVICE, 1)],
            "a covered segment is not read"
        );
        assert_eq!(
            plan.order,
            vec![
                // Predates the anchor: an older checkpoint, and a segment the
                // anchor saw but cannot prove it holds.
                checkpoint_key(PSEUDONYM, 3),
                segment_key(PSEUDONYM, DEVICE, 4),
                anchor.clone(),
                // Everything after the anchor, in key order. The other lane
                // sorts first only because `ff…` < `testdevice`; across lanes
                // there is no true ordering to recover, and Loro makes the
                // updates commute anyway.
                //
                // A lane the anchor never mentioned belongs *after* it: its
                // history cannot be assumed older than a checkpoint that never
                // saw it, and the safe side of that guess is the one where the
                // anchor does not delete resources this lane created.
                segment_key(PSEUDONYM, &other, 2),
                segment_key(PSEUDONYM, DEVICE, 9),
            ]
        );
    }

    /// Nothing is skipped on the word of a checkpoint that could not be opened.
    ///
    /// Replaying everything restores strictly more than trusting coverage read
    /// from an object we never decrypted.
    #[tokio::test]
    async fn an_unopenable_checkpoint_falls_back_to_replaying_everything() {
        let source = Db::init_temp("vault_bad_anchor_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();
        rename(&source, &drive, "renamed").await;
        backup_delta(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        // A checkpoint number this key cannot open: garbage where the anchor
        // should be.
        let mangled = MemoryVaultStore::new();
        for object_key in vault.list(&drive_prefix(PSEUDONYM)).unwrap() {
            mangled
                .put(&object_key, &vault.get(&object_key).unwrap())
                .unwrap();
        }
        mangled
            .put(&checkpoint_key(PSEUDONYM, 9), b"not a vault object")
            .unwrap();

        let target = Db::init_temp("vault_bad_anchor_target").await.unwrap();
        let summary = restore(&target, &key, &mangled).await;

        assert_eq!(
            summary.objects_skipped, 0,
            "an anchor that could not be opened must not decide what to skip"
        );
        assert_eq!(
            summary.packs_read, 2,
            "both real objects still replay: {summary:?}"
        );
    }

    /// A sealed pack must not leak the subjects it carries: subject visibility
    /// is exactly what the privacy budget promises to hide.
    #[test]
    fn sealed_packs_do_not_reveal_subjects() {
        let pack = Pack::new(
            vec![PackEntry {
                subject: "did:ad:drive/secret-resource".into(),
                update: vec![1, 2, 3],
            }],
            vec![],
        );
        let sealed = envelope::seal(&key(), ObjectKind::Pack, &pack.encode().unwrap()).unwrap();
        let needle = b"secret-resource";
        assert!(
            !sealed.windows(needle.len()).any(|w| w == needle),
            "subject leaked into the sealed pack"
        );
    }

    const FOLDER: &str = "https://atomicdata.dev/classes/Folder";

    /// What a host driver does around one pass: ask the vault what it already
    /// holds, export against that, and — unless told otherwise — confirm.
    ///
    /// Tests drive the real decision path rather than pinning a segment number,
    /// because *which* object a pass produces is now part of the behaviour under
    /// test. The first pass over a vault with no anchor is a checkpoint; every
    /// pass after it is a delta.
    async fn backup_with(
        store: &Db,
        drive: &Subject,
        key: &DriveVaultKey,
        vault: &dyn VaultObjectStore,
        device: &str,
        policy: CheckpointPolicy,
        confirm: bool,
    ) -> Option<BackupSummary> {
        let keys = vault.list(&drive_prefix(PSEUDONYM)).unwrap();

        let mut observed: BTreeMap<String, u32> = BTreeMap::new();
        let mut highest_checkpoint = 0u64;
        for object_key in &keys {
            if let Some((lane, segment)) = parse_segment_key(object_key) {
                let slot = observed.entry(lane).or_insert(0);
                *slot = (*slot).max(segment);
            }
            if let Some(n) = parse_checkpoint_key(object_key) {
                highest_checkpoint = highest_checkpoint.max(n);
            }
        }
        let segment = observed.get(device).copied().unwrap_or(0) + 1;

        let summary = export_vault_segment(
            store,
            drive,
            key,
            vault,
            PSEUDONYM,
            device,
            segment,
            highest_checkpoint + 1,
            highest_checkpoint > 0,
            &observed,
            policy,
        )
        .await
        .unwrap();

        if confirm && summary.is_some() {
            commit_lane_state(store, PSEUDONYM, device, segment).unwrap();
        }
        summary
    }

    /// Change one resource, the way a user would.
    async fn rename(store: &Db, subject_str: &str, name: &str) {
        let subject = Subject::from_raw(subject_str, store.get_base_domain().as_deref());
        let mut resource = store.get_resource(&subject).await.unwrap();
        let doc = resource.build_state_doc().unwrap();
        doc.set_property(crate::urls::NAME, &crate::Value::String(name.into()))
            .unwrap();
        doc.commit_with_message(&format!("rename to {name}"));
        resource.apply_state_doc(doc).unwrap();
        store
            .add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();
    }

    /// One confirmed pass on the default cadence.
    async fn backup(
        store: &Db,
        drive: &Subject,
        key: &DriveVaultKey,
        vault: &dyn VaultObjectStore,
        device: &str,
    ) -> Option<BackupSummary> {
        backup_with(
            store,
            drive,
            key,
            vault,
            device,
            CheckpointPolicy::default(),
            true,
        )
        .await
    }

    /// A pass that never takes a checkpoint, for tests about delta chains.
    async fn backup_delta(
        store: &Db,
        drive: &Subject,
        key: &DriveVaultKey,
        vault: &dyn VaultObjectStore,
        device: &str,
    ) -> Option<BackupSummary> {
        backup_with(
            store,
            drive,
            key,
            vault,
            device,
            CheckpointPolicy {
                max_segments: u32::MAX,
                bytes_ratio: f64::INFINITY,
            },
            true,
        )
        .await
    }

    /// Restore everything the vault holds for this drive into `store`.
    async fn restore(
        store: &Db,
        key: &DriveVaultKey,
        vault: &dyn VaultObjectStore,
    ) -> RestoreSummary {
        import_vault_batch(store, key, vault, &drive_prefix(PSEUDONYM), None)
            .await
            .unwrap()
    }

    /// Read a drive's resources as `(subject, propvals-debug)` pairs, for
    /// comparing two stores. Compares the *materialized projection*, not the
    /// CRDT bytes: a restore that reproduced the oplog but not the derived
    /// state would still be a broken restore from the user's point of view.
    async fn drive_contents(store: &Db, drive: &Subject) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for subject_str in crate::sync::engine::collect_drive_subjects(store, drive).await {
            let subject = Subject::from_raw(&subject_str, None);
            if let Ok(resource) = store.get_resource(&subject).await {
                let mut props: Vec<String> = resource
                    .get_propvals()
                    .iter()
                    .filter(|(k, _)| k.as_str() != crate::urls::LORO_UPDATE)
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                props.sort();
                out.push((subject_str, props.join("|")));
            }
        }
        out.sort();
        out
    }

    /// The whole point of the feature, headless: make changes, back them up,
    /// lose the device entirely, restore into an empty store, and get the same
    /// drive back. This is the "clear browser storage and sign in again" flow
    /// with the browser and the network taken out of the picture.
    #[tokio::test]
    async fn a_wiped_store_is_restored_from_the_vault() {
        let source = Db::init_temp("vault_round_trip_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        for i in 0..3 {
            source
                .create_resource(FOLDER, &drive, &format!("note-{i}"), None)
                .await
                .unwrap();
        }
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let before = drive_contents(&source, &drive_subject).await;
        assert!(
            before.len() >= 4,
            "expected a drive plus children: {before:?}"
        );

        let key = key();
        let vault = MemoryVaultStore::new();
        let backup = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("a populated drive must produce a pack");
        // The drive, its children, and the one agent the drive grants rights to.
        assert_eq!(backup.resources, before.len() + 1);

        // The device is gone: a brand new store, sharing nothing with the old.
        let restored = Db::init_temp("vault_round_trip_restored").await.unwrap();
        let result = restore(&restored, &key, &vault).await;
        assert_eq!(result.packs_read, 1);
        assert_eq!(result.resources_restored, before.len() + 1);

        let after = drive_contents(&restored, &drive_subject).await;
        assert_eq!(after, before, "restored drive must match the original");
    }

    /// The person comes back with the account, not just the files.
    ///
    /// An agent resource is nobody's child, so the drive walk never sees it;
    /// on the hosted app there is no node to fetch it from either. Left out of
    /// the pack, a restore on a second browser opened the drive with an empty
    /// name in settings — the first thing a returning user noticed.
    #[tokio::test]
    async fn the_drive_owner_is_restored_with_the_drive() {
        let source = Db::init_temp("vault_agent_source").await.unwrap();
        let (agent, drive) = source.setup("alice").await.unwrap();
        let agent_subject = agent.subject.clone();
        let mut profile = source.get_resource(&agent_subject).await.unwrap();
        profile
            .set_unsafe(
                crate::urls::NAME.into(),
                crate::Value::String("Alice Returning".into()),
            )
            .unwrap();
        source
            .add_resource_opts(&profile, false, true, true)
            .await
            .unwrap();

        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("a populated drive must produce a pack");

        let restored = Db::init_temp("vault_agent_restored").await.unwrap();
        restore(&restored, &key, &vault).await;

        let name = restored
            .get_resource(&agent_subject)
            .await
            .expect("the drive's agent must come back with the drive")
            .get(crate::urls::NAME)
            .expect("with its profile")
            .to_string();
        assert_eq!(name, "Alice Returning");
    }

    /// The bug a backup must not have: a resource deleted after an earlier
    /// segment was written must stay deleted through a wipe-and-restore.
    ///
    /// Before deletions were exported, segment 1 still held the resource's full
    /// oplog and a restore brought it back — the vault silently undoing its
    /// owner's delete.
    #[tokio::test]
    async fn a_deleted_resource_does_not_come_back_after_restore() {
        let source = Db::init_temp("vault_delete_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let keep = source
            .create_resource(FOLDER, &drive, "keep", None)
            .await
            .unwrap();
        let doomed = source
            .create_resource(FOLDER, &drive, "doomed", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        // Segment 1: both resources are backed up.
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("first pack");
        commit_lane_state(&source, PSEUDONYM, DEVICE, 1).unwrap();

        // The user deletes one, then a later backup runs.
        let doomed_subject = Subject::from_raw(&doomed, source.get_base_domain().as_deref());
        source.remove_resource(&doomed_subject).await.unwrap();
        let second = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("second pack carries the deletion");
        assert_eq!(
            second.tombstones, 1,
            "the deletion must reach the vault, not just the local store"
        );

        // Restore everything into a fresh store.
        let restored = Db::init_temp("vault_delete_restored").await.unwrap();
        restore(&restored, &key, &vault).await;

        let subjects = crate::sync::engine::collect_drive_subjects(&restored, &drive_subject).await;
        assert!(
            subjects.contains(&Subject::from_raw(&keep, None).pure_id()),
            "the kept resource must survive: {subjects:?}"
        );
        assert!(
            !subjects.contains(&doomed_subject.pure_id()),
            "the deleted resource must not be resurrected: {subjects:?}"
        );
    }

    /// A restore that re-creates a locally-destroyed subject must lift its
    /// tombstone, or `is_tombstoned` keeps suppressing it from every future
    /// bulk sync and the resource never reaches another replica (F11).
    #[tokio::test]
    async fn restoring_a_locally_destroyed_subject_clears_its_tombstone() {
        let source = Db::init_temp("vault_clear_tombstone_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let note = source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        // A second device destroyed the same subject locally.
        let restored = Db::init_temp("vault_clear_tombstone_restored")
            .await
            .unwrap();
        crate::sync::tombstones::record_tombstone(&restored, &note);
        assert!(crate::sync::tombstones::is_tombstoned(&restored, &note));

        restore(&restored, &key, &vault).await;

        assert!(
            !crate::sync::tombstones::is_tombstoned(&restored, &note),
            "a subject the backup re-created must not stay tombstoned"
        );
    }

    /// A seal whose upload never happened must not advance the lane. Otherwise
    /// the next pass computes deletions against a segment that is not in the
    /// vault, and the delete is reported against nothing.
    #[tokio::test]
    async fn an_uncommitted_export_does_not_advance_the_lane() {
        let source = Db::init_temp("vault_uncommitted_export").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let doomed = source
            .create_resource(FOLDER, &drive, "doomed", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        // Sealed but never confirmed — the upload failed.
        backup_with(
            &source,
            &drive_subject,
            &key,
            &vault,
            DEVICE,
            CheckpointPolicy::default(),
            false,
        )
        .await
        .unwrap();

        source
            .remove_resource(&Subject::from_raw(
                &doomed,
                source.get_base_domain().as_deref(),
            ))
            .await
            .unwrap();

        let second = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("still exports the surviving resources");
        assert_eq!(
            second.tombstones, 0,
            "nothing was ever backed up, so nothing can be reported deleted"
        );
    }

    /// Each device appends only to its own lane, so a restore that used one
    /// lane's prefix would silently drop every other device's history.
    #[tokio::test]
    async fn restore_spans_every_device_lane() {
        let source = Db::init_temp("vault_multi_lane_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        // The same drive backed up from two different devices.
        let other_device = "ff".repeat(32);
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();
        source
            .create_resource(FOLDER, &drive, "second-note", None)
            .await
            .unwrap();
        backup(&source, &drive_subject, &key, &vault, &other_device)
            .await
            .unwrap();

        let restored = Db::init_temp("vault_multi_lane_restored").await.unwrap();
        let summary = restore(&restored, &key, &vault).await;
        assert_eq!(
            summary.packs_read, 2,
            "the drive prefix must reach the anchor and the second lane"
        );

        // A lane prefix reaches only one, which is the bug this guards.
        let one_lane = Db::init_temp("vault_multi_lane_one").await.unwrap();
        let partial = import_vault_batch(
            &one_lane,
            &key,
            &vault,
            &lane_prefix(PSEUDONYM, &other_device),
            None,
        )
        .await
        .unwrap();
        assert_eq!(partial.packs_read, 1);
    }

    /// A subject that disappears without a tombstone is not claimed as deleted.
    /// Inventing a tombstone would delete real data on restore — a far worse
    /// failure than carrying a stale resource for another cycle.
    ///
    /// The pass has to be provoked by a real edit, because since Phase 2 an
    /// untouched drive produces no object at all — see
    /// [`an_unchanged_drive_costs_nothing`].
    #[tokio::test]
    async fn a_vanished_but_untombstoned_subject_is_not_reported_deleted() {
        let source = Db::init_temp("vault_no_false_tombstone").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let note = source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        rename(&source, &note, "renamed").await;

        let second = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("an edited drive still exports");
        assert_eq!(second.tombstones, 0);
    }

    /// A subject that vanishes without a tombstone stays *known* to the lane.
    ///
    /// The pass claims no deletion for it — inventing one would delete real
    /// data. But it must not forget the subject either: a lane that forgets can
    /// never claim the deletion when it does arrive, and the resource lives on
    /// in an earlier object for a restore to bring back. Both halves are the
    /// same rule from opposite sides.
    #[tokio::test]
    async fn a_subject_that_vanishes_without_a_tombstone_stays_known() {
        let source = Db::init_temp("vault_vanished_stays_known").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let doomed_str = source
            .create_resource(FOLDER, &drive, "doomed", None)
            .await
            .unwrap();
        let keeper = source
            .create_resource(FOLDER, &drive, "keeper", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        // Out of the walk, but with no tombstone: what a transient read failure
        // or an authorization change looks like from here.
        let doomed = Subject::from_raw(&doomed_str, source.get_base_domain().as_deref());
        source
            .kv
            .remove(crate::db::trees::Tree::LoroSnapshots, doomed_str.as_bytes())
            .unwrap();
        source.remove_resource(&doomed).await.ok();
        crate::sync::tombstones::clear_tombstone(&source, &doomed_str);

        rename(&source, &keeper, "touched").await;
        let second = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("the edit still ships");
        assert_eq!(
            second.tombstones, 0,
            "no tombstone exists, so none may be claimed"
        );

        assert!(
            read_lane_state(&source, PSEUDONYM, DEVICE)
                .cursors
                .contains_key(&doomed_str),
            "the lane must still remember it backed this subject up, or it can \
             never claim the deletion when one finally arrives"
        );
    }

    /// The headline of Phase 2: backing up an untouched drive writes nothing.
    ///
    /// Phase 1 exported every resource's whole oplog on every pass, so five
    /// backups of an unchanged five-folder drive cost five copies of it —
    /// stored bytes tracked how often somebody pressed the button rather than
    /// how much data they had, which made any published per-GB quota a lie.
    #[tokio::test]
    async fn an_unchanged_drive_costs_nothing() {
        let source = Db::init_temp("vault_unchanged_drive").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        for i in 0..5 {
            source
                .create_resource(FOLDER, &drive, &format!("folder-{i}"), None)
                .await
                .unwrap();
        }
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        let first = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("the first pass anchors the vault");
        assert_eq!(first.unchanged, 0, "nothing was cached yet");
        let objects_after_first = vault.list(&drive_prefix(PSEUDONYM)).unwrap().len();

        for _ in 0..4 {
            assert!(
                backup(&source, &drive_subject, &key, &vault, DEVICE)
                    .await
                    .is_none(),
                "an unchanged drive must not produce an object"
            );
        }

        assert_eq!(
            vault.list(&drive_prefix(PSEUDONYM)).unwrap().len(),
            objects_after_first,
            "five passes over an unchanged drive must cost exactly one object"
        );
    }

    /// A one-resource edit costs one resource, not the drive.
    ///
    /// This is the economic claim the whole format rests on: `export_updates_since`
    /// output grows with the size of the edit, not the size of the document, so
    /// a delta pack has to be a small fraction of the anchor it hangs off.
    #[tokio::test]
    async fn one_edit_costs_one_edit() {
        let source = Db::init_temp("vault_small_delta").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let mut subjects = Vec::new();
        for i in 0..40 {
            subjects.push(
                source
                    .create_resource(FOLDER, &drive, &format!("folder-{i}"), None)
                    .await
                    .unwrap(),
            );
        }
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        let anchor = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("the first pass anchors the vault");
        assert!(anchor.resources >= 40);

        rename(&source, &subjects[0], "touched").await;

        let delta = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("one edit must still be backed up");
        assert_eq!(delta.kind, SegmentKind::Pack);
        assert_eq!(
            delta.resources, 1,
            "only the edited resource belongs in the pack"
        );
        assert_eq!(
            delta.unchanged,
            anchor.resources - 1,
            "every other resource must be recognised as unchanged from its version vector alone"
        );
        assert!(
            delta.sealed_bytes * 4 < anchor.sealed_bytes,
            "a one-resource delta ({} B) must be far smaller than a {}-resource anchor ({} B)",
            delta.sealed_bytes,
            anchor.resources,
            anchor.sealed_bytes
        );
    }

    /// A delta is not self-sufficient, and a chain of them still restores.
    #[tokio::test]
    async fn a_delta_chain_restores_the_drive() {
        let source = Db::init_temp("vault_delta_chain").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let note = source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let subject = Subject::from_raw(&note, source.get_base_domain().as_deref());
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();
        for name in ["one", "two", "three"] {
            rename(&source, &note, name).await;
            let pass = backup_delta(&source, &drive_subject, &key, &vault, DEVICE)
                .await
                .expect("each edit ships");
            assert_eq!(pass.kind, SegmentKind::Pack);
        }

        let expected_versions =
            crate::history::versions(&source.get_resource(&subject).await.unwrap())
                .unwrap()
                .len();

        let target = Db::init_temp("vault_delta_chain_target").await.unwrap();
        restore(&target, &key, &vault).await;

        let restored = target.get_resource(&subject).await.unwrap();
        assert_eq!(
            restored.get(crate::urls::NAME).unwrap().to_string(),
            "three",
            "the chain must replay to the latest state"
        );
        assert_eq!(
            crate::history::versions(&restored).unwrap().len(),
            expected_versions,
            "and carry every version the source had — a chain must lose no history \
             a single self-sufficient segment would have kept"
        );
    }

    /// Losing one link of a delta chain must not look like a successful
    /// restore of a drive that is missing most of itself.
    ///
    /// It is not detected — nothing in the format lets a restorer prove a
    /// segment is absent — but the outcome is pinned here so the claim in
    /// `plan_restore` stays honest: this is exactly why the control plane must
    /// prune against checkpoint coverage rather than segment recency.
    #[tokio::test]
    async fn a_broken_delta_chain_loses_the_edits_in_the_missing_link() {
        let source = Db::init_temp("vault_broken_chain").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let note = source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let subject = Subject::from_raw(&note, source.get_base_domain().as_deref());
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();
        rename(&source, &note, "one").await;
        backup_delta(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();
        rename(&source, &note, "two").await;
        backup_delta(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        // Drop the middle segment, as a retention sweep that ignored coverage
        // would.
        let mutilated = MemoryVaultStore::new();
        let dropped = segment_key(PSEUDONYM, DEVICE, 1);
        for object_key in vault.list(&drive_prefix(PSEUDONYM)).unwrap() {
            if object_key != dropped {
                mutilated
                    .put(&object_key, &vault.get(&object_key).unwrap())
                    .unwrap();
            }
        }

        let target = Db::init_temp("vault_broken_chain_target").await.unwrap();
        restore(&target, &key, &mutilated).await;

        let restored = target.get_resource(&subject).await.unwrap();
        assert_ne!(
            restored.get(crate::urls::NAME).unwrap().to_string(),
            "two",
            "a delta whose predecessor is gone cannot be applied — if this ever \
             passes, deltas became self-sufficient and the pruning rule can relax"
        );
    }

    /// Restores get retried, and lanes from several devices overlap by design.
    /// Importing the same pack twice must converge rather than duplicate —
    /// Loro dedups by `(peerId, counter)`, and this pins that we rely on it.
    #[tokio::test]
    async fn importing_the_same_pack_twice_is_idempotent() {
        let source = Db::init_temp("vault_idempotent_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let before = drive_contents(&source, &drive_subject).await;

        let key = key();
        let vault = MemoryVaultStore::new();
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        let restored = Db::init_temp("vault_idempotent_restored").await.unwrap();
        restore(&restored, &key, &vault).await;
        let once = drive_contents(&restored, &drive_subject).await;
        restore(&restored, &key, &vault).await;
        let twice = drive_contents(&restored, &drive_subject).await;

        assert_eq!(once, before);
        assert_eq!(twice, once, "a second import must not change the result");
    }

    /// The blind-vault claim in one assertion: whoever holds the objects
    /// without the drive key gets nothing back.
    #[tokio::test]
    async fn a_restore_without_the_right_key_fails() {
        let source = Db::init_temp("vault_wrong_key_source").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        source
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());

        let vault = MemoryVaultStore::new();
        backup(&source, &drive_subject, &key(), &vault, DEVICE)
            .await
            .unwrap();

        let restored = Db::init_temp("vault_wrong_key_restored").await.unwrap();
        let attacker = DriveVaultKey::from_bytes([0xFF; 32], 1);
        let err = import_vault_batch(&restored, &attacker, &vault, &drive_prefix(PSEUDONYM), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("decrypt"), "{err}");
    }

    /// An untouched drive should not produce an object every backup tick.
    #[tokio::test]
    async fn an_empty_drive_produces_no_object() {
        let store = Db::init_temp("vault_empty_drive").await.unwrap();
        let unknown = Subject::from_raw("did:ad:nonexistentdrive", None);
        let vault = MemoryVaultStore::new();
        let out = backup(&store, &unknown, &key(), &vault, DEVICE).await;
        assert!(out.is_none(), "nothing to back up should mean no object");
        assert!(vault.is_empty());
    }

    #[test]
    fn a_pack_round_trips_through_a_store() {
        let vault = MemoryVaultStore::new();
        let pack = Pack::new(
            vec![PackEntry {
                subject: "s".into(),
                update: vec![9, 9, 9],
            }],
            vec!["gone".into()],
        );
        let sealed = envelope::seal(&key(), ObjectKind::Pack, &pack.encode().unwrap()).unwrap();
        let object_key = segment_key(PSEUDONYM, DEVICE, 1);
        vault.put(&object_key, &sealed).unwrap();

        let fetched = vault.get(&object_key).unwrap();
        let (_, plaintext) = envelope::open(&key(), &fetched).unwrap();
        assert_eq!(Pack::decode(&plaintext).unwrap(), pack);
    }
    /// A restored resource keeps its edit history, not just its current state.
    ///
    /// This is a property of exporting *updates* rather than snapshots of the
    /// materialized state: the pack carries the oplog, so the version list a
    /// user sees after a restore is the one they had. Worth pinning down —
    /// "your backup silently flattened three months of history into one
    /// version" is the kind of loss nobody notices until they need it, and the
    /// other restore tests all compare the materialized projection, which
    /// would be identical either way.
    #[tokio::test]
    async fn a_restore_keeps_edit_history() {
        let source = Db::init_temp("vault_history_roundtrip").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let subject_str = source
            .create_resource(FOLDER, &drive, "history", None)
            .await
            .unwrap();
        let subject = Subject::from_raw(&subject_str, source.get_base_domain().as_deref());

        // Distinct messages, because `history::versions` groups by commit
        // boundary — without them Loro merges same-peer edits inside a second
        // into one change and there is no history to lose.
        for name in ["one", "two", "three"] {
            let mut resource = source.get_resource(&subject).await.unwrap();
            let doc = resource.build_state_doc().unwrap();
            doc.set_property(crate::urls::NAME, &crate::Value::String(name.into()))
                .unwrap();
            doc.commit_with_message(&format!("rename to {name}"));
            resource.apply_state_doc(doc).unwrap();
            source
                .add_resource_opts(&resource, false, true, true)
                .await
                .unwrap();
        }

        let before = crate::history::versions(&source.get_resource(&subject).await.unwrap())
            .unwrap()
            .len();
        assert!(
            before > 1,
            "the fixture must produce a history worth preserving, got {before}"
        );

        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();
        backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .unwrap();

        let target = Db::init_temp("vault_history_roundtrip_target")
            .await
            .unwrap();
        restore(&target, &key, &vault).await;

        let restored = target.get_resource(&subject).await.unwrap();
        let after = crate::history::versions(&restored).unwrap().len();

        assert_eq!(
            after, before,
            "a restore must bring back every version, not just the latest state"
        );
    }

    /// The newest **checkpoint** alone restores the drive, with its history.
    ///
    /// This is the Phase 2 successor to `the_newest_segment_alone_restores_the_drive`,
    /// and the succession is the point. Phase 1 exported every resource's whole
    /// oplog on every pass, so *any* segment restored the drive by itself, and
    /// retention could keep the newest one and drop the rest. Phase 2 trades
    /// that away: a delta pack needs its chain, so what is self-sufficient is
    /// now the checkpoint, and pruning must keep the newest checkpoint plus
    /// everything it does not cover.
    ///
    /// Two consequences still hold and still drive product decisions:
    ///
    ///  - Retention cannot be sold as "restore points". Every restore already
    ///    brings the full history back; older objects add nothing on that
    ///    front. What they uniquely hold is resources *deleted* since — an
    ///    undelete window, not a history window.
    ///  - Pruning is safe as long as it prunes against checkpoint coverage
    ///    rather than against segment recency. `VaultService::prune_drive` in
    ///    atomic-saas is the other half of this test.
    #[tokio::test]
    async fn the_newest_checkpoint_alone_restores_the_drive() {
        let source = Db::init_temp("vault_latest_checkpoint").await.unwrap();
        let (_agent, drive) = source.setup("alice").await.unwrap();
        let kept_str = source
            .create_resource(FOLDER, &drive, "kept", None)
            .await
            .unwrap();
        let kept = Subject::from_raw(&kept_str, source.get_base_domain().as_deref());

        for name in ["one", "two", "three"] {
            let mut resource = source.get_resource(&kept).await.unwrap();
            let doc = resource.build_state_doc().unwrap();
            doc.set_property(crate::urls::NAME, &crate::Value::String(name.into()))
                .unwrap();
            doc.commit_with_message(&format!("rename to {name}"));
            resource.apply_state_doc(doc).unwrap();
            source
                .add_resource_opts(&resource, false, true, true)
                .await
                .unwrap();
        }

        // Present before the first checkpoint, deleted before the second — the
        // one thing an older object holds that the newest does not.
        let doomed_str = source
            .create_resource(FOLDER, &drive, "doomed", None)
            .await
            .unwrap();
        let doomed = Subject::from_raw(&doomed_str, source.get_base_domain().as_deref());

        let drive_subject = Subject::from_raw(&drive, source.get_base_domain().as_deref());
        let key = key();
        let vault = MemoryVaultStore::new();

        // Pass 1 anchors the vault; pass 2 is a delta carrying the deletion;
        // pass 3 is forced to re-anchor, which is what a retention sweep needs
        // before it can drop anything.
        let first = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("a populated drive must produce an object");
        assert_eq!(first.kind, SegmentKind::Checkpoint);

        source.remove_resource(&doomed).await.unwrap();

        let second = backup(&source, &drive_subject, &key, &vault, DEVICE)
            .await
            .expect("a deletion must be shipped");
        assert_eq!(second.kind, SegmentKind::Pack);
        assert_eq!(second.tombstones, 1);

        source
            .create_resource(FOLDER, &drive, "after", None)
            .await
            .unwrap();
        let third = backup_with(
            &source,
            &drive_subject,
            &key,
            &vault,
            DEVICE,
            CheckpointPolicy {
                max_segments: 1,
                bytes_ratio: 1.0,
            },
            true,
        )
        .await
        .expect("the policy asked for a fresh anchor");
        assert_eq!(third.kind, SegmentKind::Checkpoint);
        assert_eq!(
            third.coverage.get(DEVICE),
            Some(&1),
            "a checkpoint consumes no segment number, so an anchor taken when \
             this lane's next segment is 2 subsumes everything through 1"
        );

        // A vault holding ONLY the newest checkpoint, as a retention sweep
        // acting on that coverage would leave it.
        let newest = checkpoint_key(PSEUDONYM, 2);
        let latest_only = MemoryVaultStore::new();
        latest_only
            .put(&newest, &vault.get(&newest).unwrap())
            .unwrap();

        let target = Db::init_temp("vault_latest_checkpoint_target")
            .await
            .unwrap();
        restore(&target, &key, &latest_only).await;

        let restored = target.get_resource(&kept).await.unwrap();
        assert_eq!(
            crate::history::versions(&restored).unwrap().len(),
            5,
            "the newest checkpoint must carry the whole version history on its own"
        );
        assert_eq!(
            restored.get(crate::urls::NAME).unwrap().to_string(),
            "three",
            "and the current state"
        );
        assert!(
            target.get_resource(&doomed).await.is_err(),
            "a resource deleted before this checkpoint must stay deleted — recovering it is what an OLDER object would be kept for"
        );
    }
}
