//! The pack format — Phase 1 of
//! `atomic-saas/planning/CLOUD_VAULT_ARCHITECTURE.md`.
//!
//! A pack is a batch of Loro *updates*, never snapshots. That distinction is
//! the whole economic argument for the vault: `export_updates_since` output
//! grows with the size of the edit, whereas a snapshot grows with the size of
//! the document. Backing up a one-word change to a large resource must cost one
//! word, not the resource.
//!
//! Packs are also why resource *counts* stay hidden: many resources ride in one
//! sealed object, so the operator sees one object of some size rather than a
//! per-resource object stream they could count and correlate.

use crate::errors::AtomicResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Pack layout version, independent of the envelope's. The envelope governs how
/// bytes are encrypted; this governs what those bytes mean once open.
///
/// **2 means "not necessarily self-sufficient".** A format-1 pack carried every
/// resource's whole oplog, so any one of them restored the drive alone. A
/// format-2 pack may be a *delta* against this lane's cursor, and restoring it
/// without the checkpoint it hangs off gives back part of a drive.
///
/// The bump exists so an older build refuses these rather than half-restoring
/// them. It skips `Checkpoint` objects by kind before it ever decodes one, so a
/// pre-Phase-2 client pointed at a Phase-2 vault would otherwise import the
/// deltas, skip the anchor, and report a successful restore of a drive that is
/// missing most of itself. Refusing to parse is the loud failure; the quiet one
/// is what this vault keeps producing when we let it.
pub const PACK_FORMAT: u8 = 2;

/// Formats this build can read. Writing is always [`PACK_FORMAT`].
const READABLE_FORMATS: &[u8] = &[1, 2];

/// One resource's worth of CRDT history in a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackEntry {
    /// The resource's `pure_id()` — the same key `Tree::LoroSnapshots` uses, so
    /// a restore does not have to reconstruct subjects from query params.
    pub subject: String,
    /// `AtomicLoroDoc::export_updates_since` output. Opaque here on purpose:
    /// the pack layer never interprets CRDT bytes.
    pub update: Vec<u8>,
}

/// A batch of updates plus the deletions that happened alongside them.
///
/// Tombstones travel *with* the updates rather than in a separate object
/// because a restore that applied updates without them would resurrect deleted
/// resources — a delete is not an absence of data, it is data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pack {
    pub format: u8,
    pub entries: Vec<PackEntry>,
    /// Subjects deleted in this segment, as `pure_id()` strings.
    pub tombstones: Vec<String>,
    /// Checkpoints only: lanes whose ops this checkpoint provably contains,
    /// device pubkey → last inclusive segment. **Prunable** — the control plane
    /// deletes covered segments, so a lane may only appear here when the
    /// publisher can show it holds those ops (it wrote them, or it imported
    /// them). Empty on a lane pack.
    #[serde(default)]
    pub coverage: BTreeMap<String, u32>,
    /// Checkpoints only: the newest segment each lane had when this checkpoint
    /// was published, device pubkey → segment.
    ///
    /// Weaker than [`Self::coverage`] and used for a different job: coverage
    /// decides what may be *deleted*, observed decides replay *order*. A
    /// segment at or below the observed mark predates the checkpoint and must
    /// be applied before it; one above it came after and must be applied
    /// after. Without that split a checkpoint's tombstone would be undone by an
    /// older segment that still holds the resource — a backup resurrecting
    /// deleted data, which is the one failure this format must not have.
    #[serde(default)]
    pub observed: BTreeMap<String, u32>,
}

impl Pack {
    pub fn new(entries: Vec<PackEntry>, tombstones: Vec<String>) -> Self {
        Self {
            format: PACK_FORMAT,
            entries,
            tombstones,
            coverage: BTreeMap::new(),
            observed: BTreeMap::new(),
        }
    }

    /// A checkpoint's pack: the same batch, plus the two lane maps that make it
    /// an anchor rather than another segment.
    pub fn checkpoint(
        entries: Vec<PackEntry>,
        tombstones: Vec<String>,
        coverage: BTreeMap<String, u32>,
        observed: BTreeMap<String, u32>,
    ) -> Self {
        Self {
            format: PACK_FORMAT,
            entries,
            tombstones,
            coverage,
            observed,
        }
    }

    /// Nothing changed since the last segment — worth checking before sealing,
    /// so an idle device does not upload an object per backup tick.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.tombstones.is_empty()
    }

    /// MessagePack rather than JSON: these are byte payloads, and base64ing
    /// every CRDT update into JSON would inflate the one thing the format
    /// exists to keep small.
    pub fn encode(&self) -> AtomicResult<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| format!("failed to encode vault pack: {e}").into())
    }

    pub fn decode(bytes: &[u8]) -> AtomicResult<Self> {
        let pack: Pack = rmp_serde::from_slice(bytes)
            .map_err(|e| format!("failed to decode vault pack: {e}"))?;
        if !READABLE_FORMATS.contains(&pack.format) {
            return Err(format!(
                "unsupported vault pack format {}, this build reads {READABLE_FORMATS:?}",
                pack.format
            )
            .into());
        }
        Ok(pack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Pack {
        Pack::new(
            vec![
                PackEntry {
                    subject: "did:ad:drive/resource-a".to_string(),
                    update: vec![1, 2, 3, 4],
                },
                PackEntry {
                    subject: "did:ad:drive/resource-b".to_string(),
                    update: vec![5, 6],
                },
            ],
            vec!["did:ad:drive/deleted".to_string()],
        )
    }

    #[test]
    fn round_trips() {
        let pack = sample();
        let decoded = Pack::decode(&pack.encode().unwrap()).unwrap();
        assert_eq!(decoded, pack);
    }

    #[test]
    fn preserves_update_bytes_exactly() {
        // CRDT bytes must survive verbatim; a lossy encoding would corrupt
        // history in a way that only shows up at restore time.
        let update: Vec<u8> = (0u8..=255).collect();
        let pack = Pack::new(
            vec![PackEntry {
                subject: "s".into(),
                update: update.clone(),
            }],
            vec![],
        );
        let decoded = Pack::decode(&pack.encode().unwrap()).unwrap();
        assert_eq!(decoded.entries[0].update, update);
    }

    #[test]
    fn an_unknown_format_is_refused() {
        let mut pack = sample();
        pack.format = 99;
        let encoded = pack.encode().unwrap();
        let err = Pack::decode(&encoded).unwrap_err().to_string();
        assert!(err.contains("format"), "{err}");
    }

    #[test]
    fn a_format_1_pack_still_opens() {
        // Vaults written before Phase 2 hold format-1 packs, and a build that
        // could not read them would make every existing backup unrestorable.
        let mut pack = sample();
        pack.format = 1;
        let decoded = Pack::decode(&pack.encode().unwrap()).unwrap();
        assert_eq!(decoded.format, 1);
        assert_eq!(decoded.entries.len(), 2);
        assert!(
            decoded.coverage.is_empty() && decoded.observed.is_empty(),
            "the lane maps did not exist in format 1 and must default to empty"
        );
    }

    #[test]
    fn a_checkpoint_carries_its_lane_maps() {
        let coverage = BTreeMap::from([("dev-a".to_string(), 7u32)]);
        let observed = BTreeMap::from([("dev-a".to_string(), 7u32), ("dev-b".to_string(), 3)]);
        let pack = Pack::checkpoint(vec![], vec!["gone".into()], coverage, observed);
        let decoded = Pack::decode(&pack.encode().unwrap()).unwrap();

        assert_eq!(decoded.coverage.get("dev-a"), Some(&7));
        assert_eq!(
            decoded.observed.get("dev-b"),
            Some(&3),
            "a lane can be observed without being covered: seen in the vault, \
             not provably held by the publisher"
        );
        assert_eq!(
            decoded.coverage.get("dev-b"),
            None,
            "claiming coverage the publisher cannot prove would let the control \
             plane delete segments nothing else holds"
        );
    }

    #[test]
    fn garbage_errors_rather_than_panics() {
        assert!(Pack::decode(b"not a pack").is_err());
        assert!(Pack::decode(&[]).is_err());
    }

    #[test]
    fn empty_is_detected() {
        assert!(Pack::new(vec![], vec![]).is_empty());
        assert!(!sample().is_empty());
        // A pack carrying only deletions still has to be uploaded.
        assert!(!Pack::new(vec![], vec!["gone".into()]).is_empty());
    }
}
