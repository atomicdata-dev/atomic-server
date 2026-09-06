//! Tombstones for resources destroyed locally. Used during Iroh/WS bulk sync so
//! peers delete instead of re-uploading or resurrecting deleted subjects.
//!
//! A tombstone is a one-byte marker on the `PluginMeta` tree. The *signed*
//! destroy commit, when there is one, is not stored here: it is the subject's
//! latest row in [`crate::envelopes`] (`Tree::Envelopes`), which
//! `apply_commit` writes for every signed commit. [`destroy_envelope`] reads
//! it from there so `SYNC_DIFF.removeCommits` can carry the same envelope the
//! live `COMMIT` path forwards.

use crate::db::trees::Tree;
use crate::Db;

const PREFIX: &[u8] = b"tombstone:";

fn tombstone_key(subject: &str) -> Vec<u8> {
    let pure = crate::Subject::from_raw(subject, None).pure_id();
    let mut key = Vec::with_capacity(PREFIX.len() + pure.len());
    key.extend_from_slice(PREFIX);
    key.extend_from_slice(pure.as_bytes());
    key
}

/// Remember that this subject was intentionally destroyed on this device.
pub fn record_tombstone(store: &Db, subject: &str) {
    let key = tombstone_key(subject);
    let _ = store.kv.insert(Tree::PluginMeta, &key, &[1]);
}

/// The signed destroy commit JSON for this tombstone, if this node kept it:
/// the subject's latest envelope, when that envelope is a destroy. `None`
/// for an unsigned tombstone (cascade delete, cache eviction, a peer that
/// sent `remove[]` without an envelope) or a missing one.
pub fn destroy_envelope(store: &Db, subject: &str) -> Option<String> {
    if !is_tombstoned(store, subject) {
        return None;
    }
    crate::envelopes::latest_envelope(store, subject)
        .filter(|envelope| envelope.is_destroy())
        .map(|envelope| envelope.json)
}

/// True if we previously destroyed this subject here (do not re-import from peers).
pub fn is_tombstoned(store: &Db, subject: &str) -> bool {
    let key = tombstone_key(subject);
    store
        .kv
        .get(Tree::PluginMeta, &key)
        .ok()
        .flatten()
        .is_some()
}

/// Clear a tombstone — the subject was legitimately re-created (F11,
/// planning/unified-sync.md). A tombstone only means "don't resurrect this
/// deleted subject"; once a genesis commit re-creates it, that invariant is
/// stale and must not keep suppressing it from future bulk-sync imports
/// (`is_tombstoned` gates `import_sync_push` and the `SYNC_VV` remove-list)
/// or the newly-recreated resource silently never reaches other replicas.
/// No-op if there was no tombstone to clear.
pub fn clear_tombstone(store: &Db, subject: &str) {
    let key = tombstone_key(subject);
    let _ = store.kv.remove(Tree::PluginMeta, &key);
}

#[cfg(test)]
mod key_normalization_tests {
    use super::*;

    /// `tombstone_key` normalizes via `Subject::pure_id()`, which strips query
    /// params/fragments. This matters in practice: `apply_destroy_unchecked`
    /// (ws_apply.rs) used to mis-key Loro snapshot lookups by the raw subject
    /// and miss `?drive=`-suffixed forms — the same class of bug would silently
    /// split one subject's tombstone into two never-consulted-together keys if
    /// `record_tombstone`/`is_tombstoned` didn't normalize consistently.
    #[tokio::test]
    async fn drive_suffixed_and_bare_subject_share_a_tombstone() {
        let db = Db::init_temp("tombstone_key_norm_query").await.unwrap();
        let bare = "https://example.test/some-resource";
        let drive_suffixed = "https://example.test/some-resource?drive=https://example.test/";

        record_tombstone(&db, bare);

        assert!(
            is_tombstoned(&db, drive_suffixed),
            "a `?drive=`-suffixed and bare form of the same subject must normalize to the same tombstone key"
        );
    }

    /// Companion: a trailing-slash variant of the same subject must also hit
    /// the same key.
    #[tokio::test]
    async fn trailing_slash_and_bare_subject_share_a_tombstone() {
        let db = Db::init_temp("tombstone_key_norm_slash").await.unwrap();
        let bare = "https://example.test/some-resource";
        let trailing_slash = "https://example.test/some-resource/";

        record_tombstone(&db, bare);

        assert!(
            is_tombstoned(&db, trailing_slash),
            "a trailing-slash and bare form of the same subject must normalize to the same tombstone key"
        );
    }

    #[tokio::test]
    async fn unsigned_tombstone_has_no_envelope() {
        let db = Db::init_temp("tombstone_unsigned_no_envelope")
            .await
            .unwrap();
        let subject = "did:ad:example";
        record_tombstone(&db, subject);
        assert!(is_tombstoned(&db, subject));
        assert_eq!(destroy_envelope(&db, subject), None);
    }
}
