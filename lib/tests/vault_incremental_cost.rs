//! Phase 2 cost shape, measured rather than asserted.
//!
//! `#[ignore]` because it builds thousands of resources: it is a measurement to
//! re-run when the export path changes, not a gate on every `cargo test`. Run
//! with `cargo test --features db-redb --release vault_incremental_cost -- --ignored --nocapture`.
use atomic_lib::db::Db;
use atomic_lib::storelike::Storelike;
use atomic_lib::vault::dek::DriveVaultKey;
use atomic_lib::vault::store::{MemoryVaultStore, VaultObjectStore};
use atomic_lib::vault::sync::{
    commit_lane_state, drive_prefix, export_vault_segment, CheckpointPolicy, HistoryKeep,
    SegmentKind,
};
use atomic_lib::Subject;
use std::collections::BTreeMap;
use std::time::Instant;

const FOLDER: &str = "https://atomicdata.dev/classes/Folder";
const PSEUDONYM: &str = "benchpseudonym";
const DEVICE: &str = "aa";

async fn pass(
    store: &Db,
    drive: &Subject,
    key: &DriveVaultKey,
    vault: &MemoryVaultStore,
    segment: u32,
    checkpoint_n: u64,
    has_checkpoint: bool,
) -> Option<(SegmentKind, usize, usize, usize)> {
    pass_with(
        store,
        drive,
        key,
        vault,
        segment,
        checkpoint_n,
        has_checkpoint,
        CheckpointPolicy::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn pass_with(
    store: &Db,
    drive: &Subject,
    key: &DriveVaultKey,
    vault: &MemoryVaultStore,
    segment: u32,
    checkpoint_n: u64,
    has_checkpoint: bool,
    policy: CheckpointPolicy,
) -> Option<(SegmentKind, usize, usize, usize)> {
    let summary = export_vault_segment(
        store,
        drive,
        key,
        vault,
        PSEUDONYM,
        DEVICE,
        segment,
        checkpoint_n,
        has_checkpoint,
        &BTreeMap::new(),
        policy,
    )
    .await
    .unwrap()?;
    commit_lane_state(store, PSEUDONYM, DEVICE, segment).unwrap();
    Some((
        summary.kind,
        summary.resources,
        summary.unchanged,
        summary.sealed_bytes,
    ))
}

#[tokio::test]
#[ignore]
async fn vault_incremental_cost() {
    println!(
        "\n| resources | anchor bytes | anchor ms | idle pass ms | 1-edit bytes | 1-edit ms |"
    );
    println!("| --- | --- | --- | --- | --- | --- |");

    for n in [100usize, 500, 2000] {
        let store = Db::init_temp(&format!("vault_bench_{n}")).await.unwrap();
        let (_agent, drive) = store.setup("alice").await.unwrap();
        let drive_subject = Subject::from_raw(&drive, store.get_base_domain().as_deref());
        let mut subjects = Vec::new();
        for i in 0..n {
            subjects.push(
                store
                    .create_resource(FOLDER, &drive, &format!("folder-{i}"), None)
                    .await
                    .unwrap(),
            );
        }
        let key = DriveVaultKey::from_bytes([5u8; 32], 1);
        let vault = MemoryVaultStore::new();

        let t = Instant::now();
        let (kind, _, _, anchor_bytes) = pass(&store, &drive_subject, &key, &vault, 1, 1, false)
            .await
            .expect("anchor");
        let anchor_ms = t.elapsed().as_millis();
        assert_eq!(kind, SegmentKind::Checkpoint);

        // An idle pass: every resource's version vector still matches.
        let t = Instant::now();
        let idle = pass(&store, &drive_subject, &key, &vault, 1, 2, true).await;
        let idle_ms = t.elapsed().as_millis();
        assert!(idle.is_none(), "an unchanged drive must produce no object");

        // One resource edited out of n.
        let subject = Subject::from_raw(&subjects[0], store.get_base_domain().as_deref());
        let mut resource = store.get_resource(&subject).await.unwrap();
        let doc = resource.build_state_doc().unwrap();
        doc.set_property(
            atomic_lib::urls::NAME,
            &atomic_lib::Value::String("touched".into()),
        )
        .unwrap();
        doc.commit_with_message("touch");
        resource.apply_state_doc(doc).unwrap();
        store
            .add_resource_opts(&resource, false, true, true)
            .await
            .unwrap();

        let t = Instant::now();
        let (kind, resources, unchanged, delta_bytes) =
            pass(&store, &drive_subject, &key, &vault, 1, 2, true)
                .await
                .expect("one edit ships");
        let delta_ms = t.elapsed().as_millis();
        assert_eq!(kind, SegmentKind::Pack);
        assert_eq!(resources, 1);
        // n folders plus the drive and its agent, minus the one that was edited.
        assert_eq!(unchanged, n + 1);

        println!("| {n} | {anchor_bytes} | {anchor_ms} | {idle_ms} | {delta_bytes} | {delta_ms} |");
        let _ = vault.list(&drive_prefix(PSEUDONYM));
    }
}

/// Delta cost of repeated edits to one document, per envelope retention.
///
/// Delta packs ship only envelopes newer than the lane's cursor, and each
/// signed commit carries a Loro delta rather than a full snapshot, so the
/// bytes per pass stay roughly flat (under `all` retention the previous pass's
/// newest envelope is re-shipped, a constant overhead) instead of growing with
/// the number of earlier edits or the size of the document. Run with
/// `cargo test --features db-redb --release vault_envelope_growth -- --ignored --nocapture`.
#[tokio::test]
#[ignore]
async fn vault_envelope_growth() {
    use atomic_lib::envelopes::EnvelopeRetention;

    for retention in [EnvelopeRetention::Latest, EnvelopeRetention::All] {
        let store = Db::init_temp(&format!("vault_envelope_growth_{}", retention.as_str()))
            .await
            .unwrap();
        store.set_envelope_retention(retention);
        let (_agent, drive) = store.setup("alice").await.unwrap();
        let drive_subject = Subject::from_raw(&drive, store.get_base_domain().as_deref());
        let note = store
            .create_resource(FOLDER, &drive, "note", None)
            .await
            .unwrap();
        let key = DriveVaultKey::from_bytes([5u8; 32], 1);
        let vault = MemoryVaultStore::new();
        pass(&store, &drive_subject, &key, &vault, 1, 1, false)
            .await
            .expect("anchor");

        let subject = Subject::from_raw(&note, store.get_base_domain().as_deref());
        let mut sizes = Vec::new();
        // A tiny drive would otherwise trip the bytes-ratio and write a
        // checkpoint, which ships every envelope by design.
        let policy = CheckpointPolicy {
            max_segments: 1000,
            bytes_ratio: 1e9,
            history: HistoryKeep::Full,
        };
        for i in 0..40usize {
            let mut resource = store.get_resource(&subject).await.unwrap();
            resource
                .set(
                    atomic_lib::urls::NAME.into(),
                    atomic_lib::Value::String(format!("edit-{i}")),
                    &store,
                )
                .await
                .unwrap();
            // A signed commit, so the resource gains an envelope.
            resource.save_locally(&store).await.unwrap();
            let (kind, _, _, bytes) = pass_with(
                &store,
                &drive_subject,
                &key,
                &vault,
                i as u32 + 1,
                1,
                true,
                policy,
            )
            .await
            .expect("edit ships");
            assert_eq!(kind, SegmentKind::Pack);
            sizes.push(bytes);
        }
        println!(
            "retention={} first={} last={} total={} per-edit={:?}",
            retention.as_str(),
            sizes[0],
            sizes[39],
            sizes.iter().sum::<usize>(),
            sizes
        );
        // Regression guard: a signed commit used to embed a full snapshot,
        // so the last pass was 3-4x the first. The first pass under `all`
        // also carries the genesis, hence the min with the second.
        let baseline = sizes[0].min(sizes[1]);
        assert!(
            sizes[39] < baseline + 1500,
            "{}: last delta ({}) grew past baseline ({}) + 1500 bytes",
            retention.as_str(),
            sizes[39],
            baseline
        );
    }
}

/// What "Discard history" buys: the same doc, checkpointed whole and as a
/// current-state-only (shallow) snapshot, after many edits. Run with
/// `cargo test --features db-redb --release vault_checkpoint_history_cost -- --ignored --nocapture`.
#[tokio::test]
#[ignore]
async fn vault_checkpoint_history_cost() {
    let store = Db::init_temp("vault_checkpoint_history_cost")
        .await
        .unwrap();
    let (_agent, drive) = store.setup("alice").await.unwrap();
    let drive_subject = Subject::from_raw(&drive, store.get_base_domain().as_deref());
    let note = store
        .create_resource(FOLDER, &drive, "note", None)
        .await
        .unwrap();
    let subject = Subject::from_raw(&note, store.get_base_domain().as_deref());
    let key = DriveVaultKey::from_bytes([5u8; 32], 1);

    let mut total = 0usize;
    for edits in [10usize, 100, 400] {
        let done = total;
        total = edits;
        for i in done..edits {
            let mut resource = store.get_resource(&subject).await.unwrap();
            resource
                .set(
                    atomic_lib::urls::NAME.into(),
                    atomic_lib::Value::String(format!("edit-{i}")),
                    &store,
                )
                .await
                .unwrap();
            resource.save_locally(&store).await.unwrap();
        }
        {
            let d = store
                .get_resource(&subject)
                .await
                .unwrap()
                .build_state_doc()
                .unwrap();
            println!(
                "note doc: full snapshot {} B, shallow {} B",
                d.export_snapshot().len(),
                d.export_shallow_snapshot().len()
            );
        }
        let mut sizes = Vec::new();
        for history in [HistoryKeep::Full, HistoryKeep::CurrentStateOnly] {
            let vault = MemoryVaultStore::new();
            let summary = export_vault_segment(
                &store,
                &drive_subject,
                &key,
                &vault,
                PSEUDONYM,
                DEVICE,
                1,
                1,
                false,
                &BTreeMap::new(),
                CheckpointPolicy {
                    history,
                    ..CheckpointPolicy::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
            sizes.push(summary.sealed_bytes);
        }
        println!(
            "{edits} edits: full checkpoint {} B, current-state checkpoint {} B ({:.1}x smaller)",
            sizes[0],
            sizes[1],
            sizes[0] as f64 / sizes[1] as f64
        );
        assert!(sizes[1] < sizes[0]);
    }
}
