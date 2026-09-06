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
    commit_lane_state, drive_prefix, export_vault_segment, CheckpointPolicy, SegmentKind,
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
        CheckpointPolicy::default(),
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
