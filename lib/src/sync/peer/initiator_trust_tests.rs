//! When THIS node dials a peer (the initiator side,
//! `sync_drive_with_peer_using_outcome`), it used to trust that peer
//! unconditionally — serve any subject it named in `pull` straight from the
//! snapshot tree with no `check_read`, import its `SYNC_PUSH` as
//! `ForAgent::Sudo`, and apply its `remove[]` deletes with no rights check.
//! Dialing a peer never established the peer's rights. These tests exercise
//! the three gate helpers directly, mirroring how
//! `live_write_admission_tests` exercises `admitted_for_drive`.
use super::*;
use crate::Db;
use std::collections::HashMap;

/// Build a drive whose read/write is restricted to `owner` (no public
/// grant) plus one child resource under it. Returns `(drive_did, child)`.
pub(super) async fn private_drive_with_child(
    db: &Db,
    owner: &crate::agents::Agent,
) -> (String, String) {
    let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::IS_A.into(),
        crate::Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
    );
    builder.set(
        crate::urls::NAME.into(),
        crate::Value::String("Private Drive".into()),
    );
    builder.set(
        crate::urls::WRITE.into(),
        crate::Value::ResourceArray(vec![owner.subject.to_string().into()]),
    );
    builder.set(
        crate::urls::READ.into(),
        crate::Value::ResourceArray(vec![owner.subject.to_string().into()]),
    );
    let commit = crate::commit::Commit::create_did(builder, owner, db)
        .await
        .unwrap();
    let drive_did = commit.subject.to_string();
    let opts = crate::commit::CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        update_index: true,
        ..crate::commit::CommitOpts::no_validations_no_index()
    };
    db.apply_commit(commit, &opts).await.unwrap();
    db.set_active_drive(&drive_did).unwrap();

    let child = db
        .create_resource(
            crate::urls::CLASS,
            &drive_did,
            "Secret Doc",
            // A schema-valid Class instance (shortname + description), so
            // a later commit against it, a destroy included, is judged on
            // signature and rights rather than tripping validation.
            Some(vec![
                (
                    crate::urls::DESCRIPTION,
                    crate::Value::String("top secret".into()),
                ),
                (
                    crate::urls::SHORTNAME,
                    crate::Value::Slug("secret-doc".into()),
                ),
            ]),
        )
        .await
        .unwrap();
    (drive_did, child)
}

/// A peer we dialed that only proved `Public` (or nothing) must NOT be
/// served snapshots for subjects it can't read — even though it named them
/// in its `pull` list. The old code read `Tree::LoroSnapshots` directly and
/// handed the bytes over regardless.
#[tokio::test]
async fn pull_serving_refuses_unreadable_subjects_for_public_peer() {
    let db = Db::init_temp("initiator_pull_public").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;

    // Public peer asks for the secret child — must get nothing.
    let served = crate::sync::engine::collect_readable_snapshots(
        &db,
        &ForAgent::Public,
        std::slice::from_ref(&child),
        None,
    )
    .await;
    assert!(
        served.is_empty(),
        "a Public peer must not be served a snapshot for a subject it can't read"
    );

    // The rightful owner asking for the same subject IS served — proving
    // the gate rejects on rights, not on some unrelated failure.
    let served_owner = crate::sync::engine::collect_readable_snapshots(
        &db,
        &ForAgent::AgentSubject(alice.subject.clone()),
        std::slice::from_ref(&child),
        None,
    )
    .await;
    assert_eq!(
        served_owner.len(),
        1,
        "the owner must still be served the snapshot it can read"
    );
    assert_eq!(served_owner[0].0, child);
}

/// A stranger agent (proved identity, but no rights on this drive) is
/// treated the same as Public for the pull-serving gate.
#[tokio::test]
async fn pull_serving_refuses_unreadable_subjects_for_stranger() {
    let db = Db::init_temp("initiator_pull_stranger").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;
    let mallory = db.create_agent(Some("Mallory")).await.unwrap();

    let served = crate::sync::engine::collect_readable_snapshots(
        &db,
        &ForAgent::AgentSubject(mallory.subject.clone()),
        &[child],
        None,
    )
    .await;
    assert!(
        served.is_empty(),
        "a peer that authenticated as an unrelated agent must not receive unreadable snapshots"
    );
}

/// A node the owner deliberately paired with may replicate what the owner
/// can read, even though its own agent holds no rights on the drive.
///
/// Without this, two of the same person's machines sync nothing: the
/// serving node refuses every subject because the peer's node agent is a
/// stranger to the drive, and the only remedy is hand-writing an ACL entry
/// naming that agent — per device, per drive, with no prompt and no error.
/// Pairing is already an authenticated choice by the owner; this treats it
/// as one.
#[tokio::test]
async fn a_paired_replica_receives_what_the_owner_can_read() {
    let db = Db::init_temp("paired_replica_serves").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;

    // The replica's own identity: a node agent, granted nothing.
    let replica_node = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999";
    let replica_agent = db.create_agent(Some("Replica")).await.unwrap();
    let as_replica = ForAgent::AgentSubject(replica_agent.subject.clone());

    // Not paired yet — rights only, so nothing is served.
    let unpaired = crate::sync::engine::collect_readable_snapshots(
        &db,
        &as_replica,
        std::slice::from_ref(&child),
        Some(replica_node),
    )
    .await;
    assert!(
        unpaired.is_empty(),
        "a node the owner never dialled must not be served"
    );

    // The owner pairs with it.
    add_known_peer(&db, replica_node, "Replica");

    let paired = crate::sync::engine::collect_readable_snapshots(
        &db,
        &as_replica,
        &[child],
        Some(replica_node),
    )
    .await;
    assert_eq!(
        paired.len(),
        1,
        "a paired replica must receive what the owner can read"
    );
}

/// A peer we dialed that isn't admitted for the drive must NOT be able to
/// delete + tombstone a subject we legitimately hold via `remove[]`. The
/// old code called `apply_destroy` (unchecked) for every remove entry.
#[tokio::test]
async fn remove_rejected_for_unadmitted_peer_known_subject() {
    let db = Db::init_temp("initiator_remove_stranger").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;
    let mallory = db.create_agent(Some("Mallory")).await.unwrap();

    let mut cache = HashMap::new();
    apply_peer_remove(
        &db,
        &ForAgent::AgentSubject(mallory.subject.clone()),
        &child,
        false,
        &mut cache,
        None,
    )
    .await;

    assert!(
        db.get_resource(&child.as_str().into()).await.is_ok(),
        "an unadmitted peer's remove[] entry must NOT delete a subject we hold"
    );
    assert!(
        !crate::sync::tombstones::is_tombstoned(&db, &child),
        "an unadmitted peer's remove[] entry must NOT tombstone a subject we hold"
    );
}

/// The rightful owner's remove IS applied — proving the gate is about
/// rights, not a blanket refusal that would break legitimate reconcile.
#[tokio::test]
async fn remove_applied_for_admitted_owner() {
    let db = Db::init_temp("initiator_remove_owner").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;

    let mut cache = HashMap::new();
    apply_peer_remove(
        &db,
        &ForAgent::AgentSubject(alice.subject.clone()),
        &child,
        false,
        &mut cache,
        None,
    )
    .await;

    assert!(
        db.get_resource(&child.as_str().into()).await.is_err(),
        "the owner's remove[] entry must delete the subject"
    );
    assert!(
        crate::sync::tombstones::is_tombstoned(&db, &child),
        "the owner's remove[] entry must record a tombstone"
    );
}

/// A signed destroy envelope is applied as a COMMIT: the connection's
/// AUTH identity does not authorise the delete, the commit's signer does.
/// Mallory's session can relay Alice's destroy and it still lands.
#[tokio::test]
async fn signed_remove_envelope_applies_even_when_connection_agent_is_a_stranger() {
    let db = Db::init_temp("initiator_remove_signed").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;
    let mallory = db.create_agent(Some("Mallory")).await.unwrap();

    let subject = crate::Subject::from_raw(&child, None);
    let resource = db.get_resource(&subject).await.unwrap();
    let mut builder = crate::commit::CommitBuilder::new(subject.clone());
    builder.destroy(true);
    let commit = builder.sign(&alice, &db, &resource).await.unwrap();
    let commit_json = commit
        .into_resource(&db)
        .await
        .unwrap()
        .to_json_ad(None)
        .unwrap();

    let mut cache = HashMap::new();
    apply_peer_remove(
        &db,
        &ForAgent::AgentSubject(mallory.subject.clone()),
        &child,
        false,
        &mut cache,
        Some(&commit_json),
    )
    .await;

    assert!(
        db.get_resource(&subject).await.is_err(),
        "a valid destroy envelope must apply regardless of the connection agent"
    );
    assert!(crate::sync::tombstones::is_tombstoned(&db, &child));
    assert!(
        crate::sync::tombstones::destroy_envelope(&db, &child).is_some(),
        "the applied destroy must leave its envelope on the tombstone"
    );
}

/// A tampered envelope must not fall back to the unsigned tombstone path.
#[tokio::test]
async fn tampered_remove_envelope_does_not_delete() {
    let db = Db::init_temp("initiator_remove_tampered").await.unwrap();
    let alice = crate::agents::Agent::new(Some("Alice")).unwrap();
    db.set_default_agent(alice.clone());
    let (_drive, child) = private_drive_with_child(&db, &alice).await;

    let subject = crate::Subject::from_raw(&child, None);
    let resource = db.get_resource(&subject).await.unwrap();
    let mut builder = crate::commit::CommitBuilder::new(subject.clone());
    builder.destroy(true);
    let commit = builder.sign(&alice, &db, &resource).await.unwrap();
    let commit_json = commit
        .into_resource(&db)
        .await
        .unwrap()
        .to_json_ad(None)
        .unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&commit_json).unwrap();
    json[crate::urls::SIGNATURE] = serde_json::Value::String("AAAA".into());
    let tampered = json.to_string();

    let mut cache = HashMap::new();
    apply_peer_remove(
        &db,
        &ForAgent::AgentSubject(alice.subject.clone()),
        &child,
        false,
        &mut cache,
        Some(&tampered),
    )
    .await;

    assert!(
        db.get_resource(&subject).await.is_ok(),
        "a tampered destroy envelope must not delete, even from the owner"
    );
    assert!(!crate::sync::tombstones::is_tombstoned(&db, &child));
}
