use super::*;
use crate::sync::policy::OwnerPolicy;
use crate::Value;
use std::sync::Arc;

fn signed_opts(agent: &crate::agents::Agent) -> CommitOpts {
    CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    }
}

/// A commit that brings a new drive into being, signed by `agent`.
async fn new_drive_commit(db: &crate::Db, agent: &crate::agents::Agent) -> Commit {
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::DRIVE.to_string().into()]),
    );
    builder.set(crate::urls::NAME.into(), Value::String("A Drive".into()));
    Commit::create_did(builder, agent, db).await.unwrap()
}

#[tokio::test]
async fn a_stranger_cannot_create_a_drive_on_someone_elses_node() {
    let db = crate::Db::init_temp("owner_gate_stranger").await.unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();
    let stranger = db.create_agent(Some("Stranger")).await.unwrap();

    db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

    let commit = new_drive_commit(&db, &stranger).await;
    let err = db
        .apply_commit(commit, &signed_opts(&stranger))
        .await
        .expect_err("a stranger must not be able to genesis a drive on a gated node")
        .to_string();

    // The person reading this clicked a button; the message has to be about
    // them, not about enrollment bookkeeping.
    assert!(err.contains("does not host new Drives"), "{err}");
}

#[tokio::test]
async fn the_owner_can_still_create_drives() {
    let db = crate::Db::init_temp("owner_gate_owner").await.unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();

    db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

    let commit = new_drive_commit(&db, &owner).await;
    let subject = commit.subject.to_string();

    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("the owner must be able to create a drive on their own node");

    // And it was enrolled, so the *next* write to it is admitted without
    // re-deciding who may enroll.
    assert!(
        db.sync_policy().admit_drive_write(&subject),
        "creating a drive must enroll it"
    );
}

#[tokio::test]
async fn drives_that_predate_the_gate_keep_working() {
    // The switch from open to owner must never revoke access to data
    // already on the disk — including a guest's drive from before.
    let db = crate::Db::init_temp("owner_gate_snapshot").await.unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();
    let guest = db.create_agent(Some("Guest")).await.unwrap();

    let commit = new_drive_commit(&db, &guest).await;
    let guest_drive = commit.subject.to_string();
    db.apply_commit(commit, &signed_opts(&guest))
        .await
        .expect("open node accepts the guest drive");

    // Now the operator names an owner and restarts.
    let policy = OwnerPolicy::new(owner.subject.to_string());
    policy.enroll_existing(db.drive_subjects().await);
    db.set_sync_policy(Arc::new(policy));

    assert!(
        db.sync_policy().admit_drive_write(&guest_drive),
        "a drive created before the gate went up must stay writable"
    );
}

/// A signed commit that destroys `subject`, as the resource looks now.
async fn destroy_commit(
    db: &crate::Db,
    agent: &crate::agents::Agent,
    subject: &crate::Subject,
) -> Commit {
    use crate::storelike::Storelike;
    let resource = match db.get_resource(subject).await {
        Ok(r) => r,
        Err(_) => crate::Resource::new(subject.to_string()),
    };
    let mut builder = CommitBuilder::new(subject.clone());
    builder.destroy(true);
    builder.sign(agent, db, &resource).await.unwrap()
}

/// A signed commit creating a child of `parent`.
async fn child_commit(db: &crate::Db, agent: &crate::agents::Agent, parent: &str) -> Commit {
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::FOLDER.to_string().into()]),
    );
    builder.set(crate::urls::PARENT.into(), Value::AtomicUrl(parent.into()));
    builder.set(crate::urls::NAME.into(), Value::String("Child".into()));
    Commit::create_did(builder, agent, db).await.unwrap()
}

/// A normal (non-genesis) edit of an existing resource.
async fn rename_commit(
    db: &crate::Db,
    agent: &crate::agents::Agent,
    subject: &crate::Subject,
) -> Commit {
    use crate::storelike::Storelike;
    let resource = db.get_resource(subject).await.unwrap();
    let mut builder = CommitBuilder::new(subject.clone());
    builder.set(crate::urls::NAME.into(), Value::String("Renamed".into()));
    builder.sign(agent, db, &resource).await.unwrap()
}

/// Behind a TLS-terminating proxy the boot origin is plain http while the
/// owner's drive is enrolled at boot from what the store lists.
#[tokio::test]
async fn the_owner_can_write_and_delete_in_a_drive_enrolled_at_boot() {
    use crate::storelike::Storelike;
    let db = crate::Db::init_temp("owner_gate_boot_enrolled")
        .await
        .unwrap();
    let (owner, drive) = db.setup("Owner").await.unwrap();
    let db = db.clone_with_url("http://atomic.example.de".into());

    let policy = OwnerPolicy::new(owner.subject.to_string());
    policy.enroll_existing(db.drive_subjects().await);
    db.set_sync_policy(Arc::new(policy));

    let commit = rename_commit(&db, &owner, &crate::Subject::from(drive.clone())).await;
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("owner edits the root of a drive hosted at boot");

    let commit = child_commit(&db, &owner, &drive).await;
    let child = commit.subject.clone();
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("owner writes a child of a drive hosted at boot");

    let commit = destroy_commit(&db, &owner, &child).await;
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("owner deletes that child");
    assert!(db.get_resource(&child).await.is_err());
}

/// Create a drive on a gated node, "restart" (new policy from what is
/// stored) and keep editing the drive root.
#[tokio::test]
async fn a_drive_the_owner_created_survives_a_restart() {
    let db = crate::Db::init_temp("owner_gate_restart").await.unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();
    let db = db.clone_with_url("http://atomic.example.de".into());
    db.set_sync_policy(Arc::new(OwnerPolicy::new(owner.subject.to_string())));

    let commit = new_drive_commit(&db, &owner).await;
    let drive = commit.subject.clone();
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("owner creates a drive");

    let commit = rename_commit(&db, &owner, &drive).await;
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("owner edits the drive they just created");

    let policy = OwnerPolicy::new(owner.subject.to_string());
    policy.enroll_existing(db.drive_subjects().await);
    db.set_sync_policy(Arc::new(policy));

    let commit = rename_commit(&db, &owner, &drive).await;
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("and after a restart");
}

/// A never-saved `_new:` placeholder that gets destroyed reaches the server
/// as a destroy of a resource it has never seen. That is not a drive being
/// created and must not be answered with the owner-mode refusal.
#[tokio::test]
async fn destroying_a_resource_the_node_never_stored_is_not_a_drive_enrollment() {
    let db = crate::Db::init_temp("owner_gate_destroy_unknown")
        .await
        .unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();
    let stranger = db.create_agent(Some("Stranger")).await.unwrap();
    let db = db.clone_with_url("http://atomic.example.de".into());
    let policy = OwnerPolicy::new(owner.subject.to_string());
    policy.enroll_existing(db.drive_subjects().await);
    db.set_sync_policy(Arc::new(policy));

    for (agent, who) in [(&owner, "owner"), (&stranger, "stranger")] {
        for raw in [
            "internal:/_new:01m370mvgky7aszw76azkqxtxn",
            "https://atomic.example.de/_new:01m370mvgky7aszw76azkqxtxn",
        ] {
            let subject = crate::Subject::from_raw(raw, Some("http://atomic.example.de"));
            let commit = destroy_commit(&db, agent, &subject).await;
            let e = db
                .apply_commit(commit, &signed_opts(agent))
                .await
                .expect_err("there is nothing to destroy")
                .to_string();
            assert!(
                e.contains("no such resource to destroy"),
                "{who} {raw}: {e}"
            );
        }
    }
}

/// The owner named in the `did:ad:agent:` spelling creates a drive.
#[tokio::test]
async fn owner_genesis_is_accepted_for_either_agent_spelling() {
    let db = crate::Db::init_temp("owner_gate_spelling").await.unwrap();
    let (owner, _) = db.setup("Owner").await.unwrap();
    let legacy = crate::identifiers::to_legacy_scheme(&owner.subject.to_string());
    db.set_sync_policy(Arc::new(OwnerPolicy::new(legacy)));

    let commit = new_drive_commit(&db, &owner).await;
    db.apply_commit(commit, &signed_opts(&owner))
        .await
        .expect("owner creates a drive");
}

#[tokio::test]
async fn an_open_node_still_takes_a_drive_from_anyone() {
    // The default path, and the one every existing deployment is on.
    let db = crate::Db::init_temp("owner_gate_open").await.unwrap();
    let (_owner, _) = db.setup("Owner").await.unwrap();
    let stranger = db.create_agent(Some("Stranger")).await.unwrap();

    let commit = new_drive_commit(&db, &stranger).await;
    db.apply_commit(commit, &signed_opts(&stranger))
        .await
        .expect("an open node must behave exactly as it did before host mode existed");
}
