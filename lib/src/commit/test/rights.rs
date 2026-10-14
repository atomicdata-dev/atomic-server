use super::*;

/// A stranger's genesis naming someone else's drive as `parent`, with a
/// `write` array that lists the stranger, must be refused. The new
/// resource's grants are whatever the signer put in the commit under
/// check, so they can never stand in for `append` on the parent.
#[tokio::test]
async fn genesis_cannot_grant_itself_append_via_its_own_write_array() {
    let (store, owner) = store_with_known_agent().await;

    let mut drive_builder = CommitBuilder::new("placeholder".into());
    drive_builder.set(
        urls::IS_A.into(),
        Value::from(vec![urls::DRIVE.to_string()]),
    );
    drive_builder.set(
        urls::WRITE.into(),
        Value::from(vec![owner.subject.to_string()]),
    );
    let drive_commit = Commit::create_did(drive_builder, &owner, &store)
        .await
        .unwrap();
    let drive = store
        .apply_commit(drive_commit, &rights_opts())
        .await
        .expect("an owner may create a parentless drive")
        .resource_new
        .unwrap()
        .get_subject()
        .to_string();

    // Unknown to the store: a bare keypair is all an attacker needs.
    let stranger = Agent::new(Some("stranger")).unwrap();
    let mut child_builder = CommitBuilder::new("placeholder".into());
    child_builder.set(urls::PARENT.into(), Value::AtomicUrl(drive.as_str().into()));
    child_builder.set(
        urls::WRITE.into(),
        Value::from(vec![stranger.subject.to_string()]),
    );
    child_builder.set(urls::NAME.into(), Value::String("squatted".into()));
    let child_commit = Commit::create_did(child_builder, &stranger, &store)
        .await
        .unwrap();
    let child_subject = child_commit.subject.to_string();

    let err = store
        .apply_commit(child_commit, &rights_opts())
        .await
        .expect_err("a stranger must not create children in someone else's drive");
    assert!(
        store
            .get_resource(&child_subject.as_str().into())
            .await
            .is_err(),
        "refused child must not have been stored: {err}"
    );

    // The owner can still do exactly the same thing.
    let mut own_child = CommitBuilder::new("placeholder".into());
    own_child.set(urls::PARENT.into(), Value::AtomicUrl(drive.as_str().into()));
    own_child.set(urls::NAME.into(), Value::String("mine".into()));
    let own_commit = Commit::create_did(own_child, &owner, &store).await.unwrap();
    store
        .apply_commit(own_commit, &rights_opts())
        .await
        .expect("the drive's writer may append to it");
}

/// `did:ad:agent:{key}` is an identity. Nobody but that key (or the node
/// itself) may create it, or an attacker could squat a user's Agent
/// resource, complete with their own `write` grant, before the user's
/// first sign-in.
#[tokio::test]
async fn agent_resource_can_only_be_created_by_its_own_key() {
    let (store, _known) = store_with_known_agent().await;
    let victim = Agent::new(Some("victim")).unwrap();
    let stranger = Agent::new(Some("stranger")).unwrap();

    let squat = |signer: &Agent| {
        let mut b = CommitBuilder::new(victim.subject.clone());
        b.is_genesis = true;
        b.set(
            urls::IS_A.into(),
            Value::from(vec![urls::AGENT.to_string()]),
        );
        b.set(urls::NAME.into(), Value::String("me".into()));
        b.set(
            urls::WRITE.into(),
            Value::from(vec![signer.subject.to_string()]),
        );
        b
    };

    let by_stranger = squat(&stranger)
        .sign(
            &stranger,
            &store,
            &Resource::new(victim.subject.to_string()),
        )
        .await
        .unwrap();
    store
        .apply_commit(by_stranger, &rights_opts())
        .await
        .expect_err("only the agent itself may create its Agent resource");
    assert!(
        store
            .get_resource(&victim.subject)
            .await
            .map(|r| r.get(urls::WRITE).is_err())
            .unwrap_or(true),
        "the squatter's write grant must not have been stored"
    );

    let by_victim = squat(&victim)
        .sign(&victim, &store, &Resource::new(victim.subject.to_string()))
        .await
        .unwrap();
    store
        .apply_commit(by_victim, &rights_opts())
        .await
        .expect("an agent creates its own Agent resource");
}

/// A genesis for a child of `missing_parent`, stamped for `drive`.
async fn genesis_under_missing_parent(
    store: &Store,
    signer: &Agent,
    missing_parent: &str,
    drive: &str,
) -> Commit {
    let mut b = CommitBuilder::new("placeholder".into());
    b.set(urls::PARENT.into(), Value::AtomicUrl(missing_parent.into()));
    b.set(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()));
    b.set(urls::NAME.into(), Value::String("child".into()));
    Commit::create_did(b, signer, store).await.unwrap()
}

/// The parent-before-child path (B2 / C20): a genesis naming a parent
/// that is not materialized here yet is judged on its `drive` stamp,
/// and the stamp only counts for an agent who may append to the drive
/// it names. A stranger stamping a victim's drive gets nothing.
#[tokio::test]
async fn unresolved_parent_falls_back_to_the_drive_stamp_only_for_drive_writers() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let missing_parent =
        "did:ad:notmaterializedyet0000000000000000000000000000000000000000000000000000000==";

    let stranger = Agent::new(Some("stranger")).unwrap();
    let by_stranger = genesis_under_missing_parent(&store, &stranger, missing_parent, &drive).await;
    let squatted = by_stranger.subject.to_string();
    let err = store
        .apply_commit(by_stranger, &rights_opts())
        .await
        .expect_err("a drive stamp is not a right to append to that drive");
    assert!(
        store.get_resource(&squatted.as_str().into()).await.is_err(),
        "refused child must not have been stored: {err}"
    );

    let by_owner = genesis_under_missing_parent(&store, &owner, missing_parent, &drive).await;
    store
        .apply_commit(by_owner, &rights_opts())
        .await
        .expect("a drive writer may create children before their parent arrives");
}

/// A parentless non-DID subject claiming `isA: Drive` reserves a server
/// path. Only the node's own agent (or Sudo) may do that; a signed-in
/// stranger with rights validation on is refused.
#[tokio::test]
async fn stranger_cannot_create_a_top_level_url_drive() {
    let (store, owner) = store_with_known_agent().await;
    let subject = "http://localhost:9883/squatted-drive";

    let drive_commit = |signer: &Agent| {
        let mut b = CommitBuilder::new(subject.into());
        b.set(
            urls::IS_A.into(),
            Value::from(vec![urls::DRIVE.to_string()]),
        );
        b.set(
            urls::WRITE.into(),
            Value::from(vec![signer.subject.to_string()]),
        );
        b
    };

    let stranger = Agent::new(Some("stranger")).unwrap();
    let by_stranger = drive_commit(&stranger)
        .sign(&stranger, &store, &Resource::new(subject.into()))
        .await
        .unwrap();
    let err = store
        .apply_commit(by_stranger, &rights_opts())
        .await
        .expect_err("a stranger must not reserve a top-level path on this node")
        .to_string();
    assert!(err.contains("own agent"), "{err}");
    assert!(
        store
            .get_resource(&subject.into())
            .await
            .map(|r| r.get(urls::WRITE).is_err())
            .unwrap_or(true),
        "the squatter's drive must not have been stored"
    );

    // The node's own agent still can — that is how setup creates one.
    store.set_default_agent(owner.clone());
    let by_owner = drive_commit(&owner)
        .sign(&owner, &store, &Resource::new(subject.into()))
        .await
        .unwrap();
    store
        .apply_commit(by_owner, &rights_opts())
        .await
        .expect("the node's own agent may create a top-level drive");
}

/// The genesis cert binds the resource's original `parent` and `drive`.
/// A doc that names another parent under the same (valid) cert would put
/// the resource where the cert's signer never put it: refused.
#[tokio::test]
async fn genesis_cert_parent_must_match_the_document() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;

    let mut b = CommitBuilder::new("placeholder".into());
    b.set(urls::PARENT.into(), Value::AtomicUrl(drive.as_str().into()));
    b.set(urls::NAME.into(), Value::String("doc".into()));
    let genuine = Commit::create_did(b, &owner, &store).await.unwrap();
    genuine
        .validate_signature(&store)
        .await
        .expect("cert and document agree");

    // Same cert (so the same DID), a document that names another parent.
    let doc = crate::loro::AtomicLoroDoc::new();
    doc.import_update(genuine.loro_update.as_ref().unwrap())
        .unwrap();
    doc.set_property(
        urls::PARENT,
        &Value::AtomicUrl(
            "did:ad:somewhereelse00000000000000000000000000000000000000000000000000000000000=="
                .into(),
        ),
    )
    .unwrap();
    let mut forged = CommitBuilder::new(genuine.subject.clone());
    forged.is_genesis = true;
    forged.set_loro_update(doc.export_snapshot());
    let forged = forged
        .sign(&owner, &store, &Resource::new(genuine.subject.to_string()))
        .await
        .unwrap();
    let err = forged
        .validate_signature(&store)
        .await
        .expect_err("the document's parent contradicts the cert")
        .to_string();
    assert!(
        err.contains("does not match the resource's parent"),
        "{err}"
    );
}
