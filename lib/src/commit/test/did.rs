use super::*;

// ── DID commit tests ────────────────────────────────────────────────────

/// Creating a new `did:ad:` resource via genesis commit should succeed and
/// the resulting resource subject must start with `did:ad:`.
#[tokio::test]
async fn did_genesis_commit_creates_resource() {
    let (store, agent) = store_with_known_agent().await;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::DESCRIPTION.into(),
        Value::new("hello", &DataType::Markdown).unwrap(),
    );
    let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
    assert!(
        commit.subject.is_did(),
        "genesis subject should be a DID, got {}",
        commit.subject
    );
    assert!(!commit.subject.is_agent_did());
    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        ..CommitOpts::no_validations_no_index()
    };
    let result = store.apply_commit(commit, &opts).await.unwrap();
    let new_subject = result
        .resource_new
        .as_ref()
        .map(|r| r.get_subject().to_string())
        .unwrap_or_default();
    assert!(
        crate::identifiers::is_resource_id(&new_subject),
        "created resource subject should be an atomic: resource, got: {}",
        new_subject
    );

    // Verify the resource is actually retrievable from the store
    let stored = store
        .get_resource(&new_subject.as_str().into())
        .await
        .expect("DID resource should be retrievable after genesis commit");
    assert_eq!(
        stored.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "hello",
        "Stored resource should have the description from the commit"
    );
}

/// Two devices holding the same key mint the same personal-drive DID.
/// Applying both geneses merges the Loro docs instead of rejecting the
/// second as "already exists".
#[tokio::test]
async fn repeat_private_drive_genesis_merges() {
    let (store, agent) = store_with_known_agent().await;
    let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        validate_loro_causality: true,
        ..CommitOpts::no_validations_no_index()
    };

    let mut first = CommitBuilder::new("placeholder".into());
    first.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
    );
    first.set(
        crate::urls::NAME.into(),
        Value::String("Device A home".into()),
    );
    first.set(
        crate::urls::WRITE.into(),
        Value::ResourceArray(vec![agent.subject.to_string().into()]),
    );
    let commit_a = Commit::create_did_with_cert(first, &agent, &store, Some(cert.clone()))
        .await
        .unwrap();
    let subject = commit_a.subject.clone();
    assert_eq!(
        subject.to_string(),
        crate::genesis::GenesisCert::private_drive_subject(agent.private_key.as_ref().unwrap())
            .unwrap()
    );
    store.apply_commit(commit_a, &opts).await.unwrap();

    let mut second = CommitBuilder::new("placeholder".into());
    second.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
    );
    second.set(
        crate::urls::NAME.into(),
        Value::String("Device B home".into()),
    );
    second.set(
        crate::urls::DESCRIPTION.into(),
        Value::String("from the second device".into()),
    );
    second.set(
        crate::urls::WRITE.into(),
        Value::ResourceArray(vec![agent.subject.to_string().into()]),
    );
    let commit_b = Commit::create_did_with_cert(second, &agent, &store, Some(cert))
        .await
        .unwrap();
    assert_eq!(commit_b.subject, subject);
    store
        .apply_commit(commit_b, &opts)
        .await
        .expect("repeat genesis for the same personal-drive DID must merge");

    let merged = store.get_resource(&subject).await.unwrap();
    assert_eq!(
        merged.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "from the second device",
        "property only set on the second device must survive the merge"
    );
    assert!(merged.get(crate::urls::NAME).is_ok());
    assert_eq!(
        merged
            .get(crate::urls::IS_A)
            .unwrap()
            .to_subjects(None)
            .unwrap()[0],
        crate::urls::DRIVE
    );
}

/// A repeat genesis whose every value loses to the resource's current
/// state must still be accepted.
///
/// The device that created the drive keeps a stashed genesis commit. Rename
/// the drive, and that stash now says `name = "My drive"` while the stored
/// state says the chosen name. It contributes new ops but changes no atom,
/// which is exactly the shape the causality guard rejects — so the client
/// re-posted it every 30 seconds for as long as the app stayed open.
#[tokio::test]
async fn repeat_genesis_losing_every_value_is_accepted() {
    let (store, agent) = store_with_known_agent().await;
    let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        validate_loro_causality: true,
        ..CommitOpts::no_validations_no_index()
    };

    let mut genesis = CommitBuilder::new("placeholder".into());
    genesis.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
    );
    genesis.set(crate::urls::NAME.into(), Value::String("My drive".into()));
    genesis.set(
        crate::urls::WRITE.into(),
        Value::ResourceArray(vec![agent.subject.to_string().into()]),
    );
    let first = Commit::create_did_with_cert(genesis, &agent, &store, Some(cert.clone()))
        .await
        .unwrap();
    let subject = first.subject.clone();
    store.apply_commit(first, &opts).await.unwrap();

    // The user names their home drive.
    let stored = store.get_resource(&subject).await.unwrap();
    let mut rename = CommitBuilder::new(subject.clone());
    rename.set(
        crate::urls::NAME.into(),
        Value::String("Joeps drijf".into()),
    );
    let rename = rename.sign(&agent, &store, &stored).await.unwrap();
    store.apply_commit(rename, &opts).await.unwrap();

    // Another device mints the same cert — same DID, creation defaults.
    // Every propval it carries now loses to the rename.
    let mut stale = CommitBuilder::new("placeholder".into());
    stale.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
    );
    stale.set(crate::urls::NAME.into(), Value::String("My drive".into()));
    stale.set(
        crate::urls::WRITE.into(),
        Value::ResourceArray(vec![agent.subject.to_string().into()]),
    );
    let stale = Commit::create_did_with_cert(stale, &agent, &store, Some(cert))
        .await
        .unwrap();
    assert_eq!(stale.subject, subject);

    store
        .apply_commit(stale, &opts)
        .await
        .expect("a repeat genesis that changes nothing must be accepted, not retried forever");

    let merged = store.get_resource(&subject).await.unwrap();
    assert_eq!(
        merged.get(crate::urls::NAME).unwrap().to_string(),
        "Joeps drijf",
        "the chosen name must survive the repeat genesis"
    );
}

/// The same materialization, arriving WITHOUT the `is_genesis` flag, must
/// merge too.
///
/// Whether a second device's from-scratch doc drains as a genesis or as an
/// ordinary commit is an accident of which client path exported it. Seen in
/// the field as a 500 loop on the owner's own home drive, posted from their
/// second browser: the commit carried the creation defaults, every one lost
/// to stored state, and the causality guard read that as silent data loss.
/// The cert is what decides — it verifies against this subject and names
/// this signer, so it can only be the same author.
#[tokio::test]
async fn repeat_materialization_merges_even_when_not_flagged_genesis() {
    let (store, agent) = store_with_known_agent().await;
    let pubkey: [u8; 32] = crate::agents::decode_base64(&agent.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let cert = crate::genesis::GenesisCert::for_private_drive(pubkey);
    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        validate_loro_causality: true,
        ..CommitOpts::no_validations_no_index()
    };

    let defaults = |builder: &mut CommitBuilder| {
        builder.set(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.into()]),
        );
        builder.set(crate::urls::NAME.into(), Value::String("My drive".into()));
        builder.set(
            crate::urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        );
    };

    let mut genesis = CommitBuilder::new("placeholder".into());
    defaults(&mut genesis);
    let first = Commit::create_did_with_cert(genesis, &agent, &store, Some(cert.clone()))
        .await
        .unwrap();
    let subject = first.subject.clone();
    store.apply_commit(first, &opts).await.unwrap();

    let stored = store.get_resource(&subject).await.unwrap();
    let mut rename = CommitBuilder::new(subject.clone());
    rename.set(crate::urls::NAME.into(), Value::String("Home".into()));
    let rename = rename.sign(&agent, &store, &stored).await.unwrap();
    store.apply_commit(rename, &opts).await.unwrap();

    // Second device: same cert, same defaults — but drained as an ordinary
    // commit, so `is_genesis` never gets set.
    let mut second = CommitBuilder::new("placeholder".into());
    defaults(&mut second);
    let mut second = Commit::create_did_with_cert(second, &agent, &store, Some(cert))
        .await
        .unwrap();
    assert_eq!(second.subject, subject);
    second.is_genesis = None;
    // Re-sign: the flag is part of the signed payload.
    let stringified = second
        .serialize_deterministically_json_ad(&store)
        .await
        .unwrap();
    second.signature = Some(
        sign_message(
            &stringified,
            &agent.private_key.clone().unwrap(),
            &agent.public_key,
        )
        .unwrap(),
    );

    store.apply_commit(second, &opts).await.expect(
        "a repeat materialization is the same author by construction — merge it, do not \
             refuse it as silent data loss",
    );

    let merged = store.get_resource(&subject).await.unwrap();
    assert_eq!(
        merged.get(crate::urls::NAME).unwrap().to_string(),
        "Home",
        "the chosen name must survive the second device's defaults"
    );
}

/// A genesis retry without a verifiable cert still fails — only a
/// same-signer, same-subject cert is treated as a merge.
#[tokio::test]
async fn repeat_genesis_without_cert_is_still_rejected() {
    let (store, agent) = store_with_known_agent().await;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(crate::urls::NAME.into(), Value::String("once".into()));
    let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
    let subject = genesis.subject.clone();
    let opts = CommitOpts {
        validate_signature: false,
        validate_timestamp: false,
        validate_rights: false,
        ..CommitOpts::no_validations_no_index()
    };
    store.apply_commit(genesis, &opts).await.unwrap();

    let loro_doc = crate::loro::AtomicLoroDoc::new();
    loro_doc
        .set_property(crate::urls::NAME, &Value::String("twice".into()))
        .unwrap();
    let retry = Commit {
        subject: subject.clone(),
        signer: agent.subject.clone(),
        loro_update: Some(loro_doc.export_snapshot()),
        destroy: Some(false),
        created_at: crate::utils::now(),
        previous_commit: None,
        is_genesis: Some(true),
        signature: Some("not-checked".into()),
        url: None,
    };
    let err = store.apply_commit(retry, &opts).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("is_genesis: true, but the resource already exists"),
        "expected the old reject, got: {err}"
    );
}

/// Loro-only genesis commit (empty set map, only loroUpdate) — mimics browser behavior.
/// The resource should be stored and retrievable with materialized properties.
#[tokio::test]
async fn did_loro_only_genesis_commit_stores_resource() {
    let (store, agent) = store_with_known_agent().await;

    // Build a Loro doc with properties (mimics browser-side Loro)
    let loro_doc = crate::loro::AtomicLoroDoc::new();
    loro_doc
        .set_property(crate::urls::NAME, &Value::String("My Table".into()))
        .unwrap();
    loro_doc
        .set_property(
            crate::urls::DESCRIPTION,
            &Value::String("A test table".into()),
        )
        .unwrap();
    loro_doc
        .set_property(
            crate::urls::PUBLIC_KEY,
            &Value::String(agent.public_key.clone()),
        )
        .unwrap();

    // Export as snapshot (this is what the browser sends for genesis)
    let snapshot = loro_doc.export_snapshot();

    // Create a CommitBuilder with ONLY loroUpdate (no set map)
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set_loro_update(snapshot);

    let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
    let did_subject = commit.subject.clone();

    assert!(
        commit.loro_update.is_some(),
        "commit should have loroUpdate"
    );

    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };

    let result = store.apply_commit(commit, &opts).await.unwrap();
    assert!(result.resource_new.is_some(), "should have resource_new");

    // THE KEY TEST: verify the resource is retrievable from the store
    let stored = store
        .get_resource(&did_subject.as_str().into())
        .await
        .expect("Loro-only DID resource should be retrievable after commit");

    assert_eq!(
        stored.get(crate::urls::NAME).unwrap().to_string(),
        "My Table",
        "Name should be materialized from Loro"
    );
    assert_eq!(
        stored.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "A test table",
        "Description should be materialized from Loro"
    );
}

/// A follow-up commit to a `did:ad:` resource (after genesis) should
/// succeed when signed by the same agent.
#[tokio::test]
async fn did_followup_commit_succeeds() {
    let (store, agent) = store_with_known_agent().await;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::DESCRIPTION.into(),
        Value::new("v1", &DataType::Markdown).unwrap(),
    );
    let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
    let did_subject = genesis.subject.clone();
    let _genesis_url = genesis.url.clone();
    let opts_no_rights = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        ..CommitOpts::no_validations_no_index()
    };
    store.apply_commit(genesis, &opts_no_rights).await.unwrap();

    // Load the existing resource and edit on top of its Loro state
    let mut resource = store
        .get_resource(&did_subject.as_str().into())
        .await
        .unwrap();
    resource
        .set_unsafe(
            crate::urls::DESCRIPTION.into(),
            Value::new("v2", &DataType::Markdown).unwrap(),
        )
        .unwrap();
    let update = resource
        .get_commit_builder()
        .clone()
        .sign(&agent, &store, &resource)
        .await
        .unwrap();
    store.apply_commit(update, &opts_no_rights).await.unwrap();

    let updated = store
        .get_resource(&did_subject.as_str().into())
        .await
        .unwrap();
    assert_eq!(
        updated.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "v2"
    );
}

/// The server stamps `lastCommit` after importing a commit. That stamp is
/// an op under the server's own peer, and a peer that boots from the
/// stored snapshot builds its next edit on top of it. The author only
/// ever gets its own commit echoed back; if that echo is the commit's raw
/// bytes, the author lacks the stamp, the peer's edit parks as pending
/// and the document stops being live for the author. `fanout_delta` is
/// what the echo must carry.
#[tokio::test]
async fn fanout_delta_lets_the_author_apply_a_peer_edit_built_on_the_stored_snapshot() {
    let (store, agent) = store_with_known_agent().await;
    let agent_subject: Subject = format!("did:ad:agent:{}", agent.public_key).into();

    let author = crate::loro::AtomicLoroDoc::new();
    author
        .set_property(urls::PUBLIC_KEY, &Value::String(agent.public_key.clone()))
        .unwrap();
    author
        .set_property(urls::IS_A, &Value::ResourceArray(vec![urls::AGENT.into()]))
        .unwrap();

    let mut builder = CommitBuilder::new(agent_subject.clone());
    builder.set_loro_update(author.export_snapshot());
    builder.is_genesis = true;
    let empty_resource = Resource::new(agent_subject.to_string());
    let genesis = builder.sign(&agent, &store, &empty_resource).await.unwrap();

    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    let response = store.apply_commit(genesis, &opts).await.unwrap();

    // The echo of the author's own commit, as the live channel fans it out.
    let echo = response
        .fanout_delta()
        .expect("a Loro commit fans out a delta")
        .to_vec();
    assert_ne!(
        Some(echo.as_slice()),
        response.commit.loro_update.as_deref(),
        "the fan-out must carry more than the author's own bytes: the server's stamp"
    );
    author.import_update(&echo).unwrap();

    // A second peer boots from what the server stored and edits on top.
    let stored = store.get_resource(&agent_subject).await.unwrap();
    let peer = stored.build_state_doc().unwrap();
    let peer_before = peer.oplog_vv();
    peer.set_property(urls::NAME, &Value::String("typed by the peer".into()))
        .unwrap();
    let peer_delta = peer.export_updates_since(&peer_before);

    author.import_update(&peer_delta).unwrap();
    assert_eq!(
        author.get_string_property(urls::NAME),
        Some("typed by the peer".into()),
        "the author must apply the peer's edit without a catch-up fetch"
    );
}

/// Agent DID genesis commit should succeed even though get_resource()
/// returns a synthetic "just-in-time" agent. The Loro snapshot must be
/// persisted so follow-up commits can merge deltas correctly.
#[tokio::test]
async fn agent_did_genesis_and_followup_persists_loro() {
    let (store, agent) = store_with_known_agent().await;

    let agent_subject: Subject = format!("did:ad:agent:{}", agent.public_key).into();

    // Build a genesis Loro doc (mimics browser's handleNew)
    let loro_doc = crate::loro::AtomicLoroDoc::new();
    loro_doc
        .set_property(urls::PUBLIC_KEY, &Value::String(agent.public_key.clone()))
        .unwrap();
    loro_doc
        .set_property(urls::IS_A, &Value::ResourceArray(vec![urls::AGENT.into()]))
        .unwrap();
    let genesis_snapshot = loro_doc.export_snapshot();
    let genesis_version = loro_doc.oplog_vv();

    // Create the genesis commit via CommitBuilder (agent DIDs have a known subject)
    let mut builder = CommitBuilder::new(agent_subject.clone());
    builder.set_loro_update(genesis_snapshot);
    builder.is_genesis = true;
    let empty_resource = Resource::new(agent_subject.to_string());
    let genesis = builder.sign(&agent, &store, &empty_resource).await.unwrap();

    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };

    let result = store.apply_commit(genesis, &opts).await.unwrap();
    let genesis_commit_url = result.commit_resource.get_subject().to_string();
    assert!(
        result.resource_new.is_some(),
        "genesis should produce resource_new"
    );

    // Verify the stored resource has a loroUpdate
    let stored = store.get_resource(&agent_subject).await.unwrap();
    assert!(
        stored.get(urls::LORO_UPDATE).is_ok(),
        "Agent resource should have loroUpdate after genesis"
    );
    assert_eq!(
        stored.get(urls::PUBLIC_KEY).unwrap().to_string(),
        agent.public_key,
    );

    // Now create a follow-up commit that adds properties (mimics persistAgentAfterInvite)
    let loro_doc2 = crate::loro::AtomicLoroDoc::new();
    loro_doc2
        .import_update(&loro_doc.export_snapshot())
        .unwrap();
    loro_doc2
        .set_property(urls::NAME, &Value::String("Test Agent".into()))
        .unwrap();
    loro_doc2
        .set_property(urls::DESCRIPTION, &Value::String("My private drive".into()))
        .unwrap();
    let delta = loro_doc2.export_updates_since(&genesis_version);

    let mut builder2 = CommitBuilder::new(agent_subject.clone());
    builder2.set_loro_update(delta);
    builder2.previous_commit = Some(genesis_commit_url);
    let followup = builder2.sign(&agent, &store, &stored).await.unwrap();

    let result2 = store.apply_commit(followup, &opts).await.unwrap();
    assert!(result2.resource_new.is_some());

    // THE KEY ASSERTION: the follow-up properties must be materialized
    let stored2 = store.get_resource(&agent_subject).await.unwrap();
    assert_eq!(
        stored2.get(urls::NAME).unwrap().to_string(),
        "Test Agent",
        "Name from follow-up commit should be persisted"
    );
    assert_eq!(
        stored2.get(urls::DESCRIPTION).unwrap().to_string(),
        "My private drive",
        "Description from follow-up commit should be persisted"
    );
    assert_eq!(
        stored2.get(urls::PUBLIC_KEY).unwrap().to_string(),
        agent.public_key,
        "publicKey from genesis should still be present"
    );
}

#[tokio::test]
async fn loro_update_without_stored_snapshot_seeds_from_propvals_and_removes_deleted_props() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/loro_seeded_resource";

    let mut existing = Resource::new(subject.into());
    existing
        .set_unsafe(
            crate::urls::NAME.into(),
            Value::String("Before delete".into()),
        )
        .unwrap();
    existing
        .set_unsafe(
            crate::urls::DESCRIPTION.into(),
            Value::String("Delete me".into()),
        )
        .unwrap();

    let base_doc = crate::loro::AtomicLoroDoc::new();
    base_doc
        .set_property(crate::urls::NAME, &Value::String("Before delete".into()))
        .unwrap();
    base_doc
        .set_property(crate::urls::DESCRIPTION, &Value::String("Delete me".into()))
        .unwrap();

    let client_doc =
        crate::loro::AtomicLoroDoc::from_snapshot(&base_doc.export_snapshot()).unwrap();
    client_doc
        .remove_property(crate::urls::DESCRIPTION)
        .unwrap();
    client_doc
        .set_property(crate::urls::NAME, &Value::String("After delete".into()))
        .unwrap();

    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(client_doc.export_snapshot());
    let commit = builder.sign(&agent, &store, &existing).await.unwrap();

    let applied = commit.apply_changes(existing).await.unwrap();
    let updated = applied.resource_new;

    assert_eq!(
        updated.get(crate::urls::NAME).unwrap().to_string(),
        "After delete"
    );
    assert!(
        updated.get(crate::urls::DESCRIPTION).is_err(),
        "deleted properties should be removed from materialized propvals"
    );
    assert!(
        matches!(
            updated.get(crate::urls::LORO_UPDATE),
            Ok(Value::LoroDoc(snapshot)) if !snapshot.is_empty()
        ),
        "updated resource should keep a persisted Loro snapshot"
    );
}

#[tokio::test]
async fn did_child_keeps_parent_and_can_be_edited_with_inherited_write_rights() {
    let (store, agent) = store_with_known_agent().await;

    let drive_subject = "did:ad:test-drive";
    let mut drive = Resource::new(drive_subject.into());
    drive
        .set_unsafe(
            crate::urls::IS_A.into(),
            Value::ResourceArray(vec![crate::urls::DRIVE.to_string().into()]),
        )
        .unwrap();
    drive
        .set_unsafe(
            crate::urls::WRITE.into(),
            Value::ResourceArray(vec![agent.subject.to_string().into()]),
        )
        .unwrap();
    store.add_resource(&drive).await.unwrap();

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::PARENT.into(),
        Value::AtomicUrl(drive_subject.into()),
    );
    builder.set(
        crate::urls::NAME.into(),
        Value::String("First version".into()),
    );

    let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
    let did_subject = genesis.subject.clone();

    let opts_with_rights = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };

    store
        .apply_commit(genesis, &opts_with_rights)
        .await
        .unwrap();

    let created = store.get_resource(&did_subject).await.unwrap();
    // Added as `did:ad:`, materialized in the canonical spelling.
    assert_eq!(
        created.get(crate::urls::PARENT).unwrap().to_string(),
        crate::identifiers::canonicalize_scheme(drive_subject)
    );

    let mut updated_resource = created.clone();
    updated_resource
        .set_unsafe(
            crate::urls::DESCRIPTION.into(),
            Value::String("Second version".into()),
        )
        .unwrap();
    let update = updated_resource
        .get_commit_builder()
        .clone()
        .sign(&agent, &store, &updated_resource)
        .await
        .unwrap();

    store.apply_commit(update, &opts_with_rights).await.unwrap();

    let updated = store.get_resource(&did_subject).await.unwrap();
    assert_eq!(
        updated.get(crate::urls::PARENT).unwrap().to_string(),
        crate::identifiers::canonicalize_scheme(drive_subject)
    );
    assert_eq!(
        updated.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "Second version"
    );
}
