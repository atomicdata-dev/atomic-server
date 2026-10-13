use super::*;

/// Regression test for a real vulnerability: the admission-gate's agent
/// exemption must key off the commit's actual subject structure
/// (`is_agent_did`), never off a claimed `IS_A` propval. `IS_A` is an
/// ordinary, fully client-controlled property (the `Agent` class has no
/// required props gating it), so a version of the gate that trusted `IS_A`
/// let any client skip drive-enrollment/quota checks entirely by tagging
/// arbitrary data `IS_A: [Agent]`.
#[cfg(feature = "db")]
#[tokio::test]
async fn admission_gate_rejects_spoofed_agent_tag_on_unenrolled_drive() {
    use crate::sync::policy::AllowlistPolicy;
    use std::sync::Arc;
    use std::time::Duration;

    let db = crate::Db::init_temp("gate_spoof_test").await.unwrap();
    let (agent, drive_subject) = db.setup("Alice").await.unwrap();

    // Managed node with an empty allowlist and no bootstrap grace: nothing
    // is enrolled, so any non-agent drive write must be rejected outright.
    let policy = Arc::new(AllowlistPolicy::new());
    policy.set_grace(Duration::ZERO);
    db.set_sync_policy(policy);

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::PARENT.into(),
        Value::AtomicUrl(drive_subject.clone().into()),
    );
    // The spoof: claim to be an Agent so a naive check would exempt this
    // commit from the gate, even though the subject is an ordinary
    // resource under `drive_subject`, not an agent DID.
    builder.set(
        crate::urls::IS_A.into(),
        Value::ResourceArray(vec![crate::urls::AGENT.to_string().into()]),
    );
    let commit = Commit::create_did(builder, &agent, &db).await.unwrap();

    let opts_with_rights = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };

    let result = db.apply_commit(commit, &opts_with_rights).await;
    assert!(
        result.is_err(),
        "a spoofed IS_A: [Agent] tag must not bypass the drive-enrollment gate"
    );
}

/// Companion to the spoof-rejection test above: a genuine agent DID commit
/// (the commit's own subject is `did:ad:agent:…`) must still be admitted
/// even when its "drive" isn't enrolled — agents are legitimately outside
/// the enrollment model.
#[cfg(feature = "db")]
#[tokio::test]
async fn admission_gate_admits_real_agent_did_on_unenrolled_node() {
    use crate::sync::policy::AllowlistPolicy;
    use std::sync::Arc;
    use std::time::Duration;

    let db = crate::Db::init_temp("gate_real_agent_test").await.unwrap();
    let (agent, _drive_subject) = db.setup("Alice").await.unwrap();

    let policy = Arc::new(AllowlistPolicy::new());
    policy.set_grace(Duration::ZERO);
    db.set_sync_policy(policy);

    // The agent updates its own DID resource — a legitimate agent write,
    // unrelated to any enrolled drive.
    let mut agent_resource = db.get_resource(&agent.subject).await.unwrap();
    agent_resource
        .set_unsafe(crate::urls::NAME.into(), Value::String("Alice R.".into()))
        .unwrap();
    let commit = agent_resource
        .get_commit_builder()
        .clone()
        .sign(&agent, &db, &agent_resource)
        .await
        .unwrap();

    let opts_with_rights = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };

    db.apply_commit(commit, &opts_with_rights)
        .await
        .expect("a real agent DID commit must be exempt from the drive-enrollment gate");
}

/// F11 (planning/unified-sync.md): a rights-checked genesis commit for a
/// subject that was previously destroyed (and thus tombstoned, to stop
/// bulk-sync from resurrecting it) must clear that tombstone — otherwise
/// the legitimate re-create is invisible to future `SYNC_PUSH`/`SYNC_VV`
/// bulk-sync with other replicas forever, since `is_tombstoned` keeps
/// skipping it there.
#[cfg(feature = "db")]
#[tokio::test]
async fn genesis_commit_clears_stale_tombstone_on_own_subject() {
    let db = crate::Db::init_temp("f11_clear_tombstone_test")
        .await
        .unwrap();
    let (agent, drive_subject) = db.setup("Alice").await.unwrap();

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::PARENT.into(),
        Value::AtomicUrl(drive_subject.into()),
    );
    builder.set(crate::urls::NAME.into(), Value::String("Reborn".into()));
    let genesis = Commit::create_did(builder, &agent, &db).await.unwrap();
    let subject = genesis.subject.clone();

    // Simulate a prior local deletion of this exact subject.
    crate::sync::tombstones::record_tombstone(&db, subject.as_str());
    assert!(crate::sync::tombstones::is_tombstoned(
        &db,
        subject.as_str()
    ));

    let opts_with_rights = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    db.apply_commit(genesis, &opts_with_rights).await.unwrap();

    assert!(
        !crate::sync::tombstones::is_tombstoned(&db, subject.as_str()),
        "F11: a rights-checked genesis re-create must clear a stale tombstone on its own subject"
    );
}

/// Tampering with the signature of an otherwise valid commit must be
/// rejected when signature validation is enabled.
#[tokio::test]
async fn tampered_signature_is_rejected() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/tamper_target";
    let resource = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set(
        crate::urls::DESCRIPTION.into(),
        Value::new("legit", &DataType::Markdown).unwrap(),
    );
    let mut commit = builder.sign(&agent, &store, &resource).await.unwrap();
    // Flip the first character of the signature to invalidate it.
    commit.signature = Some(format!("XXXX{}", &commit.signature.unwrap()[4..]));

    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        ..CommitOpts::no_validations_no_index()
    };
    let err = store.apply_commit(commit, &opts).await.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("signature"),
        "expected a signature error, got: {}",
        err
    );
}

/// Signing a commit with agent B but writing to a resource that agent A
/// created (and owns) must fail signature validation.
#[tokio::test]
async fn wrong_agent_signature_is_rejected() {
    let (store, agent_a) = store_with_known_agent().await;
    let agent_b = store.create_agent(Some("agent_b")).await.unwrap();

    let subject = "https://localhost/agent_a_resource";
    let resource = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set(
        crate::urls::DESCRIPTION.into(),
        Value::new("by agent_a", &DataType::Markdown).unwrap(),
    );
    // Sign with agent_b but claim agent_a signed it by manually overriding the signer.
    let mut commit = builder.sign(&agent_b, &store, &resource).await.unwrap();
    commit.signer = agent_a.subject.clone();

    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: false,
        ..CommitOpts::no_validations_no_index()
    };
    let err = store.apply_commit(commit, &opts).await.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("signature"),
        "expected a signature error, got: {}",
        err
    );
}

/// A genesis commit's deterministic serialization must NOT include `@id`,
/// so that the subject (= the signature) is not part of the signed bytes.
#[tokio::test]
async fn genesis_deterministic_serialization_excludes_id() {
    let (store, agent) = store_with_known_agent().await;
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        crate::urls::DESCRIPTION.into(),
        Value::new("test", &DataType::Markdown).unwrap(),
    );
    let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
    let serialized = commit
        .serialize_deterministically_json_ad(&store)
        .await
        .unwrap();
    assert!(
        !serialized.contains("@id"),
        "deterministic serialization must not contain @id, got: {}",
        serialized
    );
}

/// Regression: renaming a resource with two sequential commits should
/// persist the SECOND name. Previously observed symptom: the client types
/// "New Drive" one character at a time, each keystroke sends a commit,
/// but only the first one sticks — the stored name remains "N".
///
/// This exercises the real `store.apply_commit` path (not just
/// `apply_changes`) so persistence + rehydration are part of the test.
#[tokio::test]
async fn two_sequential_commits_both_land() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/rename_target";

    // Commit 1: create resource with name="N"
    let client_doc = crate::loro::AtomicLoroDoc::new();
    client_doc
        .set_property(crate::urls::NAME, &Value::String("N".into()))
        .unwrap();
    client_doc
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    client_doc
        .set_property(crate::urls::SHORTNAME, &Value::String("n".into()))
        .unwrap();
    client_doc
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(client_doc.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &OPTS).await.unwrap();

    let after_first = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after_first.get(crate::urls::NAME).unwrap().to_string(),
        "N",
        "commit 1 should set name to N"
    );

    // Commit 2: rename to "Ne" — same Loro doc (incremental), so the
    // exported snapshot represents one op of the same peer ID.
    client_doc
        .set_property(crate::urls::NAME, &Value::String("Ne".into()))
        .unwrap();
    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(client_doc.export_snapshot());
    // previousCommit is optional audit metadata; the TS client still
    // sets it, but sign() does not auto-fill a causal chain.
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
    store.apply_commit(commit2, &OPTS).await.unwrap();

    let after_second = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
            after_second.get(crate::urls::NAME).unwrap().to_string(),
            "Ne",
            "commit 2 should rename name to Ne — if this fails, sequential commits aren't merging properly"
        );
}

#[tokio::test]
async fn body_merge_with_restored_properties_passes_causality_guard() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/body_merge_guard";
    let opts = CommitOpts {
        validate_schema: false,
        validate_constraints: false,
        validate_signature: true,
        validate_timestamp: false,
        validate_loro_causality: true,
        validate_rights: false,
        validate_for_agent: None,
        update_index: true,
        source_id: None,
    };
    let original = crate::loro::AtomicLoroDoc::new();
    original
        .set_property(crate::urls::NAME, &Value::String("Original".into()))
        .unwrap();
    original
        .doc()
        .get_map("doc")
        .insert("intro", "Original body")
        .unwrap();
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(original.export_snapshot());
    let first = builder
        .sign(&agent, &store, &Resource::new(subject.into()))
        .await
        .unwrap();
    store.apply_commit(first, &opts).await.unwrap();
    let stored = store.get_resource(&subject.into()).await.unwrap();
    let original = stored.build_state_doc().unwrap();
    let fork = crate::loro::AtomicLoroDoc::new();
    fork.import_update(&original.export_snapshot()).unwrap();
    let before = original.oplog_vv();
    fork.set_property(crate::urls::NAME, &Value::String("Fork".into()))
        .unwrap();
    fork.set_property(
        "https://atomicdata.dev/properties/originalSubject",
        &Value::String(subject.into()),
    )
    .unwrap();
    fork.doc()
        .get_map("doc")
        .insert("added", "Fork body edit")
        .unwrap();
    original.import_update(&fork.export_snapshot()).unwrap();
    original
        .set_property(crate::urls::NAME, &Value::String("Original".into()))
        .unwrap();
    original
        .remove_property("https://atomicdata.dev/properties/originalSubject")
        .unwrap();
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(original.export_updates_since(&before));
    let merged = builder.sign(&agent, &store, &stored).await.unwrap();
    store
        .apply_commit(merged, &opts)
        .await
        .expect("body changes are not a lost property write");
    let after = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after.get(crate::urls::NAME).unwrap().to_string(),
        "Original"
    );
    assert_eq!(
        after
            .build_state_doc()
            .unwrap()
            .doc()
            .get_map("doc")
            .get("added")
            .unwrap()
            .get_deep_value(),
        loro::LoroValue::from("Fork body edit")
    );
}

/// Re-applying a commit the server has already applied must be accepted
/// as an idempotent replay — NOT rejected as a silent LWW loss. The
/// browser outbox relies on this when it retransmits a commit. The
/// causality guard distinguishes "ops already in the oplog" (accept)
/// from "new ops that lost LWW" (reject).
#[tokio::test]
async fn idempotent_commit_replay_is_accepted() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/idempotent_replay_target";

    // Causality guard ON, previous-commit check OFF — matches the real
    // `/commit` apply path (a replay legitimately carries a stale
    // `previousCommit`, so that check is not the gate under test).
    let opts = CommitOpts {
        validate_schema: true,
        validate_constraints: true,
        validate_signature: true,
        validate_timestamp: false,
        validate_loro_causality: true,
        validate_rights: false,
        validate_for_agent: None,
        update_index: true,
        source_id: None,
    };

    // Commit 1: create the resource.
    let client_doc = crate::loro::AtomicLoroDoc::new();
    client_doc
        .set_property(crate::urls::NAME, &Value::String("Original".into()))
        .unwrap();
    client_doc
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    client_doc
        .set_property(crate::urls::SHORTNAME, &Value::String("orig".into()))
        .unwrap();
    client_doc
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();
    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(client_doc.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &opts).await.unwrap();

    // Commit 2: a rename.
    let after_first = store.get_resource(&subject.into()).await.unwrap();
    client_doc
        .set_property(crate::urls::NAME, &Value::String("Renamed".into()))
        .unwrap();
    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(client_doc.export_snapshot());
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();

    // Apply commit 2, then RE-APPLY the identical commit. Its ops are
    // already in the resource's oplog, so the second apply must be
    // accepted (idempotent replay), not rejected.
    store.apply_commit(commit2.clone(), &opts).await.unwrap();
    store
        .apply_commit(commit2, &opts)
        .await
        .expect("idempotent replay of an already-applied commit must be accepted");

    let after = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after.get(crate::urls::NAME).unwrap().to_string(),
        "Renamed",
        "state must be unchanged by the idempotent replay",
    );
}

/// Class `constraints` are enforced on commits, a bad map is refused when
/// the Class is written, and a peer-style apply (`validate_constraints`
/// off) keeps what another node already accepted.
#[tokio::test]
async fn class_constraints_are_enforced_on_commits() {
    let (store, agent) = store_with_known_agent().await;
    let opts = CommitOpts {
        validate_schema: true,
        validate_constraints: true,
        validate_signature: true,
        validate_timestamp: false,
        validate_loro_causality: false,
        validate_rights: false,
        validate_for_agent: None,
        update_index: true,
        source_id: None,
    };
    let class_subject = "https://localhost/constrained_class";

    async fn commit_doc(
        store: &crate::Store,
        agent: &crate::agents::Agent,
        subject: &str,
        props: &[(&str, Value)],
        opts: &CommitOpts,
    ) -> AtomicResult<()> {
        let doc = crate::loro::AtomicLoroDoc::new();
        for (prop, value) in props {
            doc.set_property(prop, value)?;
        }
        let mut builder = CommitBuilder::new(subject.into());
        builder.set_loro_update(doc.export_snapshot());
        let commit = builder
            .sign(agent, store, &Resource::new(subject.into()))
            .await?;
        store.apply_commit(commit, opts).await.map(|_| ())
    }

    let class_props = |constraints: serde_json::Value| {
        vec![
            (
                crate::urls::IS_A,
                Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
            ),
            (crate::urls::SHORTNAME, Value::String("constrained".into())),
            (crate::urls::DESCRIPTION, Value::String("desc".into())),
            (crate::urls::CONSTRAINTS, Value::Json(constraints)),
        ]
    };

    let bad = commit_doc(
        &store,
        &agent,
        "https://localhost/bad_class",
        &class_props(serde_json::json!({ crate::urls::NAME: { "minimun": 1 } })),
        &opts,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(bad.contains("Unknown constraint keyword"), "{bad}");

    commit_doc(
        &store,
        &agent,
        class_subject,
        &class_props(serde_json::json!({ crate::urls::NAME: { "maxLength": 3 } })),
        &opts,
    )
    .await
    .unwrap();

    let instance = |name: &str| {
        vec![
            (
                crate::urls::IS_A,
                Value::ResourceArray(vec![class_subject.to_string().into()]),
            ),
            (crate::urls::NAME, Value::String(name.into())),
        ]
    };

    commit_doc(
        &store,
        &agent,
        "https://localhost/ok_inst",
        &instance("abc"),
        &opts,
    )
    .await
    .unwrap();

    let err = commit_doc(
        &store,
        &agent,
        "https://localhost/long_inst",
        &instance("abcd"),
        &opts,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("Value for name breaks maxLength on class constrained:"),
        "{err}"
    );

    let peer_opts = CommitOpts {
        validate_constraints: false,
        ..opts.clone()
    };
    commit_doc(
        &store,
        &agent,
        "https://localhost/peer_inst",
        &instance("abcd"),
        &peer_opts,
    )
    .await
    .unwrap();
}

/// A commit whose Loro delta depends on ops the server never received
/// must be REJECTED — not silently accepted as an "idempotent replay".
/// Loro parks such ops as pending (VV doesn't advance, diff is empty),
/// which without an explicit guard is indistinguishable from a replay:
/// the server ACKs, the client advances its save cursor, and the missing
/// edit is permanently lost on both sides. Regression test for a real
/// incident where a form's `form-pages` update vanished this way.
#[tokio::test]
async fn commit_with_pending_loro_deps_is_rejected() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/pending_deps_target";

    let opts = CommitOpts {
        validate_schema: true,
        validate_constraints: true,
        validate_signature: true,
        validate_timestamp: false,
        validate_loro_causality: true,
        validate_rights: false,
        validate_for_agent: None,
        update_index: true,
        source_id: None,
    };

    // Commit 1: create the resource from a full snapshot.
    let client_doc = crate::loro::AtomicLoroDoc::new();
    client_doc
        .set_property(crate::urls::NAME, &Value::String("Original".into()))
        .unwrap();
    client_doc
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    client_doc
        .set_property(crate::urls::SHORTNAME, &Value::String("orig".into()))
        .unwrap();
    client_doc
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();
    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(client_doc.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &opts).await.unwrap();
    let after_first = store.get_resource(&subject.into()).await.unwrap();
    let vv_synced = client_doc.oplog_vv();

    // Edit A: never reaches the server (its commit was lost in transit).
    client_doc
        .set_property(
            crate::urls::DESCRIPTION,
            &Value::String("the lost edit".into()),
        )
        .unwrap();
    client_doc.commit_with_message("edit A");
    let vv_after_lost_edit = client_doc.oplog_vv();

    // Edit B: exported as a delta that starts AFTER edit A, so its ops
    // causally depend on ops the server never got.
    client_doc
        .set_property(crate::urls::NAME, &Value::String("Renamed".into()))
        .unwrap();
    client_doc.commit_with_message("edit B");
    let orphan_delta = client_doc.export_updates_since(&vv_after_lost_edit);

    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(orphan_delta);
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
    let err = store
        .apply_commit(commit2, &opts)
        .await
        .expect_err("a delta depending on ops the server never received must be rejected");
    assert!(
        err.to_string().contains("pending"),
        "rejection should name the pending import, got: {err}"
    );

    let after = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after.get(crate::urls::NAME).unwrap().to_string(),
        "Original",
        "the orphaned delta must not have changed stored state"
    );

    // Recovery: re-sending the FULL missing range (everything since the
    // last acked version) is accepted and lands both edits.
    let full_delta = client_doc.export_updates_since(&vv_synced);
    let mut builder3 = CommitBuilder::new(subject.into());
    builder3.set_loro_update(full_delta);
    let commit3 = builder3.sign(&agent, &store, &after_first).await.unwrap();
    store
        .apply_commit(commit3, &opts)
        .await
        .expect("re-sending the full range must be accepted");
    let recovered = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        recovered.get(crate::urls::NAME).unwrap().to_string(),
        "Renamed"
    );
    assert_eq!(
        recovered.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "the lost edit"
    );
}

/// Same as above but each commit comes from a FRESH Loro doc seeded from
/// the server's previous snapshot — simulates a client that rebuilds its
/// Loro state between commits (or a peer that joins mid-session).
#[tokio::test]
async fn two_commits_with_fresh_doc_per_commit_both_land() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/rename_fresh_doc";

    // Commit 1: name="N" from a fresh doc.
    let doc1 = crate::loro::AtomicLoroDoc::new();
    doc1.set_property(crate::urls::NAME, &Value::String("N".into()))
        .unwrap();
    doc1.set_property(
        crate::urls::IS_A,
        &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
    )
    .unwrap();
    doc1.set_property(crate::urls::SHORTNAME, &Value::String("n".into()))
        .unwrap();
    doc1.set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(doc1.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &OPTS).await.unwrap();

    let after_first = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(after_first.get(crate::urls::NAME).unwrap().to_string(), "N");

    // Commit 2: client rebuilds Loro doc from the server's stored state,
    // then mutates. This models "fresh doc per commit" client behaviour.
    let stored_snapshot = match after_first.get(crate::urls::LORO_UPDATE).unwrap() {
        Value::LoroDoc(b) => b.clone(),
        other => panic!("expected LoroDoc, got {:?}", other),
    };
    let doc2 = crate::loro::AtomicLoroDoc::from_snapshot(&stored_snapshot).unwrap();
    doc2.set_property(crate::urls::NAME, &Value::String("Ne".into()))
        .unwrap();

    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(doc2.export_snapshot());
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
    store.apply_commit(commit2, &OPTS).await.unwrap();

    let after_second = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after_second.get(crate::urls::NAME).unwrap().to_string(),
        "Ne",
        "fresh-doc-per-commit should still land the second rename"
    );
}

/// A client that booted from the stored state and then lost a race to
/// another peer branching off the same version is not a client that failed
/// to seed. Its write is gone, and that is last-writer-wins doing its job,
/// so the commit stands. Refusing it is what turned this into a retry loop
/// in the field: the client can only resend the same bytes, which lose
/// again.
///
/// Both contenders branch from the same stored version, so their `name`
/// ops carry the same lamport and the peer ID decides. Pinned so the
/// client is the one that loses.
#[tokio::test]
async fn a_concurrent_loss_by_a_seeded_client_is_accepted() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/seeded_concurrent_loss";

    let first = crate::loro::AtomicLoroDoc::new();
    first.set_peer_id(u64::MAX - 1).unwrap();
    first
        .set_property(crate::urls::NAME, &Value::String("first".into()))
        .unwrap();
    first
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    first
        .set_property(crate::urls::SHORTNAME, &Value::String("first".into()))
        .unwrap();
    first
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(first.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &OPTS).await.unwrap();

    // The client boots from what the server stored, writes, and holds the
    // bytes while someone else gets there first.
    let stored = store.get_resource(&subject.into()).await.unwrap();
    let client = stored.build_state_doc().unwrap();
    client.set_peer_id(1).unwrap();
    client
        .set_property(crate::urls::NAME, &Value::String("from the client".into()))
        .unwrap();
    let client_update = client.export_snapshot();

    // A second peer branches from the same stored version and wins the
    // tiebreak on peer ID.
    let other = stored.build_state_doc().unwrap();
    other.set_peer_id(u64::MAX - 2).unwrap();
    other
        .set_property(crate::urls::NAME, &Value::String("from the peer".into()))
        .unwrap();
    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(other.export_snapshot());
    let commit2 = builder2.sign(&agent, &store, &stored).await.unwrap();
    store.apply_commit(commit2, &OPTS).await.unwrap();

    let after_peer = store.get_resource(&subject.into()).await.unwrap();
    let mut builder3 = CommitBuilder::new(subject.into());
    builder3.set_loro_update(client_update);
    let commit3 = builder3.sign(&agent, &store, &after_peer).await.unwrap();
    store
        .apply_commit(commit3, &OPTS)
        .await
        .expect("a client that holds the stored history may lose a race");

    assert_eq!(
        store
            .get_resource(&subject.into())
            .await
            .unwrap()
            .get(crate::urls::NAME)
            .unwrap()
            .to_string(),
        "from the peer",
        "the write that won LWW is the one that stands"
    );
}

/// The same loss from a doc that never read the resource stays a
/// rejection. Nothing here shares a peer with the stored state, so the
/// client's writes did not lose a race, they vanished.
#[tokio::test]
async fn a_loss_by_a_client_that_never_saw_the_stored_state_is_rejected() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/unseeded_loss";

    let stored_doc = crate::loro::AtomicLoroDoc::new();
    stored_doc.set_peer_id(u64::MAX - 1).unwrap();
    stored_doc
        .set_property(crate::urls::NAME, &Value::String("A".into()))
        .unwrap();
    stored_doc
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    stored_doc
        .set_property(crate::urls::SHORTNAME, &Value::String("a".into()))
        .unwrap();
    stored_doc
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(stored_doc.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &OPTS).await.unwrap();

    let fresh = crate::loro::AtomicLoroDoc::new();
    fresh.set_peer_id(1).unwrap();
    fresh
        .set_property(crate::urls::NAME, &Value::String("B".into()))
        .unwrap();
    fresh
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    fresh
        .set_property(crate::urls::SHORTNAME, &Value::String("b".into()))
        .unwrap();
    fresh
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let after_first = store.get_resource(&subject.into()).await.unwrap();
    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(fresh.export_snapshot());
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
    let error = store
        .apply_commit(commit2, &OPTS)
        .await
        .expect_err("an unseeded doc losing every write is still a rejection")
        .to_string();

    assert!(
        error.contains("Commit's Loro update produced no state changes"),
        "the rejection keeps the message the client and `classify_commit_error` match on: {error}"
    );
    assert!(
        error.contains(crate::urls::NAME) && error.contains("sent") && error.contains("stored"),
        "the rejection names the write that was dropped and both sides of it: {error}"
    );
}

/// Two commits where each commit comes from a FRESH Loro doc with a
/// different peer ID, NOT seeded from the server's state. Writes to the
/// same key are concurrent — Loro's LWW tiebreak by peer ID decides which
/// one wins. We pin the peer IDs so docA always wins LWW: docB's writes
/// are guaranteed to be silently dropped against the merged state, which
/// is exactly the case the causality guard exists to catch.
#[tokio::test]
async fn body_changes_count_when_concurrent_properties_lose() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/concurrent_peers";

    // Commit 1: docA → name="A". Pin peer ID high so this peer wins LWW
    // tiebreaks against docB.
    let doc_a = crate::loro::AtomicLoroDoc::new();
    doc_a.set_peer_id(u64::MAX - 1).unwrap();
    doc_a
        .set_property(crate::urls::NAME, &Value::String("A".into()))
        .unwrap();
    doc_a
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    doc_a
        .set_property(crate::urls::SHORTNAME, &Value::String("a".into()))
        .unwrap();
    doc_a
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(doc_a.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &OPTS).await.unwrap();

    // Commit 2: docB = FRESH, NOT seeded from server. Pin peer ID low so
    // this peer always loses LWW tiebreaks against docA.
    let doc_b = crate::loro::AtomicLoroDoc::new();
    doc_b.set_peer_id(1).unwrap();
    doc_b
        .set_property(crate::urls::NAME, &Value::String("B".into()))
        .unwrap();
    doc_b
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    doc_b
        .set_property(crate::urls::SHORTNAME, &Value::String("b".into()))
        .unwrap();
    doc_b
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    doc_b
        .doc()
        .get_map("doc")
        .insert("added", "Body edit")
        .unwrap();
    let after_first = store.get_resource(&subject.into()).await.unwrap();
    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(doc_b.export_snapshot());
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
    store
        .apply_commit(commit2, &OPTS)
        .await
        .expect("a body edit is a state change");

    let after_second = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after_second.get(crate::urls::NAME).unwrap().to_string(),
        "A",
        "stored name should still be `A` since commit 2 was rejected"
    );
    assert_eq!(
        after_second
            .build_state_doc()
            .unwrap()
            .doc()
            .get_map("doc")
            .get("added")
            .unwrap()
            .get_deep_value(),
        loro::LoroValue::from("Body edit")
    );
}

#[tokio::test]
async fn two_commits_with_independent_docs_both_peers_same_key() {
    let (store, agent) = store_with_known_agent().await;
    let subject = "https://localhost/concurrent_peers";

    // Commit 1: docA → name="A". Pin peer ID high so this peer wins LWW
    // tiebreaks against docB.
    let doc_a = crate::loro::AtomicLoroDoc::new();
    doc_a.set_peer_id(u64::MAX - 1).unwrap();
    doc_a
        .set_property(crate::urls::NAME, &Value::String("A".into()))
        .unwrap();
    doc_a
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    doc_a
        .set_property(crate::urls::SHORTNAME, &Value::String("a".into()))
        .unwrap();
    doc_a
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let empty = Resource::new(subject.into());
    let mut builder = CommitBuilder::new(subject.into());
    builder.set_loro_update(doc_a.export_snapshot());
    let commit1 = builder.sign(&agent, &store, &empty).await.unwrap();
    store.apply_commit(commit1, &OPTS).await.unwrap();

    // Commit 2: docB = FRESH, NOT seeded from server. Pin peer ID low so
    // this peer always loses LWW tiebreaks against docA.
    let doc_b = crate::loro::AtomicLoroDoc::new();
    doc_b.set_peer_id(1).unwrap();
    doc_b
        .set_property(crate::urls::NAME, &Value::String("B".into()))
        .unwrap();
    doc_b
        .set_property(
            crate::urls::IS_A,
            &Value::ResourceArray(vec![crate::urls::CLASS.to_string().into()]),
        )
        .unwrap();
    doc_b
        .set_property(crate::urls::SHORTNAME, &Value::String("b".into()))
        .unwrap();
    doc_b
        .set_property(crate::urls::DESCRIPTION, &Value::String("desc".into()))
        .unwrap();

    let after_first = store.get_resource(&subject.into()).await.unwrap();
    let mut builder2 = CommitBuilder::new(subject.into());
    builder2.set_loro_update(doc_b.export_snapshot());
    let commit2 = builder2.sign(&agent, &store, &after_first).await.unwrap();
    let err = store.apply_commit(commit2, &OPTS).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("silently dropped"),
        "expected silent-drop error from causality guard, got: {msg}"
    );

    // Stored state is unchanged; commit 2 was rejected.
    let after_second = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(
        after_second.get(crate::urls::NAME).unwrap().to_string(),
        "A",
        "stored name should still be `A` since commit 2 was rejected"
    );
}

#[tokio::test]
async fn deserialize_from_json() {
    let json = r#"
        {
            "subject": "https://localhost/test",
            "loro_update": "bG9ybw==",
            "destroy": false
        }
        "#;

    let commit_builder_json: CommitBuilderJSON = serde_json::from_str(json).unwrap();
    let commit_builder = CommitBuilder::from_commit_builder_json(commit_builder_json).unwrap();

    assert_eq!(commit_builder.subject, "https://localhost/test");
    assert!(commit_builder.loro_update.is_some());
    assert!(!commit_builder.destroy);
}
