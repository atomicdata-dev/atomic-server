use super::*;
use crate::commit::builder::sign_at;

#[tokio::test]
async fn agent_and_commit() {
    let store = Store::init().await.unwrap();
    store.set_base_url("http://localhost:9883");
    store.populate().await.unwrap();
    let agent = store.create_agent(Some("test_actor")).await.unwrap();
    let subject = "https://localhost/new_thing";
    let resource = Resource::new(subject.into());
    let mut commitbuiler = crate::commit::CommitBuilder::new(subject.into());
    let property1 = crate::urls::DESCRIPTION;
    let value1 = Value::new("Some value", &DataType::Markdown).unwrap();
    commitbuiler.set(property1.into(), value1.clone());
    let property2 = crate::urls::SHORTNAME;
    let value2 = Value::new("someval", &DataType::Slug).unwrap();
    commitbuiler.set(property2.into(), value2);
    let commit = commitbuiler.sign(&agent, &store, &resource).await.unwrap();
    let _created_resource = store.apply_commit(commit, &OPTS).await.unwrap();

    let resource = store.get_resource(&subject.into()).await.unwrap();
    assert!(resource.get(property1).unwrap().to_string() == value1.to_string());
}

#[tokio::test]
async fn serialize_commit() {
    let store = Store::init().await.unwrap();
    store.set_base_url("http://localhost:9883");
    store.populate().await.unwrap();
    // Build a Loro update with some properties
    let doc = crate::loro::AtomicLoroDoc::new();
    doc.set_property(urls::SHORTNAME, &Value::String("shortname".into()))
        .unwrap();
    doc.set_property(urls::DESCRIPTION, &Value::String("Some description".into()))
        .unwrap();
    let loro_update = doc.export_snapshot();

    let commit = Commit {
        subject: "https://localhost/test".into(),
        created_at: 1603638837,
        signer: "https://localhost/author".into(),
        loro_update: Some(loro_update),
        previous_commit: None,
        is_genesis: None,
        destroy: None,
        signature: None,
        url: None,
    };
    let serialized = commit
        .serialize_deterministically_json_ad(&store)
        .await
        .unwrap();
    // Verify deterministic: serialize twice, must match
    let serialized2 = commit
        .serialize_deterministically_json_ad(&store)
        .await
        .unwrap();
    assert_eq!(serialized, serialized2);
    // Must contain loroUpdate and core fields
    assert!(serialized.contains("loroUpdate"));
    assert!(serialized.contains("https://atomicdata.dev/properties/signer"));
}

/// Regression: `sign()` must not export a stale live Loro snapshot when the
/// commit builder still has `set` entries (e.g. gallery `folderId` moves).
#[tokio::test]
async fn sign_merges_commit_set_onto_existing_loro_snapshot() {
    let store = Store::init().await.unwrap();
    store.set_base_url("http://localhost:9883");
    store.populate().await.unwrap();
    let agent = store.create_agent(Some("folder_signer")).await.unwrap();

    const FOLDER_PROP: &str = "https://atomicdata.dev/ontology/canvas/folderId";
    let mut resource = Resource::new("https://localhost/canvas-folder-sign-test".into());
    let doc = crate::loro::AtomicLoroDoc::new();
    doc.set_property(crate::urls::NAME, &Value::String("Test canvas".into()))
        .unwrap();
    let snapshot = doc.export_snapshot();
    resource
        .set_unsafe(crate::urls::LORO_UPDATE.into(), Value::LoroDoc(snapshot))
        .unwrap();
    resource.ensure_materialized().unwrap();

    resource
        .set_unsafe(
            FOLDER_PROP.into(),
            Value::String("did:ad:folder:test".into()),
        )
        .unwrap();

    let commit = resource
        .get_commit_builder()
        .clone()
        .sign(&agent, &store, &resource)
        .await
        .unwrap();
    let update = commit
        .loro_update
        .as_ref()
        .expect("commit should carry loroUpdate");
    let merged = crate::loro::AtomicLoroDoc::from_snapshot(update).unwrap();
    let props = merged.get_all_properties();
    assert!(
        props.contains_key(FOLDER_PROP),
        "signed commit must include folderId in Loro state, keys: {:?}",
        props.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn signature_matches() {
    let store = Store::init().await.unwrap();
    store.set_base_url("http://localhost:9883");
    let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
    let agent = Agent::new_from_private_key(None, private_key).unwrap();
    assert_eq!(
        agent.subject,
        // base64url (URL_SAFE_NO_PAD): agent DIDs must be URL-safe.
        "atomic:agent:7LsjMW5gOfDdJzK_atgjQ1t20J_rw8MjVg6xwqm-h8U"
    );
    store
        .add_resource(&agent.to_resource().unwrap())
        .await
        .unwrap();
    let subject = "https://localhost/new_thing";
    let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
    let property1 = crate::urls::DESCRIPTION;
    let value1 = Value::new("Some value", &DataType::String).unwrap();
    commitbuilder.set(property1.into(), value1);
    let property2 = crate::urls::SHORTNAME;
    let value2 = Value::new("someval", &DataType::String).unwrap();
    commitbuilder.set(property2.into(), value2);
    let commit = sign_at(commitbuilder, &agent, 0, &store, None, None)
        .await
        .unwrap();
    let serialized = commit
        .serialize_deterministically_json_ad(&store)
        .await
        .unwrap();

    // Commits now use loroUpdate instead of set
    assert!(
        serialized.contains("loroUpdate"),
        "Commit should contain loroUpdate, got: {}",
        serialized
    );
    assert!(
        !serialized.contains("\"set\""),
        "Commit should not contain legacy set field"
    );
    // Verify signature is valid
    commit.validate_signature(&store).await.unwrap();
}

#[test]
fn signature_basics() {
    let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
    let public_key = "7LsjMW5gOfDdJzK/atgjQ1t20J/rw8MjVg6xwqm+h8U=";
    // base64url (URL_SAFE_NO_PAD) — `sign_message` emits this form.
    let signature_expected =
        "YtDR_xo0272LHNBQtDer4LekzdkfUANFTI0eHxZhITXnbC3j0LCqDWhr6itNvo4tFnep6DCbev5OKAHH89-TDA";
    let message = "val";
    let signature = sign_message(message, private_key, public_key).unwrap();
    assert_eq!(signature, signature_expected);
}

#[tokio::test]
async fn invalid_subjects() {
    let store = Store::init().await.unwrap();
    store.set_base_url("http://localhost:9883");
    store.populate().await.unwrap();
    let agent = store.create_agent(Some("test_actor")).await.unwrap();
    let resource = Resource::new("https://localhost/test_resource".into());

    // Helper — commits now must carry a loro_update (enforced by
    // validate_and_build_response). Attach an empty-but-present Loro doc
    // so the test exercises subject validation, not Loro absence.
    let minimal_loro = || {
        let doc = crate::loro::AtomicLoroDoc::new();
        doc.export_snapshot()
    };

    // Note: "invalid URL" now parses as Subject::Internal, which is valid
    // in the in-memory Store. Subject validation is handled by the Subject type itself.
    {
        let subject = "https://localhost/?q=invalid";
        let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
        commitbuilder.set_loro_update(minimal_loro());
        let commit = commitbuilder.sign(&agent, &store, &resource).await.unwrap();
        store.apply_commit(commit, &OPTS).await.unwrap_err();
    }
    {
        let subject = "https://localhost/valid";
        let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
        commitbuilder.set_loro_update(minimal_loro());
        let commit = commitbuilder.sign(&agent, &store, &resource).await.unwrap();
        store.apply_commit(commit, &OPTS).await.unwrap();
    }
    {
        // A did:ad: subject with a subpath is structurally invalid.
        // sign() requires is_genesis=true for a new DID resource, so we
        // set that here. apply_commit then rejects the subpath as
        // "Invalid DID".
        let subject = "did:ad:cbXxQGm7UBBS5JPvl/NR/p9RJNbSMUjvA7lRYQt9lZvKZrU1FBo6Icl5uctr7i1AMZ/mElWZ3X1dApo5ifzmBg==/subpath";
        let mut commitbuilder = crate::commit::CommitBuilder::new(subject.into());
        commitbuilder.is_genesis = true;
        commitbuilder.set_loro_update(minimal_loro());
        let commit = commitbuilder.sign(&agent, &store, &resource).await.unwrap();
        let err = store.apply_commit(commit, &OPTS).await.unwrap_err();
        assert!(
            err.to_string().contains("Invalid DID"),
            "Expected Invalid DID error, got: {}",
            err
        );
    }
}
