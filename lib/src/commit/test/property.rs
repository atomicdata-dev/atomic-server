use super::*;

// --- Content-addressed Property IDs (`atomic:prop:{hash}`) ---

/// Genesis commit for a property whose subject is `id`, with the given fields.
async fn property_genesis(
    store: &Store,
    signer: &Agent,
    id: &str,
    parent: Option<&str>,
    shortname: Option<&str>,
    datatype: Option<&str>,
) -> Commit {
    let mut b = CommitBuilder::new(id.into());
    b.is_genesis = true;
    if let Some(parent) = parent {
        b.set(urls::PARENT.into(), Value::AtomicUrl(parent.into()));
    }
    if let Some(shortname) = shortname {
        b.set(urls::SHORTNAME.into(), Value::Slug(shortname.into()));
    }
    if let Some(datatype) = datatype {
        b.set(
            urls::DATATYPE_PROP.into(),
            Value::AtomicUrl(datatype.into()),
        );
    }
    b.set(urls::DESCRIPTION.into(), Value::Markdown("first".into()));
    b.sign(signer, store, &Resource::new(id.into()))
        .await
        .unwrap()
}

/// Non-genesis commit on an existing property.
async fn property_edit(
    store: &Store,
    signer: &Agent,
    id: &str,
    edit: impl FnOnce(&mut CommitBuilder),
) -> Commit {
    let mut b = CommitBuilder::new(id.into());
    edit(&mut b);
    let existing = store.get_resource(&id.into()).await.unwrap();
    b.sign(signer, store, &existing).await.unwrap()
}

#[tokio::test]
async fn property_genesis_with_matching_hash_is_created() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    let c = property_genesis(
        &store,
        &owner,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store
        .apply_commit(c, &rights_opts())
        .await
        .expect("a property with a correct ID is valid");
    let prop = store.get_property(&id).await.unwrap();
    assert_eq!(prop.shortname, "colour");
    assert_eq!(prop.subject, id);
    let res = store.get_resource(&id.as_str().into()).await.unwrap();
    // No cert: creation metadata degrades to the oplog fallback.
    assert!(res.genesis_signer().is_none());
    assert!(res.get(urls::GENESIS).is_err());
}

#[tokio::test]
async fn property_genesis_with_wrong_hash_is_rejected() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let old_id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    let c = property_genesis(
        &store,
        &owner,
        &old_id,
        Some(&drive),
        Some("color"),
        Some(urls::STRING),
    )
    .await;
    let err = store.apply_commit(c, &rights_opts()).await.unwrap_err();
    assert!(err.to_string().contains("Property ID mismatch"), "{err}");
    assert!(store.get_resource(&old_id.as_str().into()).await.is_err());
}

#[tokio::test]
async fn property_genesis_needs_parent_shortname_and_datatype() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    for (parent, shortname, datatype, missing) in [
        (None, Some("colour"), Some(urls::STRING), "parent"),
        (Some(drive.as_str()), None, Some(urls::STRING), "shortname"),
        (Some(drive.as_str()), Some("colour"), None, "datatype"),
    ] {
        let c = property_genesis(&store, &owner, &id, parent, shortname, datatype).await;
        let err = store.apply_commit(c, &rights_opts()).await.unwrap_err();
        assert!(err.to_string().contains(&format!("no {missing}")), "{err}");
    }
    assert!(store.get_resource(&id.as_str().into()).await.is_err());
}

#[tokio::test]
async fn property_genesis_needs_append_rights_on_parent() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    let stranger = Agent::new(Some("stranger")).unwrap();
    let c = property_genesis(
        &store,
        &stranger,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store
        .apply_commit(c, &rights_opts())
        .await
        .expect_err("a stranger cannot append to the drive");
    // And a parentless property can never use the parentless-DID shortcut.
    let parentless =
        crate::property_identity::property_id("atomic:x", "colour", urls::STRING).unwrap();
    let c = property_genesis(
        &store,
        &owner,
        &parentless,
        None,
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store.apply_commit(c, &rights_opts()).await.unwrap_err();
}

#[tokio::test]
async fn repeat_property_genesis_merges_with_append_rights_only() {
    let (store, owner) = store_with_known_agent().await;
    let appender = Agent::new(Some("appender")).unwrap();
    let stranger = Agent::new(Some("stranger")).unwrap();
    let mut b = CommitBuilder::new("placeholder".into());
    b.set(
        urls::IS_A.into(),
        Value::from(vec![urls::DRIVE.to_string()]),
    );
    b.set(
        urls::WRITE.into(),
        Value::from(vec![owner.subject.to_string()]),
    );
    b.set(
        urls::APPEND.into(),
        Value::from(vec![appender.subject.to_string()]),
    );
    let drive = store
        .apply_commit(
            Commit::create_did(b, &owner, &store).await.unwrap(),
            &rights_opts(),
        )
        .await
        .unwrap()
        .resource_new
        .unwrap()
        .get_subject()
        .to_string();
    let id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    let first = property_genesis(
        &store,
        &owner,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store.apply_commit(first, &rights_opts()).await.unwrap();

    let by_stranger = property_genesis(
        &store,
        &stranger,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store
        .apply_commit(by_stranger, &rights_opts())
        .await
        .expect_err("a repeat genesis still needs rights");

    let by_appender = property_genesis(
        &store,
        &appender,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store
        .apply_commit(by_appender, &rights_opts())
        .await
        .expect("the same property minted by another device merges");
    assert_eq!(store.get_property(&id).await.unwrap().shortname, "colour");
}

#[tokio::test]
async fn property_identity_fields_are_immutable() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let other_drive = owned_drive(&store, &owner).await;
    let id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    let c = property_genesis(
        &store,
        &owner,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store.apply_commit(c, &rights_opts()).await.unwrap();

    let c = property_edit(&store, &owner, &id, |b| {
        b.set(urls::SHORTNAME.into(), Value::Slug("color".into()))
    })
    .await;
    let err = store.apply_commit(c, &rights_opts()).await.unwrap_err();
    assert!(err.to_string().contains("shortname"), "{err}");
    assert!(err.to_string().contains("identity cannot change"), "{err}");

    let c = property_edit(&store, &owner, &id, |b| {
        b.set(
            urls::DATATYPE_PROP.into(),
            Value::AtomicUrl(urls::INTEGER.into()),
        )
    })
    .await;
    let err = store.apply_commit(c, &rights_opts()).await.unwrap_err();
    assert!(err.to_string().contains("datatype"), "{err}");

    let c = property_edit(&store, &owner, &id, |b| {
        b.set(
            urls::PARENT.into(),
            Value::AtomicUrl(other_drive.as_str().into()),
        )
    })
    .await;
    let err = store.apply_commit(c, &rights_opts()).await.unwrap_err();
    assert!(err.to_string().contains("parent"), "{err}");

    let c = property_edit(&store, &owner, &id, |b| b.remove(urls::SHORTNAME.into())).await;
    store.apply_commit(c, &rights_opts()).await.unwrap_err();

    let c = property_edit(&store, &owner, &id, |b| {
        b.set(urls::DESCRIPTION.into(), Value::Markdown("changed".into()))
    })
    .await;
    store
        .apply_commit(c, &rights_opts())
        .await
        .expect("a description is not part of the identity");
    let prop = store.get_property(&id).await.unwrap();
    assert_eq!(prop.shortname, "colour");
    assert_eq!(prop.description, "changed");
}

#[tokio::test]
async fn resource_stores_value_under_property_id_key() {
    let (store, owner) = store_with_known_agent().await;
    let drive = owned_drive(&store, &owner).await;
    let id = crate::property_identity::property_id(&drive, "colour", urls::STRING).unwrap();
    let c = property_genesis(
        &store,
        &owner,
        &id,
        Some(&drive),
        Some("colour"),
        Some(urls::STRING),
    )
    .await;
    store.apply_commit(c, &rights_opts()).await.unwrap();

    let mut b = CommitBuilder::new("placeholder".into());
    b.set(urls::PARENT.into(), Value::AtomicUrl(drive.as_str().into()));
    b.set(id.clone(), Value::String("red".into()));
    let c = Commit::create_did(b, &owner, &store).await.unwrap();
    let subject = c.subject.clone();
    store.apply_commit(c, &rights_opts()).await.unwrap();

    let res = store.get_resource(&subject).await.unwrap();
    assert_eq!(res.get(&id).unwrap().to_string(), "red");
    let found = res
        .resolve_shortname_to_property(&id, &store)
        .await
        .unwrap();
    assert_eq!(found.shortname, "colour");
}
