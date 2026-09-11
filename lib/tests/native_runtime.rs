//! Core startup must work without a server crate, HTTP origin, or Actix runtime.
#![cfg(all(feature = "db-redb", feature = "config", not(target_arch = "wasm32")))]

use atomic_lib::{runtime::AtomicNode, urls, Resource, Storelike, Value};

#[tokio::test]
async fn originless_node_preserves_identity_and_data_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let blobs = dir.path().join("blobs");
    let identity = dir.path().join("config.toml");
    let node = AtomicNode::open_local(&data, &blobs, None).await.unwrap();
    node.load_or_create_agent(&identity, "Native user")
        .await
        .unwrap();
    let agent = node.agent().unwrap().subject;
    assert_eq!(node.db().get_base_domain(), None);
    let flush = node.start_durable_flush().unwrap();
    let drive = node.db().create_drive("Local drive").await.unwrap();
    let mut draft = Resource::new("did:ad:placeholder".into());
    draft
        .set_unsafe(urls::NAME.into(), Value::String("Without a server".into()))
        .unwrap();
    draft
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    let saved = draft.save_as_genesis(node.db()).await.unwrap();
    let subject = saved.commit.subject;
    drop(node);
    drop(flush);

    let reopened = AtomicNode::open_local(&data, &blobs, None).await.unwrap();
    reopened
        .load_or_create_agent(&identity, "Another label")
        .await
        .unwrap();
    assert_eq!(reopened.agent().unwrap().subject, agent);
    assert_eq!(
        reopened
            .db()
            .get_resource(&subject)
            .await
            .unwrap()
            .get(urls::NAME)
            .unwrap()
            .to_string(),
        "Without a server"
    );
}

#[tokio::test]
async fn invalid_identity_config_is_not_replaced_with_a_new_identity() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("config.toml");
    let invalid = "a damaged existing identity file";
    std::fs::write(&identity, invalid).unwrap();
    let node = AtomicNode::open_local(&dir.path().join("data"), &dir.path().join("blobs"), None)
        .await
        .unwrap();
    assert!(node
        .load_or_create_agent(&identity, "Native user")
        .await
        .is_err());
    assert!(node.agent().is_none());
    assert_eq!(std::fs::read_to_string(identity).unwrap(), invalid);
}

#[tokio::test]
async fn existing_identity_can_bootstrap_a_replacement_database() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("config.toml");
    let first = AtomicNode::open_local(&dir.path().join("first"), &dir.path().join("blobs"), None)
        .await
        .unwrap();
    first
        .load_or_create_agent(&identity, "Original")
        .await
        .unwrap();
    let mut original = first.agent().unwrap();
    original.initial_drive = Some(
        first
            .db()
            .create_drive("Remembered drive")
            .await
            .unwrap()
            .into(),
    );
    let mut persisted = atomic_lib::config::read_config(Some(&identity)).unwrap();
    persisted.shared.agent_secret = original.build_secret().unwrap();
    persisted.shared.initial_drive = original.initial_drive.as_ref().map(ToString::to_string);
    persisted.save(&identity).unwrap();
    let saved_config = std::fs::read(&identity).unwrap();
    let replacement = AtomicNode::open_local(
        &dir.path().join("replacement"),
        &dir.path().join("blobs"),
        None,
    )
    .await
    .unwrap();
    replacement
        .load_or_create_agent(&identity, "Restored")
        .await
        .unwrap();
    let restored = replacement.agent().unwrap();
    assert_eq!(restored.subject, original.subject);
    assert_eq!(restored.public_key, original.public_key);
    assert_eq!(restored.initial_drive, original.initial_drive);
    assert!(replacement
        .db()
        .get_resource(&restored.subject)
        .await
        .is_ok());
    assert_eq!(std::fs::read(identity).unwrap(), saved_config);
}

#[tokio::test]
async fn legacy_identity_migrates_to_did_without_changing_key_or_client_config() {
    use atomic_lib::{
        agents::Agent,
        config::{ClientConfig, Config, SharedConfig},
    };
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("config.toml");
    let original = Agent::new(Some("Legacy")).unwrap();
    // Write the actual historical wire form, rather than serializing an
    // Agent that may already normalize the subject during construction.
    let legacy_secret = atomic_lib::agents::encode_base64(
        &serde_json::to_vec(&serde_json::json!({
            "privateKey": original.private_key.as_ref().unwrap(),
            "subject": format!("https://atomicdata.dev/agents/{}", original.public_key),
        }))
        .unwrap(),
    );
    Config {
        shared: SharedConfig {
            agent_secret: legacy_secret,
            initial_drive: None,
        },
        client: Some(ClientConfig {
            server_url: "https://example.test".into(),
        }),
    }
    .save(&identity)
    .unwrap();
    let node = AtomicNode::open_local(&dir.path().join("data"), &dir.path().join("blobs"), None)
        .await
        .unwrap();
    node.load_or_create_agent(&identity, "Migrated")
        .await
        .unwrap();
    let migrated = node.agent().unwrap();
    assert_eq!(migrated.subject, original.subject);
    assert_eq!(migrated.public_key, original.public_key);
    let config = atomic_lib::config::read_config(Some(&identity)).unwrap();
    assert_eq!(config.client.unwrap().server_url, "https://example.test");
    assert_eq!(
        Agent::from_secret(&config.shared.agent_secret)
            .unwrap()
            .subject,
        original.subject
    );
}
