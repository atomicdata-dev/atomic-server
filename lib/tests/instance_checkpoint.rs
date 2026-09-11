//! This test must also pass without workspace/server feature unification.
#![cfg(all(feature = "backup", feature = "config", not(target_arch = "wasm32")))]

use atomic_lib::{
    backup::{self, CheckpointOptions},
    db::trees::Tree,
    runtime::AtomicNode,
    Db,
};

#[tokio::test]
async fn checkpoint_restores_an_originless_node_without_a_server() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let config = root.path().join("config");
    std::fs::create_dir_all(&config).unwrap();
    let agent = atomic_lib::agents::Agent::new(None).unwrap();
    let identity = atomic_lib::config::Config {
        shared: atomic_lib::config::SharedConfig {
            agent_secret: agent.build_secret().unwrap(),
            initial_drive: None,
        },
        client: None,
    };
    identity.save(&config.join("config.toml")).unwrap();
    let db = Db::init_redb_file(&data.join("store"), None, &data.join("uploads"))
        .await
        .unwrap();
    db.kv
        .insert(Tree::PluginMeta, b"checkpoint-test", b"before")
        .unwrap();
    let options = CheckpointOptions {
        data_dir: data,
        config_dir: config.clone(),
        output_dir: root.path().join("backups"),
        build_revision: "standalone-test".into(),
    };
    let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = phases.clone();
    let observed_store = db.clone();
    let archive = backup::create(&db, &options, "native", move |phase| {
        // Compression must not extend the write pause.
        assert_eq!(
            observed_store.maintenance.is_paused(),
            phase == backup::Phase::Capturing
        );
        observed.lock().unwrap().push(phase);
    })
    .await
    .unwrap();
    assert_eq!(
        *phases.lock().unwrap(),
        [backup::Phase::Capturing, backup::Phase::Archiving]
    );
    db.kv
        .insert(Tree::PluginMeta, b"checkpoint-test", b"after")
        .unwrap();
    let target = root.path().join("restored");
    backup::verify(&archive).unwrap();
    backup::restore(&archive, &target).unwrap();
    assert!(backup::check_restore_activation(&target.join("data"), false).is_err());
    backup::check_restore_activation(&target.join("data"), true).unwrap();
    let restored = Db::init_redb_file(
        &target.join("data/store"),
        None,
        &target.join("data/uploads"),
    )
    .await
    .unwrap();
    assert_eq!(
        restored
            .kv
            .get(Tree::PluginMeta, b"checkpoint-test")
            .unwrap()
            .unwrap(),
        b"before"
    );
    let restored_identity =
        atomic_lib::config::read_config(Some(&target.join("config/config.toml"))).unwrap();
    let node = AtomicNode::from_db(restored);
    node.set_agent(
        atomic_lib::agents::Agent::from_secret(&restored_identity.shared.agent_secret).unwrap(),
    );
    assert_eq!(node.agent().unwrap().subject, agent.subject);
    assert_eq!(
        std::fs::read(target.join("config/config.toml")).unwrap(),
        std::fs::read(config.join("config.toml")).unwrap()
    );
}

#[test]
fn native_options_reject_overlapping_roots_before_creating_output() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let config = root.path().join("config");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let mut options = CheckpointOptions {
        data_dir: data.clone(),
        config_dir: config,
        output_dir: data.join("backups"),
        build_revision: "test".into(),
    };
    assert!(options.prepare().is_err());
    assert!(!options.output_dir.exists());
    options.output_dir = root.path().join("backups");
    options.config_dir = data;
    assert!(options.prepare().is_err());
    assert!(!options.output_dir.exists());
}
