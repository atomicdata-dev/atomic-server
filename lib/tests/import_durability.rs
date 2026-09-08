//! Import acknowledgement must survive abrupt process death, without Drop/flush.
#![cfg(feature = "db-redb")]
use atomic_lib::{urls, Db, Resource, Storelike, Value};
use std::path::Path;
const CHILD: &str = "ATOMIC_IMPORT_CRASH_DIR";
async fn open(path: &Path) -> Db {
    Db::init_redb_file(path, None, &path.join("uploads"))
        .await
        .unwrap()
}
#[test]
#[ignore = "subprocess entry; invoked by parent"]
fn child_import_then_abort() {
    let Ok(path) = std::env::var(CHILD) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = open(Path::new(&path)).await;
        let (agent, drive) = store.setup("Import crash test").await.unwrap();
        std::fs::write(
            Path::new(&path).join("test-agent"),
            agent.build_secret().unwrap(),
        )
        .unwrap();
        store.flush().unwrap(); // Setup completed before this import began.
        let mut resource = Resource::new("https://localhost/import-support".into());
        resource
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.clone().into()))
            .unwrap();
        resource
            .set_unsafe(
                urls::LOCAL_ID.into(),
                Value::String("provider:project:1".into()),
            )
            .unwrap();
        resource
            .set_unsafe(urls::NAME.into(), Value::String("Imported project".into()))
            .unwrap();
        resource.save_as_genesis(&store).await.unwrap();
        assert!(
            atomic_lib::import_identity::find_existing(
                &store,
                &drive.clone().into(),
                "provider:project:1"
            )
            .await
            .unwrap()
            .is_some(),
            "identity must be indexed before kill"
        );
        std::fs::write(
            Path::new(&path).join("ack.json"),
            serde_json::to_vec(&(drive, resource.get_subject().to_string())).unwrap(),
        )
        .unwrap();
        std::mem::forget(store); // Never let redb's destructor make this test pass.
    });
    std::process::abort();
}
#[tokio::test]
async fn acknowledged_import_survives_process_kill_and_retry_reuses_identity() {
    let temp = std::env::temp_dir().join(format!(
        "atomic-import-crash-{}",
        atomic_lib::utils::random_string(12)
    ));
    std::fs::create_dir_all(&temp).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "child_import_then_abort",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(CHILD, &temp)
        .output()
        .unwrap();
    assert!(!output.status.success(), "child must terminate abnormally");
    let ack = std::fs::read(temp.join("ack.json")).unwrap_or_else(|e| {
        panic!(
            "child did not reach acknowledgement: {e}; {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    let (drive, subject): (String, String) = serde_json::from_slice(&ack).unwrap();
    let store = open(&temp).await;
    let found = atomic_lib::import_identity::find_existing(
        &store,
        &drive.clone().into(),
        "provider:project:1",
    )
    .await
    .unwrap();
    assert_eq!(
        found.as_deref(),
        Some(subject.as_str()),
        "acknowledged record/identity rolled back on process death"
    );

    store.set_default_agent(
        atomic_lib::agents::Agent::from_secret(
            &std::fs::read_to_string(temp.join("test-agent")).unwrap(),
        )
        .unwrap(),
    );
    let mut child = Resource::new("https://localhost/import-entry".into());
    child
        .set_unsafe(
            urls::PARENT.into(),
            Value::AtomicUrl(subject.clone().into()),
        )
        .unwrap();
    child
        .set_unsafe(
            urls::LOCAL_ID.into(),
            Value::String("provider:entry:1".into()),
        )
        .unwrap();
    child
        .set_unsafe(
            urls::DESCRIPTION.into(),
            Value::String("Resumed entry".into()),
        )
        .unwrap();
    child
        .set_unsafe(urls::IS_A.into(), Value::ResourceArray(vec![]))
        .unwrap();
    child.save_as_genesis(&store).await.unwrap();
    assert_eq!(
        store
            .get_resource(&subject.into())
            .await
            .unwrap()
            .get(urls::NAME)
            .unwrap()
            .to_string(),
        "Imported project"
    );
    drop(store);
    std::fs::remove_dir_all(temp).unwrap();
}
