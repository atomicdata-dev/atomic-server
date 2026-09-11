//! Real process, real operator CLI, real WS replication, offline restore.
use atomic_lib::{
    agents::ForAgent,
    sync::replicate::{replicate_drive_to_remote, ReplicateAuth},
    Storelike,
};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_atomic-server")
}
fn command(root: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.env_clear().current_dir(root).args([
        "--data-dir",
        root.join("data").to_str().unwrap(),
        "--config-dir",
        root.join("config").to_str().unwrap(),
        "--cache-dir",
        root.join("cache").to_str().unwrap(),
    ]);
    cmd
}

#[tokio::test]
async fn cli_backs_up_a_running_replica_and_restores_offline() {
    let root = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let log = std::fs::File::create(root.path().join("server.log")).unwrap();
    let mut child = Server(
        command(root.path())
            .args([
                "--ip",
                "127.0.0.1",
                "--domain",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--host-mode",
                "open",
                "--backup-dir",
                root.path().join("backups").to_str().unwrap(),
            ])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if client
            .get(format!("{base}/__atomic/backup"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "server exited: {}",
            std::fs::read_to_string(root.path().join("server.log")).unwrap()
        );
        assert!(std::time::Instant::now() < deadline, "server did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // A second node feeds this replica through the actual WS sync transport.
    let source = atomic_lib::Db::init_redb_file(
        &root.path().join("source-store"),
        None,
        &root.path().join("source-uploads"),
    )
    .await
    .unwrap();
    let (agent, drive) = source.setup("Source").await.unwrap();
    let note = source
        .create_resource(atomic_lib::urls::FOLDER, &drive, "Before backup", None)
        .await
        .unwrap();
    let outcome = replicate_drive_to_remote(
        &source,
        &drive,
        &format!("ws://127.0.0.1:{port}/ws"),
        &ForAgent::AgentSubject(agent.subject.clone()),
        ReplicateAuth::Agent(Box::new(agent.clone())),
    )
    .await
    .unwrap();
    assert!(outcome.in_sync);
    let status: serde_json::Value = client
        .get(format!("{base}/__atomic/backup"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
        .into();
    assert_eq!(status, 401);
    let mut backup = command(root.path());
    backup.args(["backup", "--server", &base]);
    let output = tokio::task::spawn_blocking(move || backup.output().unwrap())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = String::from_utf8(output.stdout).unwrap();
    let archive = path.trim();
    assert!(Path::new(archive).exists());
    // The live instance stays usable after capture; a later change must not
    // alter the previously published checkpoint.
    let mut resource = source.get_resource(&note.clone().into()).await.unwrap();
    resource
        .set_string(atomic_lib::urls::NAME.into(), "After backup", &source)
        .await
        .unwrap();
    resource.save(&source).await.unwrap();
    let outcome = replicate_drive_to_remote(
        &source,
        &drive,
        &format!("ws://127.0.0.1:{port}/ws"),
        &ForAgent::AgentSubject(agent.subject.clone()),
        ReplicateAuth::Agent(Box::new(agent)),
    )
    .await
    .unwrap();
    assert!(outcome.in_sync);
    let target = root.path().join("restore");
    let output = command(root.path())
        .args([
            "restore",
            "--archive",
            archive,
            "--target",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.join("data/RESTORED_OFFLINE").exists());
    let output = Command::new(binary())
        .env_clear()
        .current_dir(root.path())
        .args([
            "--data-dir",
            target.join("data").to_str().unwrap(),
            "--config-dir",
            target.join("config").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Restored instance is offline"));
    let recovered = atomic_lib::Db::init_redb_file(
        &target.join("data/store"),
        Some(base),
        &target.join("data/uploads"),
    )
    .await
    .unwrap();
    assert_eq!(
        recovered
            .get_resource(&note.into())
            .await
            .unwrap()
            .get(atomic_lib::urls::NAME)
            .unwrap()
            .to_string(),
        "Before backup"
    );
}
