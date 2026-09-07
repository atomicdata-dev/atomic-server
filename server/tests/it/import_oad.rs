use atomic_lib::{Storelike, Subject};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    time::Duration,
};

fn command(root: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("atomic-server").unwrap();
    cmd.current_dir(root)
        .env_clear()
        .env("PUBLIC_URL", "http://localhost:9883")
        .env("OPENAPI_DOCUMENT", "api.json")
        .env("OPENAPI_OVERLAYS", "overlay.json")
        .env("API_CONSTANTS", "owner=local,repo=test")
        .env("DRIVE_OWNER", "did:ad:agent:owner")
        .args([
            "--data-dir",
            "data",
            "--config-dir",
            "config",
            "--cache-dir",
            "cache",
            "--domain",
            "localhost",
            "--port",
            "9883",
            "import-oad",
        ])
        .timeout(Duration::from_secs(60));
    cmd
}

#[tokio::test]
async fn import_oad_persists_updates_and_reports_api_failure() {
    let root = std::env::temp_dir().join(format!(
        "atomic-oad-{}",
        atomic_lib::utils::random_string(10)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let document = json!({
        "openapi": "3.0.3", "info": {"title": "Widgets", "version": "1"},
        "servers": [{"url": api}],
        "paths": {"/repos/{owner}/{repo}/issues": {"get": {
            "parameters": [
                {"name":"owner","in":"path","required":true,"schema":{"type":"string"}},
                {"name":"repo","in":"path","required":true,"schema":{"type":"string"}}
            ],
            "responses": {"200":{"description":"Issues","content":{"application/json":{
                "schema":{"type":"array","items":{"$ref":"#/components/schemas/issue"}}
            }}}}
        }}},
        "components": {"schemas":{"issue":{"type":"object","properties":{
            "number":{"type":"integer"},"title":{"type":"string"}
        }}}}
    });
    let overlay = json!({"overlay":"1.0.0","info":{"title":"CRUD","version":"1"},
        "actions":[{"target":"$.components","update":{"crudResources":{"issue":{
            "schema":{"$ref":"#/components/schemas/issue"},
            "identity":{"urlTemplate":"/repos/{owner}/{repo}/issues/{number}","bindings":{"number":{"field":"number"}}},
            "collections":{"issues":{"urlTemplate":"/repos/{owner}/{repo}/issues"}}
        }}}}]
    });
    std::fs::write(root.join("api.json"), document.to_string()).unwrap();
    std::fs::write(root.join("overlay.json"), overlay.to_string()).unwrap();

    // A mismatched ontology origin must fail before opening the database or fetching.
    let mismatch = command(&root)
        .env("PUBLIC_URL", "https://wrong.example")
        .assert()
        .failure();
    assert!(
        String::from_utf8_lossy(&mismatch.get_output().stderr).contains("PUBLIC_URL must match")
    );
    assert!(!root.join("data/store/atomic.redb").exists());

    for (status, title) in [
        ("200 OK", "First"),
        ("200 OK", "Updated"),
        ("500 Internal Server Error", "Error"),
    ] {
        let server = listener.try_clone().unwrap();
        let response = json!([{"number":1,"title":title}]).to_string();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = server.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = [0; 8192];
            let size = socket.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..size])
                .starts_with("GET /repos/local/test/issues"));
            write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        });
        let assertion = command(&root).assert();
        if status.starts_with("200") {
            assertion.success();
        } else {
            let failure = assertion.failure();
            assert!(
                String::from_utf8_lossy(&failure.get_output().stderr).contains("import incomplete")
            );
        }
        worker.join().unwrap();
        let store = atomic_lib::Db::init_redb_file(
            &root.join("data/store"),
            Some("http://localhost:9883".into()),
            &root.join("data/uploads"),
        )
        .await
        .unwrap();
        let issue = store
            .get_resource(&Subject::from("internal:/local%2Ftest/issue/1"))
            .await
            .unwrap();
        assert_eq!(
            issue
                .get("internal:/widgets/property/title")
                .unwrap()
                .to_string(),
            if title == "Error" { "Updated" } else { title }
        );
        let drive = store
            .get_resource(&Subject::from("internal:/reflector-drives/local%2Ftest"))
            .await
            .unwrap();
        assert_eq!(
            drive
                .get(atomic_lib::urls::WRITE)
                .unwrap()
                .to_subjects(None)
                .unwrap(),
            vec!["did:ad:agent:owner"]
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
