//! Full browser OAuth round trip against a local provider, with the real server running.
use atomic_lib::agents::{sign_message, Agent};
use serde_json::{json, Value};
use std::{
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
fn signed(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    agent: &Agent,
) -> reqwest::RequestBuilder {
    let timestamp = chrono::Utc::now().timestamp_millis();
    let signature = sign_message(
        format!("{url} {timestamp}").as_bytes(),
        agent.private_key.as_ref().unwrap(),
    )
    .unwrap();
    client
        .request(method, url)
        .header("x-atomic-agent", agent.subject.to_string())
        .header("x-atomic-public-key", &agent.public_key)
        .header("x-atomic-timestamp", timestamp.to_string())
        .header("x-atomic-signature", signature)
}

#[tokio::test]
async fn live_oauth_refresh_import_and_isolation() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let root = std::env::temp_dir().join(format!(
        "atomic-live-{}",
        atomic_lib::utils::random_string(10)
    ));
    let folder = root.join("spec/test");
    std::fs::create_dir_all(&folder).unwrap();
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_url = format!("http://{}", provider.local_addr().unwrap());
    let document = json!({"openapi":"3.0.3","info":{"title":"Widgets","version":"1"},
        "servers":[{"url":provider_url}],
        "x-atomic-integration":{"label":"Test","constants":{"account":"primary"},"clientIdEnv":"TEST_OAUTH_ID","clientSecretEnv":"TEST_OAUTH_SECRET"},
        "components":{
            "securitySchemes":{"oauth":{"type":"oauth2","flows":{"authorizationCode":{
                "authorizationUrl":format!("{provider_url}/authorize"),"tokenUrl":format!("{provider_url}/token"),"scopes":{"read":"Read"}
            }}}},
            "schemas":{"item":{"type":"object","properties":{"id":{"type":"string"},"title":{"type":"string"}}}},
            "crudResources":{"item":{"schema":{"$ref":"#/components/schemas/item"},"identity":{"urlTemplate":"/items/{account}/{id}","bindings":{"id":{"field":"id"}}},"collections":{"items":{"urlTemplate":"/items/{account}"}}}}
        },
        "paths":{"/items/{account}":{"get":{"parameters":[{"name":"account","in":"path","required":true,"schema":{"type":"string"}}],
            "responses":{"200":{"description":"Items","content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/item"}}}}}}}}}
    });
    std::fs::write(folder.join("test.openapi.json"), document.to_string()).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://localhost:{port}");
    let log = std::fs::File::create(root.join("server.log")).unwrap();
    let child = Command::new(assert_cmd::cargo::cargo_bin!("atomic-server"))
        .env_clear()
        .env("REFLECTOR_ROOT", &root)
        .env("TEST_OAUTH_ID", "test-client")
        .env("TEST_OAUTH_SECRET", "test-secret")
        .args([
            "--ip",
            "127.0.0.1",
            "--domain",
            "localhost",
            "--port",
            &port.to_string(),
            "--data-dir",
            root.join("data").to_str().unwrap(),
            "--config-dir",
            root.join("config").to_str().unwrap(),
            "--cache-dir",
            root.join("cache").to_str().unwrap(),
        ])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let server = Server(child);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if client
                .get(format!("{origin}/integrations"))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("server starts");
    assert_eq!(
        client
            .get(format!("{origin}/integrations"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(format!("{origin}/integrations/start?integration=test"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let alice = Agent::new(Some("Alice")).unwrap();
    let bob = Agent::new(Some("Bob")).unwrap();
    let list_url = format!("{origin}/integrations");
    let start_url = format!("{origin}/integrations/start?integration=test");
    let response = signed(&client, reqwest::Method::POST, &start_url, &alice)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "start: {}",
        response.status()
    );
    let cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let data: Value = response.json().await.unwrap();
    let auth = url::Url::parse(data["url"].as_str().unwrap()).unwrap();
    let params: std::collections::HashMap<_, _> = auth.query_pairs().into_owned().collect();
    assert_eq!(params["client_id"], "test-client");
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(
        params["redirect_uri"],
        format!("{origin}/integrations/callback")
    );
    let callback = format!(
        "{origin}/integrations/callback?state={}&code=test-code",
        params["state"]
    );
    assert_eq!(client.get(&callback).send().await.unwrap().status(), 400);

    let challenge = params["code_challenge"].clone();
    let mock = tokio::spawn(async move {
        // Initial token has already expired: exercise refresh before fetching data.
        for step in 0..3 {
            let (mut socket, _) = provider.accept().await.unwrap();
            let mut bytes = vec![];
            loop {
                let mut buf = [0; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&bytes);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(bytes).unwrap();
            let body=match step {
                0=>{
                    assert!(request.starts_with("POST /token"));
                    let fields:std::collections::HashMap<_,_>=url::form_urlencoded::parse(request.split("\r\n\r\n").nth(1).unwrap().as_bytes()).into_owned().collect();
                    assert_eq!(fields["code"],"test-code");
                    use base64::Engine;
                    assert_eq!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256,fields["code_verifier"].as_bytes())),challenge);
                    json!({"access_token":"expired-token","refresh_token":"refresh-secret","expires_in":0})
                },
                1=>{assert!(request.contains("grant_type=refresh_token"));assert!(request.contains("refresh_token=refresh-secret"));json!({"access_token":"fresh-token","expires_in":3600})},
                _=>{assert!(request.starts_with("GET /items/primary"));assert!(request.to_lowercase().contains("authorization: bearer fresh-token"));json!([{"id":"one","title":"Imported live"}])}
            }.to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    let response = client
        .get(&callback)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"], "/app/sync");
    assert_eq!(
        client
            .get(&callback)
            .header("Cookie", &cookie)
            .send()
            .await
            .unwrap()
            .status(),
        400,
        "callback is single use"
    );
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let items: Value = signed(&client, reqwest::Method::GET, &list_url, &alice)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(!items.to_string().contains("fresh-token"));
            assert!(!items.to_string().contains("refresh-secret"));
            if matches!(
                items[0]["job"]["status"].as_str(),
                Some("complete" | "failed")
            ) {
                break items;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("import finishes");
    assert_eq!(result[0]["job"]["status"], "complete", "{result}");
    tokio::time::timeout(Duration::from_secs(5), mock)
        .await
        .unwrap()
        .unwrap();
    let other: Value = signed(&client, reqwest::Method::GET, &list_url, &bob)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        other[0]["job"].is_null(),
        "jobs belong to the initiating agent"
    );
    let drive = result[0]["job"]["drive"]
        .as_str()
        .unwrap()
        .replace("internal:", &origin);
    let response = signed(&client, reqwest::Method::GET, &drive, &alice)
        .header("Accept", "application/ad+json")
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "imported drive is readable while server runs: {} {}",
        response.status(),
        response.text().await.unwrap()
    );
    let mut children = reqwest::Url::parse(&format!("{origin}/query")).unwrap();
    children
        .query_pairs_mut()
        .append_pair("property", atomic_lib::urls::PARENT)
        .append_pair("value", &drive)
        .append_pair("sort_by", atomic_lib::urls::CREATED_AT);
    let children: Value = signed(&client, reqwest::Method::GET, children.as_str(), &alice)
        .header("Accept", "application/ad+json")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        children[atomic_lib::urls::COLLECTION_MEMBERS]
            .as_array()
            .is_some_and(|members| !members.is_empty()),
        "drive contents are visible: {children}"
    );
    let response = signed(&client, reqwest::Method::GET, &drive, &bob)
        .header("Accept", "application/ad+json")
        .send()
        .await
        .unwrap();
    assert!(
        !response.status().is_success(),
        "another agent cannot read the imported drive"
    );
    // Declining consent reports a failure and never starts another import.
    let response = signed(&client, reqwest::Method::POST, &start_url, &alice)
        .send()
        .await
        .unwrap();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let data: Value = response.json().await.unwrap();
    let auth = url::Url::parse(data["url"].as_str().unwrap()).unwrap();
    let state = auth
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        client
            .get(format!(
                "{origin}/integrations/callback?state={state}&error=access_denied"
            ))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap()
            .status(),
        303
    );
    let items: Value = signed(&client, reqwest::Method::GET, &list_url, &alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(items[0]["job"]["status"], "failed");
    drop(server);
    std::fs::remove_dir_all(root).unwrap();
}
