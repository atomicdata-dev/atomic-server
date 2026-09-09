//! Two whole servers pairing over Iroh, driven through the HTTP endpoint the
//! UI actually calls.
//!
//! This covers a seam nothing else did. `replicate.rs` puts two servers
//! together but over HTTP/WS, and `atomic_lib`'s `iroh_e2e` exercises the Iroh
//! protocol with two nodes inside one process. Neither touches `POST
//! /iroh-sync` — the endpoint every browser pairing flow depends on — and
//! neither represents the desktop-to-desktop pair a user actually has.
//!
//! Separate processes are not optional here. `iroh_transport` keeps its router
//! and node identity in process globals, so servers sharing a process also
//! share one Iroh node: "pairing" would be a node dialling itself, and every
//! co-resident server would advertise the same node id regardless of whose
//! store held the data. Both servers are therefore spawned as subprocesses of
//! this test binary, and the test process runs none itself — otherwise the
//! result depends on which other test in this suite happened to boot first.
//!
//! Run with: cargo test -p atomic-server --test it iroh_pairing

use std::time::Duration;

use atomic_lib::client::connected::Client;

use crate::common::{start_server, wait_for_server};

/// Where the child writes the port it settled on. Its presence also flips the
/// `#[ignore]`d child entry point from a no-op into a running server.
const CHILD_FILE_ENV: &str = "ATOMIC_IROH_PAIR_CHILD_FILE";

/// A second, fully independent atomic-server — its own store, agent, node
/// identity and process globals.
#[test]
#[ignore = "child process entry point, driven by the parent test"]
fn child_runs_a_second_server() {
    let Some(path) = std::env::var(CHILD_FILE_ENV).ok() else {
        return;
    };

    let port = start_server("iroh_pair_peer");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        wait_for_server(port).await;
        std::fs::write(&path, port.to_string()).unwrap();
        // Stay up to be paired with. The parent kills this; the ceiling only
        // stops a stray server outliving a crashed parent.
        tokio::time::sleep(Duration::from_secs(180)).await;
    });
}

/// The node DID a server advertises on `/server`, or `None` when it has no p2p
/// transport. This is the value a pairing code carries.
async fn server_node_id(base_url: &str) -> Option<String> {
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{base_url}/server"))
        .header("Accept", "application/ad+json")
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;

    body.get(atomic_lib::urls::SERVER_NODE_ID)?
        .as_str()
        .map(str::to_string)
}

/// Poll until the server advertises a node id — Iroh binds asynchronously
/// during boot, so answering HTTP does not yet mean it can be dialled.
async fn await_node_id(base_url: &str) -> String {
    for _ in 0..300 {
        if let Some(id) = server_node_id(base_url).await {
            return id;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("{base_url} never advertised a node id");
}

/// Owns the peer server process and kills it on the way out — including when a
/// test panics. Without this, a failed assertion leaks a live server that keeps
/// answering (and pairing) for its full lifetime, which is exactly how one run
/// of this test went mysteriously green-then-red.
struct PeerServer {
    base_url: String,
    process: std::process::Child,
}

impl Drop for PeerServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Fetch a subject from a server as an anonymous reader. `did:ad:` subjects are
/// not path segments — they are resolved through `/did?subject=`.
async fn get_subject_anonymously(base_url: &str, subject: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!(
            "{base_url}/did?subject={}",
            urlencoding::encode(subject)
        ))
        .header("Accept", "application/ad+json")
        .send()
        .await
        .expect("subject request")
}

/// Block until `subject` is publicly readable on `base_url`.
///
/// The precise precondition for the pairing below: a peer can only be handed
/// what an anonymous reader may see, so dialling before the source will serve
/// it anonymously races the commit and reconciles nothing.
async fn await_publicly_readable(base_url: &str, subject: &str) {
    for _ in 0..300 {
        if get_subject_anonymously(base_url, subject)
            .await
            .status()
            .is_success()
        {
            return;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("{subject} never became publicly readable on {base_url}");
}

/// Boot an independent server subprocess, ready to pair.
async fn start_server_process(tag: &str) -> PeerServer {
    let (base_url, process) = spawn_server_process(tag).await;
    let peer = PeerServer { base_url, process };
    // Iroh binds asynchronously during boot, so answering HTTP does not yet
    // mean the node can be dialled.
    let _ = await_node_id(&peer.base_url).await;

    peer
}

/// Boot the child server and return its base URL plus a handle to kill it.
async fn spawn_server_process(tag: &str) -> (String, std::process::Child) {
    let handoff = std::env::temp_dir().join(format!(
        "atomic-iroh-pair-{}-{}.port",
        tag,
        std::process::id()
    ));
    let stderr_path = std::env::temp_dir().join(format!(
        "atomic-iroh-pair-{}-{}.stderr",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&handoff);
    let _ = std::fs::remove_file(&stderr_path);

    let stderr_file = std::fs::File::create(&stderr_path).expect("peer stderr file");
    let exe = std::env::current_exe().expect("test binary path");
    let mut child = std::process::Command::new(exe)
        // Module-qualified: this suite is one binary shared by every module, so
        // libtest knows this test as `iroh_pairing::…` and a bare name matches
        // nothing under `--exact`.
        .args([
            "iroh_pairing::child_runs_a_second_server",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(CHILD_FILE_ENV, &handoff)
        .stdout(std::process::Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .expect("spawn peer server");

    // 180s: under Mancave CI the `it` binary can share the host with other
    // nextest workers and e2e Chromium shards; peer boot regularly exceeds
    // the old 90s ceiling without being wedged.
    for _ in 0..1800 {
        if let Ok(port) = std::fs::read_to_string(&handoff) {
            if let Ok(port) = port.trim().parse::<u16>() {
                let _ = std::fs::remove_file(&stderr_path);
                return (format!("http://localhost:{port}"), child);
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            let _ = std::fs::remove_file(&stderr_path);
            panic!("peer server exited before it was ready: {status}\nstderr:\n{stderr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = child.kill();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let _ = std::fs::remove_file(&stderr_path);
    panic!("peer server never reported its port within 180s\nstderr:\n{stderr}");
}

/// Ask a server to pair with `node_did` and pull `drive`. This is byte-for-byte
/// the request `pairAndSync` in the data-browser sends.
/// `POST /iroh-sync`, signed as a fresh agent created on that server. The
/// route needs a signed-in agent: write on the drive when the node already
/// holds it, or the policy's leave to bring a new drive here (any agent on an
/// open node, which these servers are).
async fn post_iroh_sync(
    base_url: &str,
    node_did: &str,
    drive: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let agent = Client::new(base_url)
        .await
        .unwrap()
        .new_agent("Pairer")
        .await
        .unwrap();
    let url = format!("{base_url}/iroh-sync");
    let headers =
        atomic_lib::client::get_authentication_headers(&url, &agent).expect("auth headers");
    let mut request = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "nodeId": node_did, "drive": drive }));
    for (key, value) in headers {
        request = request.header(key, value);
    }
    let response = request.send().await.expect("iroh-sync request");

    let status = response.status();
    let body = response.json().await.unwrap_or(serde_json::Value::Null);

    (status, body)
}

/// The whole point: data created on one server reaches another, over Iroh,
/// because a user pasted a pairing code.
#[tokio::test]
async fn a_public_drive_reconciles_between_two_servers_over_iroh() {
    // Both servers are subprocesses, and this process runs none. `iroh_transport`
    // holds the router and node identity in globals, so every server sharing a
    // process also shares one node id — meaning a co-resident server from
    // another test in this suite could be the one A's `/server` advertises,
    // and the pairing would dial a node whose store has none of Alice's data.
    // Keeping this process server-free makes the test independent of what else
    // is running in the binary.
    let source = start_server_process("source").await;
    let url_a = source.base_url.clone();

    // Public, so the peer — running under its own, unrelated agent — is
    // allowed to read it. A private drive is covered by the rights tests; what
    // is under test here is the transport and the endpoint.
    let client = Client::new(&url_a).await.unwrap();
    let agent = client.new_agent("Alice").await.unwrap();
    let drive = client
        .new_public_drive(&agent, "Alice's public drive")
        .await
        .unwrap();

    let mut resource = client.new_resource(&drive).unwrap();
    resource.set_name("Shared note").unwrap();
    resource
        .set_unsafe(
            atomic_lib::urls::IS_A.into(),
            atomic_lib::Value::ResourceArray(vec![atomic_lib::urls::CLASS.into()]),
        )
        .unwrap();
    resource
        .set_unsafe(
            atomic_lib::urls::SHORTNAME.into(),
            atomic_lib::Value::Slug("shared-note".into()),
        )
        .unwrap();
    resource
        .set_unsafe(
            atomic_lib::urls::DESCRIPTION.into(),
            atomic_lib::Value::String("Written on Alice's server".into()),
        )
        .unwrap();
    let subject = resource.save_remote(client.store()).await.unwrap();

    let node_a = await_node_id(&url_a).await;
    assert!(
        node_a.starts_with("did:ad:node:"),
        "a pairing code carries a node DID, got {node_a}"
    );

    // A peer is handed only what the requester may read, so pairing before the
    // source will serve this anonymously would reconcile nothing.
    await_publicly_readable(&url_a, &drive).await;
    await_publicly_readable(&url_a, &subject).await;

    let peer = start_server_process("peer").await;

    let (status, body) = post_iroh_sync(&peer.base_url, &node_a, &drive).await;

    assert_eq!(status, 200, "pairing request failed: {body}");
    assert_eq!(body.get("error"), None, "pairing reported an error: {body}");

    let count = body.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
    assert!(count > 0, "nothing crossed between the servers: {body}");

    // The count is B's own report of what it imported. Reading the resource
    // back off B is the independent proof that the data is really there — and
    // reading it anonymously proves the drive stayed public across the hop.
    let response = get_subject_anonymously(&peer.base_url, &subject).await;
    assert!(
        response.status().is_success(),
        "the peer should serve Alice's synced resource, got {}",
        response.status()
    );

    let fetched: serde_json::Value = response
        .json()
        .await
        .expect("synced resource should be JSON-AD");

    assert_eq!(
        fetched.get(atomic_lib::urls::NAME).and_then(|n| n.as_str()),
        Some("Shared note"),
        "the peer served the subject but not Alice's data: {fetched}"
    );
}

/// A malformed code must be refused at the edge, with a message the pairing UI
/// can show. `runPairing` renders `data.error` verbatim, so a 500 or an empty
/// body would surface to the user as a blank failure.
#[tokio::test]
async fn pairing_with_a_malformed_node_id_is_refused_not_crashed() {
    let port = start_server("iroh_pair_reject");
    wait_for_server(port).await;
    let url = format!("http://localhost:{port}");

    for bad in [
        "not-a-did",
        "did:ad:node:tooshort",
        "iroh:abcdef",
        "did:ad:node:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        let (status, body) = post_iroh_sync(&url, bad, "did:ad:somedrive").await;

        assert_eq!(status, 400, "{bad} should be rejected, got {status} {body}");
        assert!(
            body.get("error").and_then(|e| e.as_str()).is_some(),
            "{bad} was rejected without an error message the UI could show: {body}"
        );
    }
}

/// The handler accepts the shared contract fixture verbatim.
///
/// `browser/data-browser/src/helpers/pairing.test.ts` asserts the client
/// *sends* exactly this body; this asserts the server *accepts* it. The shared
/// file is what binds them: testing each side against its own idea of the
/// shape lets a rename pass both suites and break pairing in production.
///
/// A 400 here means the field names have drifted apart. Any other status —
/// including a failure to reach the fictional node in the fixture — means the
/// request was understood, which is all this test claims.
#[tokio::test]
async fn the_handler_accepts_the_shared_pairing_contract() {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../testdata/pairing-request.json"),
        )
        .expect("shared pairing contract fixture"),
    )
    .expect("fixture should be JSON");

    // Underscore keys are documentation, not part of the wire shape.
    let body: serde_json::Map<String, serde_json::Value> = fixture
        .as_object()
        .expect("fixture is an object")
        .iter()
        .filter(|(key, _)| !key.starts_with('_'))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let port = start_server("iroh_pair_contract");
    wait_for_server(port).await;

    let response = reqwest::Client::new()
        .post(format!("http://localhost:{port}/iroh-sync"))
        .json(&serde_json::Value::Object(body))
        .send()
        .await
        .expect("iroh-sync request");

    assert_ne!(
        response.status(),
        400,
        "the server rejected the very body the browser sends — the field names \
         have drifted apart: {:?}",
        response.text().await
    );
}

/// The two required fields are exactly the two the browser sends. If either
/// name drifts, pairing breaks in production while both sides' own tests stay
/// green — this is the assertion that binds the contract together.
#[tokio::test]
async fn iroh_sync_requires_both_a_node_and_a_drive() {
    let port = start_server("iroh_pair_fields");
    wait_for_server(port).await;
    let url = format!("http://localhost:{port}");
    let http = reqwest::Client::new();

    let valid_node = format!("did:ad:node:{}", "a".repeat(64));

    for (label, payload) in [
        (
            "no nodeId",
            serde_json::json!({ "drive": "did:ad:somedrive" }),
        ),
        ("no drive", serde_json::json!({ "nodeId": valid_node })),
        ("neither", serde_json::json!({})),
    ] {
        let response = http
            .post(format!("{url}/iroh-sync"))
            .json(&payload)
            .send()
            .await
            .expect("iroh-sync request");

        assert_eq!(
            response.status(),
            400,
            "{label} should be a bad request, not a server error"
        );
    }
}

// ── Forgetting a device ────────────────────────────────────────────────────

/// The node ids a server lists as peers on `/server`.
async fn listed_peer_node_ids(base_url: &str) -> Vec<String> {
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{base_url}/server"))
        .header("Accept", "application/ad+json")
        .send()
        .await
        .expect("server resource")
        .json()
        .await
        .expect("server resource is JSON-AD");

    body.get(atomic_lib::urls::SERVER_PEERS)
        .and_then(|p| p.as_array())
        .map(|peers| {
            peers
                .iter()
                .filter_map(|peer| {
                    peer.get(atomic_lib::urls::PEER_NODE_ID)
                        .and_then(|id| id.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn forget_peer_url(base_url: &str, node_did: &str) -> String {
    format!(
        "{base_url}/forget-peer?node={}",
        urlencoding::encode(node_did)
    )
}

/// Forgetting a device is refused without a proven identity.
///
/// The bar is a valid signature rather than node-admin on purpose — the drive
/// owner is not necessarily the node's root admin — so "any signature" and "no
/// signature" are the two cases that matter, and this pins the second.
#[tokio::test]
async fn forgetting_a_device_requires_a_signature() {
    let port = start_server("forget_peer_anon");
    wait_for_server(port).await;

    let node = format!("did:ad:node:{}", "e".repeat(64));
    let response = reqwest::Client::new()
        .post(forget_peer_url(&format!("http://localhost:{port}"), &node))
        .send()
        .await
        .expect("forget-peer request");

    assert!(
        !response.status().is_success(),
        "an unsigned request must not be able to unpair someone's devices, got {}",
        response.status()
    );
}

/// The full pairing lifecycle: pair two servers, see the peer listed, forget
/// it, see it gone. Forgetting is how someone reading a server in a browser
/// disconnects a phone — the browser tab is not itself a node, so there is no
/// other way to do it.
#[tokio::test]
async fn a_paired_device_can_be_forgotten() {
    let source = start_server_process("forget_source").await;
    let node_a = await_node_id(&source.base_url).await;

    let client = Client::new(&source.base_url).await.unwrap();
    let agent = client.new_agent("Alice").await.unwrap();
    let drive = client
        .new_public_drive(&agent, "Alice's public drive")
        .await
        .unwrap();
    await_publicly_readable(&source.base_url, &drive).await;

    let peer = start_server_process("forget_peer").await;
    let (status, body) = post_iroh_sync(&peer.base_url, &node_a, &drive).await;
    assert_eq!(status, 200, "pairing should succeed: {body}");

    assert!(
        listed_peer_node_ids(&peer.base_url).await.contains(&node_a),
        "a device that just paired must be listed before it can be forgotten"
    );

    // A signature alone is not enough: a key nobody here has ever seen must
    // not be able to drop the operator's devices. The client signs the exact
    // URL it fetches, query string included, and the server rebuilds it to
    // verify.
    let stranger = Client::new(&peer.base_url)
        .await
        .unwrap()
        .new_agent("Stranger")
        .await
        .unwrap();
    let url = forget_peer_url(&peer.base_url, &node_a);
    let headers =
        atomic_lib::client::get_authentication_headers(&url, &stranger).expect("auth headers");
    let mut request = reqwest::Client::new().post(&url);
    for (key, value) in headers {
        request = request.header(key, value);
    }
    let response = request.send().await.expect("forget-peer request");
    assert!(
        !response.status().is_success(),
        "a stranger must not be able to forget a peer, got {}",
        response.status()
    );
    assert!(
        listed_peer_node_ids(&peer.base_url).await.contains(&node_a),
        "a refused forget-peer must leave the device listed"
    );

    // Alice may write the drive this peer was paired for, so Alice may undo
    // the pairing.
    let headers =
        atomic_lib::client::get_authentication_headers(&url, &agent).expect("auth headers");
    let mut request = reqwest::Client::new().post(&url);
    for (key, value) in headers {
        request = request.header(key, value);
    }
    let response = request.send().await.expect("forget-peer request");
    assert!(
        response.status().is_success(),
        "a forget-peer signed by the drive's writer must be accepted, got {}",
        response.status()
    );
    assert!(
        !listed_peer_node_ids(&peer.base_url).await.contains(&node_a),
        "the forgotten device must stop being listed"
    );
}
