//! This contains a minimal set of tests for the server.
//! Most of the more rigorous testing is done in the end-to-end tests:
//! https://github.com/atomicdata-dev/atomic-data-browser/tree/main/data-browser/tests

use crate::{appstate::AppState, config::Opts};

use super::*;
use actix_web::{
    body::MessageBody,
    dev::ServiceResponse,
    test::{self, TestRequest},
    web::Data,
    App,
};
use atomic_lib::{urls, Storelike};
use base64::Engine;

/// Returns the request with signed headers. Also adds a json-ad accept header - overwrite this if you need something else.
fn build_request_authenticated(path: &str, appstate: &AppState) -> TestRequest {
    let origin = appstate.config.get_origin();
    let url = format!("{}{}", origin, path);
    let headers = atomic_lib::client::get_authentication_headers(
        &url,
        &appstate.store.get_default_agent().unwrap(),
    )
    .expect("could not get auth headers");

    let mut prereq = test::TestRequest::with_uri(path);
    for (k, v) in headers {
        prereq = prereq.insert_header((k, v));
    }

    // Ensure the Host header matches the origin used for signing
    if let Ok(u) = url::Url::parse(&origin) {
        if let Some(host) = u.host_str() {
            let authority = if let Some(port) = u.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            prereq = prereq.insert_header(("Host", authority));
        }
    }

    prereq.insert_header(("Accept", "application/ad+json"))
}

#[actix_rt::test]
async fn server_tests() {
    // Enable logging
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,atomic_server=trace")
        .try_init();

    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts)
        .map_err(|e| format!("Initialization failed: {}", e))
        .expect("failed init config");
    // This prevents folder access issues when running concurrent tests
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    config.vector_search_index_path =
        format!("./.temp/{}/vector_search_index", unique_string).into();

    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    // For tests, we manually populate a test drive and collections
    atomic_lib::test_utils::setup_test_env(&appstate.store)
        .await
        .unwrap();

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;
    let store = &appstate.store;

    // Get HTML page
    let req =
        build_request_authenticated("/", &appstate).insert_header(("Accept", "application/html"));
    let resp = test::call_service(&app, req.to_request()).await;
    let is_success = resp.status().is_success();
    let body = get_body(resp);
    // println!("{:?}", body);
    assert!(is_success);
    assert!(body.as_str().contains("html"));

    // Should 404
    let req = test::TestRequest::with_uri("/doesnotexist")
        .append_header(("Accept", "application/ld+json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_client_error());

    // Edit the main drive, make it hidden to the public agent
    let drive_did = store.get_drive_did("localhost").await.unwrap().unwrap();
    let mut drive = store.get_resource(&drive_did).await.unwrap();
    drive
        .set(
            urls::READ.into(),
            vec![appstate.store.get_default_agent().unwrap().subject].into(),
            &appstate.store,
        )
        .await
        .unwrap();
    drive.save(store).await.unwrap();

    // Should 401 (Unauthorized)
    let req = test::TestRequest::with_uri("/").insert_header(("Accept", "application/ad+json"));
    let resp = test::call_service(&app, req.to_request()).await;
    let status = resp.status().as_u16();
    let body = get_body(resp);
    if status != 401 {
        panic!(
            "Root resource should be 401 after editing rights. Status: {}, body: {:?}",
            status, body
        );
    }

    // Get JSON-AD
    let req = build_request_authenticated("/", &appstate);
    let resp = test::call_service(&app, req.to_request()).await;
    let status = resp.status().as_u16();
    let body = get_body(resp);
    if status >= 400 {
        panic!(
            "Auth request to /properties status: {}. Expected success. Body: {}",
            status, body
        );
    }
    if !body.contains("\"@id\"") {
        panic!("response should be json-ad. Body: {}", body);
    }

    // Resources with server-side Loro state should expose their snapshot in JSON-AD
    let mut loro_resource = atomic_lib::Resource::new("/loro-sync-test".into());
    loro_resource
        .set_unsafe(
            urls::READ.into(),
            vec![appstate.store.get_default_agent().unwrap().subject.clone()].into(),
        )
        .unwrap();
    loro_resource
        .set_unsafe(
            urls::WRITE.into(),
            vec![appstate.store.get_default_agent().unwrap().subject.clone()].into(),
        )
        .unwrap();
    loro_resource
        .set_unsafe(urls::NAME.into(), "Loro Sync Test".to_string().into())
        .unwrap();
    loro_resource
        .set_unsafe(
            urls::DESCRIPTION.into(),
            atomic_lib::Value::String("Synced through CRDT".into()),
        )
        .unwrap();
    loro_resource.ensure_materialized().unwrap();
    store
        .add_resource_opts(&loro_resource, false, true, true)
        .await
        .unwrap();

    let req = build_request_authenticated("/loro-sync-test", &appstate);
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(
        resp.status().is_success(),
        "loro resource fetch should succeed"
    );
    let body = get_body(resp);
    assert!(
        body.as_str()
            .contains("\"https://atomicdata.dev/properties/loroUpdate\""),
        "resource fetch should include loroUpdate when server has a Loro snapshot: {}",
        body.as_str()
    );

    // Get JSON-LD
    let req = build_request_authenticated("/", &appstate)
        .insert_header(("Accept", "application/ld+json"));
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success(), "setup not returning JSON-LD");
    let body = get_body(resp);
    assert!(
        body.as_str().contains("@context"),
        "response should be json-ld"
    );

    // Get turtle
    let req = build_request_authenticated("/", &appstate).insert_header(("Accept", "text/turtle"));
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
    let body = get_body(resp);
    assert!(
        body.as_str().starts_with("<"),
        "response should be turtle, but was: {}",
        body.as_str()
    );

    // Get Search
    // Does not test the contents of the results - the index isn't built at this point
    let req = build_request_authenticated("/search?q=setup", &appstate);
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
    let body = get_body(resp);
    println!("{}", body.as_str());
    assert!(
        body.as_str().contains("/results"),
        "response should be a search resource"
    );

    // Get DID endpoint
    let req = build_request_authenticated("/did", &appstate);
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
    let body = get_body(resp);
    assert!(
        body.as_str().contains("Resolves a DID"),
        "response should be the DID endpoint description"
    );

    // Test path-based DID resolution (even if it doesn't exist, we should get a 404 from the store, not a 500 or 401 before getting there)
    let req = build_request_authenticated("/did:ad:test", &appstate);
    let resp = test::call_service(&app, req.to_request()).await;
    // It should be a 404 because did:ad:test doesn't exist, but it confirms it reached the handler correctly
    assert_eq!(
        resp.status(),
        404,
        "Should be a 404, because `did:ad:test` does not exist"
    );

    // Test Unauthenticated Invite with Public Key
    let issuer_agent = appstate.store.get_default_agent().unwrap();
    let target_resource_subject = "https://atomicdata.dev/test/resource";
    // We need to create the target resource to check write rights
    let mut target = atomic_lib::Resource::new(target_resource_subject.into());
    target
        .set(
            urls::READ.into(),
            vec![issuer_agent.subject.clone()].into(),
            &appstate.store,
        )
        .await
        .unwrap();
    target
        .set(
            urls::WRITE.into(),
            vec![issuer_agent.subject.clone()].into(),
            &appstate.store,
        )
        .await
        .unwrap();
    target.save_locally(&appstate.store).await.unwrap();

    let expiration = atomic_lib::utils::now() + 100000;

    // Construct the InviteToken manually as we don't have a helper in the lib for this yet
    // This replicates what the frontend does
    let mut signable_json = serde_json::Map::new();
    signable_json.insert(
        urls::TARGET.into(),
        serde_json::Value::String(target_resource_subject.into()),
    );
    signable_json.insert(urls::WRITE_BOOL.into(), serde_json::Value::Bool(true));
    signable_json.insert(
        urls::EXPIRES_AT.into(),
        serde_json::Value::Number(expiration.into()),
    );
    signable_json.insert(
        urls::SIGNER.into(),
        serde_json::Value::String(issuer_agent.subject.to_string()),
    );

    let serialized = serde_jcs::to_string(&signable_json).unwrap();
    let private_key = issuer_agent.private_key.clone().unwrap();
    let signature =
        atomic_lib::commit::sign_message(&serialized, &private_key, &issuer_agent.public_key)
            .unwrap();

    let mut map = signable_json;
    map.insert(urls::SIGNATURE.into(), serde_json::Value::String(signature));

    let bytes = serde_json::to_vec(&map).unwrap();
    let token_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let token_encoded: String =
        url::form_urlencoded::byte_serialize(token_base64.as_bytes()).collect();

    // Generate a new public key for the visitor
    let visitor_agent = atomic_lib::agents::Agent::new(None).unwrap();
    let public_key = visitor_agent.public_key; // This gives the Base64 public key
    let public_key_encoded: String =
        url::form_urlencoded::byte_serialize(public_key.as_bytes()).collect();

    let path = format!(
        "/invites?token={}&public-key={}",
        token_encoded, public_key_encoded
    );

    // Use an unauthenticated request
    let req = test::TestRequest::with_uri(&path).insert_header(("Accept", "application/ad+json"));
    let resp = test::call_service(&app, req.to_request()).await;

    assert!(
        resp.status().is_success(),
        "Invite request failed: Status {}",
        resp.status()
    );

    let body = get_body(resp);
    assert!(
        body.contains(urls::DESTINATION) || body.contains(urls::INVITE),
        "Response should contain either destination (redirect) or invite metadata. Body: {}",
        body
    );
}

#[actix_rt::test]
async fn test_did_agent_edit() {
    use atomic_lib::{agents::Agent, commit::CommitBuilder, urls, Resource, Value};
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts)
        .map_err(|e| format!("Initialization failed: {}", e))
        .expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();

    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    // 1. Create a new agent locally
    let agent = Agent::new(Some("Test User")).unwrap();
    let agent_did = agent.subject.pure_id();

    // 2. Setup onboarding: create a drive and map it
    let drive_did = "did:ad:test-drive";
    let mut drive = Resource::new(drive_did.into());
    drive.set_class(urls::DRIVE).unwrap();
    drive
        .set(
            urls::READ.into(),
            vec![urls::PUBLIC_AGENT.to_string()].into(),
            &appstate.store,
        )
        .await
        .unwrap();
    drive
        .set(
            urls::WRITE.into(),
            vec![agent_did.clone()].into(),
            &appstate.store,
        )
        .await
        .unwrap();
    appstate.store.add_resource(&drive).await.unwrap();

    appstate
        .store
        .add_drive_mapping("localhost", &Value::AtomicUrl(drive_did.into()))
        .unwrap();

    // 3. Setup the agent resource manually in the store
    let mut agent_res = agent.to_resource().unwrap();
    agent_res.set_subject(agent_did.clone());
    agent_res
        .set_unsafe(urls::NAME.into(), Value::String("Initial Name".into()))
        .unwrap();
    // Dummy last commit to avoid genesis trigger
    agent_res
        .set_unsafe(
            urls::LAST_COMMIT.into(),
            Value::AtomicUrl("dummy-initial-commit".into()),
        )
        .unwrap();
    appstate
        .store
        .add_resource_opts(&agent_res, false, false, true)
        .await
        .unwrap();

    // 4. Create a commit to edit the agent's name
    let mut builder = CommitBuilder::new(agent_did.clone().into());
    builder.set(urls::NAME.into(), Value::String("Updated Name".into()));

    let commit = builder
        .sign(&agent, &appstate.store, &agent_res)
        .await
        .unwrap();
    let mut opts = atomic_lib::commit::CommitOpts::no_validations_no_index();
    opts.update_index = true;
    appstate
        .store
        .apply_commit(commit, &opts)
        .await
        .expect("Failed to apply commit directly");

    // 5. Fetch the agent resource via GET and verify the name change
    let req = test::TestRequest::get()
        .uri(&format!("/did?subject={}", urlencoding::encode(&agent_did)))
        .insert_header(("Accept", "application/ad+json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "Fetch failed with status: {:?}",
        resp.status()
    );

    let body = get_body(resp);
    assert!(
        body.contains("Updated Name"),
        "Body does not contain 'Updated Name'. Body: {}",
        body
    );
}

#[actix_rt::test]
async fn self_signed_agent_commit_keeps_name() {
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts)
        .map_err(|e| format!("Initialization failed: {}", e))
        .expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();

    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    let agent = atomic_lib::agents::Agent::new(None).unwrap();
    let agent_did = agent.subject.pure_id();
    let empty = atomic_lib::Resource::new(agent_did.clone());

    let mut builder = atomic_lib::commit::CommitBuilder::new(agent_did.clone().into());
    builder.is_genesis = true;
    builder.set(
        urls::IS_A.into(),
        atomic_lib::Value::ResourceArray(vec![urls::AGENT.to_string().into()]),
    );
    builder.set(
        urls::NAME.into(),
        atomic_lib::Value::String("Test User".into()),
    );

    let commit = builder.sign(&agent, &appstate.store, &empty).await.unwrap();
    let body = commit
        .into_resource(&appstate.store)
        .await
        .unwrap()
        .to_json_ad(Some(&appstate.config.get_origin()))
        .unwrap();

    let req = TestRequest::post()
        .uri("/commit")
        .insert_header(("Content-Type", "application/ad+json"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "commit post failed with status {:?}: {}",
        resp.status(),
        get_body(resp)
    );

    // Authenticate the GET — the resource lives behind the default rights
    // model, so unauthenticated reads return 401.
    let req = build_request_authenticated(
        &format!("/did?subject={}", urlencoding::encode(&agent_did)),
        &appstate,
    );
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(
        resp.status().is_success(),
        "Fetch failed with status: {:?}",
        resp.status()
    );

    let body = get_body(resp);
    assert!(
        body.contains("Test User"),
        "Body does not contain persisted agent name. Body: {}",
        body
    );
}

/// Gets the body from the response as a String. Why doen't actix provide this?
fn get_body(resp: ServiceResponse) -> String {
    let boxbody = resp.into_body();
    let bytes = boxbody.try_into_bytes().unwrap();
    String::from_utf8(bytes.as_ref().into()).unwrap()
}

#[actix_rt::test]
async fn upload_download_test() {
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts).expect("failed init config");
    // Prevent folder access issues when running concurrent tests — the other
    // server tests set this; without it, parallel runs share the default
    // search-index dir and trip Tantivy's `LockBusy` on the second test.
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    // Create a valid parent drive
    let drive_did = atomic_lib::test_utils::create_test_drive(&appstate.store)
        .await
        .unwrap();

    let test_content = b"hello blake3 world";
    let expected_hash = blake3::hash(test_content).to_hex().to_string();

    // 1. Upload
    let multipart_boundary = "boundary";
    let body = format!(
        "--{multipart_boundary}\r\n\
        Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\
        Content-Type: text/plain\r\n\r\n\
        {}\r\n\
        --{multipart_boundary}--\r\n",
        String::from_utf8_lossy(test_content)
    );

    let req = build_request_authenticated(
        &format!("/upload?parent={}", urlencoding::encode(drive_did.as_str())),
        &appstate,
    )
    .method(actix_web::http::Method::POST)
    .insert_header((
        "Content-Type",
        format!("multipart/form-data; boundary={multipart_boundary}"),
    ))
    .set_payload(body)
    .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "Upload failed: {:?}",
        resp.status()
    );

    let body_str = get_body(resp);
    assert!(body_str.contains(&expected_hash));

    // 2. Verify in DB
    let hash_bytes = blake3::hash(test_content);
    let blob = appstate
        .store
        .kv
        .get(atomic_lib::db::trees::Tree::Blobs, hash_bytes.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(blob, test_content);

    // 3. Download
    let req = build_request_authenticated(&format!("/download/files/{}", expected_hash), &appstate)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // The content-addressed route only gets a hash, but it must still answer
    // with the File's real mimetype: the response carries `nosniff`, so an
    // `application/octet-stream` answer makes the browser refuse to render the
    // bytes in an `<img>` — and `downloadURL` for every client-uploaded file
    // points here.
    assert_eq!(
        resp.headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain"),
        "content-addressed download must serve the uploaded mimetype"
    );

    let downloaded_bytes = test::read_body(resp).await;
    assert_eq!(downloaded_bytes, test_content.as_slice());
}

/// `GET /drive-usage` reports a drive's resource count + blob/Loro bytes for the
/// sync page. The frontend has shipped this UI for a while, but the endpoint was
/// never implemented server-side (it 404'd), so the usage bar silently never
/// appeared — this test guards against that regressing again.
#[actix_rt::test]
async fn drive_usage_endpoint() {
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts).expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    let drive_did = atomic_lib::test_utils::create_test_drive(&appstate.store)
        .await
        .unwrap();

    // Upload a file so the drive has a resource with a blob to account for.
    let test_content = b"hello blake3 world";
    let multipart_boundary = "boundary";
    let body = format!(
        "--{multipart_boundary}\r\n\
        Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\
        Content-Type: text/plain\r\n\r\n\
        {}\r\n\
        --{multipart_boundary}--\r\n",
        String::from_utf8_lossy(test_content)
    );
    let req = build_request_authenticated(
        &format!("/upload?parent={}", urlencoding::encode(drive_did.as_str())),
        &appstate,
    )
    .method(actix_web::http::Method::POST)
    .insert_header((
        "Content-Type",
        format!("multipart/form-data; boundary={multipart_boundary}"),
    ))
    .set_payload(body)
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "upload failed: {:?}",
        resp.status()
    );

    // Now the endpoint the sync page calls should report real numbers.
    let req = build_request_authenticated(
        &format!(
            "/drive-usage?subject={}",
            urlencoding::encode(drive_did.as_str())
        ),
        &appstate,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    let body = get_body(resp);
    assert!(status.is_success(), "drive-usage status {status}: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // camelCase field names — the shape `fetchNodeDriveUsage` reads.
    assert!(
        json["resourceCount"].as_u64().unwrap() >= 1,
        "expected at least the uploaded file counted: {body}"
    );
    assert_eq!(
        json["blobBytes"].as_u64().unwrap(),
        test_content.len() as u64,
        "blobBytes should equal the uploaded content length: {body}"
    );
    assert!(json.get("loroBytes").is_some(), "loroBytes missing: {body}");
}

/// `GET /server` describes the node itself as a `Server` resource, replacing the
/// bespoke `/node-info` and `/iroh-node-id` JSON shapes. It must be real JSON-AD
/// with an `isA` of Server, so any Atomic client can read it, not just our own
/// data-browser.
#[actix_rt::test]
async fn server_info_endpoint() {
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts).expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    // A node seeded before the `Server` properties existed still has to be able
    // to say what it is. Dropping one of the Property resources stands in for
    // such a store: rendering must not depend on the ontology being present,
    // or every existing deployment answers 500 until an operator repopulates.
    appstate
        .store
        .remove_resource(&urls::SERVER_VERSION.into())
        .await
        .expect("could not remove property");

    let req = build_request_authenticated("/server", &appstate).to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    let body = get_body(resp);
    assert!(status.is_success(), "/server status {status}: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json[urls::IS_A][0].as_str(),
        Some(urls::SERVER),
        "/server should be typed as a Server: {body}"
    );
    assert_eq!(
        json[urls::SERVER_VERSION].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "version should be this build's version: {body}"
    );
    // An unmanaged (self-hosted) node reports managed:false and omits the portal.
    assert_eq!(json[urls::SERVER_MANAGED].as_bool(), Some(false), "{body}");
    assert!(
        json.get(urls::SERVER_PORTAL_URL).is_none(),
        "portalUrl should be absent on a self-hosted node: {body}"
    );
}

/// With `ATOMIC_HOME_DRIVE` set, `/server` carries the drive as `homeDrive`.
/// The property was used by the endpoint before it existed in the default
/// store, so every node with a home drive answered 500 on `/server` — and the
/// data-browser then took its own origin for "not a node": no known server,
/// no place to register a private drive on sign-in.
#[actix_rt::test]
async fn server_info_endpoint_with_home_drive() {
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
        "--home-drive",
        "http://localhost/",
    ]);

    let mut config = config::build_config(opts).expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    // Plain JSON (not JSON-AD) needs every property's datatype to render, so
    // this is the representation that failed: the JSON-AD one got away with
    // the property missing from the store.
    let req = build_request_authenticated("/server", &appstate)
        .insert_header(("Accept", "application/json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    let body = get_body(resp);
    assert!(status.is_success(), "/server status {status}: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // Plain JSON keys by shortname.
    assert_eq!(
        json["home-drive"].as_str(),
        Some("http://localhost/"),
        "homeDrive should be the configured drive: {body}"
    );
}

/// The versioning round trip: `/all-versions` lists a resource's versions, and
/// each link it hands out resolves to that resource as it was then. Both read
/// the Loro oplog. Nothing covered either endpoint before, which is how they
/// stayed broken (links pointed at `/versioning`, a path that never existed).
#[actix_rt::test]
async fn version_endpoints() {
    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts).expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;

    // A resource renamed once, each edit committed as its own change the way a
    // client authors them — otherwise the two collapse into one Loro change,
    // and there is no history to travel.
    let agent = appstate.store.get_default_agent().unwrap().subject;
    let subject = format!("{}/version-test", appstate.config.get_origin());

    let doc = atomic_lib::loro::AtomicLoroDoc::new();
    doc.set_property(urls::READ, &vec![agent.clone()].into())
        .unwrap();
    doc.set_property(urls::WRITE, &vec![agent].into()).unwrap();
    doc.set_property(urls::NAME, &"first".to_string().into())
        .unwrap();
    doc.commit_with_message("e-1");

    doc.set_property(urls::NAME, &"second".to_string().into())
        .unwrap();
    doc.commit_with_message("e-2");

    let mut resource = atomic_lib::Resource::new(subject.as_str().into());
    resource.apply_state_doc(doc).unwrap();
    appstate
        .store
        .add_resource_opts(&resource, false, true, true)
        .await
        .unwrap();

    let req = build_request_authenticated(
        &format!("/all-versions?subject={}", urlencoding::encode(&subject)),
        &appstate,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    let body = get_body(resp);
    assert!(status.is_success(), "/all-versions status {status}: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let members = json[urls::COLLECTION_MEMBERS]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        members.len() >= 2,
        "two edits should be two versions: {body}"
    );

    // Newest first, so the last member is the resource as first written.
    let oldest = members.last().unwrap().as_str().unwrap();
    assert!(
        oldest.contains("/version?subject=") && oldest.contains("version-id="),
        "a version link must address a subject at a version: {oldest}"
    );

    let path = &oldest[oldest.find("/version?").unwrap()..];
    let req = build_request_authenticated(path, &appstate).to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    let body = get_body(resp);
    assert!(status.is_success(), "{path} status {status}: {body}");

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json[urls::NAME].as_str(),
        Some("first"),
        "the oldest version should read as the resource was first written: {body}"
    );

    // ...while the resource itself is still at its latest value.
    let req = build_request_authenticated("/version-test", &appstate).to_request();
    let resp = test::call_service(&app, req).await;
    let body = get_body(resp);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json[urls::NAME].as_str(),
        Some("second"),
        "reading a version must not move the live resource: {body}"
    );
}

/// Phase 3 of `planning/atomic-forms.md`: builds a Form + FormPage + FormField
/// graph pointing at a Table/Class pair (mirroring what the Phase 2
/// data-browser builder produces), then drives the two new HTTP endpoints
/// end to end: publish gating, slug minting + resolution, a valid
/// submission landing as a table row, and the required-field / honeypot /
/// unpublished rejection paths.
#[actix_rt::test]
async fn form_submission_flow() {
    use atomic_lib::{Resource, Value};

    let unique_string = atomic_lib::utils::random_string(10);
    use clap::Parser;
    let opts = Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{}/db", unique_string),
        "--config-dir",
        &format!("./.temp/{}/config", unique_string),
    ]);

    let mut config = config::build_config(opts).expect("failed init config");
    config.search_index_path = format!("./.temp/{}/search_index", unique_string).into();
    let appstate = crate::appstate::AppState::init(config.clone())
        .await
        .expect("failed init appstate");

    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;
    let store = &appstate.store;

    // Class + Property + Table (mirrors what NewFormDialog/useFormFieldPropertySync build client-side)
    let mut class = Resource::new_instance(urls::CLASS, store).await.unwrap();
    class
        .set(
            urls::SHORTNAME.into(),
            Value::Slug("submission".into()),
            store,
        )
        .await
        .unwrap();
    class
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("A form submission row".into()),
            store,
        )
        .await
        .unwrap();
    class.save_locally(store).await.unwrap();

    let mut email_prop = Resource::new_instance(urls::PROPERTY, store).await.unwrap();
    email_prop
        .set(urls::SHORTNAME.into(), Value::Slug("email".into()), store)
        .await
        .unwrap();
    email_prop
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("Respondent email".into()),
            store,
        )
        .await
        .unwrap();
    email_prop
        .set(
            urls::DATATYPE_PROP.into(),
            Value::AtomicUrl(urls::STRING.into()),
            store,
        )
        .await
        .unwrap();
    email_prop.save_locally(store).await.unwrap();

    let mut table = Resource::new_instance(urls::TABLE, store).await.unwrap();
    table
        .set(
            urls::NAME.into(),
            Value::String("Submissions".into()),
            store,
        )
        .await
        .unwrap();
    table
        .set(
            urls::CLASSTYPE_PROP.into(),
            Value::AtomicUrl(class.get_subject().to_string().into()),
            store,
        )
        .await
        .unwrap();
    table.save_locally(store).await.unwrap();

    // FormField -> FormPage -> Form
    let mut field = Resource::new_instance(urls::FORM_FIELD, store)
        .await
        .unwrap();
    field
        .set(urls::NAME.into(), Value::String("Email".into()), store)
        .await
        .unwrap();
    field
        .set(
            urls::FORM_MAPS_TO.into(),
            Value::AtomicUrl(email_prop.get_subject().to_string().into()),
            store,
        )
        .await
        .unwrap();
    field
        .set(
            urls::FORM_FIELD_TYPE.into(),
            Value::String("email".into()),
            store,
        )
        .await
        .unwrap();
    field
        .set(urls::REQUIRED.into(), Value::Boolean(true), store)
        .await
        .unwrap();
    field.save_locally(store).await.unwrap();

    let mut page = Resource::new_instance(urls::FORM_PAGE, store)
        .await
        .unwrap();
    page.set(
        urls::FORM_FIELDS.into(),
        Value::ResourceArray(vec![field.get_subject().to_string().into()]),
        store,
    )
    .await
    .unwrap();
    page.save_locally(store).await.unwrap();

    let mut form = Resource::new_instance(urls::FORM, store).await.unwrap();
    form.set(urls::NAME.into(), Value::String("Feedback".into()), store)
        .await
        .unwrap();
    form.set(
        urls::FORM_DATA_CLASS.into(),
        Value::AtomicUrl(class.get_subject().to_string().into()),
        store,
    )
    .await
    .unwrap();
    form.set(
        urls::FORM_TARGET_TABLE.into(),
        Value::AtomicUrl(table.get_subject().to_string().into()),
        store,
    )
    .await
    .unwrap();
    form.set(
        urls::FORM_PAGES.into(),
        Value::ResourceArray(vec![page.get_subject().to_string().into()]),
        store,
    )
    .await
    .unwrap();
    // DID (genesis) subject — matches how forms are actually created by the
    // data-browser client, and exercises the slug bootstrap fallback below.
    form.save_as_genesis(store).await.unwrap();
    let form_did_id = form.get_subject().pure_id();

    // 1. Unpublished -> 410
    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition", form_did_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 410, "unpublished form should 410");

    // 1b. The unpublished HTML page (`not_available_page`) still allows
    // embedding — Phase 6 "Embedding": a stale snippet should show the
    // friendly closed-form card inside the iframe, not a browser-blocked
    // blank frame.
    let req = test::TestRequest::get()
        .uri(&format!("/form/{}", form_did_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.headers().get("Content-Security-Policy").unwrap(),
        "frame-ancestors *",
        "unpublished form page should allow embedding"
    );

    // 2. Publish, GET by DID -> 200, slug gets minted
    form.set(
        urls::FORM_PUBLISHED_AT.into(),
        Value::Timestamp(atomic_lib::utils::now()),
        store,
    )
    .await
    .unwrap();
    form.save_locally(store).await.unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition", form_did_id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "definition fetch after publish failed: {:?}",
        resp.status()
    );
    let body: serde_json::Value = serde_json::from_str(&get_body(resp)).unwrap();
    let slug = body["id"]
        .as_str()
        .expect("slug should be minted")
        .to_string();
    assert!(!slug.is_empty());
    assert_eq!(
        body["pages"][0]["blocks"][0]["mapsTo"],
        email_prop.get_subject().to_string()
    );
    assert_eq!(
        body["captcha"]["challengeUrl"],
        format!("/form/{slug}/challenge"),
        "definition should carry the captcha client config"
    );

    // 3. GET by the minted slug -> same definition
    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "definition fetch by slug failed"
    );

    // 3b. Phase 6 "Embedding": the published HTML page allows framing from
    // any origin (forms have no auth boundary once published — same trust
    // level as the direct share link).
    let req = test::TestRequest::get()
        .uri(&format!("/form/{}", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let csp = resp
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("frame-ancestors *"),
        "published form page should allow embedding: {csp}"
    );

    // 3c. Captcha: fetch a challenge and solve it natively (difficulty is
    // lowered under cfg(test) — see `crate::captcha`), mirroring what the
    // ALTCHA widget does in the visitor's browser.
    macro_rules! solve_captcha {
        () => {{
            let req = test::TestRequest::get()
                .uri(&format!("/form/{}/challenge", slug))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert!(resp.status().is_success(), "challenge fetch failed");
            let challenge: altcha::Challenge =
                serde_json::from_str(&get_body(resp)).expect("challenge should parse");
            let solution =
                altcha::solve_challenge(altcha::SolveChallengeOptions::new(&challenge))
                    .unwrap()
                    .expect("challenge should be solvable");
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "challenge": challenge,
                    "solution": solution,
                }))
                .unwrap(),
            )
        }};
    }

    // 4. Valid submission (with solved captcha) -> 201, row lands under the table
    let captcha_payload = solve_captcha!();
    let submit_body = serde_json::json!({
        "values": { email_prop.get_subject().to_string(): "visitor@example.com" },
        "altcha": captcha_payload,
    });
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&submit_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        201,
        "valid submission should succeed: {}",
        get_body(resp)
    );

    let query =
        atomic_lib::storelike::Query::new_prop_val(urls::PARENT, table.get_subject().as_str());
    let result = store.query(&query).await.unwrap();
    assert_eq!(
        result.subjects.len(),
        1,
        "submission row should exist under the table"
    );

    // 4b. Missing captcha payload -> 400
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({
            "values": { email_prop.get_subject().to_string(): "visitor2@example.com" }
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "captcha-less submission should be rejected"
    );

    // 4c. Replayed captcha payload (already consumed by step 4) -> 400
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({
            "values": { email_prop.get_subject().to_string(): "visitor2@example.com" },
            "altcha": captcha_payload,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400, "replayed captcha should be rejected");

    // 5. Missing required field -> 400 with a field error (fresh captcha —
    // field validation runs after captcha verification)
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({ "values": {}, "altcha": solve_captcha!() }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = serde_json::from_str(&get_body(resp)).unwrap();
    assert!(body["errors"][0]["message"].as_str().is_some());

    // 6. Honeypot filled -> 400 (checked before the captcha, so no payload needed)
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({
            "values": { email_prop.get_subject().to_string(): "bot@example.com" },
            "hp": "i-am-a-bot",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "honeypot-filled submission should be rejected"
    );

    // Only the one valid submission from step 4 should have landed.
    let result = store.query(&query).await.unwrap();
    assert_eq!(result.subjects.len(), 1);

    // 7. Unpublish -> submit now 410
    form.remove_propval(urls::FORM_PUBLISHED_AT).unwrap();
    form.save_locally(store).await.unwrap();

    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&submit_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 410, "submit to unpublished form should 410");

    // 8. Private links (Phase 6): republish and switch to invite-only.
    form.set(
        urls::FORM_PUBLISHED_AT.into(),
        Value::Timestamp(atomic_lib::utils::now()),
        store,
    )
    .await
    .unwrap();
    form.set(
        urls::FORM_ACCESS.into(),
        Value::String("invite-only".into()),
        store,
    )
    .await
    .unwrap();
    form.save_locally(store).await.unwrap();

    // Definition without / with an unknown code -> 403 (the questions must
    // not leak to someone holding only the share URL).
    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        403,
        "invite-only definition without code should 403"
    );

    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition?code=wrong", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        403,
        "invite-only definition with unknown code should 403"
    );

    // The HTML page is gated the same way (the definition is injected inline).
    let req = test::TestRequest::get()
        .uri(&format!("/form/{}", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        403,
        "invite-only form page without code should 403"
    );

    // Mint an invite code, child of the form (as the builder UI does).
    let mut invite = Resource::new_instance(urls::FORM_INVITE_CODE, store)
        .await
        .unwrap();
    invite
        .set(
            urls::PARENT.into(),
            Value::AtomicUrl(form.get_subject().to_string().into()),
            store,
        )
        .await
        .unwrap();
    invite
        .set(
            urls::FORM_CODE.into(),
            Value::String("secret-code".into()),
            store,
        )
        .await
        .unwrap();
    invite.save_locally(store).await.unwrap();

    // Definition with the code -> 200, and fetching does NOT consume it.
    for _ in 0..2 {
        let req = test::TestRequest::get()
            .uri(&format!("/form/{}/definition?code=secret-code", slug))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "invite-only definition with valid code should succeed: {:?}",
            resp.status()
        );
    }

    // Submit without a code -> 403 (pre-check runs before captcha
    // verification, so no solved payload is needed).
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({
            "values": { email_prop.get_subject().to_string(): "visitor3@example.com" }
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        403,
        "invite-only submit without code should 403"
    );

    // Submit with the code -> 201, and the code is now consumed.
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({
            "values": { email_prop.get_subject().to_string(): "invited@example.com" },
            "altcha": solve_captcha!(),
            "code": "secret-code",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        201,
        "invite-only submit with valid code should succeed: {}",
        get_body(resp)
    );
    let result = store.query(&query).await.unwrap();
    assert_eq!(
        result.subjects.len(),
        2,
        "invited submission should land in the table"
    );
    let invite = store
        .get_resource(&invite.get_subject().clone())
        .await
        .unwrap();
    assert!(
        invite.get(urls::USED_AT).is_ok(),
        "the invite code should be marked used after the submission"
    );

    // Replaying the consumed code -> 403 on both submit and definition.
    let req = test::TestRequest::post()
        .uri(&format!("/form/{}/submit", slug))
        .set_json(&serde_json::json!({
            "values": { email_prop.get_subject().to_string(): "sneaky@example.com" },
            "code": "secret-code",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403, "used code should be rejected at submit");

    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition?code=secret-code", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        403,
        "used code should be rejected at definition"
    );

    // No row landed for the rejected replay.
    let result = store.query(&query).await.unwrap();
    assert_eq!(result.subjects.len(), 2);

    // Switching back to public opens the plain link again.
    form.set(
        urls::FORM_ACCESS.into(),
        Value::String("public".into()),
        store,
    )
    .await
    .unwrap();
    form.save_locally(store).await.unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/form/{}/definition", slug))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "public definition should work again after switching back"
    );
}
