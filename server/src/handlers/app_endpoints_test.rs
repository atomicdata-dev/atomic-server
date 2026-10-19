//! The HTTP surface an app depends on, exercised against a real store.
//!
//! Kept here rather than in the e2e suite on purpose: none of this needs a
//! browser, and a Playwright run costs a hundred times what these do. What the
//! e2e suite is for is the one thing these cannot reach — an iframe actually
//! loading the module and talking back.

use actix_web::{
    body::MessageBody,
    dev::ServiceResponse,
    test::{self, TestRequest},
    web::Data,
    App,
};
use atomic_lib::{agents::Agent, db::app_agent::AppAgentKey, urls, Storelike, Value};

use crate::appstate::AppState;
use crate::plugins::test_fixture::{fixture, genesis, Fixture};

/// Signs as the store's default agent, the way every other server test does.
fn signed(path: &str, appstate: &AppState) -> TestRequest {
    let origin = appstate.config.get_origin();
    let url = format!("{origin}{path}");
    let headers = atomic_lib::client::get_authentication_headers(
        &url,
        &appstate.store.get_default_agent().unwrap(),
    )
    .expect("auth headers");

    let mut request = TestRequest::with_uri(path);

    for (key, value) in headers {
        request = request.insert_header((key, value));
    }

    if let Ok(parsed) = url::Url::parse(&origin) {
        if let Some(host) = parsed.host_str() {
            let authority = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            request = request.insert_header(("Host", authority));
        }
    }

    request
}

/// Signs as someone other than this node's own agent — a collaborator.
fn signed_as(path: &str, appstate: &AppState, agent: &Agent) -> TestRequest {
    let origin = appstate.config.get_origin();
    let url = format!("{origin}{path}");
    let headers =
        atomic_lib::client::get_authentication_headers(&url, agent).expect("auth headers");

    let mut request = TestRequest::with_uri(path);

    for (key, value) in headers {
        request = request.insert_header((key, value));
    }

    if let Ok(parsed) = url::Url::parse(&origin) {
        if let Some(host) = parsed.host_str() {
            let authority = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            request = request.insert_header(("Host", authority));
        }
    }

    request
}

/// Publishes an agent so the server can verify its signatures, and gives it
/// `right` on `target` — which is exactly what the Share dialog does.
async fn share(fixture: &Fixture, target: &str, agent: &Agent, right: &str) {
    let mut profile = atomic_lib::Resource::new(agent.subject.to_string());
    profile
        .set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::AGENT.into()]),
        )
        .unwrap();
    profile
        .set_unsafe(
            urls::PUBLIC_KEY.into(),
            Value::String(agent.public_key.clone()),
        )
        .unwrap();
    profile.save(&fixture.appstate.store).await.unwrap();

    let mut resource = fixture
        .appstate
        .store
        .get_resource(&target.into())
        .await
        .unwrap();
    resource
        .push(right, agent.subject.to_string().into(), true)
        .unwrap();
    resource.save(&fixture.appstate.store).await.unwrap();
}

fn create_payload(fixture: &Fixture, app: &str, name: &str) -> String {
    format!(
        r#"{{"drive":{:?},"app":{:?},"op":"create","propVals":{{{:?}:{:?}}}}}"#,
        fixture.drive,
        app,
        urls::NAME,
        name,
    )
}

fn body_of(response: ServiceResponse) -> String {
    let bytes = response
        .into_body()
        .try_into_bytes()
        .expect("a complete body");

    String::from_utf8_lossy(&bytes).to_string()
}

/// An app with a view, its own key, and something of its own to write into.
async fn app_fixture(name: &str) -> (Fixture, String) {
    let mut fixture = fixture(name).await;

    let app = genesis(
        &fixture.appstate.store,
        vec![
            (
                urls::PARENT,
                Value::AtomicUrl(fixture.drive.as_str().into()),
            ),
            (urls::NAME, Value::String("Test app".into())),
        ],
    )
    .await;

    fixture.plugin = genesis(
        &fixture.appstate.store,
        vec![
            (urls::PARENT, Value::AtomicUrl(app.as_str().into())),
            (urls::NAME, Value::String("Test app view".into())),
            (
                fixture.terms.property("plugin-source").unwrap(),
                Value::Markdown(
                    "export function view({ root }) { root.textContent = 'hi'; }".into(),
                ),
            ),
        ],
    )
    .await;

    let agent = Agent::new(Some("test app")).unwrap();

    // What `createApp` does: the app's DID goes on the app's own write list,
    // so "an app may write its own data" is what the rights walk says rather
    // than a rule stated anywhere else. Rights inherit to its children.
    let mut app_resource = fixture
        .appstate
        .store
        .get_resource(&app.as_str().into())
        .await
        .unwrap();
    app_resource
        .push(urls::WRITE, agent.subject.to_string().into(), true)
        .unwrap();
    app_resource.save(&fixture.appstate.store).await.unwrap();

    fixture
        .appstate
        .store
        .set_app_agent(
            &AppAgentKey::new(&fixture.drive, &app),
            &atomic_lib::db::app_agent::AppAgent::new(
                agent.subject.to_string(),
                agent.build_secret().unwrap(),
                0,
            ),
        )
        .unwrap();

    (fixture, app)
}

#[actix_rt::test]
async fn a_view_is_served_only_to_something_holding_a_token() {
    let (fixture, _app) = app_fixture("app_view_token").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    let query = format!(
        "drive={}&plugin={}",
        urlencoding::encode(&fixture.drive),
        urlencoding::encode(&fixture.plugin),
    );

    // No token: a plugin's source is a resource, so serving it to anyone who
    // can guess a subject would publish drive content.
    let refused = test::call_service(
        &service,
        TestRequest::with_uri(&format!("/plugin-ui?{query}&format=js")).to_request(),
    )
    .await;

    assert_eq!(refused.status(), 401);

    let minted = test::call_service(
        &service,
        signed("/plugin-view-token", &fixture.appstate)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(format!(
                r#"{{"drive":{:?},"plugin":{:?}}}"#,
                fixture.drive, fixture.plugin,
            ))
            .to_request(),
    )
    .await;

    assert_eq!(minted.status(), 200);

    let token: serde_json::Value = serde_json::from_str(&body_of(minted)).expect("json");
    let token = token["token"].as_str().expect("a token").to_string();

    let served = test::call_service(
        &service,
        TestRequest::with_uri(&format!("/plugin-ui?{query}&token={token}&format=js")).to_request(),
    )
    .await;

    assert_eq!(served.status(), 200);
    assert!(
        body_of(served).contains("export function view"),
        "the source should come from the resource, not the filesystem",
    );
}

#[actix_rt::test]
async fn a_token_does_not_open_another_plugin() {
    let (fixture, _app) = app_fixture("app_token_scope").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    let minted = test::call_service(
        &service,
        signed("/plugin-view-token", &fixture.appstate)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(format!(
                r#"{{"drive":{:?},"plugin":{:?}}}"#,
                fixture.drive, fixture.plugin,
            ))
            .to_request(),
    )
    .await;

    let token: serde_json::Value = serde_json::from_str(&body_of(minted)).expect("json");
    let token = token["token"].as_str().expect("a token").to_string();

    // A drive with one shared app must not expose every app on it.
    let elsewhere = test::call_service(
        &service,
        TestRequest::with_uri(&format!(
            "/plugin-ui?drive={}&plugin={}&token={token}&format=js",
            urlencoding::encode(&fixture.drive),
            urlencoding::encode("did:ad:someone-elses-plugin"),
        ))
        .to_request(),
    )
    .await;

    assert_eq!(elsewhere.status(), 401);
}

#[actix_rt::test]
async fn an_app_writes_its_own_data_as_itself() {
    let (fixture, app) = app_fixture("app_write_own").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    let response = test::call_service(
        &service,
        signed("/app-write", &fixture.appstate)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(format!(
                r#"{{"drive":{:?},"app":{:?},"op":"create","propVals":{{{:?}:"A note"}}}}"#,
                fixture.drive,
                app,
                urls::NAME,
            ))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), 200, "{}", body_of(response));

    // The point of routing the write through the server at all: the commit is
    // authored by the app, not by the person who happened to open it.
    let written: serde_json::Value = serde_json::from_str(&body_of(response)).expect("json");
    let subject = written["subject"].as_str().expect("a subject");

    let resource = fixture
        .appstate
        .store
        .get_resource(&subject.into())
        .await
        .unwrap();
    let last_commit = resource.get(urls::LAST_COMMIT).unwrap().to_string();
    let commit = fixture
        .appstate
        .store
        .get_resource(&last_commit.as_str().into())
        .await
        .unwrap();

    let app_agent = fixture
        .appstate
        .store
        .get_app_agent_info(&AppAgentKey::new(&fixture.drive, &app))
        .unwrap()
        .unwrap()
        .agent;

    assert_eq!(commit.get(urls::SIGNER).unwrap().to_string(), app_agent);
    assert_ne!(
        commit.get(urls::SIGNER).unwrap().to_string(),
        fixture
            .appstate
            .store
            .get_default_agent()
            .unwrap()
            .subject
            .to_string(),
        "the server signed a write an app decided on",
    );
}

#[actix_rt::test]
async fn an_app_cannot_write_outside_itself() {
    let (fixture, app) = app_fixture("app_write_outside").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    // The caller may write the whole drive. The app may not, and opening an
    // app does not lend it the opener's reach — which is the entire reason an
    // app has an identity of its own.
    let response = test::call_service(
        &service,
        signed("/app-write", &fixture.appstate)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(format!(
                r#"{{"drive":{:?},"app":{:?},"op":"create","parent":{:?},"propVals":{{}}}}"#,
                fixture.drive, app, fixture.drive,
            ))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = serde_json::from_str(&body_of(response)).unwrap();
    assert_eq!(body["https://atomicdata.dev/properties/errorCode"], 3);
    assert!(
        body["https://atomicdata.dev/properties/description"]
            .as_str()
            .unwrap()
            .contains("https://atomicdata.dev/properties/write"),
        "the refusal should identify the denied write permission",
    );
}

#[actix_rt::test]
async fn an_app_with_no_key_is_told_so() {
    let fixture = fixture("app_write_keyless").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    let response = test::call_service(
        &service,
        signed("/app-write", &fixture.appstate)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(format!(
                r#"{{"drive":{:?},"app":{:?},"op":"create","propVals":{{}}}}"#,
                fixture.drive, fixture.drive,
            ))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), 400);
    assert!(body_of(response).contains("no key of its own"));
}

#[actix_rt::test]
async fn someone_the_app_was_shared_with_can_use_it() {
    let (fixture, app) = app_fixture("app_shared_write").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    // Sharing an app is sharing a resource: the same rights arrays, the same
    // dialog, no mechanism of its own.
    let collaborator = Agent::new(Some("collaborator")).unwrap();
    share(&fixture, &app, &collaborator, urls::WRITE).await;

    // Opening it first: the view is a child of the app, so read inherits down
    // the parent chain and sharing the app shares the screen with it. Nothing
    // has to be shared twice.
    let opened = test::call_service(
        &service,
        signed_as("/plugin-view-token", &fixture.appstate, &collaborator)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(format!(
                r#"{{"drive":{:?},"plugin":{:?}}}"#,
                fixture.drive, fixture.plugin,
            ))
            .to_request(),
    )
    .await;

    assert_eq!(opened.status(), 200, "{}", body_of(opened));

    let response = test::call_service(
        &service,
        signed_as("/app-write", &fixture.appstate, &collaborator)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(create_payload(&fixture, &app, "Added by a collaborator"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), 200, "{}", body_of(response));

    // Still authored by the app, not by whoever happened to click. Two people
    // using one app produce one voice, which is what makes its data coherent.
    let written: serde_json::Value = serde_json::from_str(&body_of(response)).expect("json");
    let subject = written["subject"].as_str().expect("a subject");
    let resource = fixture
        .appstate
        .store
        .get_resource(&subject.into())
        .await
        .unwrap();
    let commit = fixture
        .appstate
        .store
        .get_resource(
            &resource
                .get(urls::LAST_COMMIT)
                .unwrap()
                .to_string()
                .as_str()
                .into(),
        )
        .await
        .unwrap();

    let app_agent = fixture
        .appstate
        .store
        .get_app_agent_info(&AppAgentKey::new(&fixture.drive, &app))
        .unwrap()
        .unwrap()
        .agent;

    assert_eq!(commit.get(urls::SIGNER).unwrap().to_string(), app_agent);
    assert_ne!(
        commit.get(urls::SIGNER).unwrap().to_string(),
        collaborator.subject.to_string(),
    );
}

#[actix_rt::test]
async fn read_only_means_look_not_touch() {
    let (fixture, app) = app_fixture("app_shared_read").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    // Shared to look at. An app's buttons must not be a way around that.
    let onlooker = Agent::new(Some("onlooker")).unwrap();
    share(&fixture, &app, &onlooker, urls::READ).await;

    let response = test::call_service(
        &service,
        signed_as("/app-write", &fixture.appstate, &onlooker)
            .method(actix_web::http::Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(create_payload(&fixture, &app, "Should not exist"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), 401, "{}", body_of(response));
}

/// A version 2 request signature (ontola/atomic-plugins#54): covers method
/// and body as well as the URL. `sign_body` is what the signer thinks it
/// sent; `send_body` is what actually goes over the wire.
fn signed_v2(
    path: &str,
    appstate: &AppState,
    method: actix_web::http::Method,
    sign_body: &str,
    send_body: &str,
) -> TestRequest {
    let origin = appstate.config.get_origin();
    let url = format!("{origin}{path}");
    let headers = atomic_lib::client::get_authentication_headers_v2(
        method.as_str(),
        &url,
        sign_body.as_bytes(),
        &appstate.store.get_default_agent().unwrap(),
    )
    .expect("auth headers");

    let mut request = TestRequest::with_uri(path)
        .method(method)
        .insert_header(("Content-Type", "application/json"))
        .set_payload(send_body.to_string());

    for (key, value) in headers {
        request = request.insert_header((key, value));
    }

    if let Ok(parsed) = url::Url::parse(&origin) {
        if let Some(host) = parsed.host_str() {
            let authority = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            request = request.insert_header(("Host", authority));
        }
    }

    request
}

/// `/plugin-view-token` and `/app-agent` accept a version 2 signature, and
/// check the body with it: the same headers on a different body are refused.
/// Version 1 keeps working on both (not required yet).
#[actix_rt::test]
async fn v2_signatures_bind_the_body() {
    use actix_web::http::Method;

    let (fixture, app) = app_fixture("app_v2_signatures").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    let body = format!(
        r#"{{"drive":{:?},"plugin":{:?}}}"#,
        fixture.drive, fixture.plugin,
    );
    let ok = test::call_service(
        &service,
        signed_v2(
            "/plugin-view-token",
            &fixture.appstate,
            Method::POST,
            &body,
            &body,
        )
        .to_request(),
    )
    .await;
    assert_eq!(ok.status(), 200, "{}", body_of(ok));

    let other = format!(
        r#"{{"drive":{:?},"plugin":{:?} }}"#,
        fixture.drive, fixture.plugin,
    );
    let swapped = test::call_service(
        &service,
        signed_v2(
            "/plugin-view-token",
            &fixture.appstate,
            Method::POST,
            &body,
            &other,
        )
        .to_request(),
    )
    .await;
    assert_eq!(swapped.status(), 401, "a different body than was signed");
    assert!(body_of(swapped).contains("version 2"));

    // The method is covered too.
    let wrong_method = test::call_service(
        &service,
        signed_v2(
            "/plugin-view-token",
            &fixture.appstate,
            Method::PUT,
            &body,
            &body,
        )
        .method(Method::POST)
        .to_request(),
    )
    .await;
    assert_eq!(wrong_method.status(), 401);

    // `/app-agent`: the key a captured v1 proof could have swapped. A GET
    // (empty body) works as v2, and a POST whose secret differs from the one
    // signed is refused before anything is stored.
    let query = format!(
        "/app-agent?drive={}&app={}",
        urlencoding::encode(&fixture.drive),
        urlencoding::encode(&app),
    );
    let read = test::call_service(
        &service,
        signed_v2(&query, &fixture.appstate, Method::GET, "", "").to_request(),
    )
    .await;
    assert_eq!(read.status(), 200, "{}", body_of(read));

    let before = fixture
        .appstate
        .store
        .get_app_agent_info(&AppAgentKey::new(&fixture.drive, &app))
        .unwrap()
        .unwrap()
        .agent;
    let signed_secret = Agent::new(None).unwrap().build_secret().unwrap();
    let attacker_secret = Agent::new(None).unwrap().build_secret().unwrap();
    let set = |secret: &str| {
        format!(
            r#"{{"drive":{:?},"app":{:?},"secret":{:?}}}"#,
            fixture.drive, app, secret
        )
    };
    let refused = test::call_service(
        &service,
        signed_v2(
            "/app-agent",
            &fixture.appstate,
            Method::POST,
            &set(&signed_secret),
            &set(&attacker_secret),
        )
        .to_request(),
    )
    .await;
    assert_eq!(refused.status(), 401);
    let after = fixture
        .appstate
        .store
        .get_app_agent_info(&AppAgentKey::new(&fixture.drive, &app))
        .unwrap()
        .unwrap()
        .agent;
    assert_eq!(before, after, "nothing was stored");

    // Version 1 still works where v2 is accepted.
    let v1 = test::call_service(
        &service,
        signed("/plugin-view-token", &fixture.appstate)
            .method(Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body.clone())
            .to_request(),
    )
    .await;
    assert_eq!(v1.status(), 200);
}

/// An endpoint that does not bind method and body yet refuses a v2
/// signature outright instead of checking it as v1, and an unknown version
/// is refused everywhere. `/upload` is the one that stays on v1: it streams a
/// multipart body, so there is nothing buffered to hash.
#[actix_rt::test]
async fn v2_is_never_downgraded_to_v1() {
    use actix_web::http::Method;

    let (fixture, _app) = app_fixture("app_v2_downgrade").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;

    let path = format!("/upload?parent={}", urlencoding::encode(&fixture.drive));
    let multipart = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhi\r\n--b--\r\n";
    let unbound = test::call_service(
        &service,
        signed_v2(&path, &fixture.appstate, Method::POST, multipart, multipart)
            .insert_header(("Content-Type", "multipart/form-data; boundary=b"))
            .to_request(),
    )
    .await;
    assert_eq!(unbound.status(), 401);
    assert!(
        body_of(unbound).contains("does not check version 2"),
        "the caller is told to sign with version 1"
    );

    let body = format!(
        r#"{{"drive":{:?},"plugin":{:?}}}"#,
        fixture.drive, fixture.plugin,
    );
    let unknown = test::call_service(
        &service,
        signed("/plugin-view-token", &fixture.appstate)
            .method(Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .insert_header(("x-atomic-signature-version", "3"))
            .set_payload(body.clone())
            .to_request(),
    )
    .await;
    assert_eq!(unknown.status(), 401);

    // A v1 proof labelled as v2 is checked as v2, and fails.
    let relabelled = test::call_service(
        &service,
        signed("/plugin-view-token", &fixture.appstate)
            .method(Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .insert_header(("x-atomic-signature-version", "2"))
            .set_payload(body)
            .to_request(),
    )
    .await;
    assert_eq!(relabelled.status(), 401);
}

/// A plugin write route that takes a JSON body (`/plugin-schedule`) accepts a
/// version 2 signature and checks the body with it: the same headers on a
/// different body are refused, which is the replay a version 1 proof allows.
/// Version 1 keeps working.
#[actix_rt::test]
async fn plugin_routes_bind_the_body_with_v2() {
    use actix_web::http::Method;

    let (fixture, _app) = app_fixture("plugin_v2_signatures").await;
    let service = test::init_service(
        App::new()
            .app_data(Data::new(fixture.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;
    let body = |interval: &str| {
        format!(
            r#"{{"drive":{:?},"plugin":{:?},"intervalSeconds":{interval}}}"#,
            fixture.drive, fixture.plugin,
        )
    };
    let stop = body("null");

    let ok = test::call_service(
        &service,
        signed_v2(
            "/plugin-schedule",
            &fixture.appstate,
            Method::POST,
            &stop,
            &stop,
        )
        .to_request(),
    )
    .await;
    assert_eq!(ok.status(), 200, "{}", body_of(ok));

    // Signed for "stop", sent as "every 60 seconds": refused, and nothing set.
    let swapped = test::call_service(
        &service,
        signed_v2(
            "/plugin-schedule",
            &fixture.appstate,
            Method::POST,
            &stop,
            &body("60"),
        )
        .to_request(),
    )
    .await;
    assert_eq!(swapped.status(), 401, "a different body than was signed");
    assert!(body_of(swapped).contains("version 2"));
    let key =
        atomic_lib::db::plugin_schedule::PluginScheduleKey::new(&fixture.drive, &fixture.plugin);
    assert!(fixture
        .appstate
        .store
        .get_plugin_schedule(&key)
        .unwrap()
        .is_none());

    let v1 = test::call_service(
        &service,
        signed("/plugin-schedule", &fixture.appstate)
            .method(Method::POST)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(stop.clone())
            .to_request(),
    )
    .await;
    assert_eq!(v1.status(), 200, "{}", body_of(v1));

    // A body that is not JSON is a 400, not a crash.
    let garbled = test::call_service(
        &service,
        signed_v2(
            "/plugin-schedule",
            &fixture.appstate,
            Method::POST,
            "{",
            "{",
        )
        .to_request(),
    )
    .await;
    assert_eq!(garbled.status(), 400);
}
