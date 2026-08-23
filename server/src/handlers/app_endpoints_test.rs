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
                Value::Markdown("export function view({ root }) { root.textContent = 'hi'; }".into()),
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
    app_resource
        .save(&fixture.appstate.store)
        .await
        .unwrap();

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
                fixture.drive, app, urls::NAME,
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
    assert!(
        body_of(response).contains("not allowed to write"),
        "the refusal should say what was refused",
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
