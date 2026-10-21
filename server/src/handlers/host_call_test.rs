//! `POST /host/call` against a real store and a real component: the signed-in
//! agent's rights bound what the app may do, and unsigned callers get nothing.

use actix_web::{
    body::MessageBody,
    dev::ServiceResponse,
    test::{self, TestRequest},
    web::Data,
    App,
};
use atomic_lib::{agents::Agent, Storelike};
use serde_json::{json, Value};

use crate::{
    appstate::AppState,
    plugins::{
        host_abi::tests::{
            count_of, counter_resource, install, share, COUNTER_MANIFEST, COUNTER_WASM,
        },
        test_fixture::fixture,
    },
};

/// A request signed over its method, URL and exactly `body` (version 2).
fn post(path: &str, appstate: &AppState, agent: Option<&Agent>, body: Value) -> TestRequest {
    post_signed_over(path, appstate, agent, &body, &body)
}

/// Signs `signed`, sends `sent`.
fn post_signed_over(
    path: &str,
    appstate: &AppState,
    agent: Option<&Agent>,
    signed: &Value,
    sent: &Value,
) -> TestRequest {
    let origin = appstate.config.get_origin();
    let mut request = TestRequest::post()
        .uri(path)
        .insert_header(("Content-Type", "application/json"))
        .set_payload(serde_json::to_vec(sent).unwrap());
    if let Some(agent) = agent {
        let headers = atomic_lib::client::get_authentication_headers_v2(
            "POST",
            &format!("{origin}{path}"),
            &serde_json::to_vec(signed).unwrap(),
            agent,
        )
        .expect("auth headers");
        for (key, value) in headers {
            request = request.insert_header((key, value));
        }
    }
    if let Some(host) = url::Url::parse(&origin).ok().and_then(|u| {
        u.host_str()
            .map(|h| u.port().map_or(h.to_string(), |p| format!("{h}:{p}")))
    }) {
        request = request.insert_header(("Host", host));
    }
    request
}

async fn json_of(response: ServiceResponse) -> (u16, Value) {
    let status = response.status().as_u16();
    let bytes = response.into_body().try_into_bytes().expect("a body");
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into())),
    )
}

#[actix_rt::test]
async fn host_call_runs_an_export_as_the_signed_in_agent_bounded_by_the_app() {
    let f = fixture("host_call_http").await;
    let db = &f.appstate.store;
    let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    let service = test::init_service(
        App::new()
            .app_data(Data::new(f.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await;
    let owner = db.get_default_agent().unwrap();
    let body = |interface: &str, args: Value| {
        json!({
            "drive": f.drive,
            "interface": interface,
            "function": "increment",
            "args": args,
        })
    };
    let good = json!({"subject": subject, "property": property});
    let counter_interface = "atomic:example/counter@1";

    // Signed by the drive's owner: the counter app runs and writes as itself.
    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            Some(&owner),
            body(counter_interface, good.clone()),
        )
        .to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    assert_eq!((status, answer), (200, json!({"result": {"count": 1}})));
    assert_eq!(count_of(db, &subject, &property).await, 1);

    // Unsigned: nothing runs.
    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            None,
            body(counter_interface, good.clone()),
        )
        .to_request(),
    )
    .await;
    assert_eq!(response.status(), 401);
    assert_eq!(count_of(db, &subject, &property).await, 1);

    // Signed by an agent with no rights on the resource: the app has them, the
    // caller does not, and the call is bounded by both.
    let stranger = Agent::new(Some("stranger")).unwrap();
    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            Some(&stranger),
            body(counter_interface, good.clone()),
        )
        .to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "forbidden");
    assert_eq!(count_of(db, &subject, &property).await, 1);

    // Arguments the export's schema refuses, and an export nobody declared.
    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            Some(&owner),
            body(counter_interface, json!({"subject": subject})),
        )
        .to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    assert_eq!(status, 400, "{answer}");
    assert_eq!(answer["error"]["code"], "invalid-argument");

    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            Some(&owner),
            body("atomic:example/missing@1", good),
        )
        .to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    assert_eq!(status, 404, "{answer}");
    assert_eq!(answer["error"]["code"], "not-found");
    assert_eq!(count_of(db, &subject, &property).await, 1);
}

async fn service_for(
    f: &crate::plugins::test_fixture::Fixture,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new()
            .app_data(Data::new(f.appstate.clone()))
            .configure(crate::routes::config_routes),
    )
    .await
}

#[actix_rt::test]
async fn a_body_altered_after_signing_is_refused() {
    let f = fixture("host_call_tamper").await;
    let db = &f.appstate.store;
    let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let service = service_for(&f).await;
    let owner = db.get_default_agent().unwrap();

    let make = |property: &str| {
        json!({
            "drive": f.drive,
            "interface": "atomic:example/counter@1",
            "function": "increment",
            "args": {"subject": subject, "property": property},
        })
    };
    let signed = make(&property);
    // Same route, same signer, other arguments.
    let sent = make("https://example.com/other-property");
    let response = test::call_service(
        &service,
        post_signed_over("/host/call", &f.appstate, Some(&owner), &signed, &sent).to_request(),
    )
    .await;
    assert_eq!(response.status(), 401);
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // The unaltered body is accepted.
    let response = test::call_service(
        &service,
        post_signed_over("/host/call", &f.appstate, Some(&owner), &signed, &signed).to_request(),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(count_of(db, &subject, &property).await, 1);
}

#[actix_rt::test]
async fn the_caller_needs_the_drive_and_its_export_needs_the_callers_effects() {
    let f = fixture("host_call_drive_rights").await;
    let db = &f.appstate.store;
    let counter = install(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let service = service_for(&f).await;
    let owner = db.get_default_agent().unwrap();
    let interface = "atomic:example/counter@1";
    let body = |extra: Value| {
        let mut body = json!({
            "drive": f.drive,
            "interface": interface,
            "function": "increment",
            "args": {"subject": subject, "property": property},
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let forbidden = |status: u16, answer: &Value| {
        assert_eq!(status, 403, "{answer}");
        assert_eq!(answer["error"]["code"], "forbidden");
    };

    // A stranger: not allowed to see the drive, so nothing is even loaded.
    let stranger = Agent::new(Some("stranger")).unwrap();
    let response = test::call_service(
        &service,
        post("/host/call", &f.appstate, Some(&stranger), body(json!({}))).to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    forbidden(status, &answer);
    assert_eq!(count_of(db, &subject, &property).await, 0);
    assert!(
        f.appstate
            .host_abi
            .providers(&f.drive, interface)
            .is_empty(),
        "the app was not loaded for a caller who may not see the drive"
    );

    // Someone who may read the drive but not write it: `increment` writes.
    let reader = Agent::new(Some("reader")).unwrap();
    share(
        db,
        &f.drive,
        &[&counter.agent, &reader.subject.to_string()],
        &[&counter.agent],
    )
    .await;
    let response = test::call_service(
        &service,
        post("/host/call", &f.appstate, Some(&reader), body(json!({}))).to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    forbidden(status, &answer);
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // A host that vouches only for reads (a sandboxed frame) cannot run a
    // write export, even as the drive's owner.
    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            Some(&owner),
            body(json!({"allowEffects": ["read"]})),
        )
        .to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    forbidden(status, &answer);
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // Allowing write lets the owner through.
    let response = test::call_service(
        &service,
        post(
            "/host/call",
            &f.appstate,
            Some(&owner),
            body(json!({"allowEffects": ["read", "write"]})),
        )
        .to_request(),
    )
    .await;
    let (status, answer) = json_of(response).await;
    assert_eq!((status, answer), (200, json!({"result": {"count": 1}})));
}
