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

fn post(path: &str, appstate: &AppState, agent: Option<&Agent>, body: Value) -> TestRequest {
    let origin = appstate.config.get_origin();
    let mut request = TestRequest::post().uri(path).set_json(body);
    if let Some(agent) = agent {
        let headers =
            atomic_lib::client::get_authentication_headers(&format!("{origin}{path}"), agent)
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
