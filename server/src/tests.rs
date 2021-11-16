//! This contains a minimal set of tests for the server.
//! Most of the more rigorous testing is done in the end-to-end tests:
//! https://github.com/joepio/atomic-data-browser/tree/main/data-browser/tests

use crate::appstate::AppState;

use super::*;
use actix_web::{
    dev::{Body, ResponseBody},
    test::{self, TestRequest},
    web, App,
};

trait BodyTest {
    fn as_str(&self) -> &str;
}

impl BodyTest for ResponseBody<Body> {
    fn as_str(&self) -> &str {
        match self {
            ResponseBody::Body(ref b) => match b {
                Body::Bytes(ref by) => std::str::from_utf8(&by).unwrap(),
                _ => panic!(),
            },
            ResponseBody::Other(ref b) => match b {
                Body::Bytes(ref by) => std::str::from_utf8(&by).unwrap(),
                _ => panic!(),
            },
        }
    }
}

/// Returns the request with signed headers. Also adds a json-ad accept header - overwrite this if you need something else.
fn build_request_authenticated(path: &str, appstate: &AppState) -> TestRequest {
    let url = format!("http://localhost{}", path);
    let headers = atomic_lib::client::get_authentication_headers(
        &url,
        &appstate.store.get_default_agent().unwrap(),
    )
    .expect("could not get auth headers");

    let mut prereq = test::TestRequest::with_uri(path);
    for (k, v) in headers {
        prereq = prereq.header(k, v.clone());
    }
    prereq.header("Accept", "application/ad+json")
}

#[actix_rt::test]
async fn init_server() {
    std::env::set_var("ATOMIC_CONFIG_DIR", "./.temp");
    // We need tro run --initialize to make sure the agent has the correct rights / drive
    std::env::set_var("ATOMIC_INITIALIZE", "true");
    let config = config::init()
        .map_err(|e| format!("Initialization failed: {}", e))
        .expect("failed init config");
    let appstate = crate::appstate::init(config.clone()).expect("failed init appstate");
    let data = web::Data::new(std::sync::Mutex::new(appstate.clone()));
    let mut app = test::init_service(
        App::new()
            .app_data(data)
            .configure(|app| crate::routes::config_routes(app, &appstate.config)),
    )
    .await;

    // Does not work, unfortunately, because the server is not accessible.
    // let fetched =
    //     atomic_lib::client::fetch_resource(&appstate.config.local_base_url, &appstate.store, None)
    //         .expect("could not fetch drive");

    // Get HTML page
    let req = build_request_authenticated("/", &appstate).header("Accept", "application/html");
    let mut resp = test::call_service(&mut app, req.to_request()).await;
    println!("response: {:?}", resp);
    assert!(resp.status().is_success());
    let body = resp.take_body();
    assert!(body.as_str().contains("html"), "no html in response");

    // Should 401 (Unauthorized)
    let req = test::TestRequest::with_uri("/properties").header("Accept", "application/ad+json");
    let resp = test::call_service(&mut app, req.to_request()).await;
    assert!(
        resp.status().is_client_error(),
        "resource should return 401 unauthorized"
    );

    // Get JSON-AD
    let req = build_request_authenticated("/properties", &appstate);
    let mut resp = test::call_service(&mut app, req.to_request()).await;
    assert!(resp.status().is_success(), "setup not returning JSON-AD");
    let body = resp.take_body();
    assert!(
        body.as_str().contains("{\n  \"@id\""),
        "response should be json-ad"
    );

    // Get JSON-LD
    let req = build_request_authenticated("/properties", &appstate)
        .header("Accept", "application/ld+json");
    let mut resp = test::call_service(&mut app, req.to_request()).await;
    assert!(resp.status().is_success(), "setup not returning JSON-LD");
    let body = resp.take_body();
    assert!(
        body.as_str().contains("@context"),
        "response should be json-ld"
    );

    // Get turtle
    let req = build_request_authenticated("/properties", &appstate).header("Accept", "text/turtle");
    let mut resp = test::call_service(&mut app, req.to_request()).await;
    assert!(resp.status().is_success());
    let body = resp.take_body();
    assert!(
        body.as_str().starts_with("<htt"),
        "response should be turtle"
    );

    // Get Search
    // Does not test the contents of the results - the index isn't built at this point
    let req = build_request_authenticated("/search?q=setup", &appstate);
    let mut resp = test::call_service(&mut app, req.to_request()).await;
    assert!(resp.status().is_success());
    let body = resp.take_body();
    println!("{}", body.as_str());
    assert!(
        body.as_str().contains("/results"),
        "response should be a search resource"
    );
}
