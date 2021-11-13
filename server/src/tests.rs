//! This contains a minimal set of tests for the server.
//! Most of the more rigorous testing is done in the end-to-end tests:
//! https://github.com/joepio/atomic-data-browser/tree/main/data-browser/tests

use super::*;
use actix_web::{
    dev::{Body, ResponseBody},
    test, web, App,
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

#[actix_rt::test]
async fn init_server() {
    std::env::set_var("ATOMIC_REBUILD_INDEX", "true");
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

    // Get HTML page
    let req = test::TestRequest::with_uri("/search?q=test").to_request();
    let mut resp = test::call_service(&mut app, req).await;
    println!("response: {:?}", resp);
    assert!(resp.status().is_success());
    let body = resp.take_body();
    assert!(body.as_str().contains("html"));

    // Should 404
    let req = test::TestRequest::with_uri("/doesnotexist")
        .header("Accept", "application/ld+json")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    // Note: This is currently 500, but should be 404 in the future!
    assert!(resp.status().is_server_error());

    // Get JSON-AD
    let req = test::TestRequest::with_uri("/setup")
        .header("Accept", "application/ad+json")
        .to_request();
    let mut resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "setup not returning JSON-AD");
    let body = resp.take_body();
    assert!(body.as_str().contains("{\n  \"@id\""));

    // Get JSON-LD
    let req = test::TestRequest::with_uri("/setup")
        .header("Accept", "application/ld+json")
        .to_request();
    let mut resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success(), "setup not returning JSON-LD");
    let body = resp.take_body();
    assert!(body.as_str().contains("@context"));

    // Get turtle
    let req = test::TestRequest::with_uri("/setup")
        .header("Accept", "text/turtle")
        .to_request();
    let mut resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success());
    let body = resp.take_body();
    assert!(body.as_str().starts_with("<htt"));

    // Get Search
    // Does not test the contents of the results - the index isn't built at this point
    let req = test::TestRequest::with_uri("/search?q=setup")
        .header("Accept", "application/ad+json")
        .to_request();
    let mut resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_success());
    let body = resp.take_body();
    println!("{}", body.as_str());
    assert!(body.as_str().contains("/results"));
}
