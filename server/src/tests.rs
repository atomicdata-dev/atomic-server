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

/// Returns the request with signed headers. Also adds a json-ad accept header - overwrite this if you need something else.
fn build_request_authenticated(path: &str, appstate: &AppState) -> TestRequest {
    // remove last slash
    let base = appstate.store.get_server_url().to_string();
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let headers = atomic_lib::client::get_authentication_headers(
        &url,
        &appstate.store.get_default_agent().unwrap(),
    )
    .expect("could not get auth headers");

    let mut prereq = test::TestRequest::with_uri(path);
    for (k, v) in headers {
        prereq = prereq.insert_header((k, v));
    }
    prereq.insert_header(("Accept", "application/ad+json"))
}

#[actix_rt::test]
async fn server_tests() {
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

    let appstate = crate::appstate::init(config.clone())
        .await
        .expect("failed to init appstate");
    let data = Data::new(appstate.clone());
    let app = test::init_service(
        App::new()
            .app_data(data)
            .configure(crate::routes::config_routes),
    )
    .await;
    let store = &appstate.store;

    // Does not work, unfortunately, because the server is not accessible.
    // let fetched =
    //     atomic_lib::client::fetch_resource(&appstate.config.server_url, &appstate.store, None)
    //         .expect("could not fetch drive");

    // Get HTML page
    let req =
        build_request_authenticated("/", &appstate).insert_header(("Accept", "application/html"));
    let resp = test::call_service(&app, req.to_request()).await;
    let is_success = resp.status().is_success();
    let body = get_body(resp);
    // println!("{:?}", body);
    assert!(is_success);
    assert!(body.as_str().contains("html"));

    // Should 200 (public)
    let req =
        test::TestRequest::with_uri("/properties").insert_header(("Accept", "application/ad+json"));
    let resp = test::call_service(&app, req.to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "properties collections should be found and public"
    );

    // Should 404
    let req = test::TestRequest::with_uri("/doesnotexist")
        .append_header(("Accept", "application/ld+json"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_client_error());

    // Edit the properties collection, make it hidden to the public agent
    let mut drive = store
        .get_resource(appstate.store.get_server_url().as_str())
        .unwrap();
    drive
        .set_propval(
            urls::READ.into(),
            vec![appstate.store.get_default_agent().unwrap().subject].into(),
            &appstate.store,
        )
        .unwrap();
    drive.save(store).unwrap();

    // Should 401 (Unauthorized)
    let req =
        test::TestRequest::with_uri("/properties").insert_header(("Accept", "application/ad+json"));
    let resp = test::call_service(&app, req.to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "resource should not be authorized for public"
    );

    // Get JSON-AD
    let req = build_request_authenticated("/properties", &appstate);
    let resp = test::call_service(&app, req.to_request()).await;
    let body = get_body(resp);
    println!("DEBUG: {:?}", body);
    // assert!(resp.status().is_success(), "setup not returning JSON-AD");
    assert!(
        body.as_str().contains("{\n  \"@id\""),
        "response should be json-ad"
    );

    // Get JSON-LD
    let req = build_request_authenticated("/properties", &appstate)
        .insert_header(("Accept", "application/ld+json"));
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success(), "setup not returning JSON-LD");
    let body = get_body(resp);
    assert!(
        body.as_str().contains("@context"),
        "response should be json-ld"
    );

    // Get turtle
    let req = build_request_authenticated("/properties", &appstate)
        .insert_header(("Accept", "text/turtle"));
    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
    let body = get_body(resp);
    assert!(
        body.as_str().starts_with("<htt"),
        "response should be turtle"
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
}

/// Gets the body from the response as a String. Why doesn't actix provide this?
fn get_body(resp: ServiceResponse) -> String {
    let boxbody = resp.into_body();
    let bytes = boxbody.try_into_bytes().unwrap();
    String::from_utf8(bytes.as_ref().into()).unwrap()
}
