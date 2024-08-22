use crate::{
    appstate::AppState,
    content_types::ContentType,
    errors::AtomicServerResult,
    helpers::{get_client_agent, get_subject},
};
use actix_web::{web, HttpResponse};
use atomic_lib::Storelike;
use simple_server_timing_header::Timer;

/// Respond to a single resource.
/// The URL should match the Subject of the resource.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_get_resource(
    path: Option<web::Path<String>>,
    appstate: web::Data<AppState>,
    req: actix_web::HttpRequest,
    conn: actix_web::dev::ConnectionInfo,
) -> AtomicServerResult<HttpResponse> {
    let mut timer = Timer::new();

    let headers = req.headers();
    // Get the subject from the path, or return the home URL
    let (subject, content_type) = get_subject(&req, &conn, &appstate)?;

    let store = &appstate.store;
    timer.add("parse_headers");

    let for_agent = get_client_agent(headers, &appstate, subject.clone())?;
    timer.add("get_agent");

    let mut builder = HttpResponse::Ok();

    tracing::debug!("get_resource: {} as {}", subject, content_type.to_mime());
    builder.append_header(("Content-Type", content_type.to_mime()));
    // This prevents the browser from displaying the JSON response upon re-opening a closed tab
    // https://github.com/atomicdata-dev/atomic-server/issues/137
    builder.append_header((
        "Cache-Control",
        "no-store, no-cache, must-revalidate, private",
    ));

    let resource = store.get_resource_extended(&subject, false, &for_agent)?;
    timer.add("get_resource");

    let response_body = match content_type {
        ContentType::Json => resource.to_json(store)?,
        ContentType::JsonLd => resource.to_json_ld(store)?,
        ContentType::JsonAd => resource.to_json_ad()?,
        ContentType::Html => resource.to_json_ad()?,
        ContentType::Turtle | ContentType::NTriples => {
            let atoms = resource.to_atoms();
            atomic_lib::serialize::atoms_to_ntriples(atoms, store)?
        }
    };
    timer.add("serialize");
    Ok(builder.body(response_body))
}
