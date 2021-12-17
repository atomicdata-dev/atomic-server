use std::sync::Mutex;

use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::HttpResponse;

/// Returns the atomic-data-browser single page application
pub async fn single_page(
    data: actix_web::web::Data<Mutex<AppState>>,
) -> AtomicServerResult<HttpResponse> {
    let appstate = data
        .lock()
        .expect("Failed to lock mutexguard in single_page");

    let template = include_str!("../../static/atomic-data-browser.html");
    let body = template
        .replace("{ script }", &appstate.config.opts.script)
        .replace("{ asset_url }", &appstate.config.opts.asset_url);

    let resp = HttpResponse::Ok()
        .content_type("text/html")
        // This prevents the browser from displaying the JSON response upon re-opening a closed tab
        // https://github.com/joepio/atomic-data-rust/issues/137
        .header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        )
        .body(body);

    Ok(resp)
}
