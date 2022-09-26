use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::HttpResponse;

/// Returns the atomic-data-browser single page application
#[tracing::instrument(skip(appstate))]
pub async fn single_page(
    appstate: actix_web::web::Data<AppState>,
) -> AtomicServerResult<HttpResponse> {
    let template = include_str!("../../templates/atomic-data-browser.html");
    let body = template
        .replace("{ script }", &appstate.config.opts.script)
        .replace("{ asset_url }", &appstate.config.opts.asset_url);

    let resp = HttpResponse::Ok()
        .content_type("text/html")
        // This prevents the browser from displaying the JSON response upon re-opening a closed tab
        // https://github.com/atomicdata-dev/atomic-data-rust/issues/137
        .insert_header((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        ))
        .body(body);

    Ok(resp)
}
