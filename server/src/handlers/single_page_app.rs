use crate::errors::BetterResult;
use actix_web::HttpResponse;

/// Returns the atomic-data-browser single page application
pub async fn single_page() -> BetterResult<HttpResponse> {
    let body = include_str!("../../static/atomic-data-browser.html");
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
