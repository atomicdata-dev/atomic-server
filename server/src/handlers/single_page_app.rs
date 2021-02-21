use actix_web::HttpResponse;
use crate::errors::BetterResult;

/// Returns the atomic-data-browser single page application
pub async fn single_page() -> BetterResult<HttpResponse> {
    let body = include_str!("../../static/atomic-data-browser.html");
    let resp = HttpResponse::Ok()
        .content_type("text/html")
        .body(body);
    Ok(resp)
}
