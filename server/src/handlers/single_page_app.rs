use actix_web::HttpResponse;

use crate::errors::BetterResult;

pub async fn single_page() -> BetterResult<HttpResponse> {
    // let path: PathBuf = "./static/atomic-react.html".parse().unwrap();
    let body = include_str!("../../static/atomic-react.html");
    let resp = HttpResponse::Ok()
        .content_type("text/html")
        .body(body);
    Ok(resp)
    // NamedFile::open(path).map_err(|e| format!("could not open file {}", e).into())
}
