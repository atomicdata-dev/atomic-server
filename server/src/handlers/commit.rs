use crate::{appstate::AppState, errors::BetterResult};
use actix_web::{web, HttpResponse};
use atomic_lib::Storelike;
use std::sync::Mutex;

/// Send and process a Commit.
/// Currently only accepts JSON
pub async fn post_commit(
    commit: web::Json<atomic_lib::Commit>,
    // commit: web::Json<Demo>,
    data: web::Data<Mutex<AppState>>,
    // req: actix_web::HttpRequest,
) -> BetterResult<HttpResponse> {
    log::info!("commit: {:?}", commit);
    let mut context = data.lock().unwrap();
    let store = &mut context.store;
    let mut builder = HttpResponse::Ok();
    let commit_resource = store.commit(commit.into_inner())?;
    let body = format!("Commit succesfully applied. Can be seen at {}", commit_resource.get_subject());
    Ok(builder.body(body))
}
