use crate::{appstate::AppState, errors::BetterResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{parse::parse_json_ad_commit_resource, Commit, Storelike};
use std::sync::Mutex;

/// Send and process a Commit.
/// Currently only accepts JSON-AD
pub async fn post_commit(
    // commit: web::Json<atomic_lib::Commit>,
    data: web::Data<Mutex<AppState>>,
    // req: actix_web::HttpRequest,
    // payload: &mut web::Payload,
    body: String,
) -> BetterResult<HttpResponse> {
    // log::info!("commit: {:?}", commit);
    let mut context = data.lock().unwrap();
    let store = &mut context.store;
    let mut builder = HttpResponse::Ok();
    let incoming_commit_resource = parse_json_ad_commit_resource(&body, store)?;
    let incoming_commit = Commit::from_resource(incoming_commit_resource)?;
    let now = atomic_lib::datetime_helpers::now();
    // 86,400,000 is 24 hrs
    let acceptable_milliseconds = 86_400_000;
    let time_ago = now - incoming_commit.created_at;
    if time_ago > acceptable_milliseconds {
        return Err(format!(
            "Commit was was createdAt {}ms ago, which is more than the maximum of {}ms.",
            time_ago, acceptable_milliseconds
        ).into());
    }
    let saved_commit_resource = store.commit(incoming_commit)?;
    // TODO: better response
    let message = format!(
        "Commit succesfully applied. Can be seen at {}",
        saved_commit_resource.get_subject()
    );
    log::info!("{}", &message);
    Ok(builder.body(message))
}
