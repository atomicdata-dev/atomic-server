use crate::{appstate::AppState, errors::BetterResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{parse::parse_json_ad_commit_resource, Commit, Storelike};
use std::sync::Mutex;

/// Send and process a Commit.
/// Currently only accepts JSON-AD
pub async fn post_commit(
    data: web::Data<Mutex<AppState>>,
    body: String,
) -> BetterResult<HttpResponse> {
    let mut context = data
        .lock()
        .expect("Failed to lock mutexguard in post_commit");
    let store = &mut context.store;
    let mut builder = HttpResponse::Ok();
    let incoming_commit_resource = parse_json_ad_commit_resource(&body, store)?;
    let incoming_commit = Commit::from_resource(incoming_commit_resource)?;
    if !incoming_commit.subject.contains(
        &store
            .get_self_url()
            .ok_or("Cannot apply commits to this store. No self_url is set.")?,
    ) {
        return Err("Subject of commit should be sent to other domain - this store can not own this resource.".into());
    }
    let saved_commit_resource = incoming_commit.apply_opts(store, true, true, true, true, true)?;
    // TODO: better response
    let message = format!(
        "Commit succesfully applied. Can be seen at {}",
        saved_commit_resource.get_subject()
    );

    // When a commit is applied, notify all webhook subscribers
    context
        .commit_monitor
        .do_send(crate::actor_messages::CommitMessage {
            subject: incoming_commit.subject,
            resource: saved_commit_resource,
        });

    log::info!("{}", &message);
    Ok(builder.body(message))
}
