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
    let mut appstate = data
        .lock()
        .expect("Failed to lock mutexguard in post_commit");
    let store = &mut appstate.store;
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
    // We don't update the index, because that's a job for the CommitMonitor. That means it can be done async in a different thread, making this commit response way faster.
    let commit_response = incoming_commit.apply_opts(store, true, true, true, true, false)?;

    // TODO: better response
    let message = format!(
        "Commit succesfully applied. Can be seen at {}",
        commit_response.commit.get_subject()
    );

    // When a commit is applied, notify all webhook subscribers
    appstate
        .commit_monitor
        .do_send(crate::actor_messages::CommitMessage {
            subject: incoming_commit.subject,
            commit_response,
        });

    log::info!("{}", &message);
    Ok(builder.body(message))
}
