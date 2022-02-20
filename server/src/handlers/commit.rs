use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{commit::CommitOpts, parse::parse_json_ad_commit_resource, Commit, Storelike};

/// Send and process a Commit.
/// Currently only accepts JSON-AD
#[tracing::instrument(skip(appstate))]
pub async fn post_commit(
    appstate: web::Data<AppState>,
    body: String,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
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
    let opts = CommitOpts {
        validate_schema: true,
        validate_signature: true,
        validate_timestamp: true,
        validate_rights: true,
        validate_previous_commit: true,
        update_index: false,
    };
    let commit_response = incoming_commit.apply_opts(store, &opts)?;

    let message = commit_response.commit_resource.to_json_ad()?;

    // When a commit is applied, notify all webhook subscribers
    // TODO: add commit handler https://github.com/joepio/atomic-data-rust/issues/253
    appstate
        .commit_monitor
        .do_send(crate::actor_messages::CommitMessage { commit_response });

    tracing::info!("{}", &message);
    Ok(builder.body(message))
}
