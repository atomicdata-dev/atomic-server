//! `GET /history-attribution?subject=<subject>` — who signed a resource's
//! history, as far as this node kept the envelopes (`atomic_lib::envelopes`).
//!
//! Read-gated like the resource itself: the caller must be allowed to read
//! `subject`. The answer is the verified signer per Loro change token, plus
//! whether every client-authored change is covered. A node on `latest`
//! retention answers with one attribution (the current state); `all` gives
//! one per change.

use crate::{
    appstate::AppState, context::RequestContext, errors::AtomicServerResult,
    helpers::get_client_agent,
};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{Storelike, Subject};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct HistoryAttributionParams {
    pub subject: String,
}

#[tracing::instrument(skip_all)]
pub async fn handle_history_attribution(
    appstate: web::Data<AppState>,
    params: web::Query<HistoryAttributionParams>,
    req: HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let origin = RequestContext::new(&req, &appstate).origin;
    let subject = params.subject.clone();

    // The client signs the full request URL (path + query); rebuild it exactly
    // so the signature check matches what it signed.
    let full_url = format!("{}{}", origin, req.uri());
    let for_agent = get_client_agent(req.headers(), &appstate, &full_url).await?;

    // A destroyed subject has no resource to check against; its drive is the
    // rights anchor, the same gate `SYNC_DIFF.removeCommits` uses. Only a
    // live resource is answered here; destroyed ones are the sync layer's.
    let resource = store.get_resource(&Subject::from(subject.as_str())).await?;
    atomic_lib::hierarchy::check_read(store, &resource, &for_agent).await?;

    let report = atomic_lib::envelopes::attribute_history(store, &subject).await?;
    Ok(HttpResponse::Ok().json(report))
}
