use crate::{appstate::AppState, errors::AtomicServerResult};
use actix_web::{web, HttpResponse};
use atomic_lib::{urls, Resource, Storelike, Subject};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GenesisParams {
    pub subject: String,
}

/// `GET /genesis?subject=<drive did>` — the drive's genesis certificate, and
/// nothing else, readable by anyone.
///
/// The certificate is self-certifying: the drive's identifier *is* the
/// signature over it, so a client that was told "this server hosts your
/// drive" (a pkarr record anyone can write) fetches this and checks the
/// signature against the identifier before trusting the server. Nobody
/// without the owner's key can produce a certificate that verifies.
///
/// What it reveals: the signer's public key, `createdAt`, the nonce and the
/// `parent` / `drive` fields of the certificate, plus the fact that this
/// server holds a drive with that identifier. It never reads, checks or
/// returns the drive's other properties, children or history, so it is not
/// routed through `check_read`. Only drives answer; any other subject
/// (resources inside a drive, agents, URLs, unknown identifiers) is a 404, so
/// the route cannot be used to probe for private resources.
///
/// Read-only. Reads are not rate limited anywhere in the server; this one is a
/// single key lookup.
#[tracing::instrument(skip_all)]
pub async fn handle_genesis(
    appstate: web::Data<AppState>,
    params: web::Query<GenesisParams>,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let raw = params.subject.trim();

    if !atomic_lib::identifiers::is_resource_id(raw) {
        return Err(not_found());
    }

    let subject = Subject::from_raw(raw, None);
    let drive = store
        .get_resource(&subject)
        .await
        .map_err(|_| not_found())?;

    let is_drive = drive
        .get(urls::IS_A)
        .ok()
        .and_then(|v| v.to_subjects(None).ok())
        .is_some_and(|classes| classes.iter().any(|c| c == urls::DRIVE));
    // The certificate rides inside the resource's CRDT snapshot; the
    // materialized properties do not carry it.
    let genesis = store
        .get_loro_snapshot(&subject)
        .and_then(|snapshot| Resource::genesis_cert_b64_from_loro_update(&snapshot))
        .filter(|g| !g.is_empty());

    match (is_drive, genesis) {
        (true, Some(genesis)) => Ok(HttpResponse::Ok()
            .content_type("application/ad+json")
            // The certificate never changes for a given identifier.
            .append_header(("Cache-Control", "public, max-age=3600"))
            .json(serde_json::json!({
                "@id": raw,
                urls::GENESIS: genesis,
            }))),
        _ => Err(not_found()),
    }
}

fn not_found() -> crate::errors::AtomicServerError {
    atomic_lib::errors::AtomicError::not_found("No such drive".to_string()).into()
}
