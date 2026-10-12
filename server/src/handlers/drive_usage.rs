use crate::{
    appstate::AppState, context::RequestContext, errors::AtomicServerResult,
    helpers::get_client_agent,
};
use actix_web::{web, HttpRequest, HttpResponse};
use atomic_lib::{Storelike, Subject};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DriveUsageParams {
    pub subject: String,
}

/// The wire shape the sync page reads (`fetchNodeDriveUsage`) — camelCase, so
/// it deliberately does not reuse `atomic_lib::DriveUsage`, whose snake_case
/// field names are the separate control-plane usage-report contract.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DriveUsageResponse {
    name: Option<String>,
    resource_count: u64,
    blob_bytes: u64,
    loro_bytes: u64,
}

/// `GET /drive-usage?subject=<drive>` — per-drive storage (resource count, blob
/// bytes, Loro-snapshot bytes) for the sync page's usage display. Generic to any
/// atomic-server, desktop included. Signed and read-checked: the caller must be
/// allowed to read the drive.
#[tracing::instrument(skip_all)]
pub async fn handle_drive_usage(
    appstate: web::Data<AppState>,
    params: web::Query<DriveUsageParams>,
    req: HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let origin = RequestContext::new(&req, &appstate).origin;
    let subject = params.subject.clone();

    // The client signs the full request URL (path + query); rebuild it exactly
    // so the signature check matches what it signed.
    let full_url = format!("{}{}", origin, req.uri());
    let for_agent = get_client_agent(req.headers(), &appstate, &full_url).await?;

    // Enforce read access on the drive itself (raw fetch + check, not the
    // extender path — this is a read-only stat, not a resource render).
    let drive = store.get_resource(&Subject::from(subject.as_str())).await?;
    atomic_lib::hierarchy::check_read(store, &drive, &for_agent).await?;

    let usage = store
        .per_drive_usage(std::slice::from_ref(&subject))
        .await?;
    let row = usage
        .into_iter()
        .next()
        .ok_or_else(|| format!("No usage found for drive {subject}"))?;

    Ok(HttpResponse::Ok().json(DriveUsageResponse {
        name: row.name,
        resource_count: row.resource_count,
        blob_bytes: row.blob_bytes,
        loro_bytes: row.loro_bytes,
    }))
}

/// `GET /drive-usage/breakdown?subject=<drive>` — every resource in the drive
/// with its history (Loro) and file (blob) bytes, so a client can draw a size
/// map of where the space goes. Same auth and read check as `/drive-usage`.
#[tracing::instrument(skip_all)]
pub async fn handle_drive_usage_breakdown(
    appstate: web::Data<AppState>,
    params: web::Query<DriveUsageParams>,
    req: HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let origin = RequestContext::new(&req, &appstate).origin;
    let subject = params.subject.clone();

    let full_url = format!("{}{}", origin, req.uri());
    let for_agent = get_client_agent(req.headers(), &appstate, &full_url).await?;

    let drive = store.get_resource(&Subject::from(subject.as_str())).await?;
    atomic_lib::hierarchy::check_read(store, &drive, &for_agent).await?;

    let rows = store.drive_usage_breakdown(&subject).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "driveSubject": subject,
        "resources": rows.iter().map(|r| serde_json::json!({
            "subject": r.subject,
            "name": r.name,
            "parent": r.parent,
            "isA": r.is_a,
            "loroBytes": r.loro_bytes,
            "blobBytes": r.blob_bytes,
        })).collect::<Vec<_>>(),
    })))
}
