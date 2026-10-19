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
    /// Whether this node currently admits the drive under its sync policy. On
    /// a managed node that is "the control plane has the drive on its
    /// allowlist"; on a self-hosted node it is whether the node hosts the
    /// drive (an open node hosts everything). Data can outlive enrollment, so
    /// `resourceCount > 0` alone does not say this. Over-quota still counts as
    /// enrolled: the drive is hosted, just full.
    enrolled: bool,
    /// Display name of the account that manages this drive, as the payer chose
    /// it. Only present when the drive is enrolled and the node was told one.
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_by: Option<String>,
}

/// Longest manager label we pass on, in characters.
const MAX_MANAGER_LABEL_CHARS: usize = 80;

/// Trim and cap a label from the policy; empty becomes `None`.
fn clean_manager_label(label: Option<String>) -> Option<String> {
    let trimmed = label?
        .trim()
        .chars()
        .take(MAX_MANAGER_LABEL_CHARS)
        .collect::<String>();
    let trimmed = trimmed.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
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

    // `drive_is_allowed`, not `admit_decision`: the latter starts a bootstrap
    // grace clock for unknown drives, and a stat must not change state.
    let enrolled = store.sync_policy().drive_is_allowed(&subject);

    let managed_by = if enrolled {
        clean_manager_label(store.sync_policy().drive_manager_label(&subject))
    } else {
        None
    };

    Ok(HttpResponse::Ok().json(DriveUsageResponse {
        enrolled,
        managed_by,
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

#[cfg(test)]
mod tests {
    use super::clean_manager_label;

    #[test]
    fn manager_label_is_trimmed_and_capped() {
        assert_eq!(clean_manager_label(None), None);
        assert_eq!(clean_manager_label(Some("   ".into())), None);
        assert_eq!(
            clean_manager_label(Some("  Acme  ".into())).as_deref(),
            Some("Acme")
        );
        let long = "é".repeat(200);
        assert_eq!(clean_manager_label(Some(long)).unwrap().chars().count(), 80);
    }
}
