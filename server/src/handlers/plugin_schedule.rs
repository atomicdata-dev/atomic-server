//! Setting and reading a plugin's schedule.
//!
//! The same shape as `/plugin-secret`, and for the same reason: a plugin's
//! schema is created per drive, so a scheduler running in Rust cannot resolve
//! its property subjects. This is host state keyed by `(drive, plugin)`.

use actix_web::{web, HttpResponse};
use atomic_lib::{
    db::plugin_schedule::{PluginSchedule, PluginScheduleInfo, PluginScheduleKey},
    hierarchy::check_write,
    Storelike,
};

use crate::{appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetScheduleBody {
    pub drive: String,
    pub plugin: String,
    /// How often to run. `null` stops it.
    pub interval_seconds: Option<u64>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleQuery {
    pub drive: String,
    pub plugin: String,
}

/// Scheduling a plugin means it will spend that plugin's secrets unattended, so
/// it takes the same rights as changing it.
async fn authorize(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &crate::context::RequestContext,
    plugin: &str,
) -> AtomicServerResult<()> {
    let store = &appstate.store;
    let resource = store.get_resource(&plugin.into()).await?;

    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject =
        atomic_lib::Subject::from_raw(&path_and_query, None).resolve(&context.origin);

    let agent = get_client_agent(req.headers(), appstate, &signed_subject).await?;
    check_write(store, &resource, &agent).await?;

    Ok(())
}

#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_set_schedule(
    appstate: web::Data<AppState>,
    body: web::Json<SetScheduleBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &body.plugin).await?;

    let key = PluginScheduleKey::new(&body.drive, &body.plugin);

    match body.interval_seconds {
        None => appstate.store.delete_plugin_schedule(&key)?,
        Some(interval) => {
            // A new schedule rather than a reset: changing the interval should
            // not discard a verdict nobody has reviewed yet.
            let existing = appstate.store.get_plugin_schedule(&key)?;
            let now = atomic_lib::utils::now();
            let mut schedule = PluginSchedule::new(interval, now)?;

            if let Some(previous) = existing {
                schedule.last_run_at = previous.last_run_at;
                schedule.pending_verdict = previous.pending_verdict;
                schedule.last_error = previous.last_error;
            }

            appstate.store.set_plugin_schedule(&key, &schedule)?;
        }
    }

    Ok(HttpResponse::Ok().json(read(&appstate, &key)?))
}

#[tracing::instrument(skip(appstate, req))]
pub async fn handle_get_schedule(
    appstate: web::Data<AppState>,
    query: web::Query<ScheduleQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.plugin).await?;

    Ok(HttpResponse::Ok().json(read(
        &appstate,
        &PluginScheduleKey::new(&query.drive, &query.plugin),
    )?))
}

/// Clears the verdict a background run left, once it has been dealt with.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_clear_pending(
    appstate: web::Data<AppState>,
    query: web::Query<ScheduleQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.plugin).await?;

    let key = PluginScheduleKey::new(&query.drive, &query.plugin);

    if let Some(mut schedule) = appstate.store.get_plugin_schedule(&key)? {
        schedule.pending_verdict = None;
        appstate.store.set_plugin_schedule(&key, &schedule)?;
    }

    Ok(HttpResponse::Ok().json(read(&appstate, &key)?))
}

fn read(
    appstate: &AppState,
    key: &PluginScheduleKey,
) -> AtomicServerResult<Option<PluginScheduleInfo>> {
    Ok(appstate
        .store
        .get_plugin_schedule(key)?
        .as_ref()
        .map(PluginScheduleInfo::from))
}
