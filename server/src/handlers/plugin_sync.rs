//! A signed caller approves a saved sandbox preview, never caller-supplied effects.
use crate::{
    appstate::AppState,
    context::RequestContext,
    errors::AtomicServerResult,
    plugins::{
        js_runtime::StoreHost,
        manifest::Manifest,
        store_host::{app_signing_for, StoreApplyHost},
        sync_session,
    },
};
use actix_web::{web, HttpRequest, HttpResponse};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub drive: String,
    pub plugin: String,
    pub release: String,
    pub config: serde_json::Value,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub drive: String,
    pub plugin: String,
    pub run: Option<String>,
}
async fn host(
    app: &AppState,
    req: &HttpRequest,
    context: &RequestContext,
    drive: &str,
    plugin: &str,
    release: Option<&str>,
) -> AtomicServerResult<StoreHost> {
    let account = super::plugin_schedule::authorize(app, req, context, plugin).await?;
    let manifest = match release {
        Some(id) => Manifest::parse(app.store.get_plugin_release(id)?.manifest)?,
        None => None,
    };
    if release.is_some() && manifest.is_none() {
        return Err("sync requires a versioned release".into());
    }
    let host = StoreHost {
        db: std::sync::Arc::new(app.store.clone()),
        plugin: plugin.into(),
        drive: drive.into(),
        for_agent: account,
        manifest,
    };
    host.validate_binding().await?;
    Ok(host)
}
pub async fn preview(
    app: web::Data<AppState>,
    body: web::Json<Preview>,
    req: HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let host = host(
        &app,
        &req,
        &context,
        &body.drive,
        &body.plugin,
        Some(&body.release),
    )
    .await?;
    Ok(HttpResponse::Ok().json(
        sync_session::preview(
            &app.store,
            &body.drive,
            &body.plugin,
            &body.release,
            body.config.clone(),
            host,
        )
        .await?,
    ))
}
pub async fn status(
    app: web::Data<AppState>,
    body: web::Json<Target>,
    req: HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    host(&app, &req, &context, &body.drive, &body.plugin, None).await?;
    Ok(HttpResponse::Ok().json(sync_session::read(&app.store, &body.drive, &body.plugin)?))
}
pub async fn apply(
    app: web::Data<AppState>,
    body: web::Json<Target>,
    req: HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    host(&app, &req, &context, &body.drive, &body.plugin, None).await?;
    let session =
        sync_session::read(&app.store, &body.drive, &body.plugin)?.ok_or("no preview exists")?;
    let run = body
        .run
        .as_deref()
        .ok_or("approval requires a reviewed run identity")?;
    let host = host(
        &app,
        &req,
        &context,
        &body.drive,
        &body.plugin,
        Some(&session.release),
    )
    .await?;
    let actor = host.for_agent.to_string();
    let mut atomic = StoreApplyHost {
        store: app.store.clone(),
        for_agent: host.for_agent.clone(),
        signing_as: app_signing_for(&app.store, &body.drive, &body.plugin).await?,
    };
    Ok(HttpResponse::Ok().json(
        sync_session::advance(
            &app.store,
            &body.drive,
            &body.plugin,
            run,
            &actor,
            host,
            &mut atomic,
        )
        .await?,
    ))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRequest {
    pub drive: String,
    pub plugin: String,
    pub run: String,
    pub interval_seconds: Option<u64>,
}
pub async fn schedule(
    app: web::Data<AppState>,
    body: web::Json<ScheduleRequest>,
    req: HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let host = host(&app, &req, &context, &body.drive, &body.plugin, None).await?;
    let state = match body.interval_seconds {
        Some(interval) => {
            crate::plugins::sync_worker::configure(
                &app.store,
                &body.drive,
                &body.plugin,
                &body.run,
                &host.for_agent.to_string(),
                interval,
            )
            .await?
        }
        None => crate::plugins::sync_worker::read(&app.store, &body.drive, &body.plugin)?,
    };
    Ok(HttpResponse::Ok().json(state))
}
