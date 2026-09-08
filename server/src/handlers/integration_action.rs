//! Shared HTTP adapter. Clients submit action inputs; only approval executes saved writes.
use crate::{
    appstate::AppState,
    context::RequestContext,
    errors::AtomicServerResult,
    plugins::{actions, js_runtime::StoreHost},
};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub drive: String,
    pub plugin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoke {
    pub drive: String,
    pub plugin: String,
    pub call: actions::Call,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approve {
    pub drive: String,
    pub plugin: String,
    pub id: String,
}
async fn host(
    app: &AppState,
    req: &HttpRequest,
    context: &RequestContext,
    drive: &str,
    plugin: &str,
) -> AtomicServerResult<StoreHost> {
    let actor = super::plugin_schedule::authorize(app, req, context, plugin).await?;
    let host = StoreHost {
        db: std::sync::Arc::new(app.store.clone()),
        drive: drive.into(),
        plugin: plugin.into(),
        for_agent: actor,
        manifest: None,
    };
    host.validate_binding().await?;
    Ok(host)
}
pub async fn list(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Target>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(actions::list(&h).await?))
}
pub async fn invoke(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Invoke>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(actions::invoke(h, body.call.clone()).await?))
}
pub async fn proposals(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Target>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(actions::proposals(&h).await?))
}
pub async fn approve(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Approve>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(actions::approve(h, &body.id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryTarget {
    pub drive: String,
    pub plugin: String,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}
pub async fn history(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<HistoryTarget>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    // Preserve the existing array response for older clients.
    if body.limit.is_none() && body.cursor.is_none() {
        return Ok(HttpResponse::Ok().json(actions::history(&h).await?));
    }
    Ok(HttpResponse::Ok()
        .json(actions::history_page(&h, body.cursor.as_deref(), body.limit.unwrap_or(50)).await?))
}
pub async fn cancel(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Approve>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    actions::cancel(&h, &body.id).await?;
    Ok(HttpResponse::Ok().json(true))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub drive: String,
    pub plugin: String,
    pub caller: String,
    pub action: String,
    pub mode: String,
}
pub async fn grant(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Grant>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    actions::set_grant(&h, &body.caller, &body.action, &body.mode).await?;
    Ok(HttpResponse::Ok().json(true))
}
pub async fn grants(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Target>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(actions::grants(&h).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    pub drive: String,
    pub plugin: String,
    pub id: String,
    pub call: actions::Call,
    pub evidence: String,
}
pub async fn inspect_recovery(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Recovery>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok()
        .json(actions::inspect_recovery(h, &body.id, body.call.clone(), &body.evidence).await?))
}
pub async fn confirm_recovery(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Approve>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    actions::confirm_recovery(&h, &body.id).await?;
    Ok(HttpResponse::Ok().json(true))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactTarget {
    pub drive: String,
    pub plugin: String,
    pub cursor: Option<String>,
    #[serde(default)]
    pub apply: bool,
    #[serde(default, rename = "includeCompleted")]
    pub include_completed: bool,
    #[serde(default, rename = "includeAutomation")]
    pub include_automation: bool,
}
pub async fn compact_history(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<CompactTarget>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(
        actions::compact_history_policy(
            &h,
            body.cursor.as_deref(),
            body.apply,
            body.include_completed,
            body.include_automation,
        )
        .await?,
    ))
}

pub async fn consumers(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<Approve>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    Ok(HttpResponse::Ok().json(actions::consumers(&h, &body.id).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbandonConsumer {
    pub drive: String,
    pub plugin: String,
    pub id: String,
    pub run: String,
    pub reason: String,
}
pub async fn abandon_consumer(
    app: web::Data<AppState>,
    req: HttpRequest,
    context: RequestContext,
    body: web::Json<AbandonConsumer>,
) -> AtomicServerResult<HttpResponse> {
    let h = host(&app, &req, &context, &body.drive, &body.plugin).await?;
    actions::abandon_consumer(&h, &body.id, &body.run, &body.reason).await?;
    Ok(HttpResponse::Ok().json(true))
}
