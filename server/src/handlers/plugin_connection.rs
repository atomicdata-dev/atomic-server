//! Signed access to a connection's private reconciliation state.
use crate::{
    appstate::AppState,
    context::RequestContext,
    errors::AtomicServerResult,
    plugins::{connection_state, js_runtime::StoreHost},
};
use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub drive: String,
    pub plugin: String,
}
async fn authorize(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &RequestContext,
    target: &Target,
) -> AtomicServerResult<()> {
    let account = super::plugin_schedule::authorize(appstate, req, context, &target.plugin).await?;
    let host = StoreHost {
        db: std::sync::Arc::new(appstate.store.clone()),
        plugin: target.plugin.clone(),
        drive: target.drive.clone(),
        for_agent: account,
        manifest: None,
    };
    host.validate_binding().await?;
    Ok(())
}
pub async fn read(
    appstate: web::Data<AppState>,
    body: web::Json<Target>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &body).await?;
    Ok(HttpResponse::Ok()
        .json(connection_state::read_resolved(&appstate.store, &body.drive, &body.plugin).await?))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub target: Target,
    pub checkpoint: connection_state::Checkpoint,
}
pub async fn checkpoint(
    appstate: web::Data<AppState>,
    body: web::Json<Update>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &body.target).await?;
    let body = body.into_inner();
    Ok(HttpResponse::Ok().json(
        connection_state::checkpoint(
            &appstate.store,
            &body.target.drive,
            &body.target.plugin,
            body.checkpoint,
        )
        .await?,
    ))
}
