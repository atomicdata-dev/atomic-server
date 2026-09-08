//! Explicit approval of one remote operation. This endpoint is not exposed to
//! the plugin interpreter; preview still has only read capabilities.
use crate::{
    appstate::AppState,
    context::RequestContext,
    errors::{AtomicServerError, AtomicServerResult},
    plugins::{
        external::{self, ExternalIntent},
        js_runtime::StoreHost,
        manifest::Manifest,
    },
};
use actix_web::{web, HttpResponse};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub drive: String,
    pub plugin: String,
    pub release: String,
    pub run: String,
    pub intent: ExternalIntent,
}

pub async fn apply(
    appstate: web::Data<AppState>,
    body: web::Json<Approval>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let account =
        super::plugin_schedule::authorize(&appstate, &req, &context, &body.plugin).await?;
    let release = appstate.store.get_plugin_release(&body.release)?;
    let manifest = Manifest::parse(release.manifest)?.ok_or_else(|| {
        AtomicServerError::bad_request("Remote writes require a versioned release")
    })?;
    let url = url::Url::parse(&body.intent.url)
        .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;
    if !manifest.allows_effect(
        Some(&body.intent.operation),
        &body.intent.method,
        &url,
        "write",
    ) {
        return Err(AtomicServerError::bad_request(
            "The release does not declare this write operation",
        ));
    }
    let mut host = StoreHost {
        db: std::sync::Arc::new(appstate.store.clone()),
        plugin: body.plugin.clone(),
        drive: body.drive.clone(),
        for_agent: account,
        manifest: Some(manifest),
    };
    host.validate_binding().await?;
    let connection = serde_json::json!([body.drive, body.plugin]).to_string();
    let receipt = external::execute(
        &appstate.store,
        &connection,
        &body.release,
        &body.run,
        &body.intent,
        &mut host,
    )
    .await?;
    Ok(HttpResponse::Ok().json(receipt))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub drive: String,
    pub plugin: String,
    pub release: String,
    pub run: String,
    pub intent: String,
}

async fn authorize_operation(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &RequestContext,
    operation: &Operation,
) -> AtomicServerResult<String> {
    let account =
        super::plugin_schedule::authorize(appstate, req, context, &operation.plugin).await?;
    let host = StoreHost {
        db: std::sync::Arc::new(appstate.store.clone()),
        plugin: operation.plugin.clone(),
        drive: operation.drive.clone(),
        for_agent: account.clone(),
        manifest: None,
    };
    host.validate_binding().await?;
    Ok(account.to_string())
}

pub async fn status(
    appstate: web::Data<AppState>,
    body: web::Json<Operation>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize_operation(&appstate, &req, &context, &body).await?;
    let connection = serde_json::json!([body.drive, body.plugin]).to_string();
    let entry = external::inspect(
        &appstate.store,
        &connection,
        &body.release,
        &body.run,
        &body.intent,
    )?;
    Ok(HttpResponse::Ok().json(entry))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    pub operation: Operation,
    pub receipt: external::Receipt,
    pub evidence: String,
}

pub async fn confirm(
    appstate: web::Data<AppState>,
    body: web::Json<Confirm>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let actor = authorize_operation(&appstate, &req, &context, &body.operation).await?;
    let op = &body.operation;
    let connection = serde_json::json!([op.drive, op.plugin]).to_string();
    external::confirm_applied(
        &appstate.store,
        &connection,
        &op.release,
        &op.run,
        &op.intent,
        body.receipt.clone(),
        external::Resolution {
            actor,
            evidence: body.evidence.clone(),
            at: atomic_lib::utils::now(),
        },
    )
    .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"resolved": true})))
}

/// Read-only broker for host-driven adapters using the same release capabilities.
pub async fn read(
    appstate: web::Data<AppState>,
    body: web::Json<Approval>,
    req: actix_web::HttpRequest,
    context: RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let account =
        super::plugin_schedule::authorize(&appstate, &req, &context, &body.plugin).await?;
    let release = appstate.store.get_plugin_release(&body.release)?;
    let manifest = Manifest::parse(release.manifest)?
        .ok_or_else(|| AtomicServerError::bad_request("Versioned release required"))?;
    let mut host = StoreHost {
        db: std::sync::Arc::new(appstate.store.clone()),
        plugin: body.plugin.clone(),
        drive: body.drive.clone(),
        for_agent: account,
        manifest: Some(manifest),
    };
    host.validate_binding().await?;
    let response = host
        .request(
            serde_json::to_string(&body.intent)
                .map_err(|e| AtomicServerError::bad_request(e.to_string()))?,
            "read",
        )
        .await?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(response))
}
