//! `POST /host/call`: calling an app's export from outside the sandbox.
//!
//! The browser and MCP are not WASM components, so they cannot use
//! `atomic:host/calls`. This is the same call, from HTTP: the provider is
//! found in the drive, the arguments are checked against its declared schema,
//! and it runs under its own Installation's rights **bounded by the signed-in
//! agent's** (a read or write needs both to be allowed). Nobody gets more than
//! they have by going through an app.
//!
//! Signed like the other plugin routes with a body: a version 2 signature, which
//! covers the method and the body hash, so a captured request cannot be replayed
//! with other arguments. An unsigned request is refused, since the public agent
//! has no business asking an app to do things.
//!
//! The agent must be able to read the drive, and to write it when the export's
//! effect is `write` or `external`. A caller that vouches for what it forwards
//! (the data browser, for a sandboxed frame) can narrow the effects with
//! `allowEffects`; a frame has no network of its own and cannot set it.

use actix_web::{http::StatusCode, web, HttpResponse};
use atomic_lib::{
    agents::ForAgent,
    hierarchy::{check_read, check_write},
    Storelike,
};

use crate::{
    appstate::AppState,
    errors::{AppErrorType, AtomicServerError, AtomicServerResult},
    helpers::get_client_agent_for_request,
    plugins::{
        host_abi::{self, code, CallBudget, ENTRY_TIMEOUT},
        manifest::ExportEffect,
    },
};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HostCallBody {
    pub drive: String,
    /// `atomic:example/counter@1`.
    pub interface: String,
    pub function: String,
    /// The arguments, a JSON object checked against the export's `inputSchema`.
    #[serde(default = "empty_object")]
    pub args: serde_json::Value,
    /// When given, only exports with one of these effects (`read`, `write`,
    /// `external`, `interactive`) run; others are `forbidden`.
    #[serde(default)]
    pub allow_effects: Option<Vec<String>>,
}

fn empty_object() -> serde_json::Value {
    serde_json::json!({})
}

/// The HTTP status an ABI error code maps to.
fn status_of(code: &str) -> StatusCode {
    match code {
        code::NOT_FOUND => StatusCode::NOT_FOUND,
        code::FORBIDDEN | code::NEEDS_APPROVAL => StatusCode::FORBIDDEN,
        code::INVALID_ARGUMENT | code::DEPTH_EXCEEDED => StatusCode::BAD_REQUEST,
        code::UNSUPPORTED => StatusCode::NOT_IMPLEMENTED,
        // The app trapped or broke its own contract.
        _ => StatusCode::BAD_GATEWAY,
    }
}

fn effect_name(effect: ExportEffect) -> &'static str {
    match effect {
        ExportEffect::Read => "read",
        ExportEffect::Write => "write",
        ExportEffect::External => "external",
        ExportEffect::Interactive => "interactive",
    }
}

fn refusal(code: &str, status: StatusCode, message: impl Into<String>) -> HttpResponse {
    HttpResponse::build(status).json(serde_json::json!({
        "error": { "code": code, "message": message.into() },
    }))
}

#[tracing::instrument(skip(appstate, raw, req))]
pub async fn handle_host_call(
    appstate: web::Data<AppState>,
    // Raw bytes, so the signature covers exactly the body acted on.
    raw: web::Bytes,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject =
        atomic_lib::Subject::from_raw(&path_and_query, None).resolve(&context.origin);

    let agent = get_client_agent_for_request(&req, &raw, &appstate, &signed_subject).await?;
    if agent == ForAgent::Public {
        return Err(AtomicServerError {
            message: "Sign the request: calling an app needs an agent".into(),
            error_type: AppErrorType::Unauthorized,
            error_resource: None,
        });
    }
    crate::helpers::enforce_write_rate_limit(&appstate, &req, &agent)?;

    let body: HostCallBody = serde_json::from_slice(&raw)
        .map_err(|e| AtomicServerError::bad_request(format!("Invalid JSON body: {e}")))?;

    // Before anything is loaded or run: the caller must see the drive.
    let store = &appstate.store;
    let drive = store.get_resource(&body.drive.as_str().into()).await?;
    if let Err(e) = check_read(store, &drive, &agent).await {
        return Ok(refusal(
            code::FORBIDDEN,
            StatusCode::FORBIDDEN,
            e.to_string(),
        ));
    }

    let db = std::sync::Arc::new(store.clone());
    appstate.host_abi.refresh(&db, &body.drive).await;

    // What the export does decides what the caller needs on the drive.
    let effect = appstate
        .host_abi
        .provider_of(&body.drive, &body.interface, &body.function)
        .and_then(|app| {
            app.export(&body.interface, &body.function)
                .map(|export| export.effect)
        });
    if let Some(effect) = effect {
        if matches!(effect, ExportEffect::Write | ExportEffect::External) {
            if let Err(e) = check_write(store, &drive, &agent).await {
                return Ok(refusal(
                    code::FORBIDDEN,
                    StatusCode::FORBIDDEN,
                    e.to_string(),
                ));
            }
        }
    }

    // Checked at every hop, not only here: an app a frame calls cannot hand
    // the call on to one that writes.
    let budget = match &body.allow_effects {
        Some(allowed) => CallBudget::default().only(
            [
                ExportEffect::Read,
                ExportEffect::Write,
                ExportEffect::External,
                ExportEffect::Interactive,
            ]
            .into_iter()
            .filter(|e| allowed.iter().any(|a| a == effect_name(*e)))
            .collect(),
        ),
        None => CallBudget::default(),
    };

    let outcome = host_abi::call_entry(
        &appstate.host_abi,
        &db,
        &body.drive,
        &body.interface,
        &body.function,
        &body.args.to_string(),
        agent,
        std::sync::Arc::new(budget),
        ENTRY_TIMEOUT,
    )
    .await;

    Ok(match outcome {
        Ok(result) => {
            let result: serde_json::Value = serde_json::from_str(&result)
                .map_err(|e| format!("an app returned something that is not JSON: {e}"))?;
            HttpResponse::Ok().json(serde_json::json!({ "result": result }))
        }
        Err(error) => HttpResponse::build(status_of(&error.code)).json(serde_json::json!({
            "error": { "code": error.code, "message": error.message },
        })),
    })
}
