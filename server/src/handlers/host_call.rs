//! `POST /host/call`: calling an app's export from outside the sandbox.
//!
//! The browser and MCP are not WASM components, so they cannot use
//! `atomic:host/calls`. This is the same call, from HTTP: the provider is
//! found in the drive, the arguments are checked against its declared schema,
//! and it runs under its own Installation's rights **bounded by the signed-in
//! agent's** (a read or write needs both to be allowed). Nobody gets more than
//! they have by going through an app.
//!
//! Signed like every plugin route: the request is signed over its URL, and an
//! unsigned request is refused, since the public agent has no business asking
//! an app to do things.

use actix_web::{http::StatusCode, web, HttpResponse};
use atomic_lib::agents::ForAgent;

use crate::{
    appstate::AppState,
    errors::{AppErrorType, AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
    plugins::host_abi::{self, code},
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

#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_host_call(
    appstate: web::Data<AppState>,
    body: web::Json<HostCallBody>,
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

    let agent = get_client_agent(req.headers(), &appstate, &signed_subject).await?;
    if agent == ForAgent::Public {
        return Err(AtomicServerError {
            message: "Sign the request: calling an app needs an agent".into(),
            error_type: AppErrorType::Unauthorized,
            error_resource: None,
        });
    }

    let body = body.into_inner();
    let db = std::sync::Arc::new(appstate.store.clone());
    let outcome = host_abi::call_as(
        &appstate.host_abi,
        &db,
        &body.drive,
        &body.interface,
        &body.function,
        &body.args.to_string(),
        agent,
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
