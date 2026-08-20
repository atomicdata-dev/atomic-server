//! Running a plugin server-side.
//!
//! The counterpart to the browser's Run action, for plugins that need the
//! network or a credential. It returns a verdict and writes nothing: the
//! browser plans it, shows the diff, and the user approves — exactly as for a
//! run that happened in a Worker.
//!
//! That symmetry is the point. The placement changes; the contract does not.

use actix_web::{web, HttpResponse};
use atomic_lib::{hierarchy::check_write, Storelike};

use crate::{
    appstate::AppState, errors::AtomicServerResult, helpers::get_client_agent, plugins::js_runtime,
};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RunBody {
    pub drive: String,
    pub plugin: String,
    /// The plugin's JavaScript. Sent by the caller rather than read from the
    /// resource so an unsaved edit can be run — the same as pressing Run in the
    /// browser before saving.
    pub source: String,
    /// The RunInput as JSON: trigger, records, config, cursor.
    pub input: String,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RunResponse {
    /// The verdict as JSON, when the plugin produced one.
    pub verdict: Option<String>,
    /// Why it did not.
    pub error: Option<String>,
}

/// Running a plugin can spend its secrets, so it takes the same rights as
/// changing it. Read access would let anyone who can see a plugin drain the
/// credentials attached to it.
#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_plugin_run(
    appstate: web::Data<AppState>,
    body: web::Json<RunBody>,
    req: actix_web::HttpRequest,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let resource = store.get_resource(&body.plugin.clone().into()).await?;
    let agent = get_client_agent(req.headers(), &appstate, &body.plugin).await?;
    check_write(store, &resource, &agent).await?;

    let runtime = js_runtime::embedded_runtime()?;

    let host = js_runtime::StoreHost {
        db: std::sync::Arc::new(store.clone()),
        plugin: body.plugin.clone(),
        drive: body.drive.clone(),
    };

    let outcome = runtime.run(&body.source, &body.input, host).await?;

    // A plugin that failed is a result to render, not a 500: the browser shows
    // the message beside the run that produced it.
    Ok(HttpResponse::Ok().json(match outcome {
        Ok(verdict) => RunResponse {
            verdict: Some(verdict),
            error: None,
        },
        Err(error) => RunResponse {
            verdict: None,
            error: Some(error),
        },
    }))
}
