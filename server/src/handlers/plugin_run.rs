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
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
    plugins::js_runtime,
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
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;
    let resource = store.get_resource(&body.plugin.clone().into()).await?;

    // Signed over the request URL, as every other signed endpoint is.
    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject =
        atomic_lib::Subject::from_raw(&path_and_query, None).resolve(&context.origin);

    let agent = get_client_agent(req.headers(), &appstate, &signed_subject).await?;
    check_write(store, &resource, &agent).await?;

    let runtime = js_runtime::embedded_runtime()?;
    let manifest = js_runtime::describe_manifest(&body.source).await?;
    check_upload(manifest.as_ref(), &body.input)?;

    let host =
        js_runtime::StoreHost::bound(store, &body.drive, &body.plugin, agent, manifest).await?;

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

/// The JSON limit for `/plugin-run`: an uploaded file travels inside `input`,
/// a JSON string inside the JSON body, so escaping can grow it severalfold
/// (every quote in XML gains two backslashes). The declared `maxBytes` is what
/// actually bounds the file; see [`check_upload`].
pub const RUN_JSON_LIMIT: usize = crate::serve::PAYLOAD_MAX;

/// A file handed to the plugin (`input.upload`) must be one it declared it
/// accepts, and no larger than it said. The browser checks this too, before
/// reading the file; this is the check that holds.
fn check_upload(
    manifest: Option<&crate::plugins::manifest::Manifest>,
    input: &str,
) -> AtomicServerResult<()> {
    let input: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| AtomicServerError::bad_request(format!("input is not JSON: {e}")))?;
    let Some(upload) = input.get("upload") else {
        return Ok(());
    };
    let accepts = manifest.map(|m| m.accepts.as_slice()).unwrap_or_default();
    if accepts.is_empty() {
        return Err(AtomicServerError::bad_request(
            "This plugin does not accept files",
        ));
    }
    let Some(text) = upload.get("text").and_then(|t| t.as_str()) else {
        return Err(AtomicServerError::bad_request(
            "input.upload needs the file as text",
        ));
    };
    let max = accepts.iter().map(|a| a.max_bytes()).max().unwrap_or(0);
    if text.len() as u64 > max {
        return Err(AtomicServerError::bad_request(format!(
            "This file is {} bytes; this plugin accepts at most {max}",
            text.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_upload;
    use crate::plugins::manifest::Manifest;

    fn manifest(raw: serde_json::Value) -> Manifest {
        Manifest::parse(raw).unwrap().unwrap()
    }

    #[test]
    fn uploads_need_a_declaration_and_respect_its_size() {
        let accepting = manifest(serde_json::json!({
            "schemaVersion": 2,
            "accepts": [{"as": "text", "maxBytes": 4}],
        }));
        let plain = manifest(serde_json::json!({"schemaVersion": 2}));
        let upload = |text: &str| serde_json::json!({"upload": {"text": text}}).to_string();

        assert!(check_upload(Some(&accepting), &upload("1234")).is_ok());
        assert!(check_upload(Some(&accepting), &upload("12345"))
            .unwrap_err()
            .message
            .contains("at most 4"));
        assert!(check_upload(Some(&plain), &upload("1")).is_err());
        assert!(check_upload(None, &upload("1")).is_err());
        assert!(check_upload(Some(&accepting), r#"{"upload":{}}"#).is_err());
        // A run without a file is not affected.
        assert!(check_upload(None, r#"{"trigger":{"kind":"manual"}}"#).is_ok());
    }
}
