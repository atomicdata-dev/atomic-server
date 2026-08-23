//! Writing as an app, on behalf of the person using it.
//!
//! An app's view runs in the browser, and in Atomic a commit is signed by
//! whoever's key is in the page — which is the user's. So a write from an
//! app's UI was authored by the person, bounded only by what the host page
//! chose to allow. That is the host being polite, not the server refusing.
//!
//! Here the server performs the write instead, signed by the app's own agent
//! and checked against the app's own rights. The bound stops being advisory,
//! the author is the app, and a click in a tab lands the same way a scheduled
//! run does.
//!
//! Reads are deliberately not routed through here. They stay on the session's
//! store, so an app sees what the person looking at it can see. A write
//! persists and is attributable; a read is already on their screen. Proxying
//! reads would also mean a round trip and no cache for every property an app
//! renders.

use std::collections::HashMap;

use actix_web::{web, HttpResponse};
use atomic_lib::{
    agents::ForAgent, db::app_agent::AppAgentKey, hierarchy::check_read, Storelike, Subject,
};
use serde_json::Value as Json;

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
    plugins::apply::{ApplyHost, CreateRequest},
    plugins::store_host::StoreApplyHost,
};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppWriteBody {
    pub drive: String,
    pub app: String,
    /// `create`, `save`, `remove` or `destroy`.
    pub op: String,
    pub subject: Option<String>,
    pub parent: Option<String>,
    #[serde(default)]
    pub is_a: Vec<String>,
    #[serde(default)]
    pub prop_vals: HashMap<String, Json>,
    #[serde(default)]
    pub properties: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppWriteResult {
    /// The subject that exists now. Differs from what was asked for on a
    /// create, because a DID drive mints it from the signature.
    pub subject: String,
}

#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_app_write(
    appstate: web::Data<AppState>,
    body: web::Json<AppWriteBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let store = &appstate.store;

    // Read rights on the app: opening it is enough to drive it. What it may
    // then write is the app's business, not this person's — which is the whole
    // point of the app having an identity.
    let app_resource = store.get_resource(&body.app.as_str().into()).await?;

    let path_and_query = req
        .head()
        .uri
        .path_and_query()
        .ok_or("Path must be given")?
        .to_string();
    let signed_subject = Subject::from_raw(&path_and_query, None).resolve(&context.origin);

    let agent = get_client_agent(req.headers(), &appstate, &signed_subject).await?;
    check_read(store, &app_resource, &agent).await?;

    let key = AppAgentKey::new(&body.drive, &body.app);
    let app_agent = store.get_app_agent_info(&key)?.ok_or_else(|| {
        AtomicServerError::bad_request(
            "This app has no key of its own, so it cannot write. Recreate it, or give it one.",
        )
    })?;

    // Rights are the app's, not the caller's. A person who may write the whole
    // drive does not lend that reach to an app just by opening it.
    let mut host = StoreApplyHost {
        store: store.clone(),
        for_agent: ForAgent::AgentSubject(Subject::from_raw(&app_agent.agent, None)),
        signing_as: Some(key),
    };

    let body = body.into_inner();

    let subject = match body.op.as_str() {
        "create" => {
            host.create(CreateRequest {
                // Defaults to the app: the one place it may always write, so
                // the only sensible default.
                parent: body.parent.unwrap_or_else(|| body.app.clone()),
                is_a: body.is_a,
                prop_vals: body.prop_vals,
            })
            .await
        }
        "save" => {
            let subject = required(body.subject)?;
            host.set(&subject, body.prop_vals).await.map(|_| subject)
        }
        "remove" => {
            let subject = required(body.subject)?;
            host.remove(&subject, body.properties)
                .await
                .map(|_| subject)
        }
        "destroy" => {
            let subject = required(body.subject)?;
            host.destroy(&subject).await.map(|_| subject)
        }
        other => {
            return Err(AtomicServerError::bad_request(format!(
                "An app cannot {other}",
            )))
        }
    }
    .map_err(AtomicServerError::bad_request)?;

    Ok(HttpResponse::Ok().json(AppWriteResult { subject }))
}

fn required(subject: Option<String>) -> AtomicServerResult<String> {
    subject.ok_or_else(|| AtomicServerError::bad_request("That needs a subject"))
}
