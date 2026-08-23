//! Handing an app's signing key to the node that will use it.
//!
//! The key is minted in the browser, where the app is created, and posted
//! here once. It is never returned: the only accessor hands it to a closure
//! that signs, and nothing that gives a private key back to a caller can
//! promise where it goes next.
//!
//! Why the node holds it at all: an app that imports at 3am has nobody to ask
//! for a credential, so whatever signs its writes must be openable unattended.
//! At rest it is wrapped with the node key, like every other secret here.

use actix_web::{web, HttpResponse};
use atomic_lib::{
    agents::{Agent, ForAgent},
    db::app_agent::{AppAgent, AppAgentKey},
    hierarchy::check_write,
    Storelike,
};

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAppAgentBody {
    pub drive: String,
    pub app: String,
    /// The agent secret, as `Agent::buildSecret` produces it.
    pub secret: String,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppAgentQuery {
    pub drive: String,
    pub app: String,
}

/// Deliberately not `Debug`: the body holds a private key, and a handler that
/// logs its arguments on error is how secrets reach a log file.
#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_set_app_agent(
    appstate: web::Data<AppState>,
    body: web::Json<SetAppAgentBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    // Write rights on the app: giving it an identity is changing what it can
    // do, which is at least as consequential as editing it.
    let agent = authorize(&appstate, &req, &context, &body.app).await?;

    let ForAgent::AgentSubject(_) = &agent else {
        return Err(AtomicServerError::bad_request(
            "Only a signed-in agent can give an app a key",
        ));
    };

    // Parsed before storing, so a malformed key fails now rather than at 3am
    // in a scheduler with nobody watching.
    let parsed = Agent::from_secret(&body.secret)
        .map_err(|e| AtomicServerError::bad_request(format!("That is not an agent secret: {e}")))?;

    let key = AppAgentKey::new(&body.drive, &body.app);
    appstate.store.set_app_agent(
        &key,
        &AppAgent::new(
            parsed.subject.to_string(),
            body.secret.clone(),
            atomic_lib::utils::now(),
        ),
    )?;

    Ok(HttpResponse::Ok().json(appstate.store.get_app_agent_info(&key)?))
}

/// Which DID an app writes as. Never the key itself.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_get_app_agent(
    appstate: web::Data<AppState>,
    query: web::Query<AppAgentQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.app).await?;

    Ok(HttpResponse::Ok().json(
        appstate
            .store
            .get_app_agent_info(&AppAgentKey::new(&query.drive, &query.app))?,
    ))
}

/// Revokes by forgetting. The agent resource and its ACL entries stay: what
/// stops mattering is that this node can act as it.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_delete_app_agent(
    appstate: web::Data<AppState>,
    query: web::Query<AppAgentQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.app).await?;

    appstate
        .store
        .delete_app_agent(&AppAgentKey::new(&query.drive, &query.app))?;

    Ok(HttpResponse::Ok().finish())
}

async fn authorize(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &crate::context::RequestContext,
    app: &str,
) -> AtomicServerResult<ForAgent> {
    let store = &appstate.store;
    let resource = store.get_resource(&app.into()).await?;

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

    Ok(agent)
}
