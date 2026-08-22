//! Setting and reading what makes a plugin run when the data changes.
//!
//! The same shape as `/plugin-schedule`, and for the same reason: host state
//! keyed by `(drive, plugin)`, because a plugin's schema is created per drive
//! and a Rust listener cannot resolve its property subjects.

use actix_web::{web, HttpResponse};
use atomic_lib::{
    agents::ForAgent,
    db::{
        plugin_schedule::AutoApplyGrant,
        plugin_trigger::{PluginTrigger, PluginTriggerInfo, PluginTriggerKey},
        PropVal, QueryFilter,
    },
    hierarchy::check_write,
    Storelike, Value,
};

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FilterBody {
    pub property: Option<String>,
    pub value: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetTriggerBody {
    pub drive: String,
    pub plugin: String,
    /// The ANDed constraints a resource must match. `null` removes the trigger.
    pub filters: Option<Vec<FilterBody>>,
    #[serde(default)]
    pub on_enter: bool,
    #[serde(default)]
    pub on_leave: bool,
    /// Write without review. Only accepted with a reviewed run behind it.
    #[serde(default)]
    pub auto_apply: bool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TriggerQuery {
    pub drive: String,
    pub plugin: String,
}

/// A trigger spends the plugin's secrets whenever the data moves, so it takes
/// the same rights as changing the plugin.
async fn authorize(
    appstate: &AppState,
    req: &actix_web::HttpRequest,
    context: &crate::context::RequestContext,
    plugin: &str,
) -> AtomicServerResult<ForAgent> {
    let store = &appstate.store;
    let resource = store.get_resource(&plugin.into()).await?;

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

#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_set_trigger(
    appstate: web::Data<AppState>,
    body: web::Json<SetTriggerBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let agent = authorize(&appstate, &req, &context, &body.plugin).await?;
    let key = PluginTriggerKey::new(&body.drive, &body.plugin);

    let Some(filters) = &body.filters else {
        appstate.store.delete_plugin_trigger(&key)?;

        return Ok(HttpResponse::Ok().json(read(&appstate, &key)?));
    };

    if filters.is_empty() {
        // An unconstrained query matches the whole drive, which would run the
        // plugin on every write anywhere. Refused rather than allowed with a
        // warning: nobody means this.
        return Err(AtomicServerError::bad_request(
            "A trigger needs at least one condition, or it would run on every change to the drive",
        ));
    }

    crate::handlers::plugin_schedule::refuse_if_unattended_is_impossible(
        &appstate,
        &body.drive,
        &body.plugin,
    )
    .await?;

    let query = QueryFilter {
        filters: filters
            .iter()
            .map(|filter| PropVal {
                property: filter.property.clone(),
                value: filter.value.as_ref().map(|v| Value::String(v.clone())),
                ..Default::default()
            })
            .collect(),
        sort_by: None,
        drive: body.drive.as_str().into(),
    };

    let mut trigger = PluginTrigger::new(query, body.on_enter, body.on_leave)
        .map_err(|e| AtomicServerError::bad_request(e.to_string()))?;

    if body.auto_apply {
        // The same precondition a schedule's grant has, checked the same way.
        let reviewed =
            crate::handlers::plugin_schedule::reviewed_run(&appstate, &body.drive, &body.plugin)
                .await?;

        let ForAgent::AgentSubject(subject) = &agent else {
            return Err(AtomicServerError::bad_request(
                "Only a signed-in agent can allow a plugin to write unattended",
            ));
        };

        trigger.auto_apply = Some(AutoApplyGrant {
            agent: subject.to_string(),
            granted_at: atomic_lib::utils::now(),
            reviewed_run: Some(reviewed),
        });
    }

    appstate.store.set_plugin_trigger(&key, &trigger)?;

    Ok(HttpResponse::Ok().json(read(&appstate, &key)?))
}

#[tracing::instrument(skip(appstate, req))]
pub async fn handle_get_trigger(
    appstate: web::Data<AppState>,
    query: web::Query<TriggerQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.plugin).await?;

    Ok(HttpResponse::Ok().json(read(
        &appstate,
        &PluginTriggerKey::new(&query.drive, &query.plugin),
    )?))
}

fn read(
    appstate: &AppState,
    key: &PluginTriggerKey,
) -> AtomicServerResult<Option<PluginTriggerInfo>> {
    Ok(appstate
        .store
        .get_plugin_trigger(key)?
        .as_ref()
        .map(PluginTriggerInfo::from))
}
