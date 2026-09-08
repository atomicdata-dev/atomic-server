//! Setting and reading a plugin's schedule.
//!
//! The same shape as `/plugin-secret`, and for the same reason: a plugin's
//! schema is created per drive, so a scheduler running in Rust cannot resolve
//! its property subjects. This is host state keyed by `(drive, plugin)`.

use actix_web::{web, HttpResponse};
use atomic_lib::{
    agents::ForAgent,
    db::plugin_schedule::{AutoApplyGrant, PluginSchedule, PluginScheduleInfo, PluginScheduleKey},
    hierarchy::check_write,
    Storelike,
};

use crate::{
    appstate::AppState,
    errors::{AtomicServerError, AtomicServerResult},
    helpers::get_client_agent,
    plugins::scheduler::drive_terms,
};

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetScheduleBody {
    pub drive: String,
    pub plugin: String,
    /// How often to run. `null` stops it.
    pub interval_seconds: Option<u64>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleQuery {
    pub drive: String,
    pub plugin: String,
}

/// Scheduling a plugin means it will spend that plugin's secrets unattended, so
/// it takes the same rights as changing it.
pub(crate) async fn authorize(
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
pub async fn handle_set_schedule(
    appstate: web::Data<AppState>,
    body: web::Json<SetScheduleBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let agent = authorize(&appstate, &req, &context, &body.plugin).await?;

    let key = PluginScheduleKey::new(&body.drive, &body.plugin);

    match body.interval_seconds {
        None => appstate.store.delete_plugin_schedule(&key)?,
        Some(interval) => {
            refuse_if_unattended_is_impossible(&appstate, &body.drive, &body.plugin).await?;

            // A new schedule rather than a reset: changing the interval should
            // not discard a verdict nobody has reviewed yet.
            let existing = appstate.store.get_plugin_schedule(&key)?;
            let now = atomic_lib::utils::now();
            let mut schedule = PluginSchedule::new(interval, now)?;
            schedule.run_as = Some(agent.to_string());

            if let Some(previous) = existing {
                schedule.running = previous.running;
                schedule.last_run_at = previous.last_run_at;
                schedule.pending_verdict = previous.pending_verdict;
                schedule.last_error = previous.last_error;
                // Consent is about what may be written, not how often — so
                // changing the interval does not silently revoke it.
                schedule.auto_apply = previous.auto_apply;
            }

            appstate.store.set_plugin_schedule(&key, &schedule)?;
        }
    }

    Ok(HttpResponse::Ok().json(read(&appstate, &key)?))
}

#[tracing::instrument(skip(appstate, req))]
pub async fn handle_get_schedule(
    appstate: web::Data<AppState>,
    query: web::Query<ScheduleQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.plugin).await?;

    Ok(HttpResponse::Ok().json(read(
        &appstate,
        &PluginScheduleKey::new(&query.drive, &query.plugin),
    )?))
}

/// Clears the verdict a background run left, once it has been dealt with.
#[tracing::instrument(skip(appstate, req))]
pub async fn handle_clear_pending(
    appstate: web::Data<AppState>,
    query: web::Query<ScheduleQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &query.plugin).await?;

    let key = PluginScheduleKey::new(&query.drive, &query.plugin);

    if let Some(mut schedule) = appstate.store.get_plugin_schedule(&key)? {
        schedule.pending_verdict = None;
        appstate.store.set_plugin_schedule(&key, &schedule)?;
    }

    Ok(HttpResponse::Ok().json(read(&appstate, &key)?))
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AutoApplyBody {
    pub drive: String,
    pub plugin: String,
    pub enabled: bool,
}

/// Lets a scheduled run write without anyone looking at the diff first.
///
/// Only offered once this plugin has produced a run someone actually reviewed
/// and applied. Granting it before that would mean approving code by its
/// description rather than by what it does — which is the one thing the whole
/// propose-then-approve model exists to avoid.
#[tracing::instrument(skip(appstate, body, req))]
pub async fn handle_set_auto_apply(
    appstate: web::Data<AppState>,
    body: web::Json<AutoApplyBody>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    let agent = authorize(&appstate, &req, &context, &body.plugin).await?;
    let key = PluginScheduleKey::new(&body.drive, &body.plugin);

    let mut schedule = appstate.store.get_plugin_schedule(&key)?.ok_or_else(|| {
        AtomicServerError::bad_request(
            "This plugin has no schedule, so there is nothing to apply automatically",
        )
    })?;

    if !body.enabled {
        schedule.auto_apply = None;
        appstate.store.set_plugin_schedule(&key, &schedule)?;

        return Ok(HttpResponse::Ok().json(read(&appstate, &key)?));
    }

    let (reviewed, approved_source) = reviewed_run(&appstate, &body.drive, &body.plugin).await?;

    crate::plugins::js_runtime::describe_manifest(&approved_source).await?;

    let ForAgent::AgentSubject(subject) = &agent else {
        return Err(AtomicServerError::bad_request(
            "Only a signed-in agent can allow a plugin to write unattended",
        ));
    };

    schedule.auto_apply = Some(AutoApplyGrant {
        agent: subject.to_string(),
        granted_at: atomic_lib::utils::now(),
        reviewed_run: Some(reviewed),
        release: Some(
            appstate.store.publish_plugin_release(
                &atomic_lib::db::plugin_release::PluginRelease {
                    source: approved_source.clone(),
                    manifest: serde_json::json!(
                        crate::plugins::js_runtime::describe_manifest(&approved_source).await?
                    ),
                    runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
                    schemas: crate::plugins::scheduler::plugin_schema_bindings(
                        &appstate.store,
                        &body.drive,
                        &body.plugin,
                    )
                    .await?,
                },
            )?,
        ),
        source: Some(approved_source),
    });

    appstate.store.set_plugin_schedule(&key, &schedule)?;

    Ok(HttpResponse::Ok().json(read(&appstate, &key)?))
}

/// Refuses to arm a plugin whose secrets need a person present.
///
/// Checked when the schedule or trigger is set, not when it fires: a run at
/// 3am has nobody to tell, and "it silently stopped importing a week ago" is
/// the failure this exists to prevent.
pub async fn refuse_if_unattended_is_impossible(
    appstate: &AppState,
    drive: &str,
    plugin: &str,
) -> AtomicServerResult<()> {
    let blocked = appstate
        .store
        .plugin_secrets_needing_a_person(drive, plugin)?;

    if blocked.is_empty() {
        return Ok(());
    }

    Err(AtomicServerError::bad_request(format!(
        "This plugin cannot run unattended: {} can only be opened while you are here. \
         Run it manually, or store that credential so this node can open it.",
        blocked.join(", "),
    )))
}

/// The most recent run of this plugin whose changes a person applied.
///
/// Errors when there is none — the caller is asking to skip review, and the
/// evidence that review has happened at least once is the precondition.
pub async fn reviewed_run(
    appstate: &AppState,
    drive: &str,
    plugin: &str,
) -> AtomicServerResult<(String, String)> {
    let terms = drive_terms(&appstate.store, drive)
        .await
        .ok_or_else(|| AtomicServerError::bad_request("This drive has no plugin vocabulary yet"))?;
    let status_property = terms
        .property("run-status")
        .ok_or_else(|| AtomicServerError::bad_request("This drive has no run records yet"))?;
    let started_property = terms.property("started-at");
    let source_property = terms
        .property("plugin-source")
        .ok_or_else(|| AtomicServerError::bad_request("No plugin source property"))?;
    let current_source = crate::plugins::scheduler::plugin_source(&appstate.store, drive, plugin)
        .await
        .ok_or_else(|| AtomicServerError::bad_request("The plugin has no source"))?;

    let current_schemas =
        crate::plugins::scheduler::plugin_schema_bindings(&appstate.store, drive, plugin).await?;
    let plugin_resource = appstate.store.get_resource(&plugin.into()).await?;
    let runs = plugin_resource.get_children(&appstate.store).await?;

    let mut best: Option<(i64, String)> = None;

    for run in runs {
        let reviewed_schemas: std::collections::BTreeMap<String, String> = terms
            .property("plugin-schemas")
            .and_then(|p| run.get(p).ok())
            .and_then(|v| serde_json::from_str(&v.to_string()).ok())
            .unwrap_or_default();
        if reviewed_schemas != current_schemas {
            continue;
        }

        if run
            .get(source_property)
            .ok()
            .map(|v| v.to_string())
            .as_deref()
            != Some(current_source.as_str())
        {
            continue;
        }
        let Ok(status) = run.get(status_property) else {
            continue;
        };

        // `partial` counts: some changes were written, which means a person
        // saw the diff and said yes.
        if !matches!(status.to_string().as_str(), "applied" | "partial") {
            continue;
        }

        let at = started_property
            .and_then(|property| run.get(property).ok())
            .and_then(|value| value.to_int().ok())
            .unwrap_or_default();

        if best.as_ref().is_none_or(|(previous, _)| at >= *previous) {
            best = Some((at, run.get_subject().to_string()));
        }
    }

    best.map(|(_, subject)| (subject, current_source))
        .ok_or_else(|| {
            AtomicServerError::bad_request(
                "Run this plugin and apply its changes once before letting it write on its own",
            )
        })
}

fn read(
    appstate: &AppState,
    key: &PluginScheduleKey,
) -> AtomicServerResult<Option<PluginScheduleInfo>> {
    Ok(appstate
        .store
        .get_plugin_schedule(key)?
        .as_ref()
        .map(PluginScheduleInfo::from))
}

/// Resume the saved plan under its original approval, never rerun the script.
pub async fn handle_resume(
    appstate: web::Data<AppState>,
    body: web::Json<ScheduleQuery>,
    req: actix_web::HttpRequest,
    context: crate::context::RequestContext,
) -> AtomicServerResult<HttpResponse> {
    authorize(&appstate, &req, &context, &body.plugin).await?;
    let _execution = crate::plugins::scheduler::EXECUTION_LOCK.lock().await;
    let key = PluginScheduleKey::new(&body.drive, &body.plugin);
    let mut schedule = appstate
        .store
        .get_plugin_schedule(&key)?
        .ok_or_else(|| AtomicServerError::bad_request("No schedule to resume"))?;
    let verdict = schedule
        .pending_verdict
        .clone()
        .ok_or_else(|| AtomicServerError::bad_request("No saved proposal to resume"))?;
    let grant = schedule.auto_apply.clone().ok_or_else(|| {
        AtomicServerError::bad_request("Resume requires the original unattended approval")
    })?;
    let at = schedule
        .last_run_at
        .ok_or_else(|| AtomicServerError::bad_request("No original run timestamp"))?;
    schedule.running = true;
    appstate.store.set_plugin_schedule(&key, &schedule)?;
    let result = crate::plugins::scheduler::auto_apply(&appstate, &key, &verdict, &grant, at).await;
    schedule.running = false;
    match result {
        Ok(_) => {
            schedule.pending_verdict = None;
            schedule.last_error = None;
        }
        Err(error) => schedule.last_error = Some(error),
    }
    appstate.store.set_plugin_schedule(&key, &schedule)?;
    Ok(HttpResponse::Ok().json(PluginScheduleInfo::from(&schedule)))
}
