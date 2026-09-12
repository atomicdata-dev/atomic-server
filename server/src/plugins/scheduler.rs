//! Scheduled plugins run as their authorizing actor. Atomic writes and external
//! integration actions have separate grants. Unapproved actions persist a wait;
//! resuming reuses the original input and completed external receipts.

use std::collections::HashMap;
use std::sync::Arc;

use atomic_lib::agents::ForAgent;
use atomic_lib::db::plugin_schedule::{AutoApplyGrant, PluginScheduleKey};
use atomic_lib::{urls, Db, Storelike};

use crate::appstate::AppState;
use crate::plugins::apply::ApplyOptions;
use crate::plugins::js_runtime;
use crate::plugins::plan::plan_verdict;
use crate::plugins::run_log;
use crate::plugins::store_host::StoreApplyHost;

/// How often to look for work. Well below the minimum interval a plugin may
/// ask for, so a run is late by seconds rather than by a whole period.
const TICK_SECONDS: u64 = 15;

/// A drive's plugin vocabulary, by shortname.
///
/// A plugin's properties and classes are created per drive, so their subjects
/// are not constants the server can hold. The scheduler has no browser to ask,
/// so it walks drive → default ontology → properties and classes, and matches
/// on shortname.
pub struct DriveTerms {
    pub properties: HashMap<String, String>,
    pub classes: HashMap<String, String>,
}

impl DriveTerms {
    pub fn property(&self, shortname: &str) -> Option<&str> {
        self.properties.get(shortname).map(String::as_str)
    }

    pub fn class(&self, shortname: &str) -> Option<&str> {
        self.classes.get(shortname).map(String::as_str)
    }
}

pub async fn drive_terms(store: &Db, drive: &str) -> Option<DriveTerms> {
    let drive_resource = store.get_resource(&drive.into()).await.ok()?;
    let ontology = drive_resource.get(urls::DEFAULT_ONTOLOGY).ok()?.to_string();
    let ontology_resource = store.get_resource(&ontology.as_str().into()).await.ok()?;

    let mut terms = DriveTerms {
        properties: HashMap::new(),
        classes: HashMap::new(),
    };

    for (list, into) in [
        (urls::PROPERTIES, &mut terms.properties),
        (urls::CLASSES, &mut terms.classes),
    ] {
        let subjects = match ontology_resource.get(list) {
            Ok(value) => value.to_subjects(None).ok()?,
            // An ontology with no classes yet is not an error; it just has
            // nothing to offer.
            Err(_) => continue,
        };

        for subject in subjects {
            let Ok(resource) = store.get_resource(&subject.as_str().into()).await else {
                continue;
            };

            if let Ok(shortname) = resource.get(urls::SHORTNAME) {
                into.insert(shortname.to_string(), subject);
            }
        }
    }

    Some(terms)
}

/// The source of a plugin, resolved through the drive's ontology.
pub async fn plugin_source(store: &Db, drive: &str, plugin: &str) -> Option<String> {
    let property = drive_terms(store, drive)
        .await?
        .properties
        .remove("plugin-source")?;
    let plugin_resource = store.get_resource(&plugin.into()).await.ok()?;

    plugin_resource
        .get(&property)
        .ok()
        .map(|value| value.to_string())
}

pub async fn plugin_schema_bindings(
    store: &Db,
    drive: &str,
    plugin: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let Some(terms) = drive_terms(store, drive).await else {
        return Ok(Default::default());
    };
    let Some(property) = terms.property("plugin-schemas") else {
        return Ok(Default::default());
    };
    let resource = store
        .get_resource(&plugin.into())
        .await
        .map_err(|e| e.to_string())?;
    let Ok(value) = resource.get(property) else {
        return Ok(Default::default());
    };
    serde_json::from_str(&value.to_string()).map_err(|e| format!("invalid schema bindings: {e}"))
}

/// One pass over everything due.
///
/// Returns how many ran, so the caller (and a test) can tell a quiet tick from
/// a broken one.
pub(crate) static EXECUTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run_due(appstate: &AppState) -> usize {
    let _execution = EXECUTION_LOCK.lock().await;
    let now = atomic_lib::utils::now();

    let due = match appstate.store.due_plugin_schedules(now) {
        Ok(due) => due,
        Err(e) => {
            tracing::warn!("could not read plugin schedules: {e}");

            return 0;
        }
    };

    let mut ran = 0;

    for (key, mut schedule) in due {
        if schedule.running || schedule.pending_verdict.is_some() {
            if let Some(at) = schedule.last_run_at {
                let journal = super::journal::Journal::new(
                    &appstate.store,
                    &key.drive,
                    &key.plugin,
                    &format!("cron:{at}"),
                );
                match journal.terminal() {
                    Ok(Some(_)) => {
                        schedule.running = false;
                        schedule.pending_verdict = None;
                        schedule.last_error = None;
                        schedule.advance(now);
                        if let Err(e) = appstate.store.set_plugin_schedule(&key, &schedule) {
                            tracing::warn!(%e, "could not acknowledge completed scheduled run");
                        }
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(%e, "could not read scheduled completion receipt");
                        continue;
                    }
                    Ok(None) => {}
                }
            }
        }
        // Advanced before the run, not after: a plugin that hangs or panics
        // must not be picked up again on the next tick and every tick after.
        let action_waits = schedule
            .pending_verdict
            .as_deref()
            .and_then(super::actions::waits);
        if schedule.running || (schedule.pending_verdict.is_some() && action_waits.is_none()) {
            continue;
        }
        let resuming = action_waits.is_some();
        if let Some(waits) = action_waits {
            if schedule.last_error.is_some() {
                continue;
            }
            let actor = schedule
                .run_as
                .as_deref()
                .or_else(|| schedule.auto_apply.as_ref().map(|g| g.agent.as_str()))
                .unwrap_or_default();
            match super::actions::waits_ready(
                Arc::new(appstate.store.clone()),
                &key.drive,
                actor,
                &waits,
            )
            .await
            {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) => {
                    schedule.record_error(e);
                    let _ = appstate.store.set_plugin_schedule(&key, &schedule);
                    continue;
                }
            }
        }
        if !resuming {
            schedule.advance(now);
        }
        let run_at = schedule.last_run_at.unwrap_or(now);
        schedule.running = true;
        schedule.last_error =
            Some("Run interrupted; reconcile its effects before reactivating".into());
        if let Err(error) = appstate.store.set_plugin_schedule(&key, &schedule) {
            tracing::warn!(plugin = %key.plugin, %error, "could not claim scheduled run");
            continue;
        }

        match run_one(appstate, &key).await {
            Ok(verdict) if super::actions::waits(&verdict).is_some() => {
                schedule.record_verdict(verdict);
                schedule.next_run_at = now;
            }
            Ok(verdict) => match schedule.auto_apply.clone() {
                None => schedule.record_verdict(verdict),
                Some(grant) => {
                    schedule.pending_verdict = Some(verdict.clone());
                    if let Err(error) = appstate.store.set_plugin_schedule(&key, &schedule) {
                        tracing::warn!(%error, "could not persist proposal before apply");
                        continue;
                    }
                    match auto_apply(appstate, &key, &verdict, &grant, run_at).await {
                        Ok(summary) => {
                            tracing::info!(plugin = %key.plugin, "{summary}");
                            schedule.pending_verdict = None;
                            schedule.last_error = None;
                        }
                        Err(e) => {
                            tracing::warn!(plugin = %key.plugin, "auto-apply failed: {e}");
                            // The verdict is kept, so what the run proposed is
                            // still reviewable by hand.
                            schedule.record_verdict(verdict);
                            schedule.last_error = Some(e);
                        }
                    }
                }
            },
            Err(e) => {
                tracing::warn!(plugin = %key.plugin, "scheduled run failed: {e}");
                schedule.record_error(e);
            }
        }

        if resuming && schedule.pending_verdict.is_none() {
            schedule.advance(now);
        }
        schedule.running = false;
        if let Err(e) = appstate.store.set_plugin_schedule(&key, &schedule) {
            tracing::warn!(plugin = %key.plugin, "could not save schedule: {e}");
        }

        ran += 1;
    }

    ran
}

/// Plans a verdict and writes it, for a plugin that has been granted that.
///
/// Everything the grant allows is checked against the granting agent's rights,
/// not the server's: the commit is signed with the server's key because that
/// is the only one it holds, and without this a plugin would be a way to write
/// anywhere.
///
/// The vocabulary needed to log the run is resolved before anything is
/// written. A run that wrote and could not say so would be worse than one that
/// refused.
pub(crate) async fn auto_apply(
    appstate: &AppState,
    key: &PluginScheduleKey,
    verdict: &str,
    grant: &AutoApplyGrant,
    now: i64,
) -> Result<String, String> {
    let terms = drive_terms(&appstate.store, &key.drive)
        .await
        .ok_or("this drive has no plugin vocabulary")?;

    if terms.class("plugin-run").is_none() {
        return Err("this drive has no plugin-run class, so the run could not be recorded".into());
    }

    let parsed: serde_json::Value =
        serde_json::from_str(verdict).map_err(|e| format!("the verdict is not JSON: {e}"))?;

    let mut host = StoreApplyHost::for_installation(
        &appstate.store,
        &key.drive,
        &key.plugin,
        ForAgent::AgentSubject(atomic_lib::Subject::from_raw(&grant.agent, None)),
    )
    .await?;

    let plan = plan_verdict(&parsed, &mut host).await;
    let journal = super::journal::Journal::new(
        &appstate.store,
        &key.drive,
        &key.plugin,
        &format!("cron:{now}"),
    );
    let plan = journal.plan(&plan)?;

    // A blocked plan is still logged: "it silently did nothing" and "it never
    // ran" have to be tellable apart.
    let report = if plan.blocked {
        None
    } else {
        Some(
            super::apply::apply_plan_recorded(
                &plan,
                &mut host,
                ApplyOptions::default(),
                Some(&journal),
            )
            .await?,
        )
    };

    let summary = match &report {
        None => "the plan was blocked, so nothing was written".to_string(),
        Some(report) => format!(
            "applied {} change(s), {} failed",
            report.applied, report.failed
        ),
    };

    run_log::record_run(
        &mut host,
        &terms,
        &key.plugin,
        "cron",
        now,
        &plan,
        report.as_ref(),
    )
    .await
    .map_err(|e| format!("{summary}, but the run could not be recorded: {e}"))?;

    if plan.blocked
        || report
            .as_ref()
            .is_some_and(|r| r.failed > 0 || r.stopped_early)
    {
        return Err(summary);
    }
    journal.finish(&summary)?;
    Ok(summary)
}

async fn run_one(appstate: &AppState, key: &PluginScheduleKey) -> Result<String, String> {
    let source = plugin_source(&appstate.store, &key.drive, &key.plugin)
        .await
        .ok_or("the plugin has no source")?;

    let runtime = js_runtime::embedded_runtime().map_err(|e| e.to_string())?;

    let schedule = appstate
        .store
        .get_plugin_schedule(key)
        .map_err(|e| e.to_string())?
        .ok_or("schedule no longer exists")?;
    let source = match &schedule.auto_apply {
        Some(grant) => match &grant.release {
            Some(id) => {
                appstate
                    .store
                    .get_plugin_release(id)
                    .map_err(|e| e.to_string())?
                    .source
            }
            None => grant
                .source
                .clone()
                .ok_or("reactivate auto-apply to pin the approved source")?,
        },
        None => source,
    };
    let schemas = match schedule
        .auto_apply
        .as_ref()
        .and_then(|grant| grant.release.as_ref())
    {
        Some(id) => {
            appstate
                .store
                .get_plugin_release(id)
                .map_err(|e| e.to_string())?
                .schemas
        }
        None if schedule.auto_apply.is_none() => {
            plugin_schema_bindings(&appstate.store, &key.drive, &key.plugin).await?
        }
        None => Default::default(),
    };
    let agent = schedule
        .run_as
        .as_ref()
        .or_else(|| schedule.auto_apply.as_ref().map(|g| &g.agent))
        .ok_or("reactivate this schedule to authorize its reads")?;
    let execution_agent = ForAgent::AgentSubject(agent.as_str().into());
    let host = js_runtime::StoreHost {
        db: Arc::new(appstate.store.clone()),
        plugin: key.plugin.clone(),
        drive: key.drive.clone(),
        for_agent: execution_agent,
        manifest: js_runtime::describe_manifest(&source).await?,
    };

    host.validate_binding().await?;

    let input = serde_json::json!({
        "trigger": {"kind":"cron", "id":format!("cron:{}",schedule.last_run_at.unwrap_or(0)), "at":schedule.last_run_at.unwrap_or_else(atomic_lib::utils::now), "subject":key.plugin},
        "schemas": schemas,
        "cursor": latest_cursor(&appstate.store, &key.drive, &key.plugin).await,
    })
    .to_string();

    let context_key = format!(
        "integration-cron-context/v1/{}",
        serde_json::json!([key.drive, key.plugin])
    );
    let identity = serde_json::json!([agent, source, schemas]);
    let input = if schedule
        .pending_verdict
        .as_deref()
        .and_then(super::actions::waits)
        .is_some()
    {
        let bytes = appstate
            .store
            .kv
            .get(
                atomic_lib::db::trees::Tree::PluginMeta,
                context_key.as_bytes(),
            )
            .map_err(|e| e.to_string())?
            .ok_or("saved action continuation unavailable")?;
        let saved: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if saved["identity"] != identity {
            return Err(
                "scheduled action source, account or schema changed; review before continuing"
                    .into(),
            );
        }
        saved["input"]
            .as_str()
            .ok_or("invalid saved continuation")?
            .to_string()
    } else {
        appstate
            .store
            .kv
            .insert(
                atomic_lib::db::trees::Tree::PluginMeta,
                context_key.as_bytes(),
                &serde_json::to_vec(&serde_json::json!({"identity":identity,"input":input}))
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        appstate.store.flush().map_err(|e| e.to_string())?;
        input
    };

    runtime
        .run_triggered(&source, &input, host)
        .await
        .map_err(|e| e.to_string())?
}

/// Restore only a checkpoint attached to a fully successful recorded run.
pub async fn latest_cursor(store: &Db, drive: &str, plugin: &str) -> Option<String> {
    let terms = drive_terms(store, drive).await?;
    let cursor = terms.property("run-cursor")?;
    let status = terms.property("run-status")?;
    let at = terms.property("started-at")?;
    let plugin = store.get_resource(&plugin.into()).await.ok()?;
    plugin
        .get_children(store)
        .await
        .ok()?
        .iter()
        .filter(|run| {
            run.get(status)
                .ok()
                .is_some_and(|v| v.to_string() == "applied")
        })
        .filter_map(|run| {
            Some((
                run.get(at).ok()?.to_int().ok()?,
                run.get(cursor).ok()?.to_string(),
            ))
        })
        .max_by_key(|(at, _)| *at)
        .map(|(_, cursor)| cursor)
}

/// Starts the loop. Does nothing but sleep on a server with no schedules.
pub fn spawn(appstate: AppState) {
    actix_web::rt::spawn(async move {
        loop {
            actix_web::rt::time::sleep(std::time::Duration::from_secs(TICK_SECONDS)).await;

            let ran = run_due(&appstate).await;

            if ran > 0 {
                tracing::info!("ran {ran} scheduled plugin(s)");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_fixture::{children_named, fixture, write_plugin, Fixture};

    /// Grants auto-apply (or not) and makes the schedule due right now.
    async fn arm(fixture: &Fixture, auto_apply: bool) -> PluginScheduleKey {
        let key = PluginScheduleKey::new(&fixture.drive, &fixture.plugin);
        let mut schedule = atomic_lib::db::plugin_schedule::PluginSchedule::new(3600, 0).unwrap();
        schedule.next_run_at = 0;
        schedule.run_as = Some(
            fixture
                .appstate
                .store
                .get_default_agent()
                .unwrap()
                .subject
                .to_string(),
        );

        if auto_apply {
            schedule.auto_apply = Some(AutoApplyGrant {
                agent: fixture
                    .appstate
                    .store
                    .get_default_agent()
                    .unwrap()
                    .subject
                    .to_string(),
                granted_at: 0,
                reviewed_run: None,
                release: Some(
                    fixture
                        .appstate
                        .store
                        .publish_plugin_release(&atomic_lib::db::plugin_release::PluginRelease {
                            source: plugin_source(
                                &fixture.appstate.store,
                                &fixture.drive,
                                &fixture.plugin,
                            )
                            .await
                            .unwrap(),
                            manifest: serde_json::Value::Null,
                            runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
                            schemas: Default::default(),
                        })
                        .unwrap(),
                ),
                source: plugin_source(&fixture.appstate.store, &fixture.drive, &fixture.plugin)
                    .await,
            });
        }

        fixture
            .appstate
            .store
            .set_plugin_schedule(&key, &schedule)
            .unwrap();

        key
    }

    #[actix_rt::test]
    async fn abandoned_schedule_is_acknowledged_without_applying_its_saved_plan() {
        let mut f = fixture("abandoned_schedule").await;
        write_plugin(&mut f, "Must stay absent").await;
        let key = arm(&f, false).await;
        assert_eq!(run_due(&f.appstate).await, 1);
        let mut schedule = f.appstate.store.get_plugin_schedule(&key).unwrap().unwrap();
        let journal = super::super::journal::Journal::new(
            &f.appstate.store,
            &key.drive,
            &key.plugin,
            &format!("cron:{}", schedule.last_run_at.unwrap()),
        );
        journal.abandon("operator", "No longer needed").unwrap();
        schedule.next_run_at = 0;
        f.appstate
            .store
            .set_plugin_schedule(&key, &schedule)
            .unwrap();
        assert_eq!(run_due(&f.appstate).await, 0);
        assert!(f
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap()
            .pending_verdict
            .is_none());
        assert!(journal.finished().unwrap().is_none());
        assert_eq!(children_named(&f, &f.drive, "Must stay absent").await, 0);
    }

    #[actix_rt::test]
    async fn finished_schedule_acknowledges_without_replaying_or_reading_old_waits() {
        let mut f = fixture("finished_schedule").await;
        write_plugin(&mut f, "Finished once").await;
        let key = arm(&f, true).await;
        assert_eq!(run_due(&f.appstate).await, 1);
        let mut saved = f.appstate.store.get_plugin_schedule(&key).unwrap().unwrap();
        let journal = super::super::journal::Journal::new(
            &f.appstate.store,
            &key.drive,
            &key.plugin,
            &format!("cron:{}", saved.last_run_at.unwrap()),
        );
        let finished = journal.finished().unwrap().unwrap();
        saved.running = true;
        saved.next_run_at = 0;
        saved.pending_verdict =
            Some(r#"{"integrationWaits":[{"connection":"gone","id":"gone"}]}"#.into());
        f.appstate.store.set_plugin_schedule(&key, &saved).unwrap();
        assert_eq!(run_due(&f.appstate).await, 0);
        let recovered = f.appstate.store.get_plugin_schedule(&key).unwrap().unwrap();
        assert!(!recovered.running);
        assert!(recovered.pending_verdict.is_none());
        assert!(recovered.last_error.is_none());
        assert_eq!(children_named(&f, &f.drive, "Finished once").await, 1);
        assert_eq!(journal.finished().unwrap().unwrap(), finished);
        assert_eq!(run_due(&f.appstate).await, 0);
    }

    #[actix_rt::test]
    async fn integration_approval_resumes_same_scheduled_run_without_repeating_write() {
        use atomic_lib::Value;
        let mut f = fixture("scheduled_action_continuation").await;
        write_plugin(&mut f, "After issue approval").await;
        let original = plugin_source(&f.appstate.store, &f.drive, &f.plugin)
            .await
            .unwrap();
        let release = f
            .appstate
            .store
            .publish_plugin_release(&atomic_lib::db::plugin_release::PluginRelease {
                source: include_str!("../../../integrations/github-issues/plugin.js").into(),
                manifest: serde_json::from_str(include_str!(
                    "../../../integrations/github-issues/manifest.fixture.json"
                ))
                .unwrap(),
                runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
                schemas: Default::default(),
            })
            .unwrap();
        let mut plugin = f
            .appstate
            .store
            .get_resource(&f.plugin.as_str().into())
            .await
            .unwrap();
        plugin.set_unsafe(f.terms.property("plugin-connection").unwrap().into(),Value::Json(serde_json::json!({"release":release,"config":{"repository":"atomic-fixtures/issues"}}))).unwrap();
        plugin
            .set_unsafe(
                f.terms.property("automation-integrations").unwrap().into(),
                Value::ResourceArray(vec![f.plugin.as_str().into()]),
            )
            .unwrap();
        let source=format!("{}\nexport function run(ctx) {{ctx.integration({{connection:{},release:{},call:{{action:'create_issue',arguments:{{title:'Synthetic'}},id:ctx.trigger.id}}}});return original(ctx);}}",original.replace("function run(","function original("),serde_json::json!(f.plugin),serde_json::json!(release));
        plugin
            .set_unsafe(
                f.terms.property("plugin-source").unwrap().into(),
                Value::Markdown(source),
            )
            .unwrap();
        plugin.save(&f.appstate.store).await.unwrap();
        let key = arm(&f, true).await;
        assert_eq!(run_due(&f.appstate).await, 1);
        assert_eq!(
            children_named(&f, &f.drive, "After issue approval").await,
            0
        );
        assert!(super::super::actions::waits(
            f.appstate
                .store
                .get_plugin_schedule(&key)
                .unwrap()
                .unwrap()
                .pending_verdict
                .as_deref()
                .unwrap()
        )
        .is_some());
        let host = js_runtime::StoreHost {
            db: Arc::new(f.appstate.store.clone()),
            drive: f.drive.clone(),
            plugin: f.plugin.clone(),
            for_agent: ForAgent::AgentSubject(
                f.appstate
                    .store
                    .get_default_agent()
                    .unwrap()
                    .subject
                    .clone(),
            ),
            manifest: None,
        };
        let p = super::super::actions::proposals(&host)
            .await
            .unwrap()
            .remove(0);
        struct Provider(usize);
        #[async_trait::async_trait]
        impl super::super::external::ExternalHost for Provider {
            async fn execute(
                &mut self,
                _: &super::super::external::ExternalIntent,
            ) -> Result<super::super::external::Receipt, String> {
                self.0 += 1;
                Ok(super::super::external::Receipt {
                    status: 201,
                    body: "{}".into(),
                })
            }
        }
        let mut provider = Provider(0);
        super::super::external::execute(
            &f.appstate.store,
            &serde_json::json!([f.drive, f.plugin]).to_string(),
            &p.release,
            &p.id,
            &p.intent,
            &mut provider,
        )
        .await
        .unwrap();
        run_due(&f.appstate).await;
        run_due(&f.appstate).await;
        assert_eq!(provider.0, 1);
        assert!(f
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap()
            .pending_verdict
            .is_none());
        assert_eq!(
            children_named(&f, &f.drive, "After issue approval").await,
            1
        );
    }

    #[actix_rt::test]
    async fn review_of_an_older_source_cannot_authorize_the_current_draft() {
        use crate::plugins::test_fixture::genesis;
        use atomic_lib::{urls, Value};
        let mut fixture = fixture("reviewed_source").await;
        write_plugin(&mut fixture, "Current").await;
        let source = plugin_source(&fixture.appstate.store, &fixture.drive, &fixture.plugin)
            .await
            .unwrap();
        let run = genesis(
            &fixture.appstate.store,
            vec![
                (
                    urls::PARENT,
                    Value::AtomicUrl(fixture.plugin.as_str().into()),
                ),
                (
                    fixture.terms.property("run-status").unwrap(),
                    Value::String("applied".into()),
                ),
                (
                    fixture.terms.property("plugin-source").unwrap(),
                    Value::Markdown("older source".into()),
                ),
            ],
        )
        .await;
        assert!(crate::handlers::plugin_schedule::reviewed_run(
            &fixture.appstate,
            &fixture.drive,
            &fixture.plugin
        )
        .await
        .is_err());
        let mut resource = fixture
            .appstate
            .store
            .get_resource(&run.as_str().into())
            .await
            .unwrap();
        resource
            .set_unsafe(
                fixture.terms.property("plugin-source").unwrap().into(),
                Value::Markdown(source.clone()),
            )
            .unwrap();
        resource.save(&fixture.appstate.store).await.unwrap();
        assert_eq!(
            crate::handlers::plugin_schedule::reviewed_run(
                &fixture.appstate,
                &fixture.drive,
                &fixture.plugin
            )
            .await
            .unwrap(),
            (run.clone(), source)
        );
        // Reviewing the same code does not authorize different schema bindings.
        let schemas_property = fixture.terms.property("plugin-schemas").unwrap();
        let mut plugin = fixture
            .appstate
            .store
            .get_resource(&fixture.plugin.as_str().into())
            .await
            .unwrap();
        plugin
            .set_unsafe(
                schemas_property.into(),
                Value::Json(serde_json::json!({"row": "https://example.com/other-class"})),
            )
            .unwrap();
        plugin.save(&fixture.appstate.store).await.unwrap();
        assert!(crate::handlers::plugin_schedule::reviewed_run(
            &fixture.appstate,
            &fixture.drive,
            &fixture.plugin
        )
        .await
        .is_err());
    }

    #[actix_rt::test]
    async fn editing_a_draft_does_not_change_the_approved_source() {
        let mut fixture = fixture("pinned_plugin").await;
        write_plugin(&mut fixture, "Approved output").await;
        arm(&fixture, true).await;
        let mut plugin = fixture
            .appstate
            .store
            .get_resource(&fixture.plugin.as_str().into())
            .await
            .unwrap();
        plugin
            .set_unsafe(
                fixture.terms.property("plugin-source").unwrap().into(),
                atomic_lib::Value::Markdown(
                    "export function run() { throw new Error('unapproved code'); }".into(),
                ),
            )
            .unwrap();
        plugin.save(&fixture.appstate.store).await.unwrap();
        assert_eq!(run_due(&fixture.appstate).await, 1);
        assert_eq!(
            children_named(&fixture, &fixture.drive, "Approved output").await,
            1
        );
    }

    #[actix_rt::test]
    async fn pending_or_interrupted_runs_are_not_replayed() {
        let mut fixture = fixture("pending_plugin").await;
        write_plugin(&mut fixture, "Must not replay").await;
        let key = arm(&fixture, true).await;
        let mut schedule = fixture
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap();
        schedule.running = true;
        fixture
            .appstate
            .store
            .set_plugin_schedule(&key, &schedule)
            .unwrap();
        assert_eq!(run_due(&fixture.appstate).await, 0);
        schedule.running = false;
        schedule.pending_verdict = Some("original proposal".into());
        fixture
            .appstate
            .store
            .set_plugin_schedule(&key, &schedule)
            .unwrap();
        assert_eq!(run_due(&fixture.appstate).await, 0);
        assert_eq!(
            fixture
                .appstate
                .store
                .get_plugin_schedule(&key)
                .unwrap()
                .unwrap()
                .pending_verdict,
            schedule.pending_verdict
        );
        assert_eq!(
            children_named(&fixture, &fixture.drive, "Must not replay").await,
            0
        );
    }

    #[actix_rt::test]
    async fn an_unattended_run_waits_for_review_by_default() {
        let mut fixture = fixture("plugin_no_grant").await;
        write_plugin(&mut fixture, "Waited for").await;

        let key = arm(&fixture, false).await;

        assert_eq!(run_due(&fixture.appstate).await, 1);

        let schedule = fixture
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap();

        assert!(
            schedule.pending_verdict.is_some(),
            "the verdict is kept for review: {:?}",
            schedule.last_error,
        );
        assert_eq!(
            children_named(&fixture, &fixture.drive.clone(), "Waited for").await,
            0,
            "nothing may be written without a grant",
        );
    }

    #[actix_rt::test]
    async fn a_revoked_installation_cannot_resume_a_granted_schedule() {
        let mut fixture = fixture("revoked_schedule").await;
        write_plugin(&mut fixture, "Must not appear").await;
        let key = arm(&fixture, true).await;
        fixture
            .appstate
            .store
            .delete_app_agent(&atomic_lib::db::app_agent::AppAgentKey::new(
                &fixture.drive,
                &fixture.plugin,
            ))
            .unwrap();
        assert_eq!(run_due(&fixture.appstate).await, 1);
        let schedule = fixture
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap();
        assert!(schedule.last_error.unwrap().contains("revoked"));
        assert_eq!(
            children_named(&fixture, &fixture.drive, "Must not appear").await,
            0
        );
    }

    #[actix_rt::test]
    async fn a_granted_run_writes_as_the_app_not_as_the_server() {
        let mut fixture = fixture("plugin_signs_as_app").await;
        write_plugin(&mut fixture, "Signed by the app").await;

        // The app's own key, which is what `app_signing_for` looks for. Keyed
        // on the plugin itself here; in the product it hangs off the app the
        // plugin sits under, which the same lookup walks up to find.
        let app_agent = atomic_lib::agents::Agent::new(Some("the app")).unwrap();
        fixture
            .appstate
            .store
            .set_app_agent(
                &atomic_lib::db::app_agent::AppAgentKey::new(&fixture.drive, &fixture.plugin),
                &atomic_lib::db::app_agent::AppAgent::new(
                    app_agent.subject.to_string(),
                    app_agent.build_secret().unwrap(),
                    0,
                ),
            )
            .unwrap();

        // The app key must independently be authorized for its target drive.
        let mut drive = fixture
            .appstate
            .store
            .get_resource(&fixture.drive.as_str().into())
            .await
            .unwrap();
        let mut writers = drive
            .get(atomic_lib::urls::WRITE)
            .ok()
            .and_then(|v| v.to_subjects(None).ok())
            .unwrap_or_default();
        writers.push(app_agent.subject.to_string());
        drive
            .set_unsafe(
                atomic_lib::urls::WRITE.into(),
                atomic_lib::Value::ResourceArray(writers.into_iter().map(Into::into).collect()),
            )
            .unwrap();
        drive.save(&fixture.appstate.store).await.unwrap();
        let key = arm(&fixture, true).await;

        assert_eq!(run_due(&fixture.appstate).await, 1);
        assert_eq!(
            fixture
                .appstate
                .store
                .get_plugin_schedule(&key)
                .unwrap()
                .unwrap()
                .last_error,
            None,
        );

        // The signer is the author: a commit carries one identity, so if the
        // server signed this, the history says the server decided it.
        let written = fixture
            .appstate
            .store
            .get_resource(&fixture.drive.as_str().into())
            .await
            .unwrap()
            .get_children(&fixture.appstate.store)
            .await
            .unwrap()
            .into_iter()
            .find(|child| {
                child
                    .get(urls::NAME)
                    .is_ok_and(|name| name.to_string() == "Signed by the app")
            })
            .expect("the run should have written its resource");

        let last_commit = written.get(urls::LAST_COMMIT).unwrap().to_string();
        let commit = fixture
            .appstate
            .store
            .get_resource(&last_commit.as_str().into())
            .await
            .unwrap();

        assert_eq!(
            commit.get(urls::SIGNER).unwrap().to_string(),
            app_agent.subject.to_string(),
            "the commit was signed by something other than the app",
        );

        let server_agent = fixture
            .appstate
            .store
            .get_default_agent()
            .unwrap()
            .subject
            .to_string();

        assert_ne!(commit.get(urls::SIGNER).unwrap().to_string(), server_agent,);
    }

    #[actix_rt::test]
    async fn a_grant_writes_only_where_its_agent_could_have() {
        let mut fixture = fixture("plugin_wrong_agent").await;
        write_plugin(&mut fixture, "Should not exist").await;

        let key = arm(&fixture, true).await;

        // The commit is signed by the server's own agent either way — it is
        // the only key the server holds. So if rights were not checked against
        // the agent named in the grant, a plugin would be a way to write
        // anywhere on the server.
        let mut schedule = fixture
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap();
        schedule.auto_apply.as_mut().unwrap().agent =
            "https://atomicdata.dev/agents/nobody".to_string();
        fixture
            .appstate
            .store
            .set_plugin_schedule(&key, &schedule)
            .unwrap();

        assert_eq!(run_due(&fixture.appstate).await, 1);

        assert_eq!(
            children_named(&fixture, &fixture.drive.clone(), "Should not exist").await,
            0,
        );

        let after = fixture
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap();

        assert!(after.last_error.is_some(), "the refusal must be visible");
        assert!(
            after.pending_verdict.is_some(),
            "and what it proposed stays reviewable by hand",
        );
    }

    #[actix_rt::test]
    async fn a_granted_run_writes_and_records_what_it_wrote() {
        let mut fixture = fixture("plugin_granted").await;
        write_plugin(&mut fixture, "Made unattended").await;

        let key = arm(&fixture, true).await;

        assert_eq!(run_due(&fixture.appstate).await, 1);

        let schedule = fixture
            .appstate
            .store
            .get_plugin_schedule(&key)
            .unwrap()
            .unwrap();

        assert_eq!(schedule.last_error, None, "the run should have applied");
        assert_eq!(
            schedule.pending_verdict, None,
            "nothing is left waiting once it has been applied",
        );
        assert_eq!(
            children_named(&fixture, &fixture.drive.clone(), "Made unattended").await,
            1,
        );

        // And the account of having written it.
        let runs = fixture
            .appstate
            .store
            .get_resource(&fixture.plugin.as_str().into())
            .await
            .unwrap()
            .get_children(&fixture.appstate.store)
            .await
            .unwrap();

        let status_property = fixture.terms.property("run-status").unwrap();
        let statuses: Vec<String> = runs
            .iter()
            .filter_map(|run| run.get(status_property).ok().map(|v| v.to_string()))
            .collect();

        assert_eq!(statuses, vec!["applied".to_string()]);
    }
}
