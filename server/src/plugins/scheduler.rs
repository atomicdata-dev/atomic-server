//! Runs plugins nobody is watching.
//!
//! An unattended run *fetches*; it does not write. The whole model is that a
//! run proposes and a person approves, and at 3am there is nobody to approve —
//! so the verdict is kept against the schedule and the plugin's page offers it
//! for review. Overnight it finds forty new events; in the morning you see the
//! diff.
//!
//! Applying automatically is a separate decision that needs its own consent,
//! and it needs the planner and applier to exist in Rust — today they live in
//! TypeScript, which is where the approving happens anyway.

use std::collections::HashMap;
use std::sync::Arc;

use atomic_lib::agents::ForAgent;
use atomic_lib::db::plugin_schedule::{AutoApplyGrant, PluginScheduleKey};
use atomic_lib::{urls, Db, Storelike};

use crate::appstate::AppState;
use crate::plugins::apply::{apply_plan, ApplyOptions};
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

/// One pass over everything due.
///
/// Returns how many ran, so the caller (and a test) can tell a quiet tick from
/// a broken one.
pub async fn run_due(appstate: &AppState) -> usize {
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
        // Advanced before the run, not after: a plugin that hangs or panics
        // must not be picked up again on the next tick and every tick after.
        schedule.advance(now);

        match run_one(appstate, &key).await {
            Ok(verdict) => match schedule.auto_apply.clone() {
                None => schedule.record_verdict(verdict),
                Some(grant) => match auto_apply(appstate, &key, &verdict, &grant, now).await {
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
                },
            },
            Err(e) => {
                tracing::warn!(plugin = %key.plugin, "scheduled run failed: {e}");
                schedule.record_error(e);
            }
        }

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
async fn auto_apply(
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

    let mut host = StoreApplyHost {
        store: appstate.store.clone(),
        for_agent: ForAgent::AgentSubject(atomic_lib::Subject::from_raw(&grant.agent, None)),
        signing_as: crate::plugins::store_host::app_signing_for(
            &appstate.store,
            &key.drive,
            &key.plugin,
        )
        .await,
    };

    let plan = plan_verdict(&parsed, &mut host).await;

    // A blocked plan is still logged: "it silently did nothing" and "it never
    // ran" have to be tellable apart.
    let report = if plan.blocked {
        None
    } else {
        Some(apply_plan(&plan, &mut host, ApplyOptions::default()).await?)
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

    Ok(summary)
}

async fn run_one(appstate: &AppState, key: &PluginScheduleKey) -> Result<String, String> {
    let source = plugin_source(&appstate.store, &key.drive, &key.plugin)
        .await
        .ok_or("the plugin has no source")?;

    let runtime = js_runtime::embedded_runtime().map_err(|e| e.to_string())?;

    let host = js_runtime::StoreHost {
        db: Arc::new(appstate.store.clone()),
        plugin: key.plugin.clone(),
        drive: key.drive.clone(),
    };

    let input = format!(
        "{{\"trigger\":{{\"kind\":\"cron\",\"at\":{},\"subject\":{:?}}}}}",
        atomic_lib::utils::now(),
        key.plugin,
    );

    runtime
        .run(&source, &input, host)
        .await
        .map_err(|e| e.to_string())?
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
    fn arm(fixture: &Fixture, auto_apply: bool) -> PluginScheduleKey {
        let key = PluginScheduleKey::new(&fixture.drive, &fixture.plugin);
        let mut schedule = atomic_lib::db::plugin_schedule::PluginSchedule::new(3600, 0).unwrap();
        schedule.next_run_at = 0;

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
    async fn an_unattended_run_waits_for_review_by_default() {
        let mut fixture = fixture("plugin_no_grant").await;
        write_plugin(&mut fixture, "Waited for").await;

        let key = arm(&fixture, false);

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

        let key = arm(&fixture, true);

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

        let key = arm(&fixture, true);

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

        let key = arm(&fixture, true);

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
