//! Running a plugin because the data changed.
//!
//! The store already decides when a resource enters or leaves a watched query
//! — that is how `SUBSCRIBE_QUERY` pushes live updates. This listens to the
//! same events on behalf of plugins.
//!
//! Two things make that safe to leave running. A plugin does not re-trigger
//! itself: the resources its own run wrote are remembered and skipped, or an
//! importer that creates a row matching its own query would run forever. And
//! a plugin that manages to fire in a tight loop anyway is stopped by a cap
//! and says so, rather than quietly eating the server.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use atomic_lib::agents::ForAgent;
use atomic_lib::db::plugin_trigger::{Edge, PluginTrigger, PluginTriggerKey};
use tokio::sync::Mutex;

use crate::appstate::AppState;
use crate::plugins::apply::ApplyOptions;
use crate::plugins::js_runtime;
use crate::plugins::plan::plan_verdict;
use crate::plugins::run_log;
use crate::plugins::scheduler::{drive_terms, plugin_source};
use crate::plugins::store_host::StoreApplyHost;

/// How many times one plugin may be triggered inside [`RATE_WINDOW_MS`].
///
/// Not a performance budget. A plugin whose writes feed its own query is the
/// failure this catches, and it is the kind that saturates a machine in
/// seconds if nothing stops it.
const RATE_LIMIT: usize = 30;
const RATE_WINDOW_MS: i64 = 60_000;

/// How long the same edge on the same subject is treated as already handled.
///
/// Covers a duplicate event within one run of the server — the same commit
/// applied twice, say. It is deliberately not durable: after a restart there
/// are no events to replay either, so there is nothing to be idempotent
/// against.
const DEDUP_WINDOW_MS: i64 = 30_000;

#[derive(Default)]
struct Guard {
    /// `(plugin, subject, edge)` to when it last fired.
    recent: HashMap<(String, String, &'static str), i64>,
    /// Subjects a plugin's own run wrote, so it does not answer its own echo.
    written: HashSet<(String, String)>,
    /// When each plugin fired, for the cap.
    fires: HashMap<String, VecDeque<i64>>,
}

impl Guard {
    /// Whether this edge should run, recording it when it should.
    fn admit(&mut self, plugin: &str, subject: &str, edge: Edge, now: i64) -> Result<(), String> {
        if self
            .written
            .remove(&(plugin.to_string(), subject.to_string()))
        {
            return Err("this plugin wrote it itself".to_string());
        }

        let key = (plugin.to_string(), subject.to_string(), edge.as_str());

        if let Some(last) = self.recent.get(&key) {
            if now - last < DEDUP_WINDOW_MS {
                return Err("already handled".to_string());
            }
        }

        let fires = self.fires.entry(plugin.to_string()).or_default();

        while fires.front().is_some_and(|at| now - at > RATE_WINDOW_MS) {
            fires.pop_front();
        }

        if fires.len() >= RATE_LIMIT {
            return Err(format!(
                "stopped after {RATE_LIMIT} runs in a minute — its own writes are probably \
                 matching its own query",
            ));
        }

        fires.push_back(now);
        self.recent.insert(key, now);
        self.prune(now);

        Ok(())
    }

    fn prune(&mut self, now: i64) {
        self.recent.retain(|_, at| now - *at < DEDUP_WINDOW_MS);
    }

    fn remember_writes(&mut self, plugin: &str, subjects: impl Iterator<Item = String>) {
        for subject in subjects {
            self.written.insert((plugin.to_string(), subject));
        }
    }
}

/// Starts listening. Does nothing on a server with no triggers.
pub fn spawn(appstate: AppState) {
    // Watched queries are stored, but a trigger whose watch entry was lost
    // would never fire again and nothing would say so. Re-registering at
    // startup is cheap and makes the two consistent by construction.
    match appstate.store.watch_plugin_trigger_queries() {
        Ok(0) => {}
        Ok(n) => tracing::info!("watching {n} plugin trigger quer(ies)"),
        Err(e) => tracing::warn!("could not re-watch plugin trigger queries: {e}"),
    }

    let guard = Arc::new(Mutex::new(Guard::default()));
    let mut events = appstate.store.subscribe_events();

    actix_web::rt::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            drain(&appstate, &guard).await;
            tokio::select! {
                _ = tick.tick() => {},
                event = events.recv() => {
                    if matches!(event, Err(tokio::sync::broadcast::error::RecvError::Closed)) { break; }
                    // Lag only loses a wake-up, never the persisted work.
                }
            }
        }
    });
}

async fn drain(appstate: &AppState, guard: &Arc<Mutex<Guard>>) {
    let _worker = appstate.store.lock_plugin("trigger-delivery").await;
    let events = match appstate.store.queued_plugin_events() {
        Ok(events) => events,
        Err(e) => {
            tracing::error!("cannot read plugin event queue: {e}");
            return;
        }
    };
    let mut attempted = 0;
    for mut event in events {
        if attempted >= 100 {
            break;
        }
        let key = event.key.clone();
        let trigger = match appstate.store.get_plugin_trigger(&key) {
            Ok(Some(trigger)) => trigger,
            Ok(None) => {
                let _ = appstate.store.acknowledge_plugin_event(&event);
                continue;
            }
            Err(_) => continue,
        };
        let journal = super::journal::Journal::new(
            &appstate.store,
            &key.drive,
            &key.plugin,
            &format!("query:{}", event.id),
        );
        match journal.terminal() {
            Ok(Some(_)) => {
                let mut stored = trigger.clone();
                if stored.pending_verdict == event.verdict {
                    stored.pending_verdict = None;
                    stored.last_error = None;
                    if let Err(e) = appstate.store.set_plugin_trigger(&key, &stored) {
                        record_error(appstate, &key, &trigger, e.to_string());
                        continue;
                    }
                }
                if let Err(e) = appstate.store.acknowledge_plugin_event(&event) {
                    record_error(appstate, &key, &trigger, e.to_string());
                }
                continue;
            }
            Err(e) => {
                record_error(appstate, &key, &trigger, e);
                continue;
            }
            Ok(None) => {}
        }
        let mut resuming_action = false;
        if let Some(waits) = event.verdict.as_deref().and_then(super::actions::waits) {
            let actor = trigger
                .run_as
                .as_deref()
                .or_else(|| trigger.auto_apply.as_ref().map(|g| g.agent.as_str()))
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
                Err(e) => {
                    record_error(appstate, &key, &trigger, e);
                    continue;
                }
                Ok(true) => {
                    event.verdict = None;
                    event.waiting_for_review = false;
                    resuming_action = true;
                }
            }
        }
        if event.waiting_for_review {
            if trigger.pending_verdict.is_none() {
                let _ = appstate.store.acknowledge_plugin_event(&event);
                continue;
            }
            if trigger.auto_apply.is_none() {
                continue;
            }
            event.waiting_for_review = false;
        }
        if trigger.last_error.is_some()
            || (trigger.pending_verdict.is_some() && event.verdict.is_none() && !resuming_action)
        {
            continue;
        }
        if event.verdict.is_none() && !resuming_action {
            let mut protection = guard.lock().await;
            if protection
                .written
                .remove(&(key.plugin.clone(), event.subject.clone()))
            {
                let _ = appstate.store.acknowledge_plugin_event(&event);
                continue;
            }
            // Queue identities, unlike a subject/time window, distinguish two
            // genuine arrivals and survive slow or paused delivery.
            if let Err(reason) =
                protection.admit(&key.plugin, &event.id, event.edge, atomic_lib::utils::now())
            {
                if reason.starts_with("stopped after") {
                    record_error(appstate, &key, &trigger, reason);
                }
                continue;
            }
        }
        attempted += 1;
        match run(appstate, guard, &key, &trigger, &mut event).await {
            Ok(_) if !event.waiting_for_review => {
                if let Err(e) = appstate.store.acknowledge_plugin_event(&event) {
                    record_error(appstate, &key, &trigger, e.to_string());
                }
            }
            Ok(_) => {}
            Err(e) => record_error(appstate, &key, &trigger, e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    appstate: &AppState,
    guard: &Arc<Mutex<Guard>>,
    key: &PluginTriggerKey,
    trigger: &PluginTrigger,
    event: &mut atomic_lib::db::plugin_trigger::QueuedEvent,
) -> Result<String, String> {
    let subject = event.subject.as_str();
    let edge = event.edge;
    let now = event.at;
    let source = plugin_source(&appstate.store, &key.drive, &key.plugin)
        .await
        .ok_or("the plugin has no source")?;

    let source = match &trigger.auto_apply {
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
    let runtime = js_runtime::embedded_runtime().map_err(|e| e.to_string())?;

    let agent = trigger
        .run_as
        .as_ref()
        .or_else(|| trigger.auto_apply.as_ref().map(|g| &g.agent))
        .ok_or("reactivate this trigger to authorize its reads")?;
    let execution_agent = ForAgent::AgentSubject(agent.as_str().into());
    let host = js_runtime::StoreHost {
        db: Arc::new(appstate.store.clone()),
        plugin: key.plugin.clone(),
        drive: key.drive.clone(),
        for_agent: execution_agent,
        manifest: js_runtime::describe_manifest(&source).await?,
    };

    // The subject is the resource that moved, not the plugin: what a query
    // trigger is *about* is that row.
    host.validate_binding().await?;

    let schemas = match trigger
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
        None if trigger.auto_apply.is_none() => {
            super::scheduler::plugin_schema_bindings(&appstate.store, &key.drive, &key.plugin)
                .await?
        }
        None => Default::default(),
    };
    let input = serde_json::json!({"trigger":{"kind":"query","id":event.id,"at":now,"subject":subject,"edge":edge.as_str()},"schemas":schemas}).to_string();

    let authorization = serde_json::json!([agent, source]).to_string();
    if event
        .authorization
        .as_ref()
        .is_some_and(|old| old != &authorization)
    {
        return Err("the event's approved source or account changed; resolve its saved proposal before continuing".into());
    }
    event.authorization = Some(authorization);
    let verdict = match &event.verdict {
        Some(verdict) => verdict.clone(),
        None => runtime
            .run_triggered(&source, &input, host)
            .await
            .map_err(|e| e.to_string())??,
    };
    event.verdict = Some(verdict.clone());
    let action_wait = super::actions::waits(&verdict).is_some();
    event.waiting_for_review = action_wait || trigger.auto_apply.is_none();
    appstate
        .store
        .save_plugin_event(event)
        .map_err(|e| e.to_string())?;

    let mut stored = trigger.clone();
    stored.pending_verdict = Some(verdict.clone());
    appstate
        .store
        .set_plugin_trigger(key, &stored)
        .map_err(|e| e.to_string())?;
    if action_wait {
        return Ok("waiting for integration action approval".into());
    }
    let Some(grant) = trigger.auto_apply.clone() else {
        return Ok("proposal saved for review; trigger paused until resolved".into());
    };

    let terms = drive_terms(&appstate.store, &key.drive)
        .await
        .ok_or("this drive has no plugin vocabulary")?;

    if terms.class("plugin-run").is_none() {
        return Err("this drive has no plugin-run class, so the run could not be recorded".into());
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&verdict).map_err(|e| format!("the verdict is not JSON: {e}"))?;

    let mut apply_host = StoreApplyHost {
        store: appstate.store.clone(),
        for_agent: ForAgent::AgentSubject(atomic_lib::Subject::from_raw(&grant.agent, None)),
        signing_as: crate::plugins::store_host::app_signing_for(
            &appstate.store,
            &key.drive,
            &key.plugin,
        )
        .await?,
    };

    let plan = plan_verdict(&parsed, &mut apply_host).await;
    let journal = super::journal::Journal::new(
        &appstate.store,
        &key.drive,
        &key.plugin,
        &format!("query:{}", event.id),
    );
    let plan = journal.plan(&plan)?;

    let report = if plan.blocked {
        None
    } else {
        Some(
            super::apply::apply_plan_recorded(
                &plan,
                &mut apply_host,
                ApplyOptions::default(),
                Some(&journal),
            )
            .await?,
        )
    };

    if let Some(report) = &report {
        // Before the record is written, so the record itself cannot look like
        // a change worth reacting to.
        guard.lock().await.remember_writes(
            &key.plugin,
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.subject.clone()),
        );
    }

    let summary = match &report {
        None => "the plan was blocked, so nothing was written".to_string(),
        Some(report) => format!(
            "applied {} change(s), {} failed",
            report.applied, report.failed
        ),
    };

    run_log::record_run(
        &mut apply_host,
        &terms,
        &key.plugin,
        "query",
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
    stored.pending_verdict = None;
    stored.last_error = None;
    appstate
        .store
        .set_plugin_trigger(key, &stored)
        .map_err(|e| e.to_string())?;
    Ok(summary)
}

/// Keeps a failure where someone will find it.
fn record_error(
    appstate: &AppState,
    key: &PluginTriggerKey,
    trigger: &PluginTrigger,
    error: String,
) {
    let mut stored = appstate
        .store
        .get_plugin_trigger(key)
        .ok()
        .flatten()
        .unwrap_or_else(|| trigger.clone());
    stored.last_error = Some(error);

    if let Err(e) = appstate.store.set_plugin_trigger(key, &stored) {
        tracing::warn!(plugin = %key.plugin, "could not record the trigger failure: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_fixture::{children_named, fixture, write_plugin, Fixture};
    use atomic_lib::db::plugin_schedule::AutoApplyGrant;
    use atomic_lib::db::QueryFilter;
    use atomic_lib::storelike::PropVal;
    use atomic_lib::{urls, Resource, Storelike, Value};

    /// The query the trigger watches: anything on the drive marked `watched`.
    fn watched_query(fixture: &Fixture) -> QueryFilter {
        QueryFilter {
            filters: vec![PropVal {
                property: Some(urls::DESCRIPTION.to_string()),
                value: Some(Value::Markdown("watched".to_string())),
                ..Default::default()
            }],
            sort_by: None,
            drive: fixture.drive.as_str().into(),
        }
    }

    async fn arm(fixture: &Fixture, auto_apply: bool) -> PluginTriggerKey {
        let key = PluginTriggerKey::new(&fixture.drive, &fixture.plugin);
        let mut trigger = PluginTrigger::new(watched_query(fixture), true, false).unwrap();

        trigger.run_as = Some(
            fixture
                .appstate
                .store
                .get_default_agent()
                .unwrap()
                .subject
                .to_string(),
        );
        if auto_apply {
            trigger.auto_apply = Some(AutoApplyGrant {
                agent: fixture
                    .appstate
                    .store
                    .get_default_agent()
                    .unwrap()
                    .subject
                    .to_string(),
                granted_at: 0,
                reviewed_run: None,
                release: None,
                source: plugin_source(&fixture.appstate.store, &fixture.drive, &fixture.plugin)
                    .await,
            });
        }

        fixture
            .appstate
            .store
            .set_plugin_trigger(&key, &trigger)
            .unwrap();

        key
    }

    /// Writes a resource that enters the watched query.
    async fn add_watched(fixture: &Fixture, name: &str) -> String {
        let mut resource = Resource::new("did:ad:placeholder".into());

        for (property, value) in [
            (
                urls::PARENT,
                Value::AtomicUrl(fixture.drive.as_str().into()),
            ),
            (urls::NAME, Value::String(name.to_string())),
            (urls::DESCRIPTION, Value::Markdown("watched".to_string())),
        ] {
            resource.set_unsafe(property.into(), value).unwrap();
        }

        resource
            .save_as_genesis(&fixture.appstate.store)
            .await
            .unwrap();

        resource.get_subject().to_string()
    }

    /// Waits for the listener to catch up, or gives up.
    ///
    /// The listener is a spawned task reacting to a broadcast, so there is no
    /// handle to await. Polling for the effect beats sleeping for a guess: a
    /// fixed sleep is either flaky or slow, and usually both.
    async fn wait_for(fixture: &Fixture, name: &str, expected: usize) -> usize {
        for _ in 0..100 {
            let found = children_named(fixture, &fixture.drive.clone(), name).await;

            if found >= expected {
                return found;
            }

            actix_web::rt::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        children_named(fixture, &fixture.drive.clone(), name).await
    }

    #[actix_rt::test]
    async fn abandoned_event_is_acknowledged_without_applying_its_saved_plan() {
        let mut f = fixture("abandoned_event").await;
        write_plugin(&mut f, "Must stay absent").await;
        let key = arm(&f, false).await;
        add_watched(&f, "Arrival").await;
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        let event = f.appstate.store.queued_plugin_events().unwrap().remove(0);
        let journal = super::super::journal::Journal::new(
            &f.appstate.store,
            &key.drive,
            &key.plugin,
            &format!("query:{}", event.id),
        );
        journal.abandon("operator", "No longer needed").unwrap();
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert!(f.appstate.store.queued_plugin_events().unwrap().is_empty());
        assert!(journal.finished().unwrap().is_none());
        assert_eq!(children_named(&f, &f.drive, "Must stay absent").await, 0);
    }

    #[actix_rt::test]
    async fn finished_event_acknowledges_without_replaying_or_reading_old_waits() {
        let mut f = fixture("finished_event").await;
        write_plugin(&mut f, "Finished event once").await;
        let key = arm(&f, true).await;
        add_watched(&f, "Arrival").await;
        let mut event = f.appstate.store.queued_plugin_events().unwrap().remove(0);
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        let journal = super::super::journal::Journal::new(
            &f.appstate.store,
            &key.drive,
            &key.plugin,
            &format!("query:{}", event.id),
        );
        let finished = journal.finished().unwrap().unwrap();
        event.waiting_for_review = true;
        event.verdict = Some(r#"{"integrationWaits":[{"connection":"gone","id":"gone"}]}"#.into());
        f.appstate.store.save_plugin_event(&event).unwrap();
        let mut trigger = f.appstate.store.get_plugin_trigger(&key).unwrap().unwrap();
        trigger.pending_verdict = event.verdict.clone();
        f.appstate.store.set_plugin_trigger(&key, &trigger).unwrap();
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert!(f.appstate.store.queued_plugin_events().unwrap().is_empty());
        assert!(f
            .appstate
            .store
            .get_plugin_trigger(&key)
            .unwrap()
            .unwrap()
            .pending_verdict
            .is_none());
        assert_eq!(children_named(&f, &f.drive, "Finished event once").await, 1);
        assert_eq!(journal.finished().unwrap().unwrap(), finished);
    }

    #[actix_rt::test]
    #[ignore = "subprocess helper"]
    async fn child_persists_arrival_then_exits_without_cleanup() {
        let Ok(path) = std::env::var("ATOMIC_TRIGGER_CRASH_REPORT") else {
            return;
        };
        let mut f = fixture("trigger_hard_restart").await;
        write_plugin(&mut f, "After hard restart").await;
        arm(&f, true).await;
        add_watched(&f, "Arrived before crash").await;
        f.appstate.store.flush().unwrap();
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "data": f.appstate.config.store_path.parent().unwrap(),
                "config": f.appstate.config.config_dir,
                "drive": f.drive, "plugin": f.plugin,
            }))
            .unwrap(),
        )
        .unwrap();
        // exit bypasses destructors and the database's graceful shutdown.
        std::process::exit(73);
    }

    #[actix_rt::test]
    async fn a_hard_restart_delivers_a_saved_arrival_once() {
        use clap::Parser;
        let report = std::env::temp_dir().join(format!(
            "atomic-trigger-{}.json",
            atomic_lib::utils::random_string(16)
        ));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "plugins::triggers::tests::child_persists_arrival_then_exits_without_cleanup",
                "--exact",
                "--ignored",
            ])
            .env("ATOMIC_TRIGGER_CRASH_REPORT", &report)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
        let opts = crate::config::Opts::parse_from([
            "atomic-server",
            "--data-dir",
            meta["data"].as_str().unwrap(),
            "--config-dir",
            meta["config"].as_str().unwrap(),
        ]);
        let appstate = AppState::init(crate::config::build_config(opts).unwrap())
            .await
            .unwrap();
        let drive = meta["drive"].as_str().unwrap().to_string();
        let f = Fixture {
            terms: drive_terms(&appstate.store, &drive).await.unwrap(),
            appstate,
            drive,
            plugin: meta["plugin"].as_str().unwrap().into(),
        };
        assert_eq!(f.appstate.store.queued_plugin_events().unwrap().len(), 1);
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(children_named(&f, &f.drive, "After hard restart").await, 1);
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(children_named(&f, &f.drive, "After hard restart").await, 1);
        assert!(f.appstate.store.queued_plugin_events().unwrap().is_empty());
        std::fs::remove_file(report).unwrap();
    }

    #[actix_rt::test]
    async fn scripts_receive_the_persisted_event_identity() {
        let mut f = fixture("trigger_identity").await;
        write_plugin(&mut f, "placeholder").await;
        let source = format!(
            r#"export function run(ctx) {{
            if (!ctx.trigger.id) throw new Error('missing durable event identity');
            return {{ intents: [{{op:'create',localId:'event',parent:{:?},isA:[],set:{{
                'https://atomicdata.dev/properties/name':ctx.trigger.id
            }}}}],problems:[] }};
        }}"#,
            f.drive
        );
        let mut plugin = f
            .appstate
            .store
            .get_resource(&f.plugin.as_str().into())
            .await
            .unwrap();
        plugin
            .set(
                f.terms.property("plugin-source").unwrap().into(),
                Value::Markdown(source),
                &f.appstate.store,
            )
            .await
            .unwrap();
        plugin.save(&f.appstate.store).await.unwrap();
        arm(&f, true).await;
        add_watched(&f, "arrived").await;
        let id = f.appstate.store.queued_plugin_events().unwrap()[0]
            .id
            .clone();
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(children_named(&f, &f.drive, &id).await, 1);
    }

    #[actix_rt::test]
    async fn enabling_automatic_delivery_keeps_the_waiting_event() {
        let mut f = fixture("trigger_enable_with_backlog").await;
        write_plugin(&mut f, "Kept waiting event").await;
        let key = arm(&f, false).await;
        add_watched(&f, "waiting").await;
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        let previous = f.appstate.store.get_plugin_trigger(&key).unwrap().unwrap();
        arm(&f, true).await;
        let mut updated = f.appstate.store.get_plugin_trigger(&key).unwrap().unwrap();
        updated.pending_verdict = previous.pending_verdict;
        f.appstate.store.set_plugin_trigger(&key, &updated).unwrap();
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(children_named(&f, &f.drive, "Kept waiting event").await, 1);
        assert!(f.appstate.store.queued_plugin_events().unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn queued_arrivals_survive_no_listener_and_a_pending_review() {
        let mut f = fixture("plugin_durable_arrivals").await;
        write_plugin(&mut f, "Durable notification").await;
        let key = arm(&f, false).await;
        add_watched(&f, "first").await;
        add_watched(&f, "second").await;
        assert_eq!(f.appstate.store.queued_plugin_events().unwrap().len(), 2);
        let guard = Arc::new(Mutex::new(Guard::default()));
        drain(&f.appstate, &guard).await;
        drain(&f.appstate, &guard).await;
        assert_eq!(f.appstate.store.queued_plugin_events().unwrap().len(), 2);
        // Resolve the first review, then approve future execution. A fresh
        // worker has no in-memory state from the previous delivery attempt.
        arm(&f, true).await;
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(
            children_named(&f, &f.drive, "Durable notification").await,
            1
        );
        assert!(f.appstate.store.queued_plugin_events().unwrap().is_empty());
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(
            children_named(&f, &f.drive, "Durable notification").await,
            1
        );
        assert!(f
            .appstate
            .store
            .get_plugin_trigger(&key)
            .unwrap()
            .unwrap()
            .last_error
            .is_none());
    }

    #[actix_rt::test]
    async fn integration_approval_resumes_same_event_without_repeating_write() {
        let mut f = fixture("action_continuation").await;
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
        arm(&f, true).await;
        add_watched(&f, "Arrival").await;
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(
            children_named(&f, &f.drive, "After issue approval").await,
            0
        );
        assert_eq!(f.appstate.store.queued_plugin_events().unwrap().len(), 1);
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
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        drain(&f.appstate, &Arc::new(Mutex::new(Guard::default()))).await;
        assert_eq!(provider.0, 1);
        assert!(f.appstate.store.queued_plugin_events().unwrap().is_empty());
        assert_eq!(
            children_named(&f, &f.drive, "After issue approval").await,
            1
        );
    }

    #[actix_rt::test]
    async fn a_resource_entering_the_query_runs_the_plugin() {
        let mut fixture = fixture("plugin_trigger_enter").await;
        write_plugin(&mut fixture, "Saw an arrival").await;
        arm(&fixture, true).await;
        spawn(fixture.appstate.clone());

        add_watched(&fixture, "Arrived").await;

        assert_eq!(wait_for(&fixture, "Saw an arrival", 1).await, 1);
    }

    #[actix_rt::test]
    async fn without_a_grant_a_triggered_run_writes_nothing() {
        let mut fixture = fixture("plugin_trigger_no_grant").await;
        write_plugin(&mut fixture, "Should not exist").await;
        let key = arm(&fixture, false).await;
        spawn(fixture.appstate.clone());

        add_watched(&fixture, "Arrived").await;

        // Give the listener the same budget the passing case gets, so this is
        // "it ran and refused to write" rather than "we did not wait".
        assert_eq!(wait_for(&fixture, "Should not exist", 1).await, 0);
        assert!(fixture
            .appstate
            .store
            .get_plugin_trigger(&key)
            .unwrap()
            .unwrap()
            .pending_verdict
            .is_some());
    }

    #[actix_rt::test]
    async fn a_plugin_does_not_answer_its_own_echo() {
        let mut guard = Guard::default();
        guard.remember_writes("p", ["did:ad:written".to_string()].into_iter());

        assert!(guard
            .admit("p", "did:ad:written", Edge::Enter, 1_000)
            .is_err());
        // Only the once: the next genuine change to that resource must run.
        assert!(guard
            .admit("p", "did:ad:written", Edge::Enter, 100_000)
            .is_ok());
    }

    #[test]
    fn the_same_edge_twice_runs_once() {
        let mut guard = Guard::default();

        assert!(guard.admit("p", "s", Edge::Enter, 1_000).is_ok());
        assert!(guard.admit("p", "s", Edge::Enter, 1_100).is_err());
        // The other edge is a different thing that happened.
        assert!(guard.admit("p", "s", Edge::Leave, 1_100).is_ok());
        // And once the window passes, so is the same edge again.
        assert!(guard
            .admit("p", "s", Edge::Enter, 1_000 + DEDUP_WINDOW_MS)
            .is_ok());
    }

    #[test]
    fn a_plugin_feeding_its_own_query_is_stopped() {
        let mut guard = Guard::default();

        for i in 0..RATE_LIMIT {
            assert!(
                guard
                    .admit("p", &format!("s{i}"), Edge::Enter, 1_000)
                    .is_ok(),
                "run {i} should be allowed",
            );
        }

        let stopped = guard.admit("p", "one-too-many", Edge::Enter, 1_000);

        assert!(stopped.is_err());
        assert!(stopped.unwrap_err().contains("its own query"));
        // Another plugin is unaffected; the cap is per plugin, not per server.
        assert!(guard.admit("other", "s", Edge::Enter, 1_000).is_ok());
    }
}
