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

use atomic_lib::db::plugin_trigger::{Edge, PluginTrigger, PluginTriggerKey};
use atomic_lib::{agents::ForAgent, DbEvent};
use tokio::sync::Mutex;

use crate::appstate::AppState;
use crate::plugins::apply::{apply_plan, ApplyOptions};
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
        while let Ok(event) = events.recv().await {
            let DbEvent::QueryMembershipChanged {
                query_id,
                subject,
                added,
                ..
            } = event
            else {
                continue;
            };

            let triggers = match appstate.store.plugin_triggers_for_query(&query_id) {
                Ok(triggers) => triggers,
                Err(e) => {
                    tracing::warn!("could not read plugin triggers: {e}");
                    continue;
                }
            };

            for (key, trigger) in triggers {
                let edge = Edge::of(added);

                if !trigger.wants(edge) {
                    continue;
                }

                fire(&appstate, &guard, key, trigger, &subject, edge).await;
            }
        }
    });
}

async fn fire(
    appstate: &AppState,
    guard: &Arc<Mutex<Guard>>,
    key: PluginTriggerKey,
    trigger: PluginTrigger,
    subject: &str,
    edge: Edge,
) {
    let now = atomic_lib::utils::now();

    if let Err(reason) = guard.lock().await.admit(&key.plugin, subject, edge, now) {
        // A rate stop is a fault worth surfacing; the other two are the guard
        // doing its job on every ordinary echo.
        if reason.starts_with("stopped after") {
            tracing::warn!(plugin = %key.plugin, "{reason}");
            record_error(appstate, &key, &trigger, reason);
        }

        return;
    }

    match run(appstate, guard, &key, &trigger, subject, edge, now).await {
        Ok(summary) => tracing::info!(plugin = %key.plugin, "{edge:?} on {subject}: {summary}"),
        Err(e) => {
            tracing::warn!(plugin = %key.plugin, "triggered run failed: {e}");
            record_error(appstate, &key, &trigger, e);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    appstate: &AppState,
    guard: &Arc<Mutex<Guard>>,
    key: &PluginTriggerKey,
    trigger: &PluginTrigger,
    subject: &str,
    edge: Edge,
    now: i64,
) -> Result<String, String> {
    let source = plugin_source(&appstate.store, &key.drive, &key.plugin)
        .await
        .ok_or("the plugin has no source")?;

    let runtime = js_runtime::embedded_runtime().map_err(|e| e.to_string())?;

    let host = js_runtime::StoreHost {
        db: Arc::new(appstate.store.clone()),
        plugin: key.plugin.clone(),
        drive: key.drive.clone(),
    };

    // The subject is the resource that moved, not the plugin: what a query
    // trigger is *about* is that row.
    let input = format!(
        "{{\"trigger\":{{\"kind\":\"query\",\"at\":{now},\"subject\":{:?},\"edge\":{:?}}}}}",
        subject,
        edge.as_str(),
    );

    let verdict = runtime
        .run(&source, &input, host)
        .await
        .map_err(|e| e.to_string())??;

    let Some(grant) = trigger.auto_apply.clone() else {
        // Without a grant a triggered run has nowhere to wait: unlike a
        // schedule, there is no single next run to attach a verdict to, and
        // the edge that produced it will not come round again.
        return Ok(format!(
            "produced a verdict, but this trigger may not write ({} bytes withheld)",
            verdict.len(),
        ));
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
    };

    let plan = plan_verdict(&parsed, &mut apply_host).await;

    let report = if plan.blocked {
        None
    } else {
        Some(apply_plan(&plan, &mut apply_host, ApplyOptions::default()).await?)
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

    Ok(summary)
}

/// Keeps a failure where someone will find it.
fn record_error(
    appstate: &AppState,
    key: &PluginTriggerKey,
    trigger: &PluginTrigger,
    error: String,
) {
    let mut stored = trigger.clone();
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

    fn arm(fixture: &Fixture, auto_apply: bool) -> PluginTriggerKey {
        let key = PluginTriggerKey::new(&fixture.drive, &fixture.plugin);
        let mut trigger = PluginTrigger::new(watched_query(fixture), true, false).unwrap();

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
    async fn a_resource_entering_the_query_runs_the_plugin() {
        let mut fixture = fixture("plugin_trigger_enter").await;
        write_plugin(&mut fixture, "Saw an arrival").await;
        arm(&fixture, true);
        spawn(fixture.appstate.clone());

        add_watched(&fixture, "Arrived").await;

        assert_eq!(wait_for(&fixture, "Saw an arrival", 1).await, 1);
    }

    #[actix_rt::test]
    async fn without_a_grant_a_triggered_run_writes_nothing() {
        let mut fixture = fixture("plugin_trigger_no_grant").await;
        write_plugin(&mut fixture, "Should not exist").await;
        arm(&fixture, false);
        spawn(fixture.appstate.clone());

        add_watched(&fixture, "Arrived").await;

        // Give the listener the same budget the passing case gets, so this is
        // "it ran and refused to write" rather than "we did not wait".
        assert_eq!(wait_for(&fixture, "Should not exist", 1).await, 0);
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
