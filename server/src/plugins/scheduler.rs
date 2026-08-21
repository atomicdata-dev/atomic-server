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

use std::sync::Arc;

use atomic_lib::db::plugin_schedule::PluginScheduleKey;
use atomic_lib::{urls, Db, Storelike};

use crate::appstate::AppState;
use crate::plugins::js_runtime;

/// How often to look for work. Well below the minimum interval a plugin may
/// ask for, so a run is late by seconds rather than by a whole period.
const TICK_SECONDS: u64 = 15;

/// The source of a plugin, resolved through the drive's ontology.
///
/// A plugin's properties are created per drive, so the subject of
/// `plugin-source` is not a constant the server can hold. The scheduler has no
/// browser to ask, so it walks drive → default ontology → properties and finds
/// the one whose shortname says what it is.
pub async fn plugin_source(store: &Db, drive: &str, plugin: &str) -> Option<String> {
    let drive_resource = store.get_resource(&drive.into()).await.ok()?;
    let ontology = drive_resource.get(urls::DEFAULT_ONTOLOGY).ok()?.to_string();

    let ontology_resource = store.get_resource(&ontology.as_str().into()).await.ok()?;
    let properties = ontology_resource
        .get(urls::PROPERTIES)
        .ok()?
        .to_subjects(None)
        .ok()?;

    let plugin_resource = store.get_resource(&plugin.into()).await.ok()?;

    for property in properties {
        let property_resource = store.get_resource(&property.as_str().into()).await.ok()?;

        let shortname = property_resource
            .get(urls::SHORTNAME)
            .ok()
            .map(|v| v.to_string());

        if shortname.as_deref() != Some("plugin-source") {
            continue;
        }

        return plugin_resource
            .get(&property)
            .ok()
            .map(|value| value.to_string());
    }

    None
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
            Ok(verdict) => schedule.record_verdict(verdict),
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
