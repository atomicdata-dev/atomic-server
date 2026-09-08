//! Persisted polling grants reuse the same sandbox session and effect journals.
use super::{js_runtime::StoreHost, manifest::Manifest, store_host::StoreApplyHost, sync_session};
use atomic_lib::{agents::ForAgent, db::trees::Tree, Db};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub drive: String,
    pub plugin: String,
    pub release: String,
    pub config: Value,
    #[serde(default)]
    pub binding_required: bool,
    pub actor: String,
    pub interval_seconds: u64,
    pub next_at: i64,
    pub error: Option<String>,
}
fn key(drive: &str, plugin: &str) -> String {
    format!("plugin-sync-schedule/v1/{}", json!([drive, plugin]))
}
pub fn read(db: &Db, drive: &str, plugin: &str) -> Result<Option<Schedule>, String> {
    db.kv
        .get(Tree::PluginMeta, key(drive, plugin).as_bytes())
        .map_err(|e| e.to_string())?
        .map(|v| serde_json::from_slice(&v).map_err(|e| e.to_string()))
        .transpose()
}
fn save(db: &Db, schedule: &Schedule) -> Result<(), String> {
    db.kv
        .insert(
            Tree::PluginMeta,
            key(&schedule.drive, &schedule.plugin).as_bytes(),
            &serde_json::to_vec(schedule).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())
}
pub async fn configure(
    db: &Db,
    drive: &str,
    plugin: &str,
    run: &str,
    actor: &str,
    interval: u64,
) -> Result<Option<Schedule>, String> {
    let _guard = db
        .lock_plugin(&format!("sync-worker:{}", key(drive, plugin)))
        .await;
    if interval == 0 {
        db.kv
            .remove(Tree::PluginMeta, key(drive, plugin).as_bytes())
            .map_err(|e| e.to_string())?;
        db.flush().map_err(|e| e.to_string())?;
        return Ok(None);
    }
    if !(60..=86400).contains(&interval) {
        return Err("sync interval must be between one minute and one day".into());
    }
    let session = sync_session::read(db, drive, plugin)?.ok_or("complete a reviewed sync first")?;
    if session.run != run
        || session.status != "complete"
        || session.approved_by.as_deref() != Some(actor)
    {
        return Err("background sync requires your completed, reviewed run".into());
    }
    let binding_required = super::release_binding::require_current(
        db,
        drive,
        plugin,
        &session.release,
        &session.config,
        session.binding_required,
    )
    .await?;
    let schedule = Schedule {
        drive: drive.into(),
        plugin: plugin.into(),
        release: session.release,
        config: session.config,
        binding_required,
        actor: actor.into(),
        interval_seconds: interval,
        next_at: atomic_lib::utils::now() + interval as i64 * 1000,
        error: None,
    };
    save(db, &schedule)?;
    Ok(Some(schedule))
}

async fn execute(db: &Db, drive: &str, plugin: &str) -> Result<(), String> {
    let _guard = db
        .lock_plugin(&format!("sync-worker:{}", key(drive, plugin)))
        .await;
    let mut schedule = read(db, drive, plugin)?;
    let mut session = sync_session::read(db, drive, plugin)?;
    // Only running work is resumed automatically. An uncertain or failed
    // effect requires an operator, regardless of whether a schedule is due.
    if session.as_ref().is_some_and(|s| s.status == "error") {
        return Ok(());
    }
    let continuing = session
        .as_ref()
        .is_some_and(|s| s.status == "running" && s.approved_by.is_some());
    let now = atomic_lib::utils::now();
    if !continuing
        && !schedule
            .as_ref()
            .is_some_and(|s| s.next_at <= now && s.error.is_none())
    {
        return Ok(());
    }
    if !continuing && session.as_ref().is_some_and(|s| s.status != "complete") {
        return Ok(());
    }
    if !continuing {
        let s = schedule.as_mut().unwrap();
        match super::release_binding::require_current(
            db,
            drive,
            plugin,
            &s.release,
            &s.config,
            s.binding_required,
        )
        .await
        {
            Ok(required) => s.binding_required = required,
            Err(error) => {
                s.error = Some(error.clone());
                save(db, s)?;
                return Err(error);
            }
        }
    }
    let (actor, release) = if continuing {
        let s = session.as_ref().unwrap();
        (s.approved_by.clone().unwrap(), s.release.clone())
    } else {
        let s = schedule.as_ref().unwrap();
        (s.actor.clone(), s.release.clone())
    };
    let host = StoreHost {
        db: std::sync::Arc::new(db.clone()),
        drive: drive.into(),
        plugin: plugin.into(),
        for_agent: ForAgent::AgentSubject(actor.as_str().into()),
        manifest: Manifest::parse(
            db.get_plugin_release(&release)
                .map_err(|e| e.to_string())?
                .manifest,
        )?,
    };
    host.validate_binding().await?;
    if !continuing {
        let s = schedule.as_mut().unwrap();
        // Persist backoff before reads; a failing provider must not be hammered.
        s.next_at = now + s.interval_seconds as i64 * 1000;
        save(db, s)?;
        match sync_session::preview(db, drive, plugin, &release, s.config.clone(), host.clone())
            .await
        {
            Ok(preview) => session = Some(preview),
            Err(e) => {
                s.error = Some(e);
                save(db, s)?;
                return Ok(());
            }
        }
    }
    let mut atomic =
        StoreApplyHost::for_installation(db, drive, plugin, host.for_agent.clone()).await?;
    let current = session.unwrap();
    let result =
        sync_session::advance(db, drive, plugin, &current.run, &actor, host, &mut atomic).await;
    if let Err(error) = result {
        if let Some(s) = schedule.as_mut() {
            s.error = Some(error.clone());
            save(db, s)?;
        }
        return Err(error);
    }
    Ok(())
}

pub async fn tick(db: &Db) -> Result<(), String> {
    let mut targets = std::collections::BTreeSet::new();
    for entry in db
        .kv
        .scan_prefix(Tree::PluginMeta, b"plugin-sync-schedule/v1/")
    {
        let (_, value) = entry.map_err(|e| e.to_string())?;
        let s: Schedule = serde_json::from_slice(&value).map_err(|e| e.to_string())?;
        targets.insert((s.drive, s.plugin));
    }
    for entry in db.kv.scan_prefix(Tree::PluginMeta, b"plugin-sync/v1/") {
        let (key, value) = entry.map_err(|e| e.to_string())?;
        let s: sync_session::Session = serde_json::from_slice(&value).map_err(|e| e.to_string())?;
        if s.status == "running" && s.approved_by.is_some() {
            let pair: (String, String) = serde_json::from_slice(&key[b"plugin-sync/v1/".len()..])
                .map_err(|e| e.to_string())?;
            targets.insert(pair);
        }
    }
    stream::iter(targets)
        .map(|(drive, plugin)| async move {
            if let Err(e) = execute(db, &drive, &plugin).await {
                tracing::warn!(%plugin, "background sync: {e}");
            }
        })
        .buffer_unordered(4)
        .collect::<Vec<_>>()
        .await;
    Ok(())
}
pub fn spawn(app: crate::appstate::AppState) {
    actix_web::rt::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            if let Err(e) = tick(&app.store).await {
                tracing::error!("sync worker: {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_fixture::{children_named, fixture, write_plugin};
    use atomic_lib::Storelike;
    #[actix_rt::test]
    #[ignore = "subprocess helper"]
    async fn child_leaves_an_approved_sync_running() {
        let Ok(path) = std::env::var("ATOMIC_BACKGROUND_CRASH_REPORT") else {
            return;
        };
        let mut f = fixture("background_hard_restart").await;
        write_plugin(&mut f, "draft").await;
        let db = &f.appstate.store;
        let actor = db.get_default_agent().unwrap().subject.to_string();
        let source = format!(
            r#"
export const manifest = {{schemaVersion:1,secrets:[],operations:[]}};
export async function run(ctx) {{
 if(ctx.phase==='preview') return {{kind:'preview',proposal:{{changes:[]}},problems:[]}};
 if(ctx.cursor===null) return {{kind:'effect',effect:{{kind:'atomic',id:'message',verdict:{{intents:[{{op:'create',localId:'message',parent:{drive},isA:[],set:{{'https://atomicdata.dev/properties/name':'Survived sync restart'}}}}],problems:[]}}}},cursor:1}};
 if(ctx.cursor<40) return {{kind:'continue',cursor:ctx.cursor+1}};
 if(ctx.cursor===40) return {{kind:'effect',effect:{{kind:'checkpoint',id:'checkpoint',records:[]}},cursor:41}};
 return {{kind:'complete'}};
}}
"#,
            drive = serde_json::to_string(&f.drive).unwrap()
        );
        let declaration = json!({"schemaVersion":1,"secrets":[],"operations":[]});
        let release = db
            .publish_plugin_release(&atomic_lib::db::plugin_release::PluginRelease {
                source,
                manifest: declaration.clone(),
                runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
                schemas: Default::default(),
            })
            .unwrap();
        let host = StoreHost {
            db: std::sync::Arc::new(db.clone()),
            drive: f.drive.clone(),
            plugin: f.plugin.clone(),
            for_agent: ForAgent::AgentSubject(actor.as_str().into()),
            manifest: Manifest::parse(declaration).unwrap(),
        };
        let preview =
            sync_session::preview(db, &f.drive, &f.plugin, &release, json!({}), host.clone())
                .await
                .unwrap();
        let mut atomic = StoreApplyHost {
            store: db.clone(),
            for_agent: host.for_agent.clone(),
            signing_as: None,
        };
        let running = sync_session::advance(
            db,
            &f.drive,
            &f.plugin,
            &preview.run,
            &actor,
            host,
            &mut atomic,
        )
        .await
        .unwrap();
        assert_eq!(running.status, "running");
        assert_eq!(
            children_named(&f, &f.drive, "Survived sync restart").await,
            1
        );
        std::fs::write(path,serde_json::to_vec(&json!({"data":f.appstate.config.store_path.parent().unwrap(),"config":f.appstate.config.config_dir,"drive":f.drive,"plugin":f.plugin})).unwrap()).unwrap();
        std::process::exit(75);
    }
    #[actix_rt::test]
    async fn a_hard_restart_finishes_approved_sync_without_a_browser_or_duplicate() {
        use clap::Parser;
        let path = std::env::temp_dir().join(format!(
            "atomic-background-{}",
            atomic_lib::utils::random_string(16)
        ));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "plugins::sync_worker::tests::child_leaves_an_approved_sync_running",
                "--exact",
                "--ignored",
            ])
            .env("ATOMIC_BACKGROUND_CRASH_REPORT", &path)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(75));
        let meta: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let opts = crate::config::Opts::parse_from([
            "atomic-server",
            "--data-dir",
            meta["data"].as_str().unwrap(),
            "--config-dir",
            meta["config"].as_str().unwrap(),
        ]);
        let appstate = crate::appstate::AppState::init(crate::config::build_config(opts).unwrap())
            .await
            .unwrap();
        let drive = meta["drive"].as_str().unwrap().to_string();
        let f = crate::plugins::test_fixture::Fixture {
            terms: crate::plugins::scheduler::drive_terms(&appstate.store, &drive)
                .await
                .unwrap(),
            appstate,
            drive,
            plugin: meta["plugin"].as_str().unwrap().into(),
        };
        tick(&f.appstate.store).await.unwrap();
        assert_eq!(
            sync_session::read(&f.appstate.store, &f.drive, &f.plugin)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        tick(&f.appstate.store).await.unwrap();
        assert_eq!(
            children_named(&f, &f.drive, "Survived sync restart").await,
            1
        );
        std::fs::remove_file(path).unwrap();
    }

    #[actix_rt::test]
    async fn background_tick_uses_pinned_package_and_reuses_completed_receipts() {
        let mut f = fixture("sync_background").await;
        write_plugin(&mut f, "unused draft").await;
        let db = &f.appstate.store;
        let actor = db.get_default_agent().unwrap().subject.to_string();
        let source = format!(
            r#"
export const manifest = {{schemaVersion:1,secrets:[],operations:[]}};
export async function run(ctx) {{
 if(ctx.phase==='preview') return {{kind:'preview',proposal:{{changes:[]}},problems:[]}};
 if(!ctx.cursor) return {{kind:'effect',effect:{{kind:'atomic',id:'message',verdict:{{intents:[{{op:'create',localId:'message',parent:{drive},isA:[],set:{{'https://atomicdata.dev/properties/name':'Background message'}}}}],problems:[]}}}},cursor:'written'}};
 if(ctx.cursor==='written') return {{kind:'effect',effect:{{kind:'checkpoint',id:'checkpoint',records:[]}},cursor:'done'}};
 return {{kind:'complete'}};
}}
"#,
            drive = serde_json::to_string(&f.drive).unwrap()
        );
        let release = db
            .publish_plugin_release(&atomic_lib::db::plugin_release::PluginRelease {
                source,
                manifest: json!({"schemaVersion":1,"secrets":[],"operations":[]}),
                runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
                schemas: Default::default(),
            })
            .unwrap();
        let host = StoreHost {
            db: std::sync::Arc::new(db.clone()),
            drive: f.drive.clone(),
            plugin: f.plugin.clone(),
            for_agent: ForAgent::AgentSubject(actor.as_str().into()),
            manifest: Manifest::parse(json!({"schemaVersion":1,"secrets":[],"operations":[]}))
                .unwrap(),
        };
        let preview =
            sync_session::preview(db, &f.drive, &f.plugin, &release, json!({}), host.clone())
                .await
                .unwrap();
        assert!(configure(db, &f.drive, &f.plugin, &preview.run, &actor, 60)
            .await
            .is_err());
        let mut atomic = StoreApplyHost {
            store: db.clone(),
            for_agent: host.for_agent.clone(),
            signing_as: None,
        };
        let done = sync_session::advance(
            db,
            &f.drive,
            &f.plugin,
            &preview.run,
            &actor,
            host,
            &mut atomic,
        )
        .await
        .unwrap();
        assert_eq!(done.status, "complete", "{:?}", done.error);
        let mut schedule = configure(db, &f.drive, &f.plugin, &done.run, &actor, 60)
            .await
            .unwrap()
            .unwrap();
        schedule.next_at = 0;
        save(db, &schedule).unwrap();
        // No browser drives this run. Reloading the grant from storage is the
        // same path used by startup; a changed draft is not the approved code.
        tick(db).await.unwrap();
        assert_eq!(children_named(&f, &f.drive, "Background message").await, 2);
        tick(db).await.unwrap();
        assert_eq!(children_named(&f, &f.drive, "Background message").await, 2);
        // Activating changed settings must not silently reuse the previous grant.
        let mut connection = db.get_resource(&f.plugin.as_str().into()).await.unwrap();
        connection
            .set_unsafe(
                f.terms.property("plugin-connection").unwrap().into(),
                atomic_lib::Value::Json(json!({"release":release,"config":{"changed":true}})),
            )
            .unwrap();
        connection.save(db).await.unwrap();
        let mut due = read(db, &f.drive, &f.plugin).unwrap().unwrap();
        due.next_at = 0;
        save(db, &due).unwrap();
        tick(db).await.unwrap();
        assert_eq!(
            children_named(&f, &f.drive, "Background message").await,
            2,
            "changed installation settings require a fresh review"
        );
        assert!(read(db, &f.drive, &f.plugin)
            .unwrap()
            .unwrap()
            .error
            .is_some());
        assert!(
            configure(db, &f.drive, &f.plugin, &done.run, "someone-else", 60)
                .await
                .is_err()
        );
    }
}
