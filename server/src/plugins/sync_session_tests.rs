use super::connection_state;
use super::sync_session::*;
use super::{
    external::{ExternalHost, ExternalIntent, Receipt},
    js_runtime::{PluginHost, StoreHost},
    store_host::StoreApplyHost,
    test_fixture::{fixture, genesis},
};
use atomic_lib::{
    agents::ForAgent, db::plugin_release::PluginRelease, urls, Db, Storelike, Value as AtomicValue,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
const SOURCE: &str = include_str!("../../../integrations/github-issues/plugin.js");
#[derive(Default)]
struct Provider {
    issues: BTreeMap<u64, Value>,
    writes: usize,
    lose: bool,
    throttle: bool,
    crash_report: Option<std::path::PathBuf>,
}
#[derive(Clone)]
struct Host {
    atomic: StoreHost,
    provider: Arc<Mutex<Provider>>,
}
#[async_trait::async_trait]
impl PluginHost for Host {
    async fn fetch(&mut self, request: String) -> Result<String, String> {
        let intent: ExternalIntent = serde_json::from_str(&request).unwrap();
        if intent.method != "GET" {
            return Err("read-only sandbox".into());
        }
        let p = self.provider.lock().unwrap();
        let url = url::Url::parse(&intent.url).unwrap();
        let (status, body) = if p.throttle {
            (429, json!({}))
        } else if intent.operation == "list" {
            let page = url
                .query_pairs()
                .find(|(k, _)| k == "page")
                .unwrap()
                .1
                .parse::<usize>()
                .unwrap();
            (
                200,
                json!(p
                    .issues
                    .values()
                    .skip((page - 1) * 100)
                    .take(100)
                    .collect::<Vec<_>>()),
            )
        } else {
            match p.issues.get(
                &url.path_segments()
                    .unwrap()
                    .next_back()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap(),
            ) {
                Some(i) => (200, i.clone()),
                None => (404, json!({})),
            }
        };
        Ok(json!({"status":status,"body":body.to_string()}).to_string())
    }
    async fn get_resource(&mut self, subject: String) -> Result<String, String> {
        self.atomic.get_resource(subject).await
    }
    async fn query(&mut self, property: String, value: String) -> Result<String, String> {
        self.atomic.query(property, value).await
    }
}
#[async_trait::async_trait]
impl ExternalHost for Host {
    async fn execute(&mut self, intent: &ExternalIntent) -> Result<Receipt, String> {
        let mut p = self.provider.lock().unwrap();
        p.writes += 1;
        let body: Value = intent
            .body
            .as_deref()
            .map(|b| serde_json::from_str(b).unwrap())
            .unwrap_or(Value::Null);
        let number = if intent.operation == "create" {
            p.issues.keys().next_back().copied().unwrap_or(0) + 1
        } else {
            url::Url::parse(&intent.url)
                .unwrap()
                .path_segments()
                .unwrap()
                .nth(4)
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        if intent.operation == "create" {
            p.issues.insert(number,json!({"number":number,"title":body["title"],"body":body["body"],"state":"open","labels":body["labels"]}));
        }
        let issue = p.issues.get_mut(&number).unwrap();
        match intent.operation.as_str() {
            "update" => {
                for (k, v) in body.as_object().unwrap() {
                    issue[k] = v.clone();
                }
            }
            "doing-add" => issue["labels"]
                .as_array_mut()
                .unwrap()
                .push(json!("atomic:doing")),
            "doing-remove" => issue["labels"]
                .as_array_mut()
                .unwrap()
                .retain(|v| v != "atomic:doing"),
            "create" => {}
            _ => panic!("unexpected effect"),
        }
        let receipt = Receipt {
            status: 200,
            body: issue.to_string(),
        };
        if let Some(path) = &p.crash_report {
            std::fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
            std::process::exit(74);
        }
        if p.lose {
            p.lose = false;
            return Err("lost provider response".into());
        }
        Ok(receipt)
    }
}
struct Test {
    appstate: crate::appstate::AppState,
    db: Db,
    drive: String,
    plugin: String,
    release: String,
    config: Value,
    host: Host,
    atomic: StoreApplyHost,
}
impl Test {
    async fn new() -> Self {
        let mut f = fixture("github_sandbox").await;
        super::test_fixture::write_plugin(&mut f, "fixture").await;
        let db = f.appstate.store.clone();
        let account = ForAgent::AgentSubject(db.get_default_agent().unwrap().subject.clone());
        let mut props = BTreeMap::new();
        for (name, datatype) in [
            ("status", urls::RESOURCE_ARRAY),
            ("number", urls::INTEGER),
            ("body", urls::MARKDOWN),
            ("arrival", urls::STRING),
        ] {
            let subject = genesis(
                &db,
                vec![
                    (
                        urls::IS_A,
                        AtomicValue::ResourceArray(vec![urls::PROPERTY.into()]),
                    ),
                    (
                        urls::PARENT,
                        AtomicValue::AtomicUrl(f.plugin.as_str().into()),
                    ),
                    (urls::SHORTNAME, AtomicValue::Slug(name.into())),
                    (urls::DESCRIPTION, AtomicValue::Markdown(name.into())),
                    (urls::DATATYPE_PROP, AtomicValue::AtomicUrl(datatype.into())),
                ],
            )
            .await;
            props.insert(name, subject);
        }
        let class = genesis(
            &db,
            vec![
                (
                    urls::IS_A,
                    AtomicValue::ResourceArray(vec![urls::CLASS.into()]),
                ),
                (
                    urls::PARENT,
                    AtomicValue::AtomicUrl(f.plugin.as_str().into()),
                ),
                (urls::SHORTNAME, AtomicValue::Slug("issue".into())),
                (urls::DESCRIPTION, AtomicValue::Markdown("issue".into())),
                (
                    urls::REQUIRES,
                    AtomicValue::ResourceArray(vec![urls::NAME.into()]),
                ),
            ],
        )
        .await;
        let config = json!({"repository":"owner/repo","table":f.plugin,"rowClass":class,"status":props["status"],"number":props["number"],"body":props["body"],"arrival":props["arrival"],"tags":{"Todo":f.drive,"Doing":f.plugin,"Done":class}});
        let release = db
            .publish_plugin_release(&PluginRelease {
                source: SOURCE.into(),
                manifest: json!({}),
                runtime: "atomic-js/1".into(),
                schemas: BTreeMap::new(),
            })
            .unwrap();
        let host = Host {
            atomic: StoreHost {
                db: Arc::new(db.clone()),
                drive: f.drive.clone(),
                plugin: f.plugin.clone(),
                for_agent: account.clone(),
                manifest: None,
            },
            provider: Default::default(),
        };
        let atomic = StoreApplyHost {
            store: db.clone(),
            for_agent: account,
            signing_as: None,
        };
        Self {
            appstate: f.appstate.clone(),
            db,
            drive: f.drive,
            plugin: f.plugin,
            release,
            config,
            host,
            atomic,
        }
    }
    async fn preview(&self) -> Result<Session, String> {
        preview(
            &self.db,
            &self.drive,
            &self.plugin,
            &self.release,
            self.config.clone(),
            self.host.clone(),
        )
        .await
    }
    async fn activate(&self) {
        let terms = super::scheduler::drive_terms(&self.db, &self.drive)
            .await
            .unwrap();
        self.edit(
            &self.plugin,
            terms.property("plugin-connection").unwrap(),
            AtomicValue::Json(json!({"release":self.release,"config":self.config})),
        )
        .await;
    }
    async fn apply(&mut self, run: &str) -> Session {
        for _ in 0..100 {
            let s = advance(
                &self.db,
                &self.drive,
                &self.plugin,
                run,
                "test",
                self.host.clone(),
                &mut self.atomic,
            )
            .await
            .unwrap();
            if s.status != "running" {
                return s;
            }
        }
        panic!("did not finish")
    }
    async fn sync(&mut self) -> Session {
        let s = self.preview().await.unwrap();
        let s = self.apply(&s.run).await;
        assert_eq!(s.status, "complete", "{:?}", s.error);
        s
    }
    async fn card(&self, title: &str) -> String {
        genesis(
            &self.db,
            vec![
                (
                    urls::IS_A,
                    AtomicValue::ResourceArray(vec![self.config["rowClass"]
                        .as_str()
                        .unwrap()
                        .into()]),
                ),
                (
                    urls::PARENT,
                    AtomicValue::AtomicUrl(self.plugin.as_str().into()),
                ),
                (urls::NAME, AtomicValue::String(title.into())),
            ],
        )
        .await
    }
    async fn edit(&self, subject: &str, prop: &str, value: AtomicValue) {
        let mut row = self.db.get_resource(&subject.into()).await.unwrap();
        row.set(prop.into(), value, &self.db).await.unwrap();
        row.save(&self.db).await.unwrap();
    }
}
fn issue(n: u64) -> Value {
    json!({"number":n,"title":format!("Issue {n}"),"body":"","state":"open","labels":["bug"]})
}
#[actix_web::test]
async fn sandbox_import_merge_columns_and_noop_with_real_atomic_storage() {
    let mut t = Test::new().await;
    t.host.provider.lock().unwrap().issues.insert(1, issue(1));
    let preview = t.preview().await.unwrap();
    assert_eq!(preview.proposal["changes"].as_array().unwrap().len(), 1);
    assert_eq!(t.host.provider.lock().unwrap().writes, 0);
    let s = t.apply(&preview.run).await;
    assert_eq!(s.status, "complete", "{:?}", s.error);
    let state = connection_state::read(&t.db, &t.drive, &t.plugin).unwrap();
    let card = state.records["1"].local.clone();
    assert_eq!(
        t.db.get_resource(&card.as_str().into())
            .await
            .unwrap()
            .get(urls::LOCAL_ID)
            .unwrap()
            .to_string(),
        "github:owner/repo:issue:1"
    );

    t.edit(&card, urls::NAME, AtomicValue::String("Local title".into()))
        .await;
    t.edit(
        &card,
        t.config["status"].as_str().unwrap(),
        AtomicValue::ResourceArray(vec![t.plugin.as_str().into()]),
    )
    .await;
    t.host.provider.lock().unwrap().issues.get_mut(&1).unwrap()["body"] = json!("Remote body");
    t.sync().await;
    {
        let p = t.host.provider.lock().unwrap();
        assert_eq!(p.issues[&1]["title"], "Local title");
        assert_eq!(p.issues[&1]["labels"], json!(["bug", "atomic:doing"]));
    }
    t.edit(
        &card,
        t.config["status"].as_str().unwrap(),
        AtomicValue::ResourceArray(vec![t.config["tags"]["Done"].as_str().unwrap().into()]),
    )
    .await;
    t.sync().await;
    {
        let p = t.host.provider.lock().unwrap();
        assert_eq!(p.issues[&1]["state"], "closed");
        assert_eq!(p.issues[&1]["labels"], json!(["bug"]));
    }
    let writes = t.host.provider.lock().unwrap().writes;
    t.sync().await;
    assert_eq!(t.host.provider.lock().unwrap().writes, writes);
}
#[actix_web::test]
async fn sandbox_create_uncertain_response_is_not_repeated() {
    let mut t = Test::new().await;
    t.card("New issue").await;
    t.host.provider.lock().unwrap().lose = true;
    let s = t.preview().await.unwrap();
    let s = t.apply(&s.run).await;
    assert_eq!(s.status, "error");
    assert!(s.pending.is_some());
    assert!(t.preview().await.is_err());
    let s = t.apply(&s.run).await;
    assert_eq!(s.status, "error");
    assert_eq!(t.host.provider.lock().unwrap().writes, 1);
}
#[actix_web::test]
async fn compatible_release_upgrade_preserves_bindings_and_pending_release() {
    let mut t = Test::new().await;
    t.activate().await;
    t.host.provider.lock().unwrap().issues.insert(1, issue(1));
    t.sync().await;
    let before = connection_state::read(&t.db, &t.drive, &t.plugin).unwrap();
    let old_release = t.release.clone();
    let mut package = t.db.get_plugin_release(&old_release).unwrap();
    package
        .source
        .push_str("\n// compatible maintenance release\n");
    t.release = t.db.publish_plugin_release(&package).unwrap();
    assert_ne!(t.release, old_release);
    t.activate().await;
    let writes = t.host.provider.lock().unwrap().writes;
    t.sync().await;
    let after = connection_state::read(&t.db, &t.drive, &t.plugin).unwrap();
    assert_eq!(before.records, after.records);
    assert_eq!(t.host.provider.lock().unwrap().writes, writes);

    t.card("Uncertain create during upgrade").await;
    t.host.provider.lock().unwrap().lose = true;
    let proposal = t.preview().await.unwrap();
    let pending = t.apply(&proposal.run).await;
    assert_eq!(pending.status, "error");
    assert!(pending.pending.is_some());
    let pinned = pending.release.clone();
    // Neither upgrade nor rollback may replace an approved unresolved effect.
    t.release = old_release;
    t.activate().await;
    assert!(t
        .preview()
        .await
        .err()
        .unwrap()
        .contains("resume the existing"));
    let saved = read(&t.db, &t.drive, &t.plugin).unwrap().unwrap();
    assert_eq!(saved.release, pinned);
    assert_eq!(saved.run, pending.run);
    let writes = t.host.provider.lock().unwrap().writes;
    t.apply(&pending.run).await;
    assert_eq!(t.host.provider.lock().unwrap().writes, writes);
    assert_eq!(
        connection_state::read(&t.db, &t.drive, &t.plugin)
            .unwrap()
            .records,
        after.records
    );
}
#[actix_web::test]
async fn sandbox_conflicts_missing_and_stale_reads_fail_closed() {
    let mut t = Test::new().await;
    t.host.provider.lock().unwrap().issues.insert(1, issue(1));
    t.sync().await;
    let card = connection_state::read(&t.db, &t.drive, &t.plugin)
        .unwrap()
        .records["1"]
        .local
        .clone();
    let s = t.preview().await.unwrap();
    t.edit(&card, urls::NAME, AtomicValue::String("Local".into()))
        .await;
    assert_eq!(t.apply(&s.run).await.status, "error");
    // Restore the reviewed state so the same approved run can finish.
    t.edit(&card, urls::NAME, AtomicValue::String("Issue 1".into()))
        .await;
    assert_eq!(t.apply(&s.run).await.status, "complete");
    t.edit(&card, urls::NAME, AtomicValue::String("Local".into()))
        .await;
    t.host.provider.lock().unwrap().issues.get_mut(&1).unwrap()["title"] = json!("Remote");
    assert!(!t.preview().await.unwrap().problems.is_empty());
    t.host.provider.lock().unwrap().issues.clear();
    assert!(!t.preview().await.unwrap().problems.is_empty());
    t.host.provider.lock().unwrap().throttle = true;
    assert!(t.preview().await.err().unwrap().contains("429"));
}

#[actix_web::test]
async fn sandbox_new_card_binds_issue_and_next_sync_does_not_repeat_write() {
    let mut t = Test::new().await;
    let card = t.card("New issue").await;
    t.sync().await;
    assert_eq!(
        connection_state::read(&t.db, &t.drive, &t.plugin)
            .unwrap()
            .records["1"]
            .local,
        card
    );
    assert_eq!(t.host.provider.lock().unwrap().writes, 1);
    t.sync().await;
    assert_eq!(t.host.provider.lock().unwrap().writes, 1);
}

#[actix_web::test]
async fn preview_cannot_execute_an_effect_and_approval_requires_saved_identity() {
    let mut t = Test::new().await;
    let package=PluginRelease{source:"export function run() { return {kind:'effect', effect:{kind:'external',id:'evil',request:{id:'evil',operation:'create',method:'POST',url:'https://api.github.com/repos/owner/repo/issues',body:'{}'}},cursor:{}}; }".into(),manifest:json!({}),runtime:"atomic-js/1".into(),schemas:BTreeMap::new()};
    let id = t.db.publish_plugin_release(&package).unwrap();
    assert!(preview(
        &t.db,
        &t.drive,
        &t.plugin,
        &id,
        t.config.clone(),
        t.host.clone()
    )
    .await
    .is_err());
    assert_eq!(t.host.provider.lock().unwrap().writes, 0);
    t.preview().await.unwrap();
    assert!(advance(
        &t.db,
        &t.drive,
        &t.plugin,
        "invented",
        "test",
        t.host.clone(),
        &mut t.atomic
    )
    .await
    .is_err());
}

#[actix_web::test]
async fn imported_issue_triggers_an_ordinary_message_automation() {
    use atomic_lib::db::{
        plugin_schedule::AutoApplyGrant,
        plugin_trigger::{PluginTrigger, PluginTriggerKey},
        QueryFilter,
    };
    use atomic_lib::storelike::PropVal;
    let mut t = Test::new().await;
    let terms = super::scheduler::drive_terms(&t.db, &t.drive)
        .await
        .unwrap();
    let room = genesis(
        &t.db,
        vec![
            (
                urls::PARENT,
                AtomicValue::AtomicUrl(t.drive.as_str().into()),
            ),
            (
                urls::NAME,
                AtomicValue::String("Issue notifications".into()),
            ),
            (
                urls::IS_A,
                AtomicValue::ResourceArray(vec!["https://atomicdata.dev/classes/ChatRoom".into()]),
            ),
        ],
    )
    .await;
    let source = format!(
        r#"export function run(ctx) {{ const row=ctx.read(ctx.trigger.subject);return {{intents:[{{op:'create',localId:'notification',parent:{room:?},isA:['https://atomicdata.dev/classes/Message'],set:{{'https://atomicdata.dev/properties/description':'New issue: '+row['https://atomicdata.dev/properties/name'],'https://atomicdata.dev/properties/about':ctx.trigger.subject}}}}],problems:[]}}; }}"#
    );
    let action = genesis(
        &t.db,
        vec![
            (
                urls::PARENT,
                AtomicValue::AtomicUrl(t.plugin.as_str().into()),
            ),
            (
                urls::NAME,
                AtomicValue::String("New issue notification".into()),
            ),
            (
                terms.property("plugin-source").unwrap(),
                AtomicValue::Markdown(source.clone()),
            ),
        ],
    )
    .await;
    let query = QueryFilter {
        drive: t.drive.as_str().into(),
        sort_by: None,
        filters: vec![
            PropVal {
                property: Some(urls::PARENT.into()),
                value: Some(AtomicValue::String(t.plugin.clone())),
                ..Default::default()
            },
            PropVal {
                property: Some(t.config["number"].as_str().unwrap().into()),
                value: None,
                ..Default::default()
            },
        ],
    };
    let mut trigger = PluginTrigger::new(query, true, false).unwrap();
    let actor = t.db.get_default_agent().unwrap().subject.to_string();
    trigger.run_as = Some(actor.clone());
    trigger.auto_apply = Some(AutoApplyGrant {
        agent: actor,
        granted_at: 0,
        reviewed_run: None,
        release: None,
        source: Some(source),
    });
    t.db.set_plugin_trigger(&PluginTriggerKey::new(&t.drive, &action), &trigger)
        .unwrap();
    super::triggers::spawn(t.appstate.clone());
    t.host.provider.lock().unwrap().issues.insert(1, issue(1));
    t.sync().await;
    let card = connection_state::read(&t.db, &t.drive, &t.plugin)
        .unwrap()
        .records["1"]
        .local
        .clone();
    for _ in 0..100 {
        let messages =
            t.db.get_resource(&room.as_str().into())
                .await
                .unwrap()
                .get_children(&t.db)
                .await
                .unwrap();
        if !messages.is_empty() {
            assert_eq!(messages.len(), 1);
            assert_eq!(
                messages[0].get(urls::DESCRIPTION).unwrap().to_string(),
                "New issue: Issue 1"
            );
            assert_eq!(
                messages[0]
                    .get("https://atomicdata.dev/properties/about")
                    .unwrap()
                    .to_string(),
                card
            );
            return;
        }
        actix_web::rt::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("imported issue did not trigger a message");
}

#[actix_rt::test]
#[ignore = "subprocess helper"]
async fn child_crashes_after_provider_accepts_write() {
    let Ok(path) = std::env::var("ATOMIC_SYNC_CRASH_REPORT") else {
        return;
    };
    let mut t = Test::new().await;
    t.card("Created across restart").await;
    let preview = t.preview().await.unwrap();
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "data": t.appstate.config.store_path.parent().unwrap(),
            "config_dir": t.appstate.config.config_dir,
            "drive": t.drive, "plugin": t.plugin, "release": t.release,
            "config": t.config, "run": preview.run,
        }))
        .unwrap(),
    )
    .unwrap();
    t.host.provider.lock().unwrap().crash_report = Some(format!("{path}.receipt").into());
    t.apply(&preview.run).await;
    panic!("the provider write should terminate the process");
}

#[actix_rt::test]
async fn hard_restart_stops_uncertain_create_then_resumes_from_verified_receipt() {
    use clap::Parser;
    let path = std::env::temp_dir().join(format!(
        "atomic-sync-{}",
        atomic_lib::utils::random_string(16)
    ));
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "plugins::sync_session_tests::child_crashes_after_provider_accepts_write",
            "--exact",
            "--ignored",
        ])
        .env("ATOMIC_SYNC_CRASH_REPORT", &path)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(74));
    let meta: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let receipt_path = format!("{}.receipt", path.display());
    let receipt: Receipt = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    let opts = crate::config::Opts::parse_from([
        "atomic-server",
        "--data-dir",
        meta["data"].as_str().unwrap(),
        "--config-dir",
        meta["config_dir"].as_str().unwrap(),
    ]);
    let appstate = crate::appstate::AppState::init(crate::config::build_config(opts).unwrap())
        .await
        .unwrap();
    let db = appstate.store.clone();
    let account = ForAgent::AgentSubject(db.get_default_agent().unwrap().subject.clone());
    let drive = meta["drive"].as_str().unwrap().to_string();
    let plugin = meta["plugin"].as_str().unwrap().to_string();
    let mut t = Test {
        appstate,
        db: db.clone(),
        drive: drive.clone(),
        plugin: plugin.clone(),
        release: meta["release"].as_str().unwrap().into(),
        config: meta["config"].clone(),
        host: Host {
            atomic: StoreHost {
                db: Arc::new(db.clone()),
                drive,
                plugin,
                for_agent: account.clone(),
                manifest: None,
            },
            provider: Arc::new(Mutex::new(Provider {
                writes: 1,
                issues: BTreeMap::from([(1, serde_json::from_str(&receipt.body).unwrap())]),
                ..Default::default()
            })),
        },
        atomic: StoreApplyHost {
            store: db,
            for_agent: account,
            signing_as: None,
        },
    };
    let run = meta["run"].as_str().unwrap();
    let paused = t.apply(run).await;
    assert_eq!(paused.status, "error");
    assert!(paused.error.as_deref().unwrap().contains("uncertain"));
    assert_eq!(t.host.provider.lock().unwrap().writes, 1);
    let pending = paused.pending.unwrap();
    let Effect::External { id, .. } = pending.effect else {
        panic!("expected remote create")
    };
    super::external::confirm_applied(
        &t.db,
        &json!([t.drive, t.plugin]).to_string(),
        &t.release,
        run,
        &id,
        receipt,
        super::external::Resolution {
            actor: "test".into(),
            evidence: "verified persisted provider issue #1".into(),
            at: atomic_lib::utils::now(),
        },
    )
    .await
    .unwrap();
    let completed = t.apply(run).await;
    assert_eq!(completed.status, "complete", "{:?}", completed.error);
    assert_eq!(t.host.provider.lock().unwrap().writes, 1);
    assert_eq!(
        connection_state::read(&t.db, &t.drive, &t.plugin)
            .unwrap()
            .records
            .len(),
        1
    );
    t.sync().await;
    assert_eq!(t.host.provider.lock().unwrap().writes, 1);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(receipt_path).unwrap();
}

#[actix_rt::test]
async fn discovery_events_exclude_backfill_and_locally_created_issues() {
    let mut t = Test::new().await;
    t.host.provider.lock().unwrap().issues.insert(1, issue(1));
    t.sync().await;
    let state = connection_state::read(&t.db, &t.drive, &t.plugin).unwrap();
    let initial = state.records.values().next().unwrap().local.clone();
    assert!(t
        .db
        .get_resource(&initial.as_str().into())
        .await
        .unwrap()
        .get(t.config["arrival"].as_str().unwrap())
        .is_err());
    t.host.provider.lock().unwrap().issues.insert(2, issue(2));
    t.sync().await;
    let local = t.card("From Atomic").await;
    t.sync().await;
    let state = connection_state::read(&t.db, &t.drive, &t.plugin).unwrap();
    let mut discoveries = Vec::new();
    for record in state.records.values() {
        let row =
            t.db.get_resource(&record.local.as_str().into())
                .await
                .unwrap();
        if row
            .get(t.config["arrival"].as_str().unwrap())
            .is_ok_and(|v| v.to_string() == "remote")
        {
            discoveries.push(record.local.clone());
        }
    }
    assert_eq!(discoveries.len(), 1);
    assert_ne!(discoveries[0], initial);
    assert_ne!(discoveries[0], local);
}

#[actix_web::test]
async fn activation_change_invalidates_an_unapproved_preview() {
    let mut t = Test::new().await;
    let terms = super::scheduler::drive_terms(&t.db, &t.drive)
        .await
        .unwrap();
    let property = terms.property("plugin-connection").unwrap();
    t.edit(
        &t.plugin,
        property,
        AtomicValue::Json(json!({"release":t.release,"config":t.config})),
    )
    .await;
    let preview = t.preview().await.unwrap();
    assert!(preview.binding_required);
    t.edit(
        &t.plugin,
        property,
        AtomicValue::Json(json!({"release":t.release,"config":{"changed":true}})),
    )
    .await;
    let result = advance(
        &t.db,
        &t.drive,
        &t.plugin,
        &preview.run,
        "test",
        t.host.clone(),
        &mut t.atomic,
    )
    .await;
    assert!(result.err().unwrap().contains("settings changed"));
    let saved = read(&t.db, &t.drive, &t.plugin).unwrap().unwrap();
    assert!(saved.approved_by.is_none());
    assert_eq!(t.host.provider.lock().unwrap().writes, 0);
}
