//! `testdata/plugin-for-testing` in the real sandbox: discovery output, and a
//! schema sync where either side renames a field without rebinding it.
use super::{
    external::{ExternalHost, ExternalIntent, Receipt},
    host_abi::{code, error, HostError},
    js_runtime::{embedded_runtime, PluginHost, StoreHost},
    store_host::StoreApplyHost,
    sync_session::*,
    test_fixture::{fixture, genesis},
};
use atomic_lib::{
    agents::ForAgent, db::plugin_release::PluginRelease, urls, Storelike, Value as AtomicValue,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const SOURCE: &str = include_str!("../../../testdata/plugin-for-testing/plugin.js");
const MANIFEST: &str = include_str!("../../../testdata/plugin-for-testing/manifest.json");

fn declared() -> super::manifest::Manifest {
    super::manifest::Manifest::parse(serde_json::from_str(MANIFEST).unwrap())
        .unwrap()
        .unwrap()
}

#[derive(Default)]
struct Provider {
    field: String,
    writes: usize,
}

#[derive(Clone)]
struct Host {
    atomic: Option<StoreHost>,
    provider: Arc<Mutex<Provider>>,
}

#[async_trait::async_trait]
impl PluginHost for Host {
    async fn abi(&mut self, function: &str, args: &str) -> Result<String, HostError> {
        if function != "net.fetch" {
            return self.atomic.as_mut().unwrap().abi(function, args).await;
        }
        let r: Value = serde_json::from_str::<Vec<Value>>(args).unwrap().remove(0);
        let (operation, method, url) = (
            r["operation"].as_str().unwrap(),
            r["method"].as_str().unwrap(),
            r["url"].as_str().unwrap(),
        );
        assert!(
            declared().allows_read(Some(operation), method, &url::Url::parse(url).unwrap()),
            "undeclared read: {operation} {url}"
        );
        assert_eq!(r["headers"]["Authorization"], "Bearer secret:provider");
        let body = match operation {
            "collections" => json!([
                {"id":"records","name":"Records","owner":"private@example.test"},
                {"id":"archive","name":"Archive","owner":"private@example.test"},
            ]),
            "schema" => json!({"id":"field","name":self.provider.lock().unwrap().field}),
            _ => return Err(error(code::INTERNAL, "unexpected read")),
        };
        Ok(json!({"status":200,"body":body.to_string()}).to_string())
    }
}

#[async_trait::async_trait]
impl ExternalHost for Host {
    async fn execute(&mut self, r: &ExternalIntent) -> Result<Receipt, String> {
        assert!(
            declared().allows_effect(
                Some(&r.operation),
                &r.method,
                &url::Url::parse(&r.url).unwrap(),
                "write"
            ),
            "undeclared write: {}",
            r.url
        );
        let body: Value = serde_json::from_str(r.body.as_deref().unwrap()).unwrap();
        let mut p = self.provider.lock().unwrap();
        p.writes += 1;
        p.field = body["name"].as_str().unwrap().into();
        Ok(Receipt {
            status: 200,
            body: json!({"id":"field","name":p.field}).to_string(),
        })
    }
}

#[actix_rt::test]
async fn discovery_runs_in_the_real_sandbox_and_minimizes_output() {
    let host = Host {
        atomic: None,
        provider: Default::default(),
    };
    let output = embedded_runtime()
        .unwrap()
        .run(
            SOURCE,
            r#"{"phase":"discover","trigger":{"kind":"manual","at":1}}"#,
            host,
        )
        .await
        .unwrap()
        .unwrap();
    let output: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(output["intents"], json!([]));
    assert_eq!(
        output["discovery"],
        json!({"collections":[
            {"id":"records","name":"Records"},
            {"id":"archive","name":"Archive"},
        ]})
    );
}

#[actix_web::test]
async fn schema_renames_sync_both_directions_without_rebinding() {
    let mut f = fixture("schema_rename").await;
    super::test_fixture::write_plugin(&mut f, "fixture").await;
    let db = f.appstate.store.clone();
    let agent = ForAgent::AgentSubject(db.get_default_agent().unwrap().subject.clone());
    let field = genesis(
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
            (urls::NAME, AtomicValue::String("Name".into())),
            (urls::SHORTNAME, AtomicValue::Slug("name".into())),
            (urls::DESCRIPTION, AtomicValue::Markdown("Name".into())),
            (
                urls::DATATYPE_PROP,
                AtomicValue::AtomicUrl(urls::STRING.into()),
            ),
        ],
    )
    .await;
    let config = json!({"collection":"records","field":field});
    let release = db
        .publish_plugin_release(&PluginRelease {
            source: Some(SOURCE.into()),
            manifest: serde_json::from_str(MANIFEST).unwrap(),
            runtime: atomic_lib::db::plugin_release::RUNTIME.into(),
            schemas: BTreeMap::from([("field".into(), field.clone())]),
            ..Default::default()
        })
        .unwrap();
    let mut plugin = db.get_resource(&f.plugin.as_str().into()).await.unwrap();
    plugin
        .set_unsafe(
            f.terms.property("plugin-connection").unwrap().into(),
            AtomicValue::Json(json!({"release":release,"config":config})),
        )
        .unwrap();
    plugin.save(&db).await.unwrap();
    let binding = super::release_binding::read(&db, &f.drive, &f.plugin)
        .await
        .unwrap();

    let provider = Arc::new(Mutex::new(Provider {
        field: "Name".into(),
        writes: 0,
    }));
    let host = Host {
        atomic: Some(StoreHost {
            db: Arc::new(db.clone()),
            drive: f.drive.clone(),
            plugin: f.plugin.clone(),
            for_agent: agent.clone(),
            manifest: None,
        }),
        provider: provider.clone(),
    };
    let mut atomic = StoreApplyHost {
        store: db.clone(),
        for_agent: agent,
        signing_as: None,
    };
    let local_name = |db: atomic_lib::Db, subject: String| async move {
        db.get_resource(&subject.as_str().into())
            .await
            .unwrap()
            .get(urls::NAME)
            .unwrap()
            .to_string()
    };

    // 0: both sides agree; 1: the provider renames; 2: Atomic renames.
    for round in 0..3 {
        if round == 1 {
            provider.lock().unwrap().field = "Title".into();
        } else if round == 2 {
            let mut property = db.get_resource(&field.as_str().into()).await.unwrap();
            property
                .set(
                    urls::NAME.into(),
                    AtomicValue::String("Heading".into()),
                    &db,
                )
                .await
                .unwrap();
            property.save(&db).await.unwrap();
        }
        let s = preview(
            &db,
            &f.drive,
            &f.plugin,
            &release,
            config.clone(),
            host.clone(),
        )
        .await
        .unwrap();
        assert!(s.problems.is_empty(), "{:?}", s.problems);
        let mut done = None;
        for _ in 0..20 {
            let next = advance(
                &db,
                &f.drive,
                &f.plugin,
                &s.run,
                "tester",
                host.clone(),
                &mut atomic,
            )
            .await
            .unwrap();
            assert_ne!(next.status, "error", "{:?}", next.error);
            if next.status == "complete" {
                done = Some(next);
                break;
            }
        }
        assert!(done.is_some(), "round {round} did not complete");

        let expected = ["Name", "Title", "Heading"][round];
        assert_eq!(local_name(db.clone(), field.clone()).await, expected);
        assert_eq!(provider.lock().unwrap().field, expected);
        assert_eq!(provider.lock().unwrap().writes, usize::from(round == 2));
        // The field stays bound to the same property, and the reviewed
        // connection is untouched: a rename is data, not a new binding.
        let state = super::connection_state::read(&db, &f.drive, &f.plugin).unwrap();
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records["schema:field"].local, field);
        assert_eq!(
            state.records["schema:field"].baseline,
            json!({"name":expected})
        );
        assert_eq!(
            super::release_binding::read(&db, &f.drive, &f.plugin)
                .await
                .unwrap(),
            binding
        );
    }
}
