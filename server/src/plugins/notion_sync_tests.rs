//! The shipped Notion bundle in QuickJS/WASM with real Atomic storage/effect journals.
use super::{
    external::{ExternalHost, ExternalIntent, Receipt},
    js_runtime::{PluginHost, StoreHost},
    store_host::StoreApplyHost,
    sync_session::*,
    test_fixture::{fixture, genesis},
};
use atomic_lib::{
    agents::ForAgent, db::plugin_release::PluginRelease, urls, Storelike, Value as A,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
const SOURCE: &str = include_str!("../../../integrations/notion/plugin.js");
fn declared_manifest() -> super::manifest::Manifest {
    super::manifest::Manifest::parse(
        serde_json::from_str(include_str!(
            "../../../integrations/notion/manifest.fixture.json"
        ))
        .unwrap(),
    )
    .unwrap()
    .unwrap()
}
const DS: &str = "11111111-1111-1111-1111-111111111111";
const VIEW: &str = "44444444-4444-4444-4444-444444444444";
const COLUMNS: &str = "https://atomicdata.dev/properties/view-columns";
const KIND: &str = "https://atomicdata.dev/properties/view-kind";
const PAGE: &str = "22222222-2222-2222-2222-222222222222";
#[derive(Default)]
struct Provider {
    pages: BTreeMap<String, Value>,
    view: Value,
    renamed: Option<String>,
    writes: usize,
    lose: bool,
}
#[derive(Clone)]
struct Host {
    atomic: StoreHost,
    provider: Arc<Mutex<Provider>>,
}
#[async_trait::async_trait]
impl PluginHost for Host {
    async fn fetch(&mut self, request: String) -> Result<String, String> {
        let r: ExternalIntent = serde_json::from_str(&request).unwrap();
        assert!(
            declared_manifest().allows_read(
                Some(&r.operation),
                &r.method,
                &url::Url::parse(&r.url).unwrap()
            ),
            "undeclared read: {}",
            r.url
        );
        let p = self.provider.lock().unwrap();
        let body = match r.operation.as_str() {
            "schema" => {
                json!({"id":DS,"properties":{"Name":{"id":"title","name":p.renamed.as_deref().unwrap_or("Name"),"type":"title"},"Count":{"id":"n","name":"Count","type":"number"}}})
            }
            "query" => {
                assert_eq!(r.method, "POST");
                json!({"results":p.pages.values().collect::<Vec<_>>(),"has_more":false,"next_cursor":null})
            }
            "view" => p.view.clone(),
            "page" => p
                .pages
                .get(r.url.rsplit('/').next().unwrap())
                .ok_or("Missing page")?
                .clone(),
            _ => return Err("Unexpected read".into()),
        };
        Ok(json!({"status":200,"body":body.to_string()}).to_string())
    }
    async fn get_resource(&mut self, s: String) -> Result<String, String> {
        self.atomic.get_resource(s).await
    }
    async fn query(&mut self, p: String, v: String) -> Result<String, String> {
        self.atomic.query(p, v).await
    }
}
#[async_trait::async_trait]
impl ExternalHost for Host {
    async fn execute(&mut self, r: &ExternalIntent) -> Result<Receipt, String> {
        assert!(
            declared_manifest().allows_effect(
                Some(&r.operation),
                &r.method,
                &url::Url::parse(&r.url).unwrap(),
                "write"
            ),
            "undeclared write: {}",
            r.url
        );
        let mut p = self.provider.lock().unwrap();
        p.writes += 1;
        let body: Value = serde_json::from_str(r.body.as_ref().unwrap()).unwrap();
        let result = if r.operation == "rename" {
            p.renamed = Some(body["properties"]["title"]["name"].as_str().unwrap().into());
            json!({})
        } else if r.operation == "view-update" {
            for (k, v) in body.as_object().unwrap() {
                p.view[k] = v.clone();
            }
            p.view.clone()
        } else {
            let id = if r.operation == "create" {
                &format!("33333333-3333-3333-3333-{:012}", p.pages.len())
            } else {
                r.url.rsplit('/').next().unwrap()
            };
            let page = p.pages.entry(id.into()).or_insert_with(
                || json!({"object":"page","id":id,"parent":{"data_source_id":DS},"properties":{}}),
            );
            for (k, v) in body["properties"].as_object().unwrap() {
                let mut value = v.clone();
                value["id"] = json!(k);
                value["type"] = json!(if k == "title" { "title" } else { "number" });
                page["properties"][k] = value;
            }
            page.clone()
        };
        if p.lose {
            p.lose = false;
            return Err("Notion accepted create but response was lost".into());
        }
        Ok(Receipt {
            status: 200,
            body: result.to_string(),
        })
    }
}
fn remote() -> Value {
    json!({"object":"page","id":PAGE,"parent":{"data_source_id":DS},"properties":{"Name":{"id":"title","type":"title","title":[{"type":"text","text":{"content":"Task"}}]},"Count":{"id":"n","type":"number","number":2}}})
}
#[actix_web::test]
async fn notion_bundle_syncs_both_directions_and_renames_without_rebinding() {
    let mut f = fixture("notion_sandbox").await;
    super::test_fixture::write_plugin(&mut f, "fixture").await;
    let db = f.appstate.store.clone();
    let agent = ForAgent::AgentSubject(db.get_default_agent().unwrap().subject.clone());
    let mut props = BTreeMap::new();
    for (label, short, datatype) in [
        ("Name", "title", urls::STRING),
        ("Count", "n", urls::INTEGER),
        ("Notion ID", "identity", urls::STRING),
        ("Discovery", "arrival", urls::STRING),
    ] {
        let s = genesis(
            &db,
            vec![
                (urls::IS_A, A::ResourceArray(vec![urls::PROPERTY.into()])),
                (urls::PARENT, A::AtomicUrl(f.plugin.as_str().into())),
                (urls::NAME, A::String(label.into())),
                (urls::SHORTNAME, A::Slug(short.into())),
                (urls::DESCRIPTION, A::Markdown(label.into())),
                (urls::DATATYPE_PROP, A::AtomicUrl(datatype.into())),
            ],
        )
        .await;
        props.insert(short, s);
    }
    let class = genesis(
        &db,
        vec![
            (urls::IS_A, A::ResourceArray(vec![urls::CLASS.into()])),
            (urls::PARENT, A::AtomicUrl(f.plugin.as_str().into())),
            (urls::SHORTNAME, A::Slug("notion-row".into())),
            (urls::DESCRIPTION, A::Markdown("Notion row".into())),
        ],
    )
    .await;
    for (url, datatype) in [(COLUMNS, urls::RESOURCE_ARRAY), (KIND, urls::STRING)] {
        let mut property = atomic_lib::Resource::new(url.into());
        property
            .set_unsafe(
                urls::IS_A.into(),
                A::ResourceArray(vec![urls::PROPERTY.into()]),
            )
            .unwrap();
        property
            .set_unsafe(urls::DATATYPE_PROP.into(), A::AtomicUrl(datatype.into()))
            .unwrap();
        property
            .set_unsafe(
                urls::SHORTNAME.into(),
                A::Slug(url.rsplit('/').next().unwrap().into()),
            )
            .unwrap();
        property
            .set_unsafe(
                urls::DESCRIPTION.into(),
                A::Markdown("View configuration".into()),
            )
            .unwrap();
        db.add_resource(&property).await.unwrap();
    }
    let view_subject = genesis(
        &db,
        vec![
            (urls::PARENT, A::AtomicUrl(f.plugin.as_str().into())),
            (urls::NAME, A::String("Tasks".into())),
            (KIND, A::String("table".into())),
            (
                COLUMNS,
                A::ResourceArray(vec![
                    props["title"].as_str().into(),
                    props["n"].as_str().into(),
                ]),
            ),
        ],
    )
    .await;
    let config = json!({"dataSource":DS,"table":f.plugin,"rowClass":class,"identity":props["identity"],"arrival":props["arrival"],"fields":[{"id":"title","property":props["title"],"type":"title"},{"id":"n","property":props["n"],"type":"number"}],"views":[{"id":VIEW,"subject":view_subject,"kind":"table"}]});
    let release = db
        .publish_plugin_release(&PluginRelease {
            source: SOURCE.into(),
            manifest: json!({}),
            runtime: "atomic-js/1".into(),
            schemas: BTreeMap::new(),
        })
        .unwrap();
    let provider = Arc::new(Mutex::new(Provider::default()));
    provider.lock().unwrap().view = json!({"id":VIEW,"name":"Tasks","type":"table","data_source_id":DS,"configuration":{"type":"table","wrap_cells":true,"properties":[{"property_id":"title","visible":true,"width":777},{"property_id":"n","visible":true}]}});
    provider.lock().unwrap().pages.insert(PAGE.into(), remote());
    let host = Host {
        atomic: StoreHost {
            db: Arc::new(db.clone()),
            drive: f.drive.clone(),
            plugin: f.plugin.clone(),
            for_agent: agent.clone(),
            manifest: None,
        },
        provider: provider.clone(),
    };
    let mut atomic = StoreApplyHost {
        store: db.clone(),
        for_agent: agent,
        signing_as: None,
    };
    for phase in 0..3 {
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
        let mut completed = false;
        for _ in 0..40 {
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
                completed = true;
                break;
            }
        }
        assert!(completed);
        let state = super::connection_state::read(&db, &f.drive, &f.plugin).unwrap();
        let subject = &state.records[&format!("page:{PAGE}")].local;
        let mut row = db.get_resource(&subject.as_str().into()).await.unwrap();
        assert_eq!(
            row.get(urls::LOCAL_ID).unwrap().to_string(),
            format!("notion:{DS}:page:{PAGE}")
        );

        if phase == 0 {
            let mut view = db
                .get_resource(&view_subject.as_str().into())
                .await
                .unwrap();
            view.set(
                COLUMNS.into(),
                A::ResourceArray(vec![
                    props["n"].as_str().into(),
                    props["title"].as_str().into(),
                ]),
                &db,
            )
            .await
            .unwrap();
            view.save(&db).await.unwrap();
            provider.lock().unwrap().view["name"] = json!("Remote rename");
            assert_eq!(row.get(&props["title"]).unwrap().to_string(), "Task");
            row.set(props["title"].clone(), A::String("Atomic edit".into()), &db)
                .await
                .unwrap();
            row.save(&db).await.unwrap();
            // Independent remote numeric edit merges with the local title.
            provider.lock().unwrap().pages.get_mut(PAGE).unwrap()["properties"]["Count"]
                ["number"] = json!(9);
            let mut property = db
                .get_resource(&props["title"].as_str().into())
                .await
                .unwrap();
            property
                .set(urls::NAME.into(), A::String("Renamed".into()), &db)
                .await
                .unwrap();
            property.save(&db).await.unwrap();
        } else if phase == 1 {
            let view = db
                .get_resource(&view_subject.as_str().into())
                .await
                .unwrap();
            assert_eq!(view.get(urls::NAME).unwrap().to_string(), "Remote rename");
            assert_eq!(
                provider.lock().unwrap().view["configuration"]["properties"][1]["width"],
                json!(777)
            );
            assert_eq!(row.get(&props["n"]).unwrap().to_int().unwrap(), 9);
            assert_eq!(provider.lock().unwrap().renamed.as_deref(), Some("Renamed"));
            let local = genesis(
                &db,
                vec![
                    (urls::PARENT, A::AtomicUrl(f.plugin.as_str().into())),
                    (urls::IS_A, A::ResourceArray(vec![class.as_str().into()])),
                    (urls::NAME, A::String("Local create".into())),
                    (&props["title"], A::String("Local create".into())),
                ],
            )
            .await;
            assert!(!local.is_empty());
        } else {
            assert_eq!(provider.lock().unwrap().pages.len(), 2);
            assert_eq!(state.records.len(), 5); // two schema identities, a view and two pages
        }
    }
    // An ambiguous create must not be repeated under the saved operation ID.
    genesis(
        &db,
        vec![
            (urls::PARENT, A::AtomicUrl(f.plugin.as_str().into())),
            (urls::IS_A, A::ResourceArray(vec![class.as_str().into()])),
            (urls::NAME, A::String("Lost response".into())),
            (&props["title"], A::String("Lost response".into())),
        ],
    )
    .await;
    provider.lock().unwrap().lose = true;
    let before = provider.lock().unwrap().writes;
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
    let mut stopped = false;
    for _ in 0..40 {
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
        if next.status == "error" {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    let again = advance(
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
    assert_eq!(again.status, "error");
    assert_eq!(provider.lock().unwrap().writes, before + 1);
}
