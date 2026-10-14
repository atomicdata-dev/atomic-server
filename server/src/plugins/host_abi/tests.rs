//! The host ABI end to end: real components (the examples under
//! `plugin-examples/`, prebuilt into `testdata/host-abi/`), real Installations
//! and Releases in a temporary store, real grants.
//!
//! Rebuild the fixtures with `scripts/build-host-abi-fixtures.sh` after
//! changing an example or `atomic-host/wit`.

use std::{io::Write, sync::Arc};

use atomic_lib::{
    agents::ForAgent,
    db::{
        app_agent::AppAgentKey,
        plugin_release::{PluginRelease, RUNTIME_WASIP2, WORLD_SANDBOXED_APP},
    },
    urls, Db, Storelike, Value,
};
use serde_json::{json, Value as Json};
use wasmtime::StoreLimitsBuilder;

use super::{
    bindings::atomic::host::{
        calls::Host as _,
        events::{Host as _, Kind},
        net::{Host as _, Request},
        store::{Host as _, Intent, Outcome, QuerySpec},
        types::{PropVal, Value as WitValue},
    },
    call_as, code,
    run::{build_host, AbiState},
    HostAbiRegistry, HostError, MAX_CALL_DEPTH,
};
use crate::plugins::{
    release,
    test_fixture::{fixture, genesis, Fixture},
};

pub(crate) const COUNTER_WASM: &[u8] = include_bytes!("../../../../testdata/host-abi/counter.wasm");
const CALLER_WASM: &[u8] = include_bytes!("../../../../testdata/host-abi/caller.wasm");
pub(crate) const COUNTER_MANIFEST: &str =
    include_str!("../../../../testdata/host-abi/counter.manifest.json");
const CALLER_MANIFEST: &str = include_str!("../../../../testdata/host-abi/caller.manifest.json");

const COUNTER: &str = "atomic:example/counter@1";
const CALLER: &str = "atomic:example/caller@1";

pub(crate) struct Installed {
    pub(crate) installation: String,
    /// The subject of the agent the Installation got when it was activated.
    pub(crate) agent: String,
}

/// Publishes a release for `wasm` and installs it in the fixture's drive, with
/// the identity a real installation gets: an app agent whose key this node holds.
pub(crate) async fn install(f: &Fixture, name: &str, manifest: &str, wasm: &[u8]) -> Installed {
    let db = &f.appstate.store;
    let manifest: Json = serde_json::from_str(manifest).unwrap();

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("plugin.wasm", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(wasm).unwrap();
    let bytes = zip.finish().unwrap().into_inner();

    let package = release::store_package(db, &bytes).await.unwrap();
    let id = db
        .publish_plugin_release(&PluginRelease {
            package: Some(package),
            manifest,
            runtime: RUNTIME_WASIP2.into(),
            world: WORLD_SANDBOXED_APP.into(),
            ..Default::default()
        })
        .unwrap();

    let installation = genesis(
        db,
        vec![
            (
                urls::IS_A,
                Value::ResourceArray(vec![urls::INSTALLATION.into()]),
            ),
            (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
            (urls::NAME, Value::String(name.into())),
            (urls::NAMESPACE, Value::String("example".into())),
            (urls::RELEASE_PROP, Value::String(id.clone())),
            (urls::RELEASE_ID, Value::String(id)),
            (urls::INSTALLATION_STATUS, Value::String("active".into())),
            (urls::GRANTS, Value::Json(json!([]))),
        ],
    )
    .await;

    // Activating the Installation (its before-commit hook) minted the identity.
    let agent = db
        .get_app_agent_info(&AppAgentKey::new(&f.drive, &installation))
        .unwrap()
        .expect("activation gave the installation an agent")
        .agent;

    Installed {
        installation,
        agent,
    }
}

pub(crate) fn owner(db: &Db) -> ForAgent {
    ForAgent::AgentSubject(db.get_default_agent().unwrap().subject)
}

/// Lets `agents` (and the drive's owner) read and write `subject`.
pub(crate) async fn share(db: &Db, subject: &str, readers: &[&String], writers: &[&String]) {
    let owner = db.get_default_agent().unwrap().subject;
    let list = |agents: &[&String]| {
        let mut all: Vec<atomic_lib::values::SubResource> = vec![owner.clone().into()];
        all.extend(
            agents
                .iter()
                .map(|a| atomic_lib::Subject::from(a.as_str()).into()),
        );
        Value::ResourceArray(all)
    };
    let mut resource = db.get_resource(&subject.into()).await.unwrap();
    resource
        .set_unsafe(urls::READ.into(), list(readers))
        .unwrap();
    resource
        .set_unsafe(urls::WRITE.into(), list(writers))
        .unwrap();
    resource.save(db).await.unwrap();
}

/// An integer property in the drive, and a resource that counts with it.
pub(crate) async fn counter_resource(f: &Fixture) -> (String, String) {
    let db = &f.appstate.store;
    let property = genesis(
        db,
        vec![
            (
                urls::IS_A,
                Value::ResourceArray(vec![urls::PROPERTY.into()]),
            ),
            (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
            (urls::SHORTNAME, Value::Slug("count".into())),
            (urls::DESCRIPTION, Value::Markdown("A count".into())),
            (urls::DATATYPE_PROP, Value::AtomicUrl(urls::INTEGER.into())),
        ],
    )
    .await;
    // A vocabulary term is public, as in a real drive: planning a write reads
    // the property as the caller and as the app.
    let mut term = db.get_resource(&property.as_str().into()).await.unwrap();
    term.set_unsafe(
        urls::READ.into(),
        Value::ResourceArray(vec![urls::PUBLIC_AGENT.into()]),
    )
    .unwrap();
    term.save(db).await.unwrap();
    let subject = genesis(
        db,
        vec![
            (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
            (urls::NAME, Value::String("Visitors".into())),
            (property.as_str(), Value::Integer(0)),
        ],
    )
    .await;
    (subject, property)
}

pub(crate) async fn count_of(db: &Db, subject: &str, property: &str) -> i64 {
    match db
        .get_resource(&subject.into())
        .await
        .unwrap()
        .get(property)
    {
        Ok(Value::Integer(n)) => *n,
        other => panic!("not an integer: {other:?}"),
    }
}

struct World {
    f: Fixture,
    registry: Arc<HostAbiRegistry>,
    db: Arc<Db>,
}

impl World {
    async fn new(name: &str) -> Self {
        let f = fixture(name).await;
        let db = Arc::new(f.appstate.store.clone());
        Self {
            f,
            registry: Arc::new(HostAbiRegistry::new()),
            db,
        }
    }

    async fn call(
        &self,
        interface: &str,
        function: &str,
        args: Json,
        caller: ForAgent,
    ) -> Result<Json, HostError> {
        call_as(
            &self.registry,
            &self.db,
            &self.f.drive,
            interface,
            function,
            &args.to_string(),
            caller,
        )
        .await
        .map(|text| serde_json::from_str(&text).unwrap())
    }

    /// The host state of an installed app, for calling the interfaces directly.
    async fn state(&self, installed: &Installed, caller: ForAgent) -> AbiState {
        self.registry.refresh(&self.db, &self.f.drive).await;
        let app = self
            .registry
            .app(&self.f.drive, &installed.installation)
            .expect("the app is loaded");
        let host = build_host(&self.registry, &self.db, &app, Some(caller), 0)
            .await
            .unwrap();
        AbiState::new(host, StoreLimitsBuilder::new().build())
    }
}

fn set(subject: &str, property: &str, value: WitValue) -> Intent {
    Intent::Set((
        subject.to_string(),
        vec![PropVal {
            property: property.to_string(),
            value,
        }],
    ))
}

#[test]
fn the_fixtures_are_built_from_the_example_manifests() {
    assert_eq!(
        COUNTER_MANIFEST,
        include_str!("../../../../plugin-examples/host-abi-counter/manifest.json"),
        "run scripts/build-host-abi-fixtures.sh"
    );
    assert_eq!(
        CALLER_MANIFEST,
        include_str!("../../../../plugin-examples/host-abi-caller/manifest.json"),
        "run scripts/build-host-abi-fixtures.sh"
    );
}

#[actix_rt::test]
async fn bump_twice_calls_the_counter_twice_through_the_host() {
    let w = World::new("host_abi_bump_twice").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    // Only the counter app may write the resource. The caller app has no rights
    // on it at all: it can only ask the counter to.
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    // The host lists what is installed, and what it offers, without running it.
    w.registry.refresh(db, &w.f.drive).await;
    let providers = w.registry.providers(&w.f.drive, COUNTER);
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].installation, counter.installation);
    let described = super::calls::describe(&w.registry, &w.f.drive, CALLER).unwrap();
    assert_eq!(
        described
            .iter()
            .map(|e| e.function.as_str())
            .collect::<Vec<_>>(),
        ["bump-twice", "recurse"]
    );

    let result = w
        .call(
            CALLER,
            "bump-twice",
            json!({"subject": subject, "property": property}),
            owner(db),
        )
        .await
        .unwrap();

    assert_eq!(result, json!({"count": 2}));
    assert_eq!(count_of(db, &subject, &property).await, 2);
    // Who signed it is the installation's agent by construction
    // (`StoreApplyHost`, tested in `store_host`). The store keeps no commit
    // history of a resource to read it back from, so what this checks is the
    // rights: the caller app has none on the resource, and the write only
    // happens because the counter app's own agent may write it.
    assert_ne!(caller.agent, counter.agent);
}

#[actix_rt::test]
async fn the_callee_never_gets_the_callers_rights() {
    let w = World::new("host_abi_no_borrowed_rights").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    // The drive owner may write; the counter app may only read. Whoever asks
    // (here the owner, with every right) the counter runs with its own grant.
    share(db, &subject, &[&counter.agent], &[]).await;

    let err = w
        .call(
            CALLER,
            "bump-twice",
            json!({"subject": subject, "property": property}),
            owner(db),
        )
        .await
        .unwrap_err();

    assert!(
        err.message.contains("Proposed"),
        "the counter's write was only proposed: {err:?}"
    );
    assert_eq!(
        count_of(db, &subject, &property).await,
        0,
        "nothing written"
    );
}

#[actix_rt::test]
async fn without_a_write_grant_apply_is_proposed_and_without_the_callers_rights_refused() {
    let w = World::new("host_abi_outcomes").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[]).await;

    // The owner may write, the app may not: proposed, kept for review.
    let mut state = w.state(&counter, owner(db)).await;
    let applied = state
        .apply(vec![set(&subject, &property, WitValue::Integer(41))])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Proposed, "{applied:?}");
    assert!(applied.undo_token.is_none());
    assert_eq!(count_of(db, &subject, &property).await, 0);
    let kept = w.registry.proposals(&w.f.drive, &counter.installation);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].verdict["intents"][0]["subject"], json!(subject));

    // Nobody who asked may write: refused, and not kept.
    let mut state = w.state(&counter, ForAgent::Public).await;
    let applied = state
        .apply(vec![set(&subject, &property, WitValue::Integer(41))])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Refused, "{applied:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);
    assert_eq!(
        w.registry
            .proposals(&w.f.drive, &counter.installation)
            .len(),
        1
    );

    // Both may: committed.
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let mut state = w.state(&counter, owner(db)).await;
    let applied = state
        .apply(vec![set(&subject, &property, WitValue::Integer(41))])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Committed, "{applied:?}");
    assert_eq!(count_of(db, &subject, &property).await, 41);

    // A plan the planner blocks is refused before rights come into it.
    let applied = state
        .apply(vec![set(
            &subject,
            &property,
            WitValue::String("many".into()),
        )])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Refused, "{applied:?}");
    assert_eq!(count_of(db, &subject, &property).await, 41);
}

#[actix_rt::test]
async fn apply_creates_with_local_ids_and_never_touches_installations() {
    let w = World::new("host_abi_create").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (_subject, _property) = counter_resource(&w.f).await;
    share(db, &w.f.drive, &[&counter.agent], &[&counter.agent]).await;

    let mut state = w.state(&counter, owner(db)).await;
    let created = state
        .apply(vec![Intent::Create(
            super::bindings::atomic::host::store::Create {
                local_id: "local:note".into(),
                parent: w.f.drive.clone(),
                classes: vec![],
                set: vec![PropVal {
                    property: urls::NAME.into(),
                    value: WitValue::String("Made by an app".into()),
                }],
            },
        )])
        .await
        .unwrap();
    assert_eq!(created.outcome, Outcome::Committed, "{created:?}");
    let (local, real) = &created.created[0];
    assert_eq!(local, "local:note");
    assert_eq!(
        db.get_resource(&real.as_str().into())
            .await
            .unwrap()
            .get(urls::NAME)
            .unwrap()
            .to_string(),
        "Made by an app"
    );

    // Its own installation is not something an app may change.
    let applied = state
        .apply(vec![set(
            &counter.installation,
            urls::NAME,
            WitValue::String("Renamed".into()),
        )])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Refused, "{applied:?}");
    assert!(applied.problems[0].message.contains("Installation"));
}

#[actix_rt::test]
async fn an_undeclared_interface_or_function_is_an_error() {
    let w = World::new("host_abi_undeclared").await;
    let db = &*w.db;
    let _counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;

    let err = w
        .call("atomic:example/missing@1", "anything", json!({}), owner(db))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::NOT_FOUND, "{err:?}");

    // The interface exists; this function is not declared by it.
    let err = w
        .call(COUNTER, "reset", json!({}), owner(db))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::NOT_FOUND, "{err:?}");
}

#[actix_rt::test]
async fn arguments_that_fail_the_input_schema_are_refused_before_the_app_runs() {
    let w = World::new("host_abi_schema").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    for bad in [
        json!({"subject": subject}),
        json!({"subject": 5, "property": property}),
        json!({"subject": subject, "property": property, "extra": true}),
        json!("not an object"),
    ] {
        let err = w
            .call(COUNTER, "increment", bad.clone(), owner(db))
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_ARGUMENT, "{bad}: {err:?}");
    }
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // The same call with valid arguments does run.
    let ok = w
        .call(
            COUNTER,
            "increment",
            json!({"subject": subject, "property": property}),
            owner(db),
        )
        .await
        .unwrap();
    assert_eq!(ok, json!({"count": 1}));
}

#[actix_rt::test]
async fn calls_between_apps_are_bounded_in_depth() {
    let w = World::new("host_abi_depth").await;
    let db = &*w.db;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;

    // Within the limit: n hops, each a fresh instance of the same app.
    let hops = MAX_CALL_DEPTH as i64 - 1;
    let ok = w
        .call(CALLER, "recurse", json!({"n": 0, "limit": hops}), owner(db))
        .await
        .unwrap();
    assert_eq!(ok, json!({"depth": hops}));

    // Past it: the host refuses, and the refusal travels back up unchanged.
    let err = w
        .call(CALLER, "recurse", json!({"n": 0, "limit": 100}), owner(db))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::DEPTH_EXCEEDED, "{err:?}");
}

#[actix_rt::test]
async fn a_paused_installation_stops_answering_on_its_next_call() {
    let w = World::new("host_abi_paused").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let args = json!({"subject": subject, "property": property});

    w.call(COUNTER, "increment", args.clone(), owner(db))
        .await
        .unwrap();

    let mut installation = db
        .get_resource(&counter.installation.as_str().into())
        .await
        .unwrap();
    installation
        .set_unsafe(
            urls::INSTALLATION_STATUS.into(),
            Value::String("paused".into()),
        )
        .unwrap();
    installation.save(db).await.unwrap();

    let err = w
        .call(COUNTER, "increment", args, owner(db))
        .await
        .unwrap_err();
    // Dropped from the registry on refresh, so nobody provides it any more.
    assert_eq!(err.code, code::NOT_FOUND, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 1);
}

#[actix_rt::test]
async fn reads_are_bounded_by_both_the_caller_and_the_installations_agent() {
    let w = World::new("host_abi_reads").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, _property) = counter_resource(&w.f).await;

    // Readable by the owner only: the app's agent has no say, so the app sees nothing.
    let mut state = w.state(&counter, owner(db)).await;
    let err = state.get(subject.clone()).await.unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");

    share(db, &subject, &[&counter.agent], &[]).await;
    let resource = state.get(subject.clone()).await.unwrap();
    assert_eq!(resource.subject, subject);
    assert!(resource
        .propvals
        .iter()
        .any(|pv| pv.property == urls::NAME && pv.value == WitValue::String("Visitors".into())));

    // The public agent cannot read it even though the app's agent can.
    let mut state = w.state(&counter, ForAgent::Public).await;
    assert!(state.get(subject.clone()).await.is_err());

    // get-many keeps order and reports each slot on its own.
    let mut state = w.state(&counter, owner(db)).await;
    let many = state
        .get_many(vec![
            subject.clone(),
            "did:ad:nothing".into(),
            subject.clone(),
        ])
        .await;
    assert!(many[0].is_ok() && many[1].is_err() && many[2].is_ok());
}

#[actix_rt::test]
async fn query_filters_pages_with_a_cursor_and_says_when_it_is_complete() {
    let w = World::new("host_abi_query").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (_subject, property) = counter_resource(&w.f).await;

    let folder = genesis(
        db,
        vec![
            (urls::PARENT, Value::AtomicUrl(w.f.drive.as_str().into())),
            (urls::NAME, Value::String("Folder".into())),
        ],
    )
    .await;
    share(db, &folder, &[&counter.agent], &[]).await;
    for (name, count) in [("a", 1), ("b", 2), ("c", 2)] {
        genesis(
            db,
            vec![
                (urls::PARENT, Value::AtomicUrl(folder.as_str().into())),
                (urls::NAME, Value::String(name.into())),
                (property.as_str(), Value::Integer(count)),
            ],
        )
        .await;
    }

    let spec = |limit, cursor: Option<String>, filters| QuerySpec {
        class: None,
        parent: Some(folder.clone()),
        filters,
        sort_by: None,
        sort_desc: false,
        limit,
        cursor,
        with_resources: false,
    };
    let mut state = w.state(&counter, owner(db)).await;

    let first = state.query(spec(Some(2), None, vec![])).await.unwrap();
    assert_eq!(first.subjects.len(), 2);
    assert!(
        !first.complete,
        "a page with more behind it is not the answer"
    );
    let cursor = first.cursor.clone().expect("a next page");

    let mut next = spec(Some(2), Some(cursor), vec![]);
    next.with_resources = true;
    let second = state.query(next).await.unwrap();
    assert_eq!(second.subjects.len(), 1);
    assert_eq!(second.resources.len(), 1);
    assert!(second.cursor.is_none() && second.complete);
    let mut seen = first.subjects.clone();
    seen.extend(second.subjects.clone());
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "the pages do not overlap");

    use super::bindings::atomic::host::store::{Filter, FilterOp};
    let eq = |op, value| {
        vec![Filter {
            property: property.clone(),
            op,
            value: Some(value),
        }]
    };
    let twos = state
        .query(spec(None, None, eq(FilterOp::Eq, WitValue::Integer(2))))
        .await
        .unwrap();
    assert_eq!(twos.subjects.len(), 2);
    assert!(twos.complete);
    let more = state
        .query(spec(None, None, eq(FilterOp::Gt, WitValue::Integer(1))))
        .await
        .unwrap();
    assert_eq!(more.subjects.len(), 2);

    // What is not supported says so, and bad input is not a crash.
    let err = state
        .query(spec(None, None, eq(FilterOp::Ne, WitValue::Integer(2))))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::UNSUPPORTED);
    let err = state
        .query(spec(Some(9999), None, vec![]))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::INVALID_ARGUMENT);
    let err = state
        .query(spec(None, Some("nope".into()), vec![]))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::INVALID_ARGUMENT);
    assert_eq!(
        state.search("x".into(), None, 5).await.unwrap_err().code,
        code::UNSUPPORTED
    );
    assert_eq!(
        state.undo("x".into()).await.unwrap_err().code,
        code::UNSUPPORTED
    );

    // A subscription is stored and can be dropped.
    let id = state.subscribe(spec(None, None, vec![])).await.unwrap();
    assert_eq!(
        w.registry
            .subscriptions(&w.f.drive, &counter.installation)
            .len(),
        1
    );
    state.unsubscribe(id).await;
    assert!(w
        .registry
        .subscriptions(&w.f.drive, &counter.installation)
        .is_empty());
}

#[actix_rt::test]
async fn events_are_pulled_with_a_cursor_and_acknowledged() {
    let w = World::new("host_abi_events").await;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let mut state = w.state(&counter, owner(&w.db)).await;
    let (drive, installation) = (w.f.drive.as_str(), counter.installation.as_str());

    assert!(state.next(None, 10).await.unwrap().is_empty());
    for subject in ["a", "b", "c"] {
        w.registry
            .push_event(drive, installation, Kind::Commit(subject.into()), None);
    }

    let first = state.next(None, 2).await.unwrap();
    assert_eq!(first.len(), 2);
    // Reading does not consume: the same events come again until acknowledged.
    assert_eq!(state.next(None, 2).await.unwrap(), first);

    state.ack(first[1].cursor.clone()).await.unwrap();
    let rest = state.next(None, 10).await.unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].kind, Kind::Commit("c".into()));
    // After an explicit cursor, from there.
    assert!(state
        .next(Some(rest[0].cursor.clone()), 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        state.ack("garbage".into()).await.unwrap_err().code,
        code::INVALID_ARGUMENT
    );
}

#[actix_rt::test]
async fn fetch_only_does_what_the_manifest_declares() {
    let w = World::new("host_abi_net").await;
    let manifest = json!({
        "schemaVersion": 2,
        "runtime": "wasip2/1",
        "world": "sandboxed-app",
        "operations": [
            {"id": "read-local", "method": "GET", "url": "http://127.0.0.1:9/data", "effect": "read"},
            {"id": "write-remote", "method": "POST", "url": "https://api.example.com/items", "effect": "write"}
        ],
    })
    .to_string();
    let app = install(&w.f, "net", &manifest, COUNTER_WASM).await;
    let mut state = w.state(&app, owner(&w.db)).await;

    let request = |operation: &str| Request {
        operation: operation.into(),
        path: String::new(),
        query: vec![("q".into(), "1".into())],
        headers: vec![],
        body: None,
        if_match: None,
    };

    let undeclared = state.fetch(request("nope")).await.unwrap_err();
    assert_eq!(undeclared.code, code::FORBIDDEN, "{undeclared:?}");

    let write = state.fetch(request("write-remote")).await.unwrap_err();
    assert_eq!(write.code, code::NEEDS_APPROVAL, "{write:?}");

    // Declared and read-only, but the destination is on this machine: the
    // egress policy refuses before anything is sent.
    let private = state.fetch(request("read-local")).await.unwrap_err();
    assert!(
        private.message.to_lowercase().contains("address")
            || private.message.to_lowercase().contains("private")
            || private.message.to_lowercase().contains("loopback")
            || private.message.to_lowercase().contains("not allowed")
            || private.message.to_lowercase().contains("refus"),
        "{private:?}"
    );
}

#[actix_rt::test]
async fn providers_are_per_drive_and_calls_do_not_leak_across_apps_without_exports() {
    let w = World::new("host_abi_providers").await;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let mut state = w.state(&counter, owner(&w.db)).await;

    assert_eq!(
        state.providers(COUNTER.into()).await,
        vec![counter.installation.clone()]
    );
    assert!(state.providers(CALLER.into()).await.is_empty());
    assert_eq!(
        state.describe(CALLER.into()).await.unwrap_err().code,
        code::NOT_FOUND
    );
    let described = state.describe(COUNTER.into()).await.unwrap();
    assert_eq!(described.len(), 1);
    assert_eq!(described[0].function, "increment");
    let schema: Json = serde_json::from_str(&described[0].input_schema).unwrap();
    assert_eq!(schema["required"], json!(["subject", "property"]));

    // Handles are accepted and ignored (see the TODO in calls.rs): a call that
    // fails for its arguments fails the same with or without them.
    let err = state
        .call(COUNTER.into(), "increment".into(), "{}".into(), vec![])
        .await
        .unwrap_err();
    assert_eq!(err.code, code::INVALID_ARGUMENT);
}
