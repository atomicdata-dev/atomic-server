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
        events::{Event, Filter, Host as _, Kind},
        net::{Host as _, Request},
        store::{Host as _, Intent, Outcome, QuerySpec},
        types::{PropVal, Value as WitValue},
    },
    call_as, call_entry, code,
    run::{app_error, build_host, with_deadline, AbiState},
    CallBudget, HostAbiRegistry, HostError, MAX_CALL_DEPTH,
};
use crate::plugins::{
    release,
    test_fixture::{fixture, genesis, Fixture},
};

pub(crate) const COUNTER_WASM: &[u8] = include_bytes!("../../../../testdata/host-abi/counter.wasm");
pub(crate) const CALLER_WASM: &[u8] = include_bytes!("../../../../testdata/host-abi/caller.wasm");
pub(crate) const COUNTER_MANIFEST: &str =
    include_str!("../../../../testdata/host-abi/counter.manifest.json");
pub(crate) const CALLER_MANIFEST: &str =
    include_str!("../../../../testdata/host-abi/caller.manifest.json");

pub(crate) const COUNTER: &str = "atomic:example/counter@1";
pub(crate) const CALLER: &str = "atomic:example/caller@1";

pub(crate) struct Installed {
    pub(crate) installation: String,
    /// The subject of the agent the Installation got when it was activated.
    pub(crate) agent: String,
}

/// Publishes a release for `wasm` and installs it in the fixture's drive, with
/// the identity a real installation gets: an app agent whose key this node holds.
pub(crate) async fn install(f: &Fixture, name: &str, manifest: &str, wasm: &[u8]) -> Installed {
    install_scoped(f, name, manifest, wasm, Vec::new()).await
}

/// The same, with more properties on the Installation (its scopes).
pub(crate) async fn install_scoped(
    f: &Fixture,
    name: &str,
    manifest: &str,
    wasm: &[u8],
    extra: Vec<(&str, Value)>,
) -> Installed {
    try_install_scoped(f, name, manifest, wasm, extra)
        .await
        .unwrap()
}

async fn try_install_scoped(
    f: &Fixture,
    name: &str,
    manifest: &str,
    wasm: &[u8],
    extra: Vec<(&str, Value)>,
) -> Result<Installed, String> {
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

    let mut props = vec![
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
    ];
    props.extend(extra);
    let mut resource = atomic_lib::Resource::new("did:ad:placeholder".into());
    for (property, value) in props {
        resource.set_unsafe(property.into(), value).unwrap();
    }
    resource
        .save_as_genesis(db)
        .await
        .map_err(|e| e.to_string())?;
    let installation = resource.get_subject().to_string();

    // Activating the Installation (its before-commit hook) minted the identity.
    let agent = db
        .get_app_agent_info(&AppAgentKey::new(&f.drive, &installation))
        .unwrap()
        .expect("activation gave the installation an agent")
        .agent;

    Ok(Installed {
        installation,
        agent,
    })
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

    /// An entry call under a budget the test chose.
    async fn call_within(
        &self,
        interface: &str,
        function: &str,
        args: Json,
        caller: ForAgent,
        budget: Arc<CallBudget>,
    ) -> Result<Json, HostError> {
        self.registry.refresh(&self.db, &self.f.drive).await;
        call_entry(
            &self.registry,
            &self.db,
            &self.f.drive,
            interface,
            function,
            &args.to_string(),
            caller,
            budget,
            super::ENTRY_TIMEOUT,
        )
        .await
        .map(|text| serde_json::from_str(&text).unwrap())
    }

    /// The host state of an installed app, for calling the interfaces directly.
    async fn state(&self, installed: &Installed, caller: ForAgent) -> AbiState {
        self.state_within(installed, caller, Arc::new(CallBudget::default()))
            .await
    }

    /// [`Self::state`] inside a chain with the budget the test chose.
    async fn state_within(
        &self,
        installed: &Installed,
        caller: ForAgent,
        budget: Arc<CallBudget>,
    ) -> AbiState {
        self.registry.refresh(&self.db, &self.f.drive).await;
        let app = self
            .registry
            .app(&self.f.drive, &installed.installation)
            .expect("the app is loaded");
        let host = build_host(
            &self.registry,
            &self.db,
            (&app.drive, &app.installation, Some(app.manifest.clone())),
            caller,
            0,
            budget,
        )
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
async fn going_through_apps_never_lets_someone_write_what_they_cannot() {
    let w = World::new("host_abi_no_confused_deputy").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    // The counter app may write; this agent may only read. Asking the caller
    // app, which asks the counter, must not turn a read right into a write.
    let reader = atomic_lib::agents::Agent::new(None)
        .unwrap()
        .subject
        .to_string();
    share(db, &subject, &[&counter.agent, &reader], &[&counter.agent]).await;

    let outcome = w
        .call(
            CALLER,
            "bump-twice",
            json!({"subject": subject, "property": property}),
            ForAgent::AgentSubject(reader.into()),
        )
        .await;

    assert!(outcome.is_err(), "the write is refused: {outcome:?}");
    assert_eq!(
        count_of(db, &subject, &property).await,
        0,
        "nothing written"
    );
}

#[actix_rt::test]
async fn a_chain_limited_to_reads_never_runs_an_export_that_writes() {
    let w = World::new("host_abi_effects_in_chain").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let reads_only =
        || Arc::new(CallBudget::default().only(vec![crate::plugins::manifest::ExportEffect::Read]));

    // The check runs in `call_export`, which every hop goes through.
    let err = w
        .call_within(
            CALLER,
            "bump-twice",
            json!({"subject": subject, "property": property}),
            owner(db),
            reads_only(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // Reads that call reads still work.
    w.call_within(
        CALLER,
        "recurse",
        json!({"n": 0, "limit": 2}),
        owner(db),
        reads_only(),
    )
    .await
    .unwrap();
}

#[actix_rt::test]
async fn every_hop_that_writes_or_reaches_out_needs_write_on_the_drive() {
    let w = World::new("host_abi_write_per_hop").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    // The reader may even write this one resource, but not the drive.
    let reader = atomic_lib::agents::Agent::new(None)
        .unwrap()
        .subject
        .to_string();
    share(
        db,
        &subject,
        &[&counter.agent, &reader],
        &[&counter.agent, &reader],
    )
    .await;

    let err = w
        .call(
            CALLER,
            "bump-twice",
            json!({"subject": subject, "property": property}),
            ForAgent::AgentSubject(reader.into()),
        )
        .await
        .unwrap_err();

    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);
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
async fn what_an_on_get_answer_references_is_read_as_the_reader_too() {
    let w = World::new("host_abi_referenced").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, _property) = counter_resource(&w.f).await;
    // The module's agent may read it; the person asking may not.
    share(db, &subject, &[&counter.agent], &[]).await;
    let state = w.state(&counter, owner(db)).await;
    let stranger = atomic_lib::agents::Agent::new(None)
        .unwrap()
        .subject
        .to_string();

    let seen = super::module::referenced_for_reader(
        &state.host,
        &ForAgent::AgentSubject(stranger.into()),
        vec![subject.clone()],
    )
    .await;
    assert!(seen.is_empty(), "{seen:?}");

    let seen =
        super::module::referenced_for_reader(&state.host, &owner(db), vec![subject.clone()]).await;
    assert_eq!(seen.len(), 1);
}

#[actix_rt::test]
async fn the_node_that_forwarded_a_call_bounds_what_the_call_can_read() {
    let w = World::new("host_abi_voucher_reads").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, _property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[]).await;

    // The caller and the app can read it, so a direct call does.
    let mut state = w.state(&counter, owner(db)).await;
    assert!(state.get(subject.clone()).await.is_ok());

    // The same call, vouched for by a node that has no rights here: the caller
    // and the app still could, the node could not, so nothing is read.
    let node = atomic_lib::agents::Agent::new(None)
        .unwrap()
        .subject
        .to_string();
    let wire = atomic_lib::sync::protocol::CallBudgetWire {
        calls: 8,
        fuel: 1_000_000,
        effects: None,
        secrets: true,
    };
    let vouched = Arc::new(CallBudget::from_wire(
        &wire,
        ForAgent::AgentSubject(node.into()),
    ));
    let mut state = w.state_within(&counter, owner(db), vouched).await;
    let err = state.get(subject.clone()).await.unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
}

#[actix_rt::test]
async fn a_read_only_chain_or_a_peer_that_cannot_write_never_commits_through_apply() {
    use crate::plugins::manifest::ExportEffect;
    use atomic_lib::sync::protocol::CallBudgetWire;

    let w = World::new("host_abi_apply_budget").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let change = || vec![set(&subject, &property, WitValue::Integer(41))];

    // Narrowed to reads: a read export that calls `apply` is forbidden.
    let reads = Arc::new(CallBudget::default().only(vec![ExportEffect::Read]));
    let mut state = w.state_within(&counter, owner(db), reads).await;
    let err = state.apply(change()).await.unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // A forwarding peer that may only read the drive vouches for the owner:
    // the owner could write, the peer could not, so nothing is written.
    let peer = atomic_lib::agents::Agent::new(None)
        .unwrap()
        .subject
        .to_string();
    let wire = CallBudgetWire {
        calls: 8,
        fuel: 1_000_000,
        effects: None,
        secrets: true,
    };
    let vouched = Arc::new(CallBudget::from_wire(
        &wire,
        ForAgent::AgentSubject(peer.into()),
    ));
    let mut state = w.state_within(&counter, owner(db), vouched).await;
    let err = state.apply(change()).await.unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // The same call in an unrestricted chain still commits.
    let mut state = w.state(&counter, owner(db)).await;
    let applied = state.apply(change()).await.unwrap();
    assert_eq!(applied.outcome, Outcome::Committed, "{applied:?}");
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

    // A cursor a guest made up must not overflow the window arithmetic.
    let huge = state
        .query(spec(Some(2), Some(usize::MAX.to_string()), vec![]))
        .await
        .unwrap();
    assert!(
        huge.subjects.is_empty() && huge.cursor.is_none(),
        "{huge:?}"
    );

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

/// Reads everything pending and acknowledges it, so a test starts from "now".
async fn drain_events(state: &mut AbiState) {
    let events = state.next(None, 100).await.unwrap();
    if let Some(last) = events.last() {
        state.ack(last.cursor.clone()).await.unwrap();
    }
}

fn commit_subjects(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match &e.kind {
            Kind::Commit(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

async fn bump_count(db: &Db, subject: &str, property: &str, name: Option<&str>, to: i64) {
    let mut resource = db.get_resource(&subject.into()).await.unwrap();
    resource
        .set_unsafe(property.into(), Value::Integer(to))
        .unwrap();
    if let Some(name) = name {
        resource
            .set_unsafe(urls::NAME.into(), Value::String(name.into()))
            .unwrap();
    }
    resource.save(db).await.unwrap();
}

#[actix_rt::test]
async fn events_are_pulled_with_a_cursor_and_acknowledged() {
    let w = World::new("host_abi_events").await;
    let counter = install_scoped(
        &w.f,
        "counter",
        COUNTER_MANIFEST,
        COUNTER_WASM,
        vec![(urls::READ_SCOPE, subtrees(&[w.f.drive.as_str()]))],
    )
    .await;
    let mut state = w.state(&counter, owner(&w.db)).await;
    drain_events(&mut state).await;
    assert!(state.next(None, 10).await.unwrap().is_empty());

    let (subject, property) = counter_resource(&w.f).await;
    bump_count(&w.db, &subject, &property, None, 1).await;

    let all = state.next(None, 100).await.unwrap();
    assert!(
        commit_subjects(&all).contains(&subject),
        "want {subject} got {all:?}"
    );
    let first = state.next(None, 1).await.unwrap();
    assert_eq!(first.len(), 1);
    // Reading does not consume: the same events come again until acknowledged.
    assert_eq!(state.next(None, 1).await.unwrap(), first);

    state.ack(first[0].cursor.clone()).await.unwrap();
    let rest = state.next(None, 100).await.unwrap();
    assert_eq!(rest.len(), all.len() - 1);
    // After an explicit cursor, from there.
    let last = rest.last().unwrap().cursor.clone();
    assert!(state.next(Some(last), 10).await.unwrap().is_empty());
    assert_eq!(
        state.ack("garbage".into()).await.unwrap_err().code,
        code::INVALID_ARGUMENT
    );
}

#[actix_rt::test]
async fn next_gets_past_a_long_run_of_events_the_app_filters_out() {
    let w = World::new("host_abi_event_stall").await;
    let counter = install_scoped(
        &w.f,
        "counter",
        COUNTER_MANIFEST,
        COUNTER_WASM,
        vec![(urls::READ_SCOPE, subtrees(&[w.f.drive.as_str()]))],
    )
    .await;
    let mut state = w.state(&counter, owner(&w.db)).await;
    drain_events(&mut state).await;
    let (subject, property) = counter_resource(&w.f).await;
    drain_events(&mut state).await;
    state
        .set_filters(vec![Filter {
            class: None,
            subtree: None,
            property: Some(property.clone()),
        }])
        .await
        .unwrap();

    // More commits that do not match than one `next` looks at, then one that
    // does. The app only ever calls `next` and acks what it was given.
    for i in 0..45 {
        let mut resource = w.db.get_resource(&subject.as_str().into()).await.unwrap();
        resource
            .set_unsafe(urls::NAME.into(), Value::String(format!("name {i}")))
            .unwrap();
        resource.save(&*w.db).await.unwrap();
    }
    bump_count(&w.db, &subject, &property, None, 1).await;

    let got = state.next(None, 10).await.unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(commit_subjects(&got), vec![subject]);
}

#[actix_rt::test]
async fn a_subscription_filters_by_class_subtree_and_property() {
    let w = World::new("host_abi_event_filters").await;
    let counter = install_scoped(
        &w.f,
        "counter",
        COUNTER_MANIFEST,
        COUNTER_WASM,
        vec![(urls::READ_SCOPE, subtrees(&[w.f.drive.as_str()]))],
    )
    .await;
    let mut state = w.state(&counter, owner(&w.db)).await;
    drain_events(&mut state).await;
    let filter = |class: Option<&str>, subtree: Option<&str>, property: Option<&str>| Filter {
        class: class.map(Into::into),
        subtree: subtree.map(Into::into),
        property: property.map(Into::into),
    };

    let (subject, property) = counter_resource(&w.f).await;
    drain_events(&mut state).await;

    // Property: only commits that changed it.
    state
        .set_filters(vec![filter(None, None, Some(&property))])
        .await
        .unwrap();
    bump_count(&w.db, &subject, &property, Some("renamed"), 1).await;
    let mut got = commit_subjects(&state.next(None, 100).await.unwrap());
    got.dedup();
    assert_eq!(got, vec![subject.clone()]);
    drain_events(&mut state).await;
    let mut resource = w.db.get_resource(&subject.as_str().into()).await.unwrap();
    resource
        .set_unsafe(urls::NAME.into(), Value::String("again".into()))
        .unwrap();
    resource.save(&*w.db).await.unwrap();
    assert!(state.next(None, 100).await.unwrap().is_empty());

    // Class: nothing here has it.
    state
        .set_filters(vec![filter(Some(urls::FOLDER), None, None)])
        .await
        .unwrap();
    assert!(state.next(Some("0".into()), 100).await.unwrap().is_empty());

    // Subtree: this resource and below, or a branch it is not in.
    state
        .set_filters(vec![filter(None, Some(&subject), None)])
        .await
        .unwrap();
    let got = commit_subjects(&state.next(Some("0".into()), 100).await.unwrap());
    assert!(
        !got.is_empty() && got.iter().all(|s| *s == subject),
        "{got:?}"
    );
    state
        .set_filters(vec![filter(None, Some(&property), None)])
        .await
        .unwrap();
    // The property is its own subtree, and the counter is not below it.
    let got = commit_subjects(&state.next(Some("0".into()), 100).await.unwrap());
    assert!(
        !got.is_empty() && got.iter().all(|s| *s == property),
        "{got:?}"
    );
}

#[actix_rt::test]
async fn an_app_never_sees_events_for_what_it_cannot_read() {
    let w = World::new("host_abi_event_rights").await;
    let (docs, inside, outside, property) = inside_and_outside(&w).await;
    let app = install_scoped(
        &w.f,
        "counter",
        COUNTER_MANIFEST,
        COUNTER_WASM,
        vec![(urls::READ_SCOPE, subtrees(&[&docs]))],
    )
    .await;
    let mut state = w.state(&app, owner(&w.db)).await;
    drain_events(&mut state).await;

    bump_count(&w.db, &outside, &property, None, 1).await;
    bump_count(&w.db, &inside, &property, None, 1).await;

    let got = commit_subjects(&state.next(None, 100).await.unwrap());
    assert!(got.contains(&inside), "{got:?}");
    assert!(!got.contains(&outside), "{got:?}");
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

    // The counter's manifest lists no `uses`, so it calls nobody, itself
    // included, whatever the arguments are.
    let err = state
        .call(COUNTER.into(), "increment".into(), "{}".into(), vec![])
        .await
        .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN);
}

/// The caller example's manifest without the interfaces it uses.
fn caller_manifest_without_uses() -> String {
    let mut manifest: Json = serde_json::from_str(CALLER_MANIFEST).unwrap();
    manifest.as_object_mut().unwrap().remove("uses").unwrap();
    manifest.to_string()
}

#[actix_rt::test]
async fn an_app_calls_only_the_interfaces_its_manifest_uses() {
    let w = World::new("host_abi_uses").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", &caller_manifest_without_uses(), CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    // The owner may do everything, the counter app may write, and still the
    // caller app may not reach the counter: it never said it would.
    let err = w
        .call(
            CALLER,
            "bump-twice",
            json!({"subject": subject, "property": property}),
            owner(db),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert!(err.message.contains("uses"), "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);
}

#[actix_rt::test]
async fn one_call_may_cause_only_so_many_calls_between_apps() {
    let w = World::new("host_abi_call_budget").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let args = json!({"subject": subject, "property": property});

    // bump-twice is three calls: itself and two to the counter. A fan-out
    // wider than the budget is cut off partway, with the same code as depth.
    let err = w
        .call_within(
            CALLER,
            "bump-twice",
            args.clone(),
            owner(db),
            Arc::new(CallBudget::new(2, super::CHAIN_FUEL)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::DEPTH_EXCEEDED, "{err:?}");
    assert_eq!(
        count_of(db, &subject, &property).await,
        1,
        "stopped halfway"
    );

    let ok = w
        .call_within(
            CALLER,
            "bump-twice",
            args,
            owner(db),
            Arc::new(CallBudget::new(3, super::CHAIN_FUEL)),
        )
        .await
        .unwrap();
    assert_eq!(ok, json!({"count": 3}));

    // And a deep chain is cut by the budget before the depth limit would be.
    let err = w
        .call_within(
            CALLER,
            "recurse",
            json!({"n": 0, "limit": 5}),
            owner(db),
            Arc::new(CallBudget::new(3, super::CHAIN_FUEL)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::DEPTH_EXCEEDED, "{err:?}");
}

#[actix_rt::test]
async fn the_apps_in_a_chain_share_one_fuel_pool_and_give_back_what_they_did_not_use() {
    let w = World::new("host_abi_fuel_pool").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let args = json!({"subject": subject, "property": property});

    // An empty pool: nothing may run.
    let err = w
        .call_within(
            CALLER,
            "bump-twice",
            args.clone(),
            owner(db),
            Arc::new(CallBudget::new(64, 0)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::DEPTH_EXCEEDED, "{err:?}");

    // A pool far too small for any app to finish in: the app is stopped.
    let err = w
        .call_within(
            CALLER,
            "bump-twice",
            args.clone(),
            owner(db),
            Arc::new(CallBudget::new(64, 1_000)),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::TRAP, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // A pool that holds one instance's full allowance (the caller's 1G)
    // and a little more: the two counter calls only fit because the first
    // returns what it did not use before the second asks.
    let budget = Arc::new(CallBudget::new(64, 1_500_000_000));
    let ok = w
        .call_within(CALLER, "bump-twice", args, owner(db), budget.clone())
        .await
        .unwrap();
    assert_eq!(ok, json!({"count": 2}));
    assert!(
        budget.fuel_left() > 1_400_000_000,
        "unused fuel went back to the pool: {}",
        budget.fuel_left()
    );
}

#[actix_rt::test]
async fn an_entry_call_has_a_deadline() {
    let stuck = std::future::pending::<Result<String, HostError>>();
    let err = with_deadline(std::time::Duration::from_millis(20), stuck)
        .await
        .unwrap_err();
    assert_eq!(err.code, code::TRAP, "{err:?}");
    assert!(err.message.contains("stopped"));

    let fast = async { Ok::<_, HostError>("{}".to_string()) };
    assert_eq!(
        with_deadline(std::time::Duration::from_secs(5), fast)
            .await
            .unwrap(),
        "{}"
    );
}

#[test]
fn an_error_code_the_abi_does_not_define_is_internal() {
    let kept = app_error(HostError {
        code: code::FORBIDDEN.into(),
        message: "no".into(),
    });
    assert_eq!(
        (kept.code.as_str(), kept.message.as_str()),
        (code::FORBIDDEN, "no")
    );

    let invented = app_error(HostError {
        code: "teapot".into(),
        message: "short and stout".into(),
    });
    assert_eq!(invented.code, code::INTERNAL);
    assert_eq!(invented.message, "short and stout");
}

#[actix_rt::test]
async fn a_release_that_cannot_be_loaded_is_not_compiled_again_on_every_call() {
    let w = World::new("host_abi_load_failure").await;
    let db = &*w.db;
    let _broken = install(&w.f, "counter", COUNTER_MANIFEST, b"not a component").await;

    for _ in 0..3 {
        w.registry.refresh(db, &w.f.drive).await;
    }
    assert_eq!(w.registry.load_attempts(), 1);
    assert!(w.registry.providers(&w.f.drive, COUNTER).is_empty());
}

#[actix_rt::test]
async fn get_many_reads_at_most_as_many_as_a_frame_does() {
    let w = World::new("host_abi_get_many_cap").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, _property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    let mut state = w.state(&counter, owner(db)).await;
    let asked = super::store::MAX_GET_MANY + 5;
    let answers = state.get_many(vec![subject.clone(); asked]).await;
    assert_eq!(answers.len(), asked);
    assert!(answers[..super::store::MAX_GET_MANY]
        .iter()
        .all(|a| a.is_ok()));
    assert!(answers[super::store::MAX_GET_MANY..]
        .iter()
        .all(|a| a.as_ref().unwrap_err().code == code::INVALID_ARGUMENT));
}

#[actix_rt::test]
async fn apply_refuses_to_turn_a_resource_into_an_installation_plugin_or_release() {
    let w = World::new("host_abi_is_a_escalation").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, _property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    let mut state = w.state(&counter, owner(db)).await;
    for class in [urls::INSTALLATION, urls::PLUGIN, urls::RELEASE] {
        let applied = state
            .apply(vec![set(
                &subject,
                urls::IS_A,
                WitValue::ResourceArray(vec![class.to_string()]),
            )])
            .await
            .unwrap();
        assert_eq!(applied.outcome, Outcome::Refused, "{class}: {applied:?}");
    }
    let still = db.get_resource(&subject.as_str().into()).await.unwrap();
    assert!(!still.has_class(urls::INSTALLATION));
}

/// The counter, declaring a `read` effect (and a secret, when asked): the wasm
/// is the same, only what the manifest claims differs.
fn counter_manifest_reading(secret: bool) -> String {
    let mut manifest: Json = serde_json::from_str(COUNTER_MANIFEST).unwrap();
    manifest["exports"][0]["effect"] = json!("read");
    if secret {
        manifest["secrets"] = json!([
            { "name": "token", "origin": "https://api.example.com" }
        ]);
    }
    manifest.to_string()
}

#[actix_rt::test]
async fn calling_an_app_that_declares_secrets_needs_write_on_the_drive() {
    for (secret, allowed) in [(true, false), (false, true)] {
        let w = World::new("host_abi_secrets_need_write").await;
        let db = &*w.db;
        let counter = install(
            &w.f,
            "counter",
            &counter_manifest_reading(secret),
            COUNTER_WASM,
        )
        .await;
        let (subject, property) = counter_resource(&w.f).await;
        let reader = atomic_lib::agents::Agent::new(None)
            .unwrap()
            .subject
            .to_string();
        // May read the drive and write the one resource, but not the drive.
        share(
            db,
            &subject,
            &[&counter.agent, &reader],
            &[&counter.agent, &reader],
        )
        .await;
        let mut drive = db.get_resource(&w.f.drive.as_str().into()).await.unwrap();
        let mut readers = match drive.get(urls::READ) {
            Ok(Value::ResourceArray(list)) => list.clone(),
            _ => Vec::new(),
        };
        readers.push(atomic_lib::Subject::from(reader.as_str()).into());
        drive
            .set_unsafe(urls::READ.into(), Value::ResourceArray(readers))
            .unwrap();
        drive.save(db).await.unwrap();

        let outcome = w
            .call(
                COUNTER,
                "increment",
                json!({"subject": subject, "property": property}),
                ForAgent::AgentSubject(reader.into()),
            )
            .await;

        if allowed {
            assert_eq!(outcome.unwrap(), json!({"count": 1}));
            assert_eq!(count_of(db, &subject, &property).await, 1);
        } else {
            let err = outcome.unwrap_err();
            assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
            assert_eq!(count_of(db, &subject, &property).await, 0);
        }
    }
}

#[actix_rt::test]
async fn a_chain_that_may_not_spend_secrets_never_runs_an_app_that_declares_them() {
    let w = World::new("host_abi_chain_without_secrets").await;
    let db = &*w.db;
    // The counter declares a secret; the caller (no secrets) reaches it.
    let mut manifest: Json = serde_json::from_str(COUNTER_MANIFEST).unwrap();
    manifest["secrets"] = json!([{ "name": "token", "origin": "https://api.example.com" }]);
    let counter = install(&w.f, "counter", &manifest.to_string(), COUNTER_WASM).await;
    let _caller = install(&w.f, "caller", CALLER_MANIFEST, CALLER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let args = json!({"subject": subject, "property": property});

    // The owner may write the drive, so the per-hop rights check passes.
    let err = w
        .call_within(
            CALLER,
            "bump-twice",
            args.clone(),
            owner(db),
            Arc::new(CallBudget::default().without_secrets()),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // Without the restriction the same call runs.
    let ok = w
        .call_within(
            CALLER,
            "bump-twice",
            args,
            owner(db),
            Arc::new(CallBudget::default()),
        )
        .await
        .unwrap();
    assert_eq!(ok, json!({"count": 2}));
}

/// Runs `source` as a QuickJS run plugin of the fixture, as `caller`, with the
/// ABI of [`super::JsAbi`]. Returns its verdict.
async fn run_js(w: &World, caller: ForAgent, budget: Option<CallBudget>, source: &str) -> Json {
    use crate::plugins::{host_abi::JsAbi, js_runtime::StoreHost};
    let manifest = crate::plugins::manifest::Manifest::parse(json!({
        "schemaVersion": 2,
        "uses": [COUNTER],
    }))
    .unwrap();
    let host = StoreHost {
        db: w.db.clone(),
        plugin: w.f.plugin.clone(),
        drive: w.f.drive.clone(),
        for_agent: caller,
        manifest,
    };
    let mut abi = JsAbi::new(host, w.registry.clone());
    if let Some(budget) = budget {
        abi = abi.with_budget(budget);
    }
    let verdict = crate::plugins::js_runtime::embedded_runtime()
        .unwrap()
        .run(source, r#"{"trigger":{"kind":"manual","at":1}}"#, abi)
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&verdict).unwrap()
}

fn bump(subject: &str, property: &str) -> String {
    format!(
        r#"export function run() {{
          const code = (f) => {{ try {{ f(); return null; }} catch (e) {{ return e.code; }} }};
          const args = {{ subject: "{subject}", property: "{property}" }};
          return {{
            intents: [],
            denied: code(() => calls.call("{COUNTER}", "increment", args)),
            undeclared: code(() => calls.call("atomic:other/x@1", "f", {{}})),
            applies: code(() => store.apply([])),
            read: store.get("{subject}").subject,
            exports: calls.describe("{COUNTER}").map((e) => e.function + ":" + e.effect),
          }};
        }}"#
    )
}

#[actix_rt::test]
async fn a_run_plugin_calls_an_export_of_an_app_and_gets_the_result() {
    let mut w = World::new("host_abi_js_calls").await;
    crate::plugins::test_fixture::write_plugin(&mut w.f, "Runner").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    // The default budget of a run is reads only: an export that writes is
    // forbidden, with the ABI's code, and the other functions answer as the
    // ABI does.
    let verdict = run_js(&w, owner(db), None, &bump(&subject, &property)).await;
    assert_eq!(verdict["denied"], code::FORBIDDEN, "{verdict}");
    assert_eq!(verdict["undeclared"], code::FORBIDDEN, "{verdict}");
    assert_eq!(verdict["applies"], code::NEEDS_APPROVAL, "{verdict}");
    assert_eq!(verdict["read"], subject.as_str(), "{verdict}");
    assert_eq!(verdict["exports"], json!(["increment:write"]), "{verdict}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // With the effect allowed the call goes through `call_export`, as the
    // owner and the counter's own agent, and the result comes back.
    let source = format!(
        r#"export function run() {{
          return {{ intents: [], result: calls.call("{COUNTER}", "increment", {{ subject: "{subject}", property: "{property}" }}) }};
        }}"#
    );
    let verdict = run_js(&w, owner(db), Some(CallBudget::default()), &source).await;
    assert_eq!(verdict["result"], json!({"count": 1}), "{verdict}");
    assert_eq!(count_of(db, &subject, &property).await, 1);
}

#[actix_rt::test]
async fn a_reader_cannot_cause_a_write_through_a_run_plugin() {
    let mut w = World::new("host_abi_js_reader").await;
    crate::plugins::test_fixture::write_plugin(&mut w.f, "Runner").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    let reader = atomic_lib::agents::Agent::new(None)
        .unwrap()
        .subject
        .to_string();
    // The reader may even write the one resource, but not the drive.
    share(
        db,
        &subject,
        &[&counter.agent, &reader],
        &[&counter.agent, &reader],
    )
    .await;

    // Even with a budget that allows writes: `call_export` asks for write on
    // the drive at this hop, of the person who ran the plugin.
    let source = format!(
        r#"export function run() {{
          try {{ calls.call("{COUNTER}", "increment", {{ subject: "{subject}", property: "{property}" }}); }}
          catch (e) {{ return {{ intents: [], code: e.code }}; }}
          return {{ intents: [], code: "wrote" }};
        }}"#
    );
    let verdict = run_js(
        &w,
        ForAgent::AgentSubject(reader.into()),
        Some(CallBudget::default()),
        &source,
    )
    .await;

    assert_eq!(verdict["code"], code::FORBIDDEN, "{verdict}");
    assert_eq!(count_of(db, &subject, &property).await, 0);
}

// -- scopes -----------------------------------------------------------------

fn subtrees(roots: &[&str]) -> Value {
    Value::ResourceArray(roots.iter().map(|r| (*r).into()).collect())
}

/// A folder `docs` with a counted resource in it, and one outside it.
async fn inside_and_outside(w: &World) -> (String, String, String, String) {
    let db = &*w.db;
    let (outside, property) = counter_resource(&w.f).await;
    let docs = genesis(
        db,
        vec![
            (urls::IS_A, Value::ResourceArray(vec![urls::FOLDER.into()])),
            (urls::PARENT, Value::AtomicUrl(w.f.drive.as_str().into())),
            (urls::NAME, Value::String("docs".into())),
        ],
    )
    .await;
    let inside = genesis(
        db,
        vec![
            (urls::PARENT, Value::AtomicUrl(docs.as_str().into())),
            (urls::NAME, Value::String("In docs".into())),
            (property.as_str(), Value::Integer(0)),
        ],
    )
    .await;
    (docs, inside, outside, property)
}

/// A read scope is a subtree: the app reads inside it, and nowhere else, even
/// when something outside it was shared with the app's agent by hand.
#[actix_rt::test]
async fn a_read_scope_limits_reads_to_its_subtree() {
    let w = World::new("host_abi_read_scope").await;
    let db = &*w.db;
    let (docs, inside, outside, _) = inside_and_outside(&w).await;
    let app = install_scoped(
        &w.f,
        "counter",
        COUNTER_MANIFEST,
        COUNTER_WASM,
        vec![(urls::READ_SCOPE, subtrees(&[&docs]))],
    )
    .await;

    let mut state = w.state(&app, owner(db)).await;
    // Activation put the agent on `docs`, which the resource inherits.
    assert_eq!(state.get(inside.clone()).await.unwrap().subject, inside);
    let err = state.get(outside.clone()).await.unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");

    // Rights the agent has by hand do not widen the scope.
    share(db, &outside, &[&app.agent], &[]).await;
    let err = state.get(outside.clone()).await.unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert!(err.message.contains("read scope"), "{err:?}");

    // Nor do queries see it.
    let list = |parent: &str| QuerySpec {
        class: None,
        parent: Some(parent.to_string()),
        filters: vec![],
        sort_by: None,
        sort_desc: false,
        limit: Some(50),
        cursor: None,
        with_resources: false,
    };
    let page = state.query(list(&docs)).await.unwrap();
    assert!(page.subjects.contains(&inside), "{page:?}");
    let page = state.query(list(&w.f.drive)).await.unwrap();
    assert!(page.subjects.contains(&docs), "{page:?}");
    assert!(!page.subjects.contains(&outside), "{page:?}");
}

/// A write scope permits a write inside it. Outside it nothing is written,
/// whatever the agent holds: the plan is kept as a proposal, as for any write
/// the app's agent may not make.
#[actix_rt::test]
async fn a_write_scope_limits_writes_to_its_subtree() {
    let w = World::new("host_abi_write_scope").await;
    let db = &*w.db;
    let (docs, inside, outside, property) = inside_and_outside(&w).await;
    let app = install_scoped(
        &w.f,
        "counter",
        COUNTER_MANIFEST,
        COUNTER_WASM,
        vec![(urls::WRITE_SCOPE, subtrees(&[&docs]))],
    )
    .await;
    share(db, &outside, &[], &[&app.agent]).await;

    let mut state = w.state(&app, owner(db)).await;
    let applied = state
        .apply(vec![set(&inside, &property, WitValue::Integer(5))])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Committed, "{applied:?}");
    assert_eq!(count_of(db, &inside, &property).await, 5);

    let applied = state
        .apply(vec![set(&outside, &property, WitValue::Integer(5))])
        .await
        .unwrap();
    assert_eq!(applied.outcome, Outcome::Proposed, "{applied:?}");
    assert!(
        applied
            .problems
            .iter()
            .any(|p| p.message.contains("write scope")),
        "{applied:?}"
    );
    assert_eq!(count_of(db, &outside, &property).await, 0);
}

/// An interface scope limits `calls` on top of the manifest's `uses`.
#[actix_rt::test]
async fn a_call_scope_limits_the_interfaces_an_app_may_call() {
    let w = World::new("host_abi_call_scope").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let caller = install_scoped(
        &w.f,
        "caller",
        CALLER_MANIFEST,
        CALLER_WASM,
        vec![(
            urls::CALL_SCOPE,
            Value::Json(json!(["atomic:example/other@1"])),
        )],
    )
    .await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    let args = json!({"subject": subject, "property": property});

    let err = w
        .call(CALLER, "bump-twice", args.clone(), owner(db))
        .await
        .unwrap_err();
    assert_eq!(err.code, code::FORBIDDEN, "{err:?}");
    assert!(err.message.contains("call scope"), "{err:?}");
    assert_eq!(count_of(db, &subject, &property).await, 0);

    // Scoped to the interface it uses, the same call goes through.
    let mut installation = db
        .get_resource(&caller.installation.as_str().into())
        .await
        .unwrap();
    installation
        .set_unsafe(urls::CALL_SCOPE.into(), Value::Json(json!([COUNTER])))
        .unwrap();
    installation.save(db).await.unwrap();
    let result = w.call(CALLER, "bump-twice", args, owner(db)).await.unwrap();
    assert_eq!(result, json!({"count": 2}));
}

/// A scope must name something that exists. (That it is in the drive and the
/// installer may write it is checked with the hierarchy's own `check_write`.)
#[actix_rt::test]
async fn a_scope_must_name_something_that_exists() {
    let w = World::new("host_abi_scope_bounds").await;
    let (_, inside, _, _) = inside_and_outside(&w).await;
    let attempt = |root: String| {
        let w = &w;
        async move {
            try_install_scoped(
                &w.f,
                "counter",
                COUNTER_MANIFEST,
                COUNTER_WASM,
                vec![(urls::READ_SCOPE, subtrees(&[&root]))],
            )
            .await
        }
    };
    let err = attempt("did:ad:nothing".into()).await.err().unwrap();
    assert!(err.contains("cannot be read"), "{err}");
    assert!(attempt(inside).await.is_ok());
}

const WORK: &str = "https://atomicdata.dev/work/v1";

/// The counter, declaring the schema it uses: a shared vocabulary and a small
/// ontology of its own, which two of its fields point into.
fn counter_with_schema(vocabulary: &str) -> String {
    let mut manifest: Json = serde_json::from_str(COUNTER_MANIFEST).unwrap();
    manifest["schema"] = json!({
        "vocabularies": [vocabulary],
        "ontology": {
            "shortname": "counting",
            "classes": [{
                "shortname": "counter",
                "properties": [{"shortname": "counted", "datatype": urls::ATOMIC_URL}],
            }],
        },
    });
    let fields = &mut manifest["exports"][0]["inputSchema"]["properties"];
    fields["subject"]["property"] = json!(format!("{vocabulary}/project"));
    fields["property"]["property"] = json!("counted");
    manifest.to_string()
}

async fn ontology_of(f: &Fixture, shortname: &str) -> Option<String> {
    atomic_lib::import_identity::find_existing(
        &f.appstate.store,
        &f.drive.as_str().into(),
        &format!("schema:ontology:{shortname}"),
    )
    .await
    .unwrap()
}

#[actix_rt::test]
async fn installing_an_app_makes_its_declared_schema_real_and_a_second_app_reuses_it() {
    let w = World::new("host_abi_app_schema").await;
    let db = &*w.db;
    assert!(ontology_of(&w.f, "counting").await.is_none());

    let manifest = counter_with_schema(WORK);
    install(&w.f, "counter", &manifest, COUNTER_WASM).await;
    let ontology = ontology_of(&w.f, "counting")
        .await
        .expect("ontology created");
    let resource = db.get_resource(&ontology.as_str().into()).await.unwrap();
    assert!(resource
        .get(urls::IS_A)
        .unwrap()
        .to_subjects(None)
        .unwrap()
        .contains(&urls::ONTOLOGY.to_string()));
    // An ordinary class and a content-addressed property, not a private format.
    let classes = resource
        .get(urls::CLASSES)
        .unwrap()
        .to_subjects(None)
        .unwrap();
    let properties = resource
        .get(urls::PROPERTIES)
        .unwrap()
        .to_subjects(None)
        .unwrap();
    assert_eq!((classes.len(), properties.len()), (1, 1));
    assert!(properties[0].starts_with("atomic:prop:"), "{properties:?}");

    // A second app that declares the same schema finds the same resources.
    let mut second: Json = serde_json::from_str(&manifest).unwrap();
    second["name"] = json!("counter-b");
    install(&w.f, "counter-b", &second.to_string(), COUNTER_WASM).await;
    assert_eq!(ontology_of(&w.f, "counting").await, Some(ontology.clone()));
    let again = db.get_resource(&ontology.as_str().into()).await.unwrap();
    assert_eq!(
        again
            .get(urls::PROPERTIES)
            .unwrap()
            .to_subjects(None)
            .unwrap(),
        properties
    );
    assert_eq!(
        again.get(urls::CLASSES).unwrap().to_subjects(None).unwrap(),
        classes
    );
    // The shared vocabulary is referenced where it lives, never copied here.
    assert!(db.get_resource(&WORK.into()).await.is_ok());
    assert!(ontology_of(&w.f, "work").await.is_none());
}

#[actix_rt::test]
async fn an_installation_that_is_refused_leaves_no_schema_behind() {
    let w = World::new("host_abi_refused_schema").await;
    install(&w.f, "counter", &counter_with_schema(WORK), COUNTER_WASM).await;

    // The same name on the same drive is refused, after its release resolved
    // and its schema checked out. Nothing of that schema is written.
    let mut other: Json = serde_json::from_str(&counter_with_schema(WORK)).unwrap();
    other["schema"]["ontology"]["shortname"] = json!("refused");
    let err = try_install_scoped(
        &w.f,
        "counter",
        &other.to_string(),
        COUNTER_WASM,
        Vec::new(),
    )
    .await
    .err()
    .unwrap();
    assert!(err.contains("already installed"), "{err}");
    assert!(ontology_of(&w.f, "refused").await.is_none());
}

#[actix_rt::test]
async fn a_vocabulary_that_does_not_exist_refuses_the_install() {
    let w = World::new("host_abi_app_schema_missing").await;
    let manifest = counter_with_schema("https://atomicdata.dev/nothing/v1");
    let err = try_install_scoped(&w.f, "counter", &manifest, COUNTER_WASM, Vec::new())
        .await
        .err()
        .unwrap();
    assert!(err.contains("is not an ontology"), "{err}");
}

#[actix_rt::test]
async fn arguments_are_checked_against_the_datatype_of_the_property_they_reference() {
    let w = World::new("host_abi_app_schema_values").await;
    let db = &*w.db;
    let counter = install(&w.f, "counter", &counter_with_schema(WORK), COUNTER_WASM).await;
    let (subject, property) = counter_resource(&w.f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    // Both are strings, so the JSON shape passes; neither is an AtomicUrl.
    for bad in [
        json!({"subject": "not a url", "property": property}),
        json!({"subject": subject, "property": "not a url"}),
    ] {
        let err = w
            .call(COUNTER, "increment", bad.clone(), owner(db))
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_ARGUMENT, "{bad}: {err:?}");
        assert!(err.message.contains("is not valid for"), "{err:?}");
    }
    assert_eq!(count_of(db, &subject, &property).await, 0);

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
