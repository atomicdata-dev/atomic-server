//! Server modules end to end: a real component (`plugin-examples/host-abi-module`,
//! prebuilt into `testdata/host-abi/module.wasm`), installed through the same
//! Installation path a class extender always took, in a temporary store.

use std::io::Write;

use atomic_lib::{
    agents::ForAgent, db::app_agent::AppAgentKey, urls, Db, Resource, Storelike, Value,
};
use serde_json::json;

use super::tests::{
    count_of, counter_resource, install as install_app, share, COUNTER_MANIFEST, COUNTER_WASM,
};
use crate::plugins::{
    release,
    test_fixture::{fixture, genesis, Fixture},
};

const COUNTER: &str = "atomic:example/counter@1";

const MODULE_WASM: &[u8] = include_bytes!("../../../../testdata/host-abi/module.wasm");

struct Module {
    agent: String,
}

fn package(full_drive_access: bool) -> Vec<u8> {
    let permissions = if full_drive_access {
        json!([{"permission": "full-drive-access", "reason": "the module writes as its own agent"}])
    } else {
        json!([])
    };
    let plugin_json = json!({
        "name": "module",
        "namespace": "example",
        "version": "1.0.0",
        "description": "Hooks on folders",
        "author": "Ontola",
        "permissions": permissions,
    });
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("plugin.wasm", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(MODULE_WASM).unwrap();
    zip.start_file("plugin.json", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(plugin_json.to_string().as_bytes()).unwrap();
    zip.finish().unwrap().into_inner()
}

/// Installs the module in the fixture's drive, as an active Installation.
async fn install(f: &Fixture, full_drive_access: bool, config: serde_json::Value) -> Module {
    install_using(f, full_drive_access, config, &[]).await
}

/// The same, with a release that declares `uses`: `plugin.json` cannot, so the
/// translated manifest is amended before the release is published.
async fn install_using(
    f: &Fixture,
    full_drive_access: bool,
    config: serde_json::Value,
    uses: &[&str],
) -> Module {
    let db = &f.appstate.store;
    let (_, mut published, mut manifest) =
        release::publish_package(db, &package(full_drive_access), None)
            .await
            .unwrap();
    manifest.uses = uses.iter().map(|u| u.to_string()).collect();
    published.manifest = serde_json::to_value(&manifest).unwrap();
    let id = db.publish_plugin_release(&published).unwrap();
    let installation = genesis(
        db,
        vec![
            (
                urls::IS_A,
                Value::ResourceArray(vec![urls::INSTALLATION.into()]),
            ),
            (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
            (urls::NAME, Value::String("module".into())),
            (urls::NAMESPACE, Value::String("example".into())),
            (urls::RELEASE_PROP, Value::String(id.clone())),
            (urls::RELEASE_ID, Value::String(id)),
            (urls::INSTALLATION_STATUS, Value::String("active".into())),
            (
                urls::GRANTS,
                Value::Json(if full_drive_access {
                    json!(["full-drive-access"])
                } else {
                    json!([])
                }),
            ),
            (urls::CONFIG, Value::Json(config)),
        ],
    )
    .await;
    assert_eq!(db.get_class_extenders_on_drive(&f.drive).len(), 1);
    let agent = db
        .get_app_agent_info(&AppAgentKey::new(&f.drive, &installation))
        .unwrap()
        .expect("the module runs as its Installation's agent")
        .agent;
    Module { agent }
}

async fn try_folder(db: &Db, drive: &str, name: &str) -> Result<String, String> {
    let mut folder = Resource::new("did:ad:placeholder".into());
    for (property, value) in [
        (urls::IS_A, Value::ResourceArray(vec![urls::FOLDER.into()])),
        (urls::PARENT, Value::AtomicUrl(drive.into())),
        (urls::NAME, Value::String(name.into())),
    ] {
        folder.set_unsafe(property.into(), value).unwrap();
    }
    folder
        .save_as_genesis(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(folder.get_subject().to_string())
}

fn owner(db: &Db) -> ForAgent {
    ForAgent::AgentSubject(db.get_default_agent().unwrap().subject)
}

/// The description the module's `on-get` wrote on a read of `folder`.
async fn extended_description(db: &Db, folder: &str) -> String {
    db.get_resource_extended(&folder.into(), false, &owner(db))
        .await
        .unwrap()
        .to_single()
        .get(urls::DESCRIPTION)
        .expect("the module extended the resource")
        .to_string()
}

async fn plain_resource(f: &Fixture, name: &str) -> String {
    genesis(
        &f.appstate.store,
        vec![
            (urls::PARENT, Value::AtomicUrl(f.drive.as_str().into())),
            (urls::NAME, Value::String(name.into())),
        ],
    )
    .await
}

async fn name_of(db: &Db, subject: &str) -> String {
    db.get_resource(&subject.into())
        .await
        .unwrap()
        .get(urls::NAME)
        .unwrap()
        .to_string()
}

#[actix_rt::test]
async fn a_before_commit_hook_can_refuse_a_commit() {
    let f = fixture("module_refuses").await;
    let db = &f.appstate.store;
    install(&f, false, json!({})).await;

    let err = try_folder(db, &f.drive, "refuse-me").await.unwrap_err();
    assert!(err.contains("this module refuses refuse-me"), "{err}");

    // Only an error problem refuses: a warning, and any other name, go through.
    try_folder(db, &f.drive, "warn-me").await.unwrap();
    let folder = try_folder(db, &f.drive, "Fine").await.unwrap();

    // The same on an update: the refused name is never stored.
    let mut resource = db.get_resource(&folder.as_str().into()).await.unwrap();
    resource
        .set_unsafe(urls::NAME.into(), Value::String("refuse-me".into()))
        .unwrap();
    let err = resource.save(db).await.unwrap_err().to_string();
    assert!(err.contains("this module refuses refuse-me"), "{err}");
    assert_eq!(name_of(db, &folder).await, "Fine");
}

#[actix_rt::test]
async fn an_on_get_hook_extends_the_resource_a_reader_gets() {
    let f = fixture("module_extends").await;
    let db = &f.appstate.store;
    let module = install(&f, false, json!({})).await;
    let folder = try_folder(db, &f.drive, "Docs").await.unwrap();

    let note = extended_description(db, &folder).await;
    let asked_by = owner(db).to_string();
    assert!(note.contains(&format!("asked by {asked_by}")), "{note}");
    assert!(note.contains(&format!("module {}", module.agent)), "{note}");

    // Extended on the way out, not stored.
    let stored = db.get_resource(&folder.as_str().into()).await.unwrap();
    assert!(stored.get(urls::DESCRIPTION).is_err());
}

/// A module without `full-drive-access` is an agent nobody gave anything:
/// what it reads and writes is what the Installation's agent may, through the
/// same code and the same error codes as an app. It cannot read the resource,
/// so planning a write to it is refused, and nothing is stored.
#[actix_rt::test]
async fn a_module_cannot_read_or_write_beyond_its_agents_rights() {
    let f = fixture("module_rights").await;
    let db = &f.appstate.store;
    let secret = plain_resource(&f, "secret").await;
    install(
        &f,
        false,
        json!({"probeRead": secret, "probeWrite": secret}),
    )
    .await;
    let folder = try_folder(db, &f.drive, "Docs").await.unwrap();

    let note = extended_description(db, &folder).await;
    assert!(note.contains("read forbidden"), "{note}");
    assert!(note.contains("write refused"), "{note}");
    assert_eq!(name_of(db, &secret).await, "secret");
}

/// The same module with the drive granted to its agent, so the checks above
/// are about rights and not about the probes failing for another reason.
#[actix_rt::test]
async fn a_module_with_full_drive_access_reads_and_writes_as_its_agent() {
    let f = fixture("module_rights_granted").await;
    let db = &f.appstate.store;
    let target = plain_resource(&f, "target").await;
    install(&f, true, json!({"probeRead": target, "probeWrite": target})).await;
    let folder = try_folder(db, &f.drive, "Docs").await.unwrap();

    let note = extended_description(db, &folder).await;
    assert!(note.contains("read ok"), "{note}");
    assert!(note.contains("write committed"), "{note}");
    assert_eq!(name_of(db, &target).await, "overwritten");
}

fn call_counter(subject: &str, property: &str) -> serde_json::Value {
    json!({"probeCall": {
        "interface": COUNTER,
        "function": "increment",
        "args": {"subject": subject, "property": property},
    }})
}

/// `calls` from a module reaches the apps of its drive: the registry is the
/// node's, not one of its own. The export runs as its own Installation's
/// agent, and the module (the caller) may write the drive.
#[actix_rt::test]
async fn a_module_hook_calls_an_app_export_and_gets_the_result() {
    let f = fixture("module_calls").await;
    let db = &f.appstate.store;
    let counter = install_app(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;
    install_using(&f, true, call_counter(&subject, &property), &[COUNTER]).await;
    let folder = try_folder(db, &f.drive, "Docs").await.unwrap();

    let note = extended_description(db, &folder).await;
    assert!(note.contains(r#"call ok {"count":1}"#), "{note}");
    assert_eq!(count_of(db, &subject, &property).await, 1);
}

/// Without write on the drive the module may not cause a `write` export, and
/// without `uses` it may not call the interface at all. Both are `forbidden`,
/// and the counter stays where it was.
#[actix_rt::test]
async fn a_module_hook_without_the_rights_is_forbidden_to_call() {
    let f = fixture("module_calls_forbidden").await;
    let db = &f.appstate.store;
    let counter = install_app(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    install_using(&f, false, call_counter(&subject, &property), &[COUNTER]).await;
    let folder = try_folder(db, &f.drive, "Docs").await.unwrap();
    let note = extended_description(db, &folder).await;
    assert!(note.contains("call forbidden"), "{note}");
    assert_eq!(count_of(db, &subject, &property).await, 0);
}

#[actix_rt::test]
async fn a_module_that_does_not_declare_uses_cannot_call() {
    let f = fixture("module_calls_undeclared").await;
    let db = &f.appstate.store;
    let counter = install_app(&f, "counter", COUNTER_MANIFEST, COUNTER_WASM).await;
    let (subject, property) = counter_resource(&f).await;
    share(db, &subject, &[&counter.agent], &[&counter.agent]).await;

    install(&f, true, call_counter(&subject, &property)).await;
    let folder = try_folder(db, &f.drive, "Docs").await.unwrap();
    let note = extended_description(db, &folder).await;
    assert!(note.contains("call forbidden"), "{note}");
    assert_eq!(count_of(db, &subject, &property).await, 0);
}
