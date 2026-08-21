//! A drive with the plugin vocabulary on it, for tests that need one.
//!
//! The browser creates this through `ensureSchema`; here it is built by hand,
//! because what these tests exercise is what the *server* does with a drive
//! that already has one. Shared between the scheduler and the trigger
//! listener, which need the same drive and would otherwise each grow their own
//! slightly different copy of it.

use std::collections::HashMap;

use atomic_lib::{urls, Db, Resource, Storelike, Value};

use crate::appstate::AppState;
use crate::plugins::scheduler::DriveTerms;

/// A drive with the plugin vocabulary on it.
///
/// The browser creates this through `ensureSchema`; here it is built by
/// hand, because the thing under test is what the server does with a drive
/// that already has one.
///
/// Everything is created through a genesis commit, the way a real drive
/// does it: a fresh server's drive is a DID, and resources under it are
/// identified by signature rather than by path.
pub struct Fixture {
    pub appstate: AppState,
    pub drive: String,
    pub plugin: String,
    pub terms: DriveTerms,
}

/// Creates a resource under a DID parent and returns the subject it got.
pub async fn genesis(store: &Db, propvals: Vec<(&str, Value)>) -> String {
    let mut resource = Resource::new("did:ad:placeholder".into());

    for (property, value) in propvals {
        resource.set_unsafe(property.into(), value).unwrap();
    }

    resource.save_as_genesis(store).await.unwrap();

    resource.get_subject().to_string()
}

pub async fn fixture(name: &str) -> Fixture {
    use clap::Parser;

    let unique = format!("{name}_{}", atomic_lib::utils::random_string(10));
    let opts = crate::config::Opts::parse_from([
        "atomic-server",
        "--initialize",
        "--data-dir",
        &format!("./.temp/{unique}/db"),
        "--config-dir",
        &format!("./.temp/{unique}/config"),
    ]);

    let mut config = crate::config::build_config(opts).unwrap();
    config.search_index_path = format!("./.temp/{unique}/search").into();
    config.vector_search_index_path = format!("./.temp/{unique}/vector").into();

    let appstate = AppState::init(config).await.unwrap();
    let store = appstate.store.clone();
    atomic_lib::test_utils::setup_test_env(&store)
        .await
        .unwrap();

    let drive = store
        .get_drive_did("localhost")
        .await
        .unwrap()
        .expect("the test env maps localhost to a drive")
        .to_string();

    let ontology = genesis(
        &store,
        vec![
            (
                urls::IS_A,
                Value::ResourceArray(vec![urls::ONTOLOGY.into()]),
            ),
            (urls::PARENT, Value::AtomicUrl(drive.as_str().into())),
            (urls::SHORTNAME, Value::Slug("plugins".into())),
            (urls::DESCRIPTION, Value::Markdown("Plugins".into())),
        ],
    )
    .await;

    let mut terms = DriveTerms {
        properties: HashMap::new(),
        classes: HashMap::new(),
    };
    let mut properties = Vec::new();

    for (shortname, datatype) in [
        ("plugin-source", urls::MARKDOWN),
        ("trigger", urls::STRING),
        ("started-at", urls::TIMESTAMP),
        ("run-status", urls::STRING),
        ("run-problems", urls::JSON),
        ("run-outcomes", urls::JSON),
        ("run-cursor", urls::STRING),
    ] {
        let subject = genesis(
            &store,
            vec![
                (
                    urls::IS_A,
                    Value::ResourceArray(vec![urls::PROPERTY.into()]),
                ),
                (urls::PARENT, Value::AtomicUrl(ontology.as_str().into())),
                (urls::SHORTNAME, Value::Slug(shortname.to_string())),
                (urls::DESCRIPTION, Value::Markdown(shortname.to_string())),
                (urls::DATATYPE_PROP, Value::AtomicUrl(datatype.into())),
            ],
        )
        .await;

        terms
            .properties
            .insert(shortname.to_string(), subject.clone());
        properties.push(subject.into());
    }

    let mut classes = Vec::new();

    for shortname in ["plugin-script", "plugin-run"] {
        let subject = genesis(
            &store,
            vec![
                (urls::IS_A, Value::ResourceArray(vec![urls::CLASS.into()])),
                (urls::PARENT, Value::AtomicUrl(ontology.as_str().into())),
                (urls::SHORTNAME, Value::Slug(shortname.to_string())),
                (urls::DESCRIPTION, Value::Markdown(shortname.to_string())),
            ],
        )
        .await;

        terms.classes.insert(shortname.to_string(), subject.clone());
        classes.push(subject.into());
    }

    let mut ontology_resource = store.get_resource(&ontology.as_str().into()).await.unwrap();
    ontology_resource
        .set_unsafe(urls::PROPERTIES.into(), Value::ResourceArray(properties))
        .unwrap();
    ontology_resource
        .set_unsafe(urls::CLASSES.into(), Value::ResourceArray(classes))
        .unwrap();
    ontology_resource.save(&store).await.unwrap();

    let mut drive_resource = store.get_resource(&drive.as_str().into()).await.unwrap();
    drive_resource
        .set_unsafe(
            urls::DEFAULT_ONTOLOGY.into(),
            Value::AtomicUrl(ontology.as_str().into()),
        )
        .unwrap();
    drive_resource.save(&store).await.unwrap();

    Fixture {
        appstate,
        drive,
        plugin: String::new(),
        terms,
    }
}

/// A plugin whose every run proposes one new resource with this name.
pub async fn write_plugin(fixture: &mut Fixture, creates: &str) {
    let source = format!(
        r#"export function run(ctx) {{
            return {{ intents: [{{ op: 'create', localId: 'made',
                parent: {:?}, isA: [],
                set: {{ "https://atomicdata.dev/properties/name": {creates:?} }} }}] }};
        }}"#,
        fixture.drive,
    );

    fixture.plugin = genesis(
        &fixture.appstate.store,
        vec![
            (
                urls::IS_A,
                Value::ResourceArray(vec![fixture.terms.class("plugin-script").unwrap().into()]),
            ),
            (
                urls::PARENT,
                Value::AtomicUrl(fixture.drive.as_str().into()),
            ),
            (urls::NAME, Value::String("Importer".into())),
            (
                fixture.terms.property("plugin-source").unwrap(),
                Value::Markdown(source),
            ),
        ],
    )
    .await;
}

pub async fn children_named(fixture: &Fixture, parent: &str, name: &str) -> usize {
    fixture
        .appstate
        .store
        .get_resource(&parent.into())
        .await
        .unwrap()
        .get_children(&fixture.appstate.store)
        .await
        .unwrap()
        .iter()
        .filter(|child| {
            child
                .get(urls::NAME)
                .is_ok_and(|value| value.to_string() == name)
        })
        .count()
}
