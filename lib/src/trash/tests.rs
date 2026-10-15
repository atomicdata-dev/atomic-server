use ntest::timeout;

use super::*;
use crate::{agents::ForAgent, collections::CollectionBuilder, Db, Storelike};

async fn setup(label: &str) -> (Db, String) {
    let store = Db::init_temp(&format!("trash_{label}_{}", crate::utils::random_string(6)))
        .await
        .unwrap();
    let (_agent, drive) = store.setup("Trasher").await.unwrap();
    (store, drive)
}

async fn folder(store: &Db, parent: &str, name: &str) -> String {
    store
        .create_resource(urls::FOLDER, parent, name, None)
        .await
        .unwrap()
}

async fn get(store: &Db, subject: &str) -> Resource {
    store.get_resource(&Subject::from(subject)).await.unwrap()
}

fn prop(resource: &Resource, property: &str) -> Option<String> {
    resource.get(property).ok().map(|v| v.to_string())
}

#[tokio::test]
#[timeout(120000)]
async fn trash_reparents_remembers_the_old_parent_and_restore_undoes_it() {
    let (store, drive) = setup("roundtrip").await;
    let home = folder(&store, &drive, "Home").await;
    let item = folder(&store, &home, "Item").await;

    assert_eq!(peek_trash_folder(&store, &drive), None);
    assert!(trash(&store, &item, &drive).await.unwrap());

    let trash_folder = peek_trash_folder(&store, &drive).expect("trash folder is created");
    let moved = get(&store, &item).await;
    assert_eq!(
        prop(&moved, urls::PARENT).as_deref(),
        Some(trash_folder.as_str())
    );
    assert_eq!(
        prop(&moved, urls::TRASHED_FROM).as_deref(),
        Some(home.as_str())
    );
    assert!(is_trashed(&store, &moved, &drive, false));
    assert!(is_subject_trashed(&store, &item, &drive, true));

    let trash_resource = get(&store, &trash_folder).await;
    assert_eq!(prop(&trash_resource, urls::NAME).as_deref(), Some("Trash"));
    assert_eq!(
        prop(&trash_resource, urls::PARENT).as_deref(),
        Some(drive.as_str())
    );

    restore(&store, &item, &drive).await.unwrap();
    let back = get(&store, &item).await;
    assert_eq!(prop(&back, urls::PARENT).as_deref(), Some(home.as_str()));
    assert_eq!(prop(&back, urls::TRASHED_FROM), None);
    assert!(!is_trashed(&store, &back, &drive, true));
}

#[tokio::test]
#[timeout(120000)]
async fn trash_is_a_noop_for_the_trash_itself_the_drive_and_items_already_in_it() {
    let (store, drive) = setup("noop").await;
    let item = folder(&store, &drive, "Item").await;
    assert!(trash(&store, &item, &drive).await.unwrap());
    let trash_folder = peek_trash_folder(&store, &drive).unwrap();

    assert!(
        !trash(&store, &item, &drive).await.unwrap(),
        "already in trash"
    );
    assert!(
        !trash(&store, &trash_folder, &drive).await.unwrap(),
        "the trash itself"
    );
    assert!(
        !trash(&store, &drive, &drive).await.unwrap(),
        "the drive itself"
    );

    // The second trash must not have clobbered the remembered parent.
    let moved = get(&store, &item).await;
    assert_eq!(
        prop(&moved, urls::TRASHED_FROM).as_deref(),
        Some(drive.as_str())
    );
    // One trash folder only.
    assert_eq!(peek_trash_folder(&store, &drive).unwrap(), trash_folder);
}

#[tokio::test]
#[timeout(120000)]
async fn trash_refuses_a_content_addressed_property() {
    let (store, drive) = setup("prop").await;
    let property = format!("atomic:prop:{}", "a".repeat(64));
    let err = trash(&store, &property, &drive).await.unwrap_err();
    assert!(
        err.to_string().contains("can't be moved to the trash"),
        "{err}"
    );
    assert_eq!(
        peek_trash_folder(&store, &drive),
        None,
        "nothing was created"
    );
}

#[tokio::test]
#[timeout(120000)]
async fn restore_falls_back_to_the_drive_when_the_old_parent_is_gone() {
    let (store, drive) = setup("fallback").await;
    let home = folder(&store, &drive, "Home").await;
    let item = folder(&store, &home, "Item").await;
    assert!(trash(&store, &item, &drive).await.unwrap());

    // Destroy the old parent. The item lives in the trash, so it survives.
    get(&store, &home).await.destroy(&store).await.unwrap();

    restore(&store, &item, &drive).await.unwrap();
    let back = get(&store, &item).await;
    assert_eq!(prop(&back, urls::PARENT).as_deref(), Some(drive.as_str()));
    assert_eq!(prop(&back, urls::TRASHED_FROM), None);
}

#[tokio::test]
#[timeout(120000)]
async fn restore_without_a_remembered_parent_goes_to_the_drive() {
    let (store, drive) = setup("noorigin").await;
    let item = folder(&store, &drive, "Item").await;
    assert!(trash(&store, &item, &drive).await.unwrap());
    let mut moved = get(&store, &item).await;
    moved.remove_propval(urls::TRASHED_FROM).unwrap();
    moved.save(&store).await.unwrap();

    restore(&store, &item, &drive).await.unwrap();
    assert_eq!(
        prop(&get(&store, &item).await, urls::PARENT).as_deref(),
        Some(drive.as_str())
    );
}

#[tokio::test]
#[timeout(120000)]
async fn is_trashed_is_direct_by_default_and_walks_ancestors_when_deep() {
    let (store, drive) = setup("deep").await;
    let outer = folder(&store, &drive, "Outer").await;
    let inner = folder(&store, &outer, "Inner").await;
    let leaf = folder(&store, &inner, "Leaf").await;
    let elsewhere = folder(&store, &drive, "Elsewhere").await;

    // No trash folder yet: nothing is trashed.
    let leaf_res = get(&store, &leaf).await;
    assert!(!is_trashed(&store, &leaf_res, &drive, true));

    assert!(trash(&store, &outer, &drive).await.unwrap());

    let leaf_res = get(&store, &leaf).await;
    assert!(
        !is_trashed(&store, &leaf_res, &drive, false),
        "direct parent only"
    );
    assert!(is_trashed(&store, &leaf_res, &drive, true));
    assert!(is_trashed(&store, &get(&store, &inner).await, &drive, true));
    assert!(!is_trashed(
        &store,
        &get(&store, &elsewhere).await,
        &drive,
        true
    ));
    // The trash folder and the drive are not themselves trashed.
    let trash_folder = peek_trash_folder(&store, &drive).unwrap();
    assert!(!is_trashed(
        &store,
        &get(&store, &trash_folder).await,
        &drive,
        true
    ));
    assert!(!is_trashed(
        &store,
        &get(&store, &drive).await,
        &drive,
        true
    ));
}

#[tokio::test]
#[timeout(120000)]
async fn is_trashed_survives_parent_cycles() {
    let (store, drive) = setup("cycle").await;
    let a = folder(&store, &drive, "A").await;
    let b = folder(&store, &a, "B").await;
    // A -> B -> A, a cycle that never reaches the trash. (Hierarchy checks run
    // in `save`; `add_resource` writes it as-is, like a corrupt synced store.)
    let _ = trash(&store, &folder(&store, &drive, "Seed").await, &drive)
        .await
        .unwrap();
    let mut a_res = get(&store, &a).await;
    a_res
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(b.as_str().into()))
        .unwrap();
    store.add_resource(&a_res).await.unwrap();

    assert!(!is_trashed(&store, &get(&store, &a).await, &drive, true));
    assert!(!is_trashed(&store, &get(&store, &b).await, &drive, true));
}

#[tokio::test]
#[timeout(120000)]
async fn a_stale_trash_pointer_is_replaced_but_a_live_one_is_kept() {
    let (store, drive) = setup("stale").await;
    let first = get_or_create_trash_folder(&store, &drive).await.unwrap();
    assert_eq!(
        get_or_create_trash_folder(&store, &drive).await.unwrap(),
        first
    );

    get(&store, &first).await.destroy(&store).await.unwrap();
    let second = get_or_create_trash_folder(&store, &drive).await.unwrap();
    assert_ne!(second, first);
    assert_eq!(peek_trash_folder(&store, &drive).unwrap(), second);
}

fn builder(parent: &str, drive: &str, include_trashed: bool) -> CollectionBuilder {
    CollectionBuilder {
        subject: "test_subject".into(),
        property: Some(urls::PARENT.into()),
        value: Some(parent.into()),
        filters: Vec::new(),
        sort_by: None,
        sort_desc: false,
        page_size: 50,
        current_page: 0,
        name: None,
        include_nested: false,
        include_external: false,
        include_trashed,
        drive: Some(Subject::from(drive)),
        aggregation: None,
        expression_filters: Vec::new(),
    }
}

async fn members(store: &Db, builder: CollectionBuilder, agent: &ForAgent) -> Vec<String> {
    let mut found = crate::collections::Collection::collect_members(store, builder, agent)
        .await
        .unwrap()
        .members;
    found.sort();
    found
}

#[tokio::test]
#[timeout(120000)]
async fn collections_hide_trashed_members_unless_asked_or_viewing_the_trash() {
    let (store, drive) = setup("collection").await;
    let keep = folder(&store, &drive, "Keep").await;
    let gone = folder(&store, &drive, "Gone").await;
    let gone_child = folder(&store, &gone, "Gone child").await;
    assert!(trash(&store, &gone, &drive).await.unwrap());
    let trash_folder = peek_trash_folder(&store, &drive).unwrap();

    for agent in [
        ForAgent::Sudo,
        ForAgent::AgentSubject(store.get_default_agent().unwrap().subject),
    ] {
        // The drive's children: the trash folder and `keep` stay, `gone` is hidden.
        let listed = members(&store, builder(&drive, &drive, false), &agent).await;
        assert!(listed.contains(&keep), "{listed:?}");
        assert!(
            listed.contains(&trash_folder),
            "the trash folder itself stays listed"
        );
        assert!(!listed.contains(&gone), "{listed:?}");

        // Opted in: everything, as before. (`gone` is no longer a child of the
        // drive, so look at the trash through `include_trashed` on a class query.)
        let mut all = builder(urls::FOLDER, &drive, true);
        all.property = Some(urls::IS_A.into());
        let everything = members(&store, all, &agent).await;
        assert!(
            everything.contains(&gone) && everything.contains(&gone_child),
            "{everything:?}"
        );

        // The same class listing hides trashed items, and items under them.
        let mut hidden = builder(urls::FOLDER, &drive, false);
        hidden.property = Some(urls::IS_A.into());
        let visible = members(&store, hidden, &agent).await;
        assert!(
            visible.contains(&keep) && visible.contains(&trash_folder),
            "{visible:?}"
        );
        assert!(
            !visible.contains(&gone) && !visible.contains(&gone_child),
            "{visible:?}"
        );

        // The Trash view: children of the trash folder are shown by default...
        let view = members(&store, builder(&trash_folder, &drive, false), &agent).await;
        assert_eq!(view, vec![gone.clone()]);
        // ...and so are the children of something inside it.
        let inside = members(&store, builder(&gone, &drive, false), &agent).await;
        assert_eq!(inside, vec![gone_child.clone()]);
    }
}

/// The browser's local DB (`wasm` `ClientDb.query`) builds a bare [`Query`] and
/// sets `exclude_trashed` from its `includeTrashed` argument, so the rule has
/// to hold on that path and not only through `Collection::collect_members`.
/// (The wasm crate has no native test target; this builds the same query.)
#[tokio::test]
#[timeout(120000)]
async fn a_bare_query_hides_trashed_rows_the_way_the_wasm_path_builds_it() {
    let (store, drive) = setup("bare_query").await;
    let keep = folder(&store, &drive, "Keep").await;
    let gone = folder(&store, &drive, "Gone").await;
    assert!(trash(&store, &gone, &drive).await.unwrap());
    let trash_folder = peek_trash_folder(&store, &drive).unwrap();

    let run = |exclude_trashed: bool, parent: Option<&str>| {
        let store = &store;
        let drive = &drive;
        let mut q = Query::new_prop_val(urls::IS_A, urls::FOLDER);
        if let Some(parent) = parent {
            q = Query::new_prop_val(urls::PARENT, parent);
        }
        q.include_nested = false;
        q.drive = Some(Subject::from(drive.as_str()));
        q.exclude_trashed = exclude_trashed;
        async move {
            let mut found: Vec<String> = store
                .query(&q)
                .await
                .unwrap()
                .subjects
                .iter()
                .map(|s| s.to_string())
                .collect();
            found.sort();
            found
        }
    };

    let hidden = run(true, None).await;
    assert!(hidden.contains(&keep), "{hidden:?}");
    assert!(!hidden.contains(&gone), "{hidden:?}");

    let all = run(false, None).await;
    assert!(all.contains(&keep) && all.contains(&gone), "{all:?}");

    // The Trash view is exempt even when exclusion is on.
    let view = run(true, Some(&trash_folder)).await;
    assert_eq!(view, vec![gone.clone()]);
}
