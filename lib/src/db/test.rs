use crate::{agents::ForAgent, urls, Subject, Value};

use super::*;
use ntest::timeout;

use std::sync::Mutex;
use tokio::sync::OnceCell;

// `#[timeout(120000)]` below: under dagger Main, nextest runs beside e2e
// Chromium shards and heavy `atomic-server::it` servers. `Db::init_temp` +
// `populate` that finish in a couple of seconds locally routinely sit
// near/past 30s on a contended Mancave run — which used to fail-fast the
// rest of the suite. 120s is the wedged-test ceiling, not the expected
// runtime. (`ntest::timeout` only accepts an integer literal.)

static DB: OnceCell<Mutex<Db>> = OnceCell::const_new();

#[tokio::test]
async fn synthetic_agent_reads_have_stable_history_without_persisting() {
    let db = Db::init_temp("synthetic_agent_read").await.unwrap();
    let agent = crate::agents::Agent::new(None).unwrap();
    let first = db.get_resource(&agent.subject).await.unwrap();
    let second = db.get_resource(&agent.subject).await.unwrap();
    assert!(first.get(urls::CREATED_AT).is_err());
    assert_eq!(
        serde_json::to_value(first.get_propvals()).unwrap(),
        serde_json::to_value(second.get_propvals()).unwrap()
    );
    assert_eq!(
        first.build_state_doc().unwrap().doc().oplog_vv(),
        second.build_state_doc().unwrap().doc().oplog_vv()
    );
    assert!(!db.has_stored_resource(&agent.subject));
}

/// A profile stored under a padded spelling of the key answers for the
/// canonical unpadded subject too, instead of an empty synthesized twin.
#[tokio::test]
async fn agent_profile_under_padded_key_answers_for_unpadded_subject() {
    let db = Db::init_temp("agent_padded_spelling").await.unwrap();
    let agent = crate::agents::Agent::new(Some("Padded")).unwrap();
    let padded = format!("{}=", agent.public_key);
    let mut stored = agent.to_resource().unwrap();
    stored.set_subject(format!("atomic:agent:{padded}"));
    stored
        .set_unsafe(urls::PUBLIC_KEY.into(), Value::String(padded.clone()))
        .unwrap();
    db.add_resource_opts(&stored, false, false, true)
        .await
        .unwrap();

    let read = db.get_resource(&agent.subject).await.unwrap();
    assert_eq!(read.get(urls::NAME).unwrap().to_string(), "Padded");
    assert_eq!(read.get_subject().to_string(), agent.subject.to_string());
}

/// Share the Db instance between tests. Otherwise, all tests try to init the same location on disk and throw errors.
/// Note that not all behavior can be properly tested with a shared database.
/// If you need a clean one, juts call init("someId").
pub async fn get_shared_db() -> &'static Mutex<Db> {
    DB.get_or_init(|| async {
        let store = Db::init_temp("shared").await.unwrap();
        crate::test_utils::setup_test_env(&store).await.unwrap();
        Mutex::new(store)
    })
    .await
}

#[tokio::test]
#[timeout(120000)]
async fn basic() {
    let store = get_shared_db().await.lock().unwrap().clone();
    // We can create a new Resource, linked to the store.
    // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
    // Let's make a new Property instance!
    let mut new_resource =
        crate::Resource::new_instance("https://atomicdata.dev/classes/Property", &store)
            .await
            .unwrap();
    // And add a description for that Property
    new_resource
        .set_shortname("description", "the age of a person", &store)
        .await
        .unwrap();
    new_resource
        .set_shortname("shortname", "age", &store)
        .await
        .unwrap();
    new_resource
        .set_shortname("datatype", crate::urls::INTEGER, &store)
        .await
        .unwrap();
    // Changes are only applied to the store after saving them explicitly.
    new_resource.save_locally(&store).await.unwrap();
    // The modified resource is saved to the store after this

    // A subject URL has been created automatically.
    let subject = new_resource.get_subject();
    let fetched_new_resource = store.get_resource(subject).await.unwrap();
    let description_val = fetched_new_resource
        .get_shortname("description", &store)
        .await
        .unwrap()
        .to_string();
    assert!(description_val == "the age of a person");

    // Try removing something
    store
        .get_resource(&crate::urls::CLASS.into())
        .await
        .unwrap();
    store
        .remove_resource(&crate::urls::CLASS.into())
        .await
        .unwrap();
    // Should throw an error, because can't remove non-existent resource
    store
        .remove_resource(&crate::urls::CLASS.into())
        .await
        .unwrap_err();
    // Should throw an error, because resource is deleted
    store.get_propvals(crate::urls::CLASS).unwrap_err();

    let all_local_resources = store.all_resources(false).count();
    let all_resources = store.all_resources(true).count();
    assert!(all_local_resources < all_resources);
}

#[tokio::test]
/// Check if a resource is properly removed from the DB after a delete command.
async fn destroy_resource_and_check_collection() {
    let store = Db::init_temp("counter").await.unwrap();
    crate::test_utils::setup_test_env(&store).await.unwrap();
    let for_agent = &ForAgent::Public;
    let agents_url = "internal:/agents".to_string();
    let agents_collection_1 = store
        .get_resource_extended(&agents_url.as_str().into(), false, for_agent)
        .await
        .unwrap();
    println!(
        "Agents collection 1: {}",
        agents_collection_1.to_json_ad(None).unwrap()
    );
    let agents_collection_count_1 = agents_collection_1
        .to_single()
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(
        agents_collection_count_1, 1,
        "There should be 1 agent in this collection initially (the agent created during init)"
    );

    // Create a new agent, check if it is added to the new Agents collection as a Member.
    let mut resource = crate::agents::Agent::new(None)
        .unwrap()
        .to_resource()
        .unwrap();
    let _res = resource.save_locally(&store).await.unwrap();
    let agents_collection_2 = store
        .get_resource_extended(&agents_url.as_str().into(), false, for_agent)
        .await
        .unwrap();
    let agents_collection_count_2 = agents_collection_2
        .to_single()
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(
        agents_collection_count_2, 2,
        "The new Agent resource did not increase the collection member count from 1 to 2."
    );

    let clone = _res.resource_new.clone().unwrap();
    let resp = _res.resource_new.unwrap().destroy(&store).await.unwrap();
    assert!(resp.resource_new.is_none());
    // Compare JSON-AD minus loroUpdate. Loro snapshots aren't byte-deterministic
    // (peer-id allocation differs per run) — the logical state is what matters.
    // Using the full to_json_ad here would compare the base64 of those snapshots
    // and flake even when the logical state is identical.
    // Compared as values, not strings: with serde_json's `preserve_order`
    // feature on (any dependency can switch it on), key order follows the
    // resource's property map, which is not stable between runs.
    fn json_ad_without_loro(r: &crate::Resource) -> serde_json::Value {
        let mut json: serde_json::Value =
            serde_json::from_str(&r.to_json_ad(None).unwrap()).unwrap();
        if let Some(obj) = json.as_object_mut() {
            obj.remove(crate::urls::LORO_UPDATE);
        }
        json
    }
    assert_eq!(
        json_ad_without_loro(resp.resource_old.as_ref().unwrap()),
        json_ad_without_loro(&clone),
        "JSON AD differs between removed resource and resource passed back from commit"
    );
    assert!(resp.resource_old.is_some());
    let agents_collection_3 = store
        .get_resource_extended(&agents_url.as_str().into(), false, for_agent)
        .await
        .unwrap();
    let agents_collection_count_3 = agents_collection_3
        .to_single()
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(
        agents_collection_count_3, 1,
        "The collection count did not decrease after destroying the resource."
    );
}

/// Regression test for stale parent-index entries leaking into `count`.
///
/// Symptom seen in the wild: a browser hit `/query?property=parent&value=<drive>`
/// and got back `totalMembers: 3` with `members: []`. The three index entries
/// pointed at resources that no longer resolved for the requesting agent —
/// destroyed, ACL-filtered, or otherwise inaccessible — but `query_basic` /
/// `query_sorted_indexed` still bumped `count` for each iter entry,
/// regardless of whether the entry survived the include_external filter
/// or whether `get_resource_extended` succeeded.
///
/// Contract under test: after destroying every resource that points
/// `parent=X`, the count for the `parent=X` query must be 0 — equal to
/// `subjects.len()`. If count drifts above subjects.len(), the parent
/// index has orphan entries that destroy didn't clean up, OR count is
/// being incremented from raw iter steps instead of returnable hits.
#[tokio::test]
async fn destroy_clears_parent_index_count() {
    let store = Db::init_temp("destroy_clears_parent_index_count")
        .await
        .unwrap();
    crate::test_utils::setup_test_env(&store).await.unwrap();

    // Use a synthetic parent subject. We don't need it to resolve as a
    // real resource — the parent-index is keyed by string value, not
    // by resource existence.
    let parent_subject = "https://example.com/parent-X";

    let mut child_subjects = Vec::new();
    for _ in 0..3 {
        let mut child = Resource::new_generate_subject(&store).unwrap();
        child
            .set(
                urls::PARENT.into(),
                Value::AtomicUrl(parent_subject.into()),
                &store,
            )
            .await
            .unwrap();
        child.save(&store).await.unwrap();
        child_subjects.push(child.get_subject().to_string());
    }

    let q = Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(parent_subject.into())),
        filters: Vec::new(),
        limit: Some(500),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: None,
        aggregation: None,
        expression_filters: Vec::new(),
    };

    let before = store.query(&q).await.unwrap();
    assert_eq!(before.count, 3, "three children indexed");
    assert_eq!(before.subjects.len(), 3, "three children returned");

    // Destroy all three. After this, the parent-index should hold no
    // entries for `parent=<parent_subject>`.
    for subject in &child_subjects {
        let mut r = store.get_resource(&subject.as_str().into()).await.unwrap();
        r.destroy(&store).await.unwrap();
    }

    let after = store.query(&q).await.unwrap();
    assert_eq!(
        after.subjects.len(),
        0,
        "no children should be returned after destroy"
    );
    assert_eq!(
        after.count, 0,
        "count must equal subjects.len() after destroy — \
         stale index entries inflate count, producing the \
         `totalMembers: 3, members: []` drift seen in the field"
    );
}

/// Companion regression test: when resources match the query filter but
/// the requesting agent isn't authorized to read them, `count` and
/// `subjects.len()` must agree. They currently don't — there's a
/// known-issue comment in the existing `queries` test (line ~408)
/// that intentionally skips this assertion, pointing at GH issue #286.
///
/// This is the actual surface of the bug observed in the field: the
/// user's server reported `totalMembers: 3, members: []` for a
/// `parent=<drive>` query. Those 3 entries weren't destroyed — they
/// were authorization-filtered, so `get_resource_extended` failed and
/// the push into `subjects` was skipped, while `count` kept marching
/// on. Once count drifts above the visible row count, the client
/// trusts the count for pagination, optimistic-add bookkeeping, and
/// (in our concrete case) keeps phantom subject DIDs in the WASM DB
/// because the count says "there's something here" but the server
/// keeps returning an empty page.
#[tokio::test]
async fn unauthorized_query_count_matches_subjects() {
    let store = Db::init_temp("unauthorized_query_count_matches_subjects")
        .await
        .unwrap();
    crate::test_utils::setup_test_env(&store).await.unwrap();

    let parent_subject = "https://example.com/parent-private";

    // Create three children. Don't set any `read` ACL — the resources
    // are only visible to Sudo / the server-internal agent, never to
    // a regular signed-in user.
    for _ in 0..3 {
        let mut child = Resource::new_generate_subject(&store).unwrap();
        child
            .set(
                urls::PARENT.into(),
                Value::AtomicUrl(parent_subject.into()),
                &store,
            )
            .await
            .unwrap();
        child.save(&store).await.unwrap();
    }

    let q = Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(parent_subject.into())),
        filters: Vec::new(),
        limit: Some(500),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        // Public agent: no ACL grants read access to the children we
        // just created, so `get_resource_extended` will fail auth on
        // each one and `subjects` will end up empty.
        for_agent: urls::PUBLIC_AGENT.into(),
        drive: None,
        aggregation: None,
        expression_filters: Vec::new(),
    };

    let res = store.query(&q).await.unwrap();

    assert_eq!(
        res.subjects.len(),
        0,
        "no subjects should be returned to an unauthorized agent"
    );
    assert_eq!(
        res.count,
        res.subjects.len(),
        "count must equal subjects.len() — count={}, subjects.len()={}. \
         Index iteration is incrementing count for entries that auth \
         filters then drop from the response, producing the \
         `totalMembers: N, members: []` drift seen in the field.",
        res.count,
        res.subjects.len(),
    );
}

async fn genesis_child(store: &Db, parent: &Subject) -> Subject {
    let mut res = Resource::new("did:ad:placeholder".into());
    res.set(urls::PARENT.into(), Value::AtomicUrl(parent.clone()), store)
        .await
        .unwrap();
    res.save_as_genesis(store)
        .await
        .unwrap()
        .resource_new
        .unwrap()
        .get_subject()
        .clone()
}

fn parent_query(parent: &Subject, limit: Option<usize>, for_agent: ForAgent) -> Query {
    Query {
        property: Some(urls::PARENT.into()),
        value: Some(Value::AtomicUrl(parent.clone())),
        filters: Vec::new(),
        limit,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        for_agent,
        drive: None,
        aggregation: None,
        expression_filters: Vec::new(),
    }
}

/// Synthetic repro from `planning/slow-collection-queries.md`: drive → folder
/// → form → many private children, queried `parent=form` as a non-authorized
/// agent. Pins remaining cost to *call counts* (a fresh store's snapshots are
/// too small to show wall-clock):
///
/// The rights walk must not full-decode ancestors (`get_resource` stays 0)
/// and must not re-fetch a parent whose verdict is already cached. Each
/// member is still shallow-fetched — a later readable sibling after a
/// private streak must not be skipped.
#[tokio::test]
async fn unauthorized_collection_query_bounds_fetch_counts() {
    let store = Db::init_temp("unauthorized_collection_query_bounds_fetch_counts")
        .await
        .unwrap();
    crate::test_utils::setup_test_env(&store).await.unwrap();

    let drive = crate::test_utils::create_test_drive(&store).await.unwrap();
    let folder = genesis_child(&store, &drive).await;
    let form = genesis_child(&store, &folder).await;

    const CHILDREN: usize = 100;
    for _ in 0..CHILDREN {
        genesis_child(&store, &form).await;
    }

    let sudo = store
        .query(&parent_query(&form, Some(500), ForAgent::Sudo))
        .await
        .unwrap();
    assert_eq!(
        sudo.subjects.len(),
        CHILDREN,
        "sanity: the form has {CHILDREN} children visible to sudo"
    );

    store.reset_fetch_counters();

    let denied = store
        .query(&parent_query(&form, Some(1), urls::PUBLIC_AGENT.into()))
        .await
        .unwrap();
    assert!(
        denied.subjects.is_empty(),
        "the public agent must not see private invite-code children"
    );

    let full_decodes = store.get_resource_call_count();
    let shallow = store.get_resource_shallow_call_count();
    assert_eq!(
        full_decodes, 0,
        "rights walk must not Loro-decode ancestors; get_resource was called {full_decodes} times"
    );
    assert!(
        shallow >= CHILDREN,
        "every member must still be shallow-fetched (a readable row after a private streak would otherwise be skipped); got {shallow}"
    );
    assert!(
        shallow <= CHILDREN + 8,
        "expected one shallow fetch per member plus a handful of ancestors, got {shallow} — \
         the parent memo is not skipping refetches"
    );
}

/// Denied members must not consume the page: a public child after a long
/// private streak is still returned. Each member can carry its own grant,
/// so a run of private siblings must not stop the scan.
#[tokio::test]
async fn unauthorized_query_skips_denials_to_fill_the_page() {
    let store = Db::init_temp("unauthorized_query_skips_denials_to_fill_the_page")
        .await
        .unwrap();
    crate::test_utils::setup_test_env(&store).await.unwrap();

    let drive = crate::test_utils::create_test_drive(&store).await.unwrap();
    let form = genesis_child(&store, &drive).await;

    for _ in 0..20 {
        genesis_child(&store, &form).await;
    }

    let mut public_child = Resource::new("did:ad:placeholder".into());
    public_child
        .set(urls::PARENT.into(), Value::AtomicUrl(form.clone()), &store)
        .await
        .unwrap();
    public_child
        .set(
            urls::READ.into(),
            Value::ResourceArray(vec![urls::PUBLIC_AGENT.into()]),
            &store,
        )
        .await
        .unwrap();
    let public_subject = public_child
        .save_as_genesis(&store)
        .await
        .unwrap()
        .resource_new
        .unwrap()
        .get_subject()
        .clone();

    let res = store
        .query(&parent_query(&form, Some(1), urls::PUBLIC_AGENT.into()))
        .await
        .unwrap();
    assert_eq!(
        res.subjects,
        vec![public_subject],
        "a public child after many private siblings must still fill page_size=1"
    );
}

#[tokio::test]
async fn get_extended_resource_pagination() {
    let store = Db::init_temp("get_extended_resource_pagination")
        .await
        .unwrap();
    crate::test_utils::setup_test_env(&store).await.unwrap();

    // Need enough local members that page 2 exists at page_size=1. This used to
    // paginate `/commits` (every write minted a member). The `/commits`
    // collection is no longer created; `/agents` has `include_external` and
    // DID subjects, so extra agents show up. `/classes` does not: class
    // subjects are `https://atomicdata.dev/…` and `include_external` is false.
    for _ in 0..5 {
        let mut agent = crate::agents::Agent::new(None)
            .unwrap()
            .to_resource()
            .unwrap();
        agent.save_locally(&store).await.unwrap();
    }

    let for_agent = &ForAgent::Public;
    let too_big = "http://localhost/agents?current_page=2&page_size=99999";
    if store
        .get_resource_extended(&too_big.into(), false, for_agent)
        .await
        .is_ok()
    {
        panic!("Page 2 should not exist, because page size is set to a high value.")
    }
    let paged = "http://localhost/agents?current_page=2&page_size=1";
    let resource = store
        .get_resource_extended(&paged.into(), false, &ForAgent::Public)
        .await
        .unwrap()
        .to_single();
    let cur_page = resource
        .get(urls::COLLECTION_CURRENT_PAGE)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(cur_page, 2);
    assert_eq!(resource.get_subject().as_str(), paged);
}

/// Generate a bunch of resources, query them.
/// Checks if cache is properly invalidated on modifying or deleting resources.
#[tokio::test]
async fn queries() {
    // Re-using the same instance can cause issues with testing concurrently.
    // let store = &DB.lock().unwrap().clone();
    let store_owned = Db::init_temp("queries").await.unwrap();
    crate::test_utils::setup_test_env(&store_owned)
        .await
        .unwrap();
    let store = &store_owned;

    let demo_val = Value::Slug("myval".to_string());
    // Nothing else in the seeded store points at it, so the count is exact.
    let demo_reference = Value::AtomicUrl("https://example.com/queries-test-target".into());

    let count = 10;
    let limit = 5;
    assert!(
        count > limit,
        "following tests might not make sense if count is less than limit"
    );

    let prop_filter = urls::DESTINATION;
    let sort_by = urls::DESCRIPTION;
    let mut subject_to_delete = "".to_string();

    for _x in 0..count {
        let mut demo_resource = Resource::new_generate_subject(store).unwrap();
        // We make one resource public
        if _x == 1 {
            demo_resource
                .set(urls::READ.into(), vec![urls::PUBLIC_AGENT].into(), store)
                .await
                .unwrap();
        } else if _x == 2 {
            subject_to_delete = demo_resource.get_subject().to_string();
        }
        demo_resource
            .set(urls::DESTINATION.into(), demo_reference.clone(), store)
            .await
            .unwrap();
        demo_resource
            .set(urls::SHORTNAME.into(), demo_val.clone(), store)
            .await
            .unwrap();
        demo_resource
            .set(
                sort_by.into(),
                Value::Markdown(crate::utils::random_string(10)),
                store,
            )
            .await
            .unwrap();
        demo_resource.save(store).await.unwrap();
    }

    let mut q = Query {
        property: Some(prop_filter.into()),
        value: Some(demo_reference.clone()),
        filters: Vec::new(),
        limit: Some(limit),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: None,
        aggregation: None,
        expression_filters: Vec::new(),
    };
    let res = store.query(&q).await.unwrap();
    assert_eq!(
        res.count, count,
        "number of references without property filter"
    );
    assert_eq!(limit, res.subjects.len(), "limit");

    // The value index answers "what points at X". A plain value has no row in
    // it, so without a property only a reference is found.
    q.property = None;
    q.value = Some(demo_val);
    let res = store.query(&q).await.unwrap();
    assert_eq!(res.count, 0, "literal value, no property filter");

    q.value = Some(demo_reference.clone());
    let res = store.query(&q).await.unwrap();
    assert_eq!(res.count, count, "reference value, no property filter");

    q.offset = 9;
    let res = store.query(&q).await.unwrap();
    assert_eq!(res.subjects.len(), count - q.offset, "offset");
    assert_eq!(res.resources.len(), 0, "no nested resources");

    q.offset = 0;
    q.include_nested = true;
    let res = store.query(&q).await.unwrap();
    assert_eq!(res.resources.len(), limit, "nested resources");

    q.sort_by = Some(sort_by.into());
    q.drive = Some(Subject::from("internal:/"));
    let mut res = store.query(&q).await.unwrap();
    assert!(!res.resources.is_empty(), "resources should be returned");
    let mut prev_resource = res.resources[0].clone();
    // For one resource, we will change the order by changing its value
    let mut resource_changed_order_opt = None;
    for (i, r) in res.resources.iter_mut().enumerate() {
        let previous = prev_resource.get(sort_by).unwrap().to_string();
        let current = r.get(sort_by).unwrap().to_string();
        assert!(
            previous <= current,
            "should be ascending: {} - {}",
            previous,
            current
        );
        // We change the order!
        if i == 4 {
            r.set(sort_by.into(), Value::Markdown("!first".into()), store)
                .await
                .unwrap();
            let resp = r.save(store).await.unwrap();
            resource_changed_order_opt = resp.resource_new.clone();
        }
        prev_resource = r.clone();
    }

    let resource_changed_order = resource_changed_order_opt.unwrap();

    assert_eq!(res.count, count, "count changed after updating one value");

    q.sort_by = Some(sort_by.into());
    let res = store.query(&q).await.unwrap();
    assert_eq!(
        res.resources[0].get_subject(),
        resource_changed_order.get_subject(),
        "order did not change after updating resource"
    );

    let mut delete_resource = store
        .get_resource(&subject_to_delete.as_str().into())
        .await
        .unwrap();
    delete_resource.destroy(store).await.unwrap();
    let res = store.query(&q).await.unwrap();
    assert!(
        !res.subjects.iter().any(|s| s.as_str() == subject_to_delete),
        "deleted resource still in results"
    );

    q.sort_desc = true;
    let res = store.query(&q).await.unwrap();
    let first = res.resources[0].get(sort_by).unwrap().to_string();
    let later = res.resources[limit - 1].get(sort_by).unwrap().to_string();
    assert!(first > later, "sort by desc");

    // We set the limit to 2 to make sure Query always returns the 1 out of 10 resources that has public rights.
    q.limit = Some(2);
    q.for_agent = urls::PUBLIC_AGENT.into();
    let res = store.query(&q).await.unwrap();
    assert_eq!(res.subjects.len(), 1, "authorized subjects");
    assert_eq!(res.resources.len(), 1, "authorized resources");
    // TODO: Ideally, the count is authorized too. But doing that could be hard. (or expensive)
    // https://github.com/atomicdata-dev/atomic-server/issues/286
    // assert_eq!(res.count, 1, "authorized count");

    println!("Filter by value, property and also Sort");
    q.property = Some(prop_filter.into());
    q.value = Some(demo_reference);
    q.sort_by = Some(sort_by.into());
    q.for_agent = ForAgent::Sudo;
    q.limit = Some(limit);
    let res = store.query(&q).await.unwrap();
    println!("res {:?}", res.subjects);
    let first = res.resources[0].get(sort_by).unwrap().to_string();
    let later = res.resources[limit - 1].get(sort_by).unwrap().to_string();
    assert!(first > later, "sort by desc");

    println!("Set a start value");
    let middle_val = res.resources[limit / 2].get(sort_by).unwrap().to_string();
    q.start_val = Some(Value::String(middle_val.clone()));
    let res = store.query(&q).await.unwrap();
    println!("res {:?}", res.subjects);

    let first = res.resources[0].get(sort_by).unwrap().to_string();
    assert!(
        first > middle_val,
        "start value not respected, found value larger than middle value of earlier query"
    );
}

/// Check if `include_external` is respected.
#[tokio::test]
async fn query_include_external() {
    let store_owned = Db::init_temp("query_include_external").await.unwrap();
    crate::test_utils::setup_test_env(&store_owned)
        .await
        .unwrap();
    let store = &store_owned;

    let mut q = Query {
        property: Some(urls::DESCRIPTION.into()),
        value: None,
        filters: Vec::new(),
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        for_agent: ForAgent::Sudo,
        drive: None,
        aggregation: None,
        expression_filters: Vec::new(),
    };
    let res_include = store.query(&q).await.unwrap();
    q.include_external = false;
    let res_no_include = store.query(&q).await.unwrap();
    println!("{:?}", res_include.subjects.len());
    println!("{:?}", res_no_include.subjects.len());
    assert!(
        res_include.subjects.len() > res_no_include.subjects.len(),
        "Amount of results should be higher for include_external"
    );
}

#[tokio::test]
async fn resources_all() {
    let store_owned = Db::init_temp("resources_all").await.unwrap();
    crate::test_utils::setup_test_env(&store_owned)
        .await
        .unwrap();
    let store = &store_owned;
    let res_no_include = store.all_resources(false).count();
    let res_include = store.all_resources(true).count();
    assert!(
        res_include > res_no_include,
        "Amount of results should be higher for include_external"
    );
}

#[tokio::test]
async fn blobs_storage() {
    let store = Db::init_temp("blobs_storage").await.unwrap();
    let data = b"some binary data";
    let hash = blake3::hash(data);
    let hash_bytes = hash.as_bytes();

    store.kv.insert(Tree::Blobs, hash_bytes, data).unwrap();
    let retrieved = store.kv.get(Tree::Blobs, hash_bytes).unwrap().unwrap();

    assert_eq!(data.to_vec(), retrieved);
}

#[tokio::test]
/// Changing these values actually correctly updates the index.
async fn invalidate_cache() {
    let store_owned = Db::init_temp("invalidate_cache").await.unwrap();
    crate::test_utils::setup_test_env(&store_owned)
        .await
        .unwrap();
    let store = &store_owned;

    // Make sure to use Properties that are not in the default store

    // Do strings work?
    test_collection_update_value(
        store,
        urls::FILENAME,
        Value::String("old_val".into()),
        Value::String("1".into()),
    )
    .await;
    // Do booleans work?
    test_collection_update_value(
        store,
        urls::IS_LOCKED,
        Value::Boolean(true),
        Value::Boolean(false),
    )
    .await;
    // Do ResourceArrays work?
    test_collection_update_value(
        store,
        urls::ATTACHMENTS,
        Value::ResourceArray(vec![
            "http://example.com/1".into(),
            "http://example.com/2".into(),
            "http://example.com/3".into(),
        ]),
        Value::ResourceArray(vec!["http://example.com/1".into()]),
    )
    .await;
}

/// Generates a bunch of resources, changes the value for one of them, checks if the order has changed correctly.
/// new_val should be lexicographically _smaller_ than old_val.
async fn test_collection_update_value(
    store: &Db,
    property_url: &str,
    old_val: Value,
    new_val: Value,
) {
    let irrelevant_property_url = urls::DESCRIPTION;
    let filter_prop = urls::DATATYPE_PROP;
    // Unique per invocation: this helper runs several times against one
    // shared store, and members that *lack* the sort property are still part
    // of a sorted collection (they sort first, under the no-value key).
    // Reusing one filter value across invocations would therefore accumulate
    // earlier invocations' resources into later result sets.
    let filter_val = Value::AtomicUrl(property_url.into());
    assert_ne!(
        property_url, irrelevant_property_url,
        "property_url should be different from urls::DESCRIPTION"
    );
    assert_ne!(
        property_url,
        filter_prop.to_string(),
        "property_url should be different from urls::REDIRECT"
    );
    println!("cache_invalidation test for {}", property_url);
    let count = 10;
    let limit = 5;
    assert!(
        count > limit,
        "the following tests might not make sense if count is less than limit"
    );

    let mut resources: Vec<Resource> = futures::future::join_all((0..count).map(async |_num| {
        let mut demo_resource = Resource::new_generate_subject(store).unwrap();
        demo_resource
            .set(property_url.into(), old_val.clone(), store)
            .await
            .unwrap();
        demo_resource
            .set(filter_prop.to_string(), filter_val.clone(), store)
            .await
            .unwrap();
        // We're only using this value to remove it later on
        demo_resource
            .set_string(irrelevant_property_url.into(), "value", store)
            .await
            .unwrap();
        demo_resource.save(store).await.unwrap();
        demo_resource
    }))
    .await;
    assert_eq!(resources.len(), count, "resources created wrong number");

    let q = Query {
        property: Some(filter_prop.into()),
        value: Some(filter_val),
        filters: Vec::new(),
        limit: Some(limit),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(property_url.into()),
        sort_desc: false,
        include_external: true,
        include_nested: true,
        for_agent: ForAgent::Sudo,
        drive: Some(Subject::from("internal:/")),
        aggregation: None,
        expression_filters: Vec::new(),
    };
    let mut res = store.query(&q).await.unwrap();
    assert_eq!(
        res.count, count,
        "Not the right amount of members in this collection"
    );

    // For one resource, we will change the order by changing its value
    let mut resource_changed_order_opt = None;
    for (i, r) in res.resources.iter_mut().enumerate() {
        // We change the order!
        if i == 4 {
            r.set(property_url.into(), new_val.clone(), store)
                .await
                .unwrap();
            r.save(store).await.unwrap();
            resource_changed_order_opt = Some(r.clone());
        }
    }

    let resource_changed_order =
        resource_changed_order_opt.expect("not enough resources in collection");

    let res = store.query(&q).await.expect("No first result ");
    assert_eq!(res.count, count, "count changed after updating one value");

    assert_eq!(
        res.subjects.first().unwrap().as_str(),
        resource_changed_order.get_subject().as_str(),
        "Updated resource is not the first Result of the new query"
    );

    // Remove one of the properties, not relevant to the query.
    // This should not impact the results
    resources[1]
        .remove_propval(irrelevant_property_url)
        .unwrap();
    resources[1].save(store).await.unwrap();
    let res = store
        .query(&q)
        .await
        .expect("No hits found after removing unrelated value");
    assert_eq!(
        res.count, count,
        "count changed after updating irrelevant value"
    );

    // Modify the filtered property.
    // This should remove the item from the results.
    resources[1].remove_propval(filter_prop).unwrap();
    resources[1].save(store).await.unwrap();
    let res = store
        .query(&q)
        .await
        .expect("No hits found after changing filter value");
    assert_eq!(
        res.count,
        count - 1,
        "Modifying the filtered value did not remove the item from the results"
    );
}

#[cfg(feature = "db-sled")]
#[tokio::test]
async fn test_migration_v2_to_v3() {
    let tmp_dir_path = ".temp/db/migration_v2_v3";
    let _try_remove_existing = std::fs::remove_dir_all(tmp_dir_path);
    // Deliberately NOT `localhost`. `resources_v2_to_v3` used to hardcode
    // "localhost" as the base domain, so a test on `https://localhost` passed
    // while every real deployment migrated its own resources to `External` and
    // kept them as HTTP URLs. A realistic domain here is what catches that.
    let server_url = "https://staging.example.com";
    let store = Db::init(
        std::path::Path::new(tmp_dir_path),
        Some(server_url.to_string()),
    )
    .await
    .unwrap();

    // Create an old-style PropValsV2
    let mut propvals = crate::db::v2_types::PropValsV2::new();
    let subject_url = format!("{}/test-resource", server_url);
    propvals.insert(
        crate::urls::DESCRIPTION.to_string(),
        crate::db::v2_types::ValueV2::String("test".to_string()),
    );
    // Add an AtomicUrl that points to itself
    propvals.insert(
        crate::urls::PARENT.to_string(),
        crate::db::v2_types::ValueV2::AtomicUrl(subject_url.clone()),
    );

    // Manually insert into resources_v2 using raw sled access
    // Drop the Db first so we can open the sled database directly
    drop(store);
    let sled_store =
        super::sled_store::SledStore::open(std::path::Path::new(tmp_dir_path)).unwrap();
    {
        let v2_tree = sled_store.raw_db().open_tree("resources_v2").unwrap();
        v2_tree
            .insert(
                subject_url.as_bytes(),
                rmp_serde::to_vec(&propvals).unwrap(),
            )
            .unwrap();
        v2_tree.flush().unwrap();
    }

    // Run migration
    super::migrations::migrate_maybe(&sled_store, Some(server_url)).unwrap();
    drop(sled_store);

    // Re-open the Db to pick up the migrated data
    let store = crate::Db::init(
        std::path::Path::new(&tmp_dir_path),
        Some(server_url.to_string()),
    )
    .await
    .unwrap();

    // Verify results in v3
    let resource = store
        .get_resource(&subject_url.clone().into())
        .await
        .unwrap();

    // The subject in the resource should now be Local
    assert!(
        matches!(resource.get_subject(), crate::Subject::Internal { .. }),
        "Subject should be Internal, but is {:?}",
        resource.get_subject()
    );

    // The value for PARENT should now be Local
    let parent = resource.get(crate::urls::PARENT).unwrap();
    if let crate::Value::AtomicUrl(s) = parent {
        assert!(
            matches!(s, crate::Subject::Internal { .. }),
            "Value should be Internal, but is {:?}",
            s
        );
    } else {
        panic!("Value should be AtomicUrl, but is {:?}", parent);
    }

    // Verify it is NOT in resources_v2 anymore (it should have been dropped)
    drop(store);
    let sled_store2 =
        super::sled_store::SledStore::open(std::path::Path::new(tmp_dir_path)).unwrap();
    assert!(!sled_store2
        .raw_db()
        .tree_names()
        .into_iter()
        .any(|n| n == "resources_v2".as_bytes()));
}

/// On `atomicdata.dev` itself, the canonical vocabulary must still RESOLVE
/// LOCALLY — not trigger a network fetch.
///
/// The vocabulary is deliberately kept `Subject::External` there (see
/// `Subject::CANONICAL_VOCABULARY_PREFIXES`) so the absolute `urls::` constants
/// keep working. But `get_resource` only network-fetches non-local subjects, so
/// if these fell through to that branch the server would issue a request to
/// ITSELF for its own ontology — an infinite loop in production, and a 500 for
/// every `/properties/*` and `/classes/*` URL.
#[cfg(feature = "db-sled")]
#[tokio::test]
async fn canonical_vocabulary_resolves_locally_on_its_own_host() {
    let tmp_dir_path = ".temp/db/canonical_vocab_serving";
    let _try_remove_existing = std::fs::remove_dir_all(tmp_dir_path);

    // Exactly production's origin.
    let store = Db::init(
        std::path::Path::new(tmp_dir_path),
        Some("https://atomicdata.dev".to_string()),
    )
    .await
    .unwrap();

    for canonical in [
        crate::urls::DESCRIPTION,
        crate::urls::SHORTNAME,
        crate::urls::IS_A,
    ] {
        let subject = crate::Subject::from_raw(canonical, Some("https://atomicdata.dev"));
        assert!(
            matches!(subject, crate::Subject::External(_)),
            "{canonical} should be External (kept canonical), got {subject:?}"
        );

        let resource = store.get_resource(&subject).await;
        assert!(
            resource.is_ok(),
            "{canonical} must resolve from the local store on its own host, \
             but failed with: {:?}. If this says 'Error when fetching', the \
             server is trying to request its own ontology over the network.",
            resource.err()
        );
    }
}

/// A `resources_v1` store must migrate all the way to `resources_v3` in ONE
/// `migrate_maybe` call.
///
/// `migrate_maybe` used to iterate a single `tree_names()` snapshot, so on a v1
/// store it ran v1→v2, created `resources_v2`, and then never consumed it —
/// because that tree didn't exist when the work list was built. `Tree::Resources`
/// (`resources_v3`) stayed empty, `migrate_from_sled` copied from that empty
/// tree, and the process exited 0. A real production store migrated 271 of
/// 184,843 resources this way, silently.
#[cfg(feature = "db-sled")]
#[tokio::test]
async fn test_migration_v1_chains_all_the_way_to_v3() {
    let tmp_dir_path = ".temp/db/migration_v1_chain";
    let _try_remove_existing = std::fs::remove_dir_all(tmp_dir_path);
    // Not `localhost` — see test_migration_v2_to_v3.
    let server_url = "https://staging.example.com";
    let store = Db::init(
        std::path::Path::new(tmp_dir_path),
        Some(server_url.to_string()),
    )
    .await
    .unwrap();
    drop(store);

    let subject_url = format!("{}/v1-resource", server_url);

    // Seed a v1-encoded resource (bincode) directly into `resources_v1`.
    let sled_store =
        super::sled_store::SledStore::open(std::path::Path::new(tmp_dir_path)).unwrap();
    {
        let mut propvals = crate::db::v1_types::PropValsV1::new();
        propvals.insert(
            crate::urls::DESCRIPTION.to_string(),
            crate::db::v1_types::ValueV1::String("from v1".to_string()),
        );
        propvals.insert(
            crate::urls::PARENT.to_string(),
            crate::db::v1_types::ValueV1::AtomicUrl(subject_url.clone()),
        );

        let v1_tree = sled_store.raw_db().open_tree("resources_v1").unwrap();
        v1_tree
            .insert(
                subject_url.as_bytes(),
                bincode1::serialize(&propvals).unwrap(),
            )
            .unwrap();
        v1_tree.flush().unwrap();
    }

    // A single call must chain v1 → v2 → v3.
    super::migrations::migrate_maybe(&sled_store, Some(server_url)).unwrap();

    // Both intermediate trees must be gone, and the data must have landed in v3.
    let names: Vec<String> = sled_store
        .raw_db()
        .tree_names()
        .iter()
        .map(|n| String::from_utf8_lossy(n).to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n == "resources_v1"),
        "resources_v1 should have been dropped, trees: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "resources_v2"),
        "resources_v2 should have been consumed by the v2→v3 step in the SAME call \
         (this is the regression: it used to be left behind, stranding all data), \
         trees: {names:?}"
    );

    // Scope the tree handle: a sled `Tree` keeps the `Db` alive, so holding it
    // across the reopen below would fail to acquire the file lock.
    {
        let v3 = sled_store.raw_db().open_tree("resources_v3").unwrap();
        assert_eq!(v3.len(), 1, "the v1 resource should be in resources_v3");
    }
    drop(sled_store);

    // And it must be readable, with its subject localized against the real
    // base domain rather than the old "localhost" placeholder.
    let store = crate::Db::init(
        std::path::Path::new(tmp_dir_path),
        Some(server_url.to_string()),
    )
    .await
    .unwrap();
    let resource = store.get_resource(&subject_url.into()).await.unwrap();
    assert!(
        matches!(resource.get_subject(), crate::Subject::Internal { .. }),
        "Subject should be Internal, but is {:?}",
        resource.get_subject()
    );
    assert_eq!(
        resource.get(crate::urls::DESCRIPTION).unwrap().to_string(),
        "from v1"
    );
}

/// Test that resources added via add_resource_opts with update_index=true
/// can be found via property-value queries (the pattern used by table/collection UI).
#[tokio::test]
async fn query_by_parent_after_add_resource() {
    let store = Db::init_temp("query_parent").await.unwrap();

    let parent_subject = "https://localhost/parent-folder";
    let child1_subject = "https://localhost/child1";
    let child2_subject = "https://localhost/child2";

    // Create parent
    let mut parent = crate::Resource::new(parent_subject.into());
    parent
        .set_unsafe(urls::NAME.into(), Value::String("Parent Folder".into()))
        .unwrap();
    store
        .add_resource_opts(&parent, false, true, true)
        .await
        .unwrap();

    // Create children with parent property
    let mut child1 = crate::Resource::new(child1_subject.into());
    child1
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_subject.into()))
        .unwrap();
    child1
        .set_unsafe(urls::NAME.into(), Value::String("Child 1".into()))
        .unwrap();
    store
        .add_resource_opts(&child1, false, true, true)
        .await
        .unwrap();

    let mut child2 = crate::Resource::new(child2_subject.into());
    child2
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_subject.into()))
        .unwrap();
    child2
        .set_unsafe(urls::NAME.into(), Value::String("Child 2".into()))
        .unwrap();
    store
        .add_resource_opts(&child2, false, true, true)
        .await
        .unwrap();

    // Query: find children of parent (this is what the table UI does)
    let query = crate::storelike::Query::new_prop_val(urls::PARENT, parent_subject);
    let result = store.query(&query).await.unwrap();

    assert_eq!(
        result.count, 2,
        "Should find 2 children, found {}. Subjects: {:?}",
        result.count, result.subjects
    );
}

#[tokio::test]
async fn sorted_parent_query_deduplicates_legacy_and_canonical_subjects() {
    let store = Db::init_temp("sorted_parent_alias_dedup").await.unwrap();
    let drive = "atomic:driveAliasDedup";
    let legacy = "did:ad:childAliasDedup";
    let canonical = "atomic:childAliasDedup";
    let row_class = "atomic:rowAliasClass";

    let child = |subject: &str| {
        let mut resource = crate::Resource::new(subject.into());
        resource
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
        resource
            .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
        resource
            .set_unsafe(urls::NAME.into(), Value::String("Document".into()))
            .unwrap();
        resource
            .set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![crate::values::SubResource::Subject(row_class.into())]),
            )
            .unwrap();
        resource
    };

    store
        .add_resource_opts(&child(legacy), false, true, true)
        .await
        .unwrap();
    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, drive);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    query.limit = Some(100);
    assert_eq!(store.query(&query).await.unwrap().count, 1);

    // Simulate an already-persisted index key written before the scheme fix.
    let filter = crate::db::query_index::QueryFilter::try_from_query(&query).unwrap();
    let sort_key = crate::db::query_index::sort_key_for(&child(legacy), urls::NAME);
    let legacy_key =
        crate::db::query_index::create_query_index_key(&filter, Some(&sort_key), Some(legacy))
            .unwrap();
    store
        .kv
        .insert(Tree::QueryMembers, &legacy_key, b"")
        .unwrap();
    let stale = store.query(&query).await.unwrap();
    assert_eq!(
        stale.count, 1,
        "stale alias inflated count: {:?}",
        stale.subjects
    );
    assert_eq!(stale.subjects.len(), 1);
    query.sort_desc = true;
    let descending = store.query(&query).await.unwrap();
    assert_eq!(descending.count, 1);
    assert_eq!(descending.subjects[0].as_str(), canonical);
    query.sort_desc = false;

    // An upgraded device rewrites the same resource under its canonical name.
    store
        .add_resource_opts(&child(canonical), false, true, true)
        .await
        .unwrap();
    let result = store.query(&query).await.unwrap();
    assert_eq!(
        result.count, 1,
        "duplicate index entries: {:?}",
        result.subjects
    );
    assert_eq!(result.subjects[0].pure_id(), canonical);

    query.offset = 1;
    let second_page = store.query(&query).await.unwrap();
    assert!(second_page.subjects.is_empty());
    assert_eq!(second_page.count, 1);

    // Table Views add an isA constraint even when the user has not sorted.
    let mut table_query = crate::storelike::Query::new_prop_val(urls::PARENT, drive);
    table_query.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(row_class.into())),
        ..Default::default()
    }];
    table_query.drive = Some(drive.into());
    table_query.limit = Some(100);
    assert_eq!(store.query(&table_query).await.unwrap().count, 1);
    let table_filter = crate::db::query_index::QueryFilter::try_from_query(&table_query).unwrap();
    let table_sort_key = crate::db::query_index::sort_key_for(&child(legacy), urls::PARENT);
    let table_legacy_key = crate::db::query_index::create_query_index_key(
        &table_filter,
        Some(&table_sort_key),
        Some(legacy),
    )
    .unwrap();
    store
        .kv
        .insert(Tree::QueryMembers, &table_legacy_key, b"")
        .unwrap();
    let table_result = store.query(&table_query).await.unwrap();
    assert_eq!(
        table_result.count, 1,
        "table aliases: {:?}",
        table_result.subjects
    );
    assert_eq!(table_result.subjects[0].as_str(), canonical);
}

#[tokio::test]
async fn basic_parent_query_deduplicates_legacy_and_canonical_subjects() {
    let store = Db::init_temp("basic_parent_alias_dedup").await.unwrap();
    let parent = "atomic:basicAliasParent";
    let legacy = "did:ad:basicAliasChild";
    let canonical = "atomic:basicAliasChild";
    let child = |subject: &str| {
        let mut resource = crate::Resource::new(subject.into());
        resource
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent.into()))
            .unwrap();
        resource
    };

    store
        .add_resource_opts(&child(legacy), false, true, true)
        .await
        .unwrap();

    // Simulate both primary index keys left by a pre-upgrade peer.
    let legacy_index_atom = child(legacy)
        .to_atoms()
        .into_iter()
        .find(|atom| atom.property == urls::PARENT)
        .unwrap()
        .to_indexable_atoms()
        .remove(0);
    let prop_key = crate::db::prop_val_sub_index::propvalsub_key(&legacy_index_atom);
    let value_key = crate::db::val_prop_sub_index::valpropsub_key(&legacy_index_atom);
    store.kv.insert(Tree::PropValSub, &prop_key, b"").unwrap();
    store.kv.insert(Tree::ValPropSub, &value_key, b"").unwrap();

    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, parent);
    let stale = store.query(&query).await.unwrap();
    assert_eq!(
        stale.count, 1,
        "stale alias inflated count: {:?}",
        stale.subjects
    );
    assert_eq!(stale.subjects[0].as_str(), canonical);
    let mut value_only = crate::storelike::Query::new();
    value_only.value = Some(Value::AtomicUrl(parent.into()));
    let value_result = store.query(&value_only).await.unwrap();
    assert_eq!(
        value_result.count, 1,
        "value index aliases: {:?}",
        value_result.subjects
    );
    assert_eq!(value_result.subjects[0].as_str(), canonical);
    query.offset = 1;
    let second_page = store.query(&query).await.unwrap();
    assert!(second_page.subjects.is_empty());
    assert_eq!(second_page.count, 1);

    store
        .add_resource_opts(&child(canonical), false, true, true)
        .await
        .unwrap();

    query.offset = 0;
    let result = store.query(&query).await.unwrap();
    assert_eq!(
        result.count, 1,
        "duplicate index entries: {:?}",
        result.subjects
    );
    assert_eq!(result.subjects[0].as_str(), canonical);
}

/// Production path: create a Drive via `store.create_drive`, add children
/// via `apply_commit` (what WebSocket/HTTP commits do), then fetch them
/// with a sorted query — the exact path the folder/table UI takes.
/// Regression guard for "refreshing the table shows new rows / doesn't
/// sort".
#[tokio::test]
async fn sorted_collection_after_apply_commit_is_stable() {
    use crate::commit::{CommitBuilder, CommitOpts};

    let store = Db::init_temp("collection_after_commit").await.unwrap();
    let agent = store.create_agent(Some("test-agent")).await.unwrap();
    store.set_default_agent(agent.clone());

    let drive_did = store.create_drive("Test Drive").await.unwrap();

    // Create children via DID-genesis commits — the frontend never picks
    // its own subject; it signs a genesis commit and the server derives the
    // DID from the signature. `Commit::create_did` is the same helper
    // `store.create_drive` uses.
    let opts = CommitOpts {
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    for name in &["alpha", "bravo", "charlie"] {
        let mut b = CommitBuilder::new("placeholder".into());
        b.set(
            urls::PARENT.into(),
            Value::AtomicUrl(drive_did.clone().into()),
        );
        b.set(urls::NAME.into(), Value::String((*name).to_string()));
        let commit = crate::commit::Commit::create_did(b, &agent, &store)
            .await
            .unwrap();
        store.apply_commit(commit, &opts).await.unwrap();
    }

    // Query via the same sorted path the UI uses.
    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, &drive_did);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive_did.clone().into());
    query.limit = Some(100);

    let first = store.query(&query).await.unwrap();
    let second = store.query(&query).await.unwrap();

    assert_eq!(
        first.subjects, second.subjects,
        "sorted query (post-commit) should be stable across calls. \
         first={:?} second={:?}",
        first.subjects, second.subjects
    );
    assert_eq!(
        first.count, second.count,
        "count should be stable across calls. first={} second={}",
        first.count, second.count
    );
    assert_eq!(first.count, 3, "should find 3 children via commits");
}

/// Sorted query — the path folder/table UIs use. Routes through
/// `query_complex`, which reads from `Tree::QueryMembers`, builds the index
/// on first miss, and watches the filter. Regression guard for the
/// "refreshing the table shows new rows / doesn't sort" symptom.
#[tokio::test]
async fn query_by_parent_sorted_is_stable_across_calls() {
    let store = Db::init_temp("query_parent_sorted").await.unwrap();

    let parent_subject = "https://localhost/parent-sorted";
    let mut parent = crate::Resource::new(parent_subject.into());
    parent
        .set_unsafe(urls::NAME.into(), Value::String("Parent".into()))
        .unwrap();
    store
        .add_resource_opts(&parent, false, true, true)
        .await
        .unwrap();

    for name in &["alpha", "bravo", "charlie"] {
        let subj = format!("https://localhost/sorted/{name}");
        let mut r = crate::Resource::new(subj);
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_subject.into()))
            .unwrap();
        r.set_unsafe(urls::NAME.into(), Value::String((*name).to_string()))
            .unwrap();
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, parent_subject);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some("https://localhost".into());
    query.limit = Some(100);

    let first = store.query(&query).await.unwrap();
    assert_eq!(
        first.count, 3,
        "first sorted query should find 3 children, got {}. Subjects: {:?}",
        first.count, first.subjects
    );

    // The critical part: re-running the same query must return the SAME
    // result. In the broken build, `is_watched` returns false on the second
    // call and the index is rebuilt, which can yield duplicates or drifting
    // ordering.
    let second = store.query(&query).await.unwrap();
    assert_eq!(
        second.count, first.count,
        "re-running the sorted query should return the same count. \
         first={} second={}. Second subjects: {:?}",
        first.count, second.count, second.subjects
    );
    assert_eq!(
        second.subjects, first.subjects,
        "sorted query results should be stable across calls, but they changed"
    );
}

/// Same test but with DID subjects (the real-world pattern).
#[tokio::test]
async fn query_by_parent_did_subjects() {
    let store = Db::init_temp("query_parent_did").await.unwrap();

    let parent_did =
        "did:ad:parentABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz012345678==";
    let child1_did =
        "did:ad:child1ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789==";
    let child2_did =
        "did:ad:child2ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890123456789==";

    // Create children with DID parent
    let mut child1 = crate::Resource::new(child1_did.into());
    child1
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_did.into()))
        .unwrap();
    child1
        .set_unsafe(urls::NAME.into(), Value::String("DID Child 1".into()))
        .unwrap();
    store
        .add_resource_opts(&child1, false, true, true)
        .await
        .unwrap();

    let mut child2 = crate::Resource::new(child2_did.into());
    child2
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_did.into()))
        .unwrap();
    child2
        .set_unsafe(urls::NAME.into(), Value::String("DID Child 2".into()))
        .unwrap();
    store
        .add_resource_opts(&child2, false, true, true)
        .await
        .unwrap();

    // Query: find children of DID parent
    let query = crate::storelike::Query::new_prop_val(urls::PARENT, parent_did);
    let result = store.query(&query).await.unwrap();

    assert_eq!(
        result.count, 2,
        "Should find 2 DID children, found {}. Subjects: {:?}",
        result.count, result.subjects
    );
}

/// Test that JSON-AD parsing + add_resource_opts indexes correctly
/// (simulates the WASM putResource path).
#[tokio::test]
async fn query_after_json_ad_import() {
    let store = Db::init_temp("query_json_import").await.unwrap();

    let parent =
        "did:ad:parentXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRST==";
    let json = format!(
        r#"{{"@id": "did:ad:childXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV==", "https://atomicdata.dev/properties/parent": "{}", "https://atomicdata.dev/properties/name": "JSON Child"}}"#,
        parent
    );

    let resource =
        crate::parse::parse_json_ad_resource(&json, &store, &crate::parse::ParseOpts::default())
            .await
            .unwrap();

    store
        .add_resource_opts(&resource, false, true, true)
        .await
        .unwrap();

    let query = crate::storelike::Query::new_prop_val(urls::PARENT, parent);
    let result = store.query(&query).await.unwrap();

    assert_eq!(
        result.count, 1,
        "Should find 1 child after JSON-AD import, found {}",
        result.count
    );
}

/// Test that a Loro-only DID genesis commit (mimicking browser behavior)
/// stores and indexes the resource correctly in a sled-backed Db.
#[tokio::test]
async fn did_loro_only_commit_sled() {
    use crate::agents::Agent;
    use crate::commit::{Commit, CommitBuilder, CommitOpts};

    let store = Db::init_temp("did_loro_commit").await.unwrap();
    store.populate().await.unwrap();

    // Create an agent
    let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
    let agent = Agent::new_from_private_key(None, private_key).unwrap();
    store
        .add_resource(&agent.to_resource().unwrap())
        .await
        .unwrap();

    // Build a Loro doc with properties (mimics browser-side)
    let loro_doc = crate::loro::AtomicLoroDoc::new();
    loro_doc
        .set_property(urls::NAME, &Value::String("My Property".into()))
        .unwrap();
    loro_doc
        .set_property(urls::DESCRIPTION, &Value::String("A test property".into()))
        .unwrap();
    loro_doc
        .set_property(urls::PUBLIC_KEY, &Value::String(agent.public_key.clone()))
        .unwrap();

    let snapshot = loro_doc.export_snapshot();

    // Create commit with ONLY loroUpdate (empty set map — browser behavior)
    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set_loro_update(snapshot);
    let commit = Commit::create_did(builder, &agent, &store).await.unwrap();
    let did_subject = commit.subject.clone();

    // Use the same opts as the real server handler (validate_rights + validate_schema)
    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_loro_causality: false,
        validate_rights: true,
        validate_schema: true,
        validate_constraints: true,
        update_index: true,
        validate_for_agent: Some(agent.subject.to_string()),
        source_id: None,
    };

    let result = store.apply_commit(commit, &opts).await.unwrap();
    assert!(result.resource_new.is_some(), "should have resource_new");

    // Verify the resource is retrievable from the sled-backed store
    let stored = store
        .get_resource(&did_subject.as_str().into())
        .await
        .expect("Loro-only DID resource should be retrievable from sled store");

    assert_eq!(
        stored.get(urls::NAME).unwrap().to_string(),
        "My Property",
        "Name should be materialized from Loro in sled store"
    );
}

/// Minimal repro for the cross-tab document sync bug.
///
/// Mimics the browser flow: a document is created via a genesis commit (no
/// RTE body yet), then the body is added via a FOLLOW-UP commit whose
/// `loroUpdate` is a full snapshot carrying a separate `documentContent` text
/// container (the RTE / ProseMirror tree). After the follow-up + a
/// `get_resource` roundtrip, `materialized_state()` — what the WS GET handler
/// serves to a second viewer — must still carry the `documentContent`
/// container. If it only carries the `properties` map, the second viewer
/// receives a properties-only doc and cross-tab CRDT sync can never converge.
#[tokio::test]
async fn loro_non_property_container_survives_commit_roundtrip() {
    use crate::agents::Agent;
    use crate::commit::{Commit, CommitBuilder, CommitOpts};

    let store = Db::init_temp("loro_container_roundtrip").await.unwrap();
    store.populate().await.unwrap();

    let private_key = "CapMWIhFUT+w7ANv9oCPqrHrwZpkP2JhzF9JnyT6WcI=";
    let agent = Agent::new_from_private_key(None, private_key).unwrap();
    store
        .add_resource(&agent.to_resource().unwrap())
        .await
        .unwrap();

    // Same opts the real WS commit handler uses (see handlers/commit.rs).
    let opts = CommitOpts {
        validate_signature: true,
        validate_timestamp: false,
        validate_loro_causality: true,
        validate_rights: true,
        validate_schema: true,
        validate_constraints: true,
        update_index: true,
        validate_for_agent: Some(agent.subject.to_string()),
        source_id: None,
    };

    // --- Genesis commit: document with just a `properties` map, no RTE body ---
    let doc = loro::LoroDoc::new();
    doc.set_record_timestamp(true);
    doc.get_map("properties")
        .insert(urls::NAME, "My Document")
        .unwrap();
    doc.commit();
    let genesis_snapshot = doc.export(loro::ExportMode::Snapshot).unwrap();

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set_loro_update(genesis_snapshot);
    let genesis = Commit::create_did(builder, &agent, &store).await.unwrap();
    let did_subject = genesis.subject.clone();
    let genesis_result = store.apply_commit(genesis, &opts).await.unwrap();
    let genesis_commit_url = genesis_result.commit_resource.get_subject().to_string();

    // --- Follow-up commit: add RTE body to a `documentContent` text container ---
    // The browser sends a full snapshot of its editor doc each commit.
    let rte = doc.get_text("documentContent");
    rte.insert(0, "RTE_BODY_TEXT").unwrap();
    doc.commit();
    let followup_snapshot = doc.export(loro::ExportMode::Snapshot).unwrap();

    // Sanity check: the snapshot the follow-up carries has the RTE container.
    {
        let check = loro::LoroDoc::new();
        check.import(&followup_snapshot).unwrap();
        assert_eq!(
            check.get_text("documentContent").to_string(),
            "RTE_BODY_TEXT",
            "precondition: follow-up snapshot carries the RTE container",
        );
    }

    let stored_before_followup = store.get_resource(&did_subject).await.unwrap();
    let mut builder2 = CommitBuilder::new(did_subject.clone());
    builder2.set_loro_update(followup_snapshot);
    builder2.set_previous_commit(genesis_commit_url);
    let followup = builder2
        .sign(&agent, &store, &stored_before_followup)
        .await
        .unwrap();

    // Route the follow-up through the exact wire path the WS commit handler
    // uses: serialize to JSON-AD (loroUpdate becomes base64), then parse it
    // back — `apply_commit_json` does precisely this.
    let wire_json = crate::client::commit_to_wire_json(&followup, &store)
        .await
        .unwrap();
    let parsed = crate::parse::parse_json_ad_commit_resource(&wire_json, &store)
        .await
        .unwrap();
    let followup_from_wire = Commit::from_resource(parsed).unwrap();
    store.apply_commit(followup_from_wire, &opts).await.unwrap();

    // (1) Plain get_resource path.
    let stored = store
        .get_resource(&did_subject)
        .await
        .expect("document should be retrievable after commit");
    let materialized = stored
        .materialized_state()
        .expect("stored document must expose a materialized Loro snapshot");
    let roundtripped = loro::LoroDoc::new();
    roundtripped.import(&materialized).unwrap();
    assert_eq!(
        roundtripped.get_text("documentContent").to_string(),
        "RTE_BODY_TEXT",
        "RTE container content must survive get_resource",
    );

    // (2) Exactly what the server's WS GET handler does: get_resource_extended
    // → to_single() → materialized_state().
    let extended = store
        .get_resource_extended(&did_subject, false, &crate::agents::ForAgent::Sudo)
        .await
        .expect("document should be retrievable via get_resource_extended")
        .to_single();
    let materialized_ext = extended
        .materialized_state()
        .expect("get_resource_extended document must expose a materialized Loro snapshot");
    let roundtripped_ext = loro::LoroDoc::new();
    roundtripped_ext.import(&materialized_ext).unwrap();
    assert_eq!(
        roundtripped_ext.get_text("documentContent").to_string(),
        "RTE_BODY_TEXT",
        "RTE container content must survive the get_resource_extended path \
         (this is what the WS GET handler serves to a second viewer)",
    );
}

/// A signed destroy commit removes the resource and stores its envelope in
/// one transaction, then tombstones the subject. Before, `apply_commit`
/// called `remove_resource`, which applied its own transaction: the resource
/// was gone before the envelope row landed, and a crash in between left a
/// deletion with no signed destroy for `SYNC_DIFF.removeCommits` to carry.
#[tokio::test]
#[timeout(120000)]
async fn destroy_commit_removes_resource_and_keeps_envelope_atomically() {
    let store = Db::init_temp("destroy_commit_envelope").await.unwrap();

    let mut resource = crate::Resource::new("did:ad:placeholder".into());
    resource
        .set(urls::NAME.into(), Value::String("doomed".into()), &store)
        .await
        .unwrap();
    let genesis = resource.save_as_genesis(&store).await.unwrap();
    let subject = genesis.resource_new.unwrap().get_subject().clone();
    let pure_id = subject.pure_id();
    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_some(),
        "test premise: a saved resource has a Loro snapshot"
    );
    assert!(
        !crate::sync::tombstones::is_tombstoned(&store, &pure_id),
        "test premise: a live resource is not tombstoned"
    );

    let mut resource = store.get_resource(&subject).await.unwrap();
    let destroy = resource.destroy(&store).await.unwrap();
    let signature = destroy
        .commit
        .signature
        .clone()
        .expect("destroy via the default agent is a signed commit");
    assert!(destroy.resource_new.is_none());

    // (a) the resource, its Loro snapshot and its stored propvals are gone.
    assert!(
        store.get_resource(&subject).await.is_err(),
        "destroyed resource must not resolve"
    );
    assert!(
        store
            .kv
            .get(Tree::Resources, pure_id.as_bytes())
            .unwrap()
            .is_none(),
        "destroyed resource row must be deleted"
    );
    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_none(),
        "Loro snapshot must be deleted with the resource"
    );

    // (b) the signed destroy envelope is the subject's latest envelope.
    let envelope = crate::envelopes::latest_envelope(&store, &pure_id)
        .expect("the destroy envelope must be stored for the destroyed subject");
    assert_eq!(envelope.signature, signature);
    assert!(envelope.is_destroy(), "latest envelope must be the destroy");

    // (c) the subject is tombstoned, and the tombstone resolves to the
    // signed destroy `SYNC_DIFF.removeCommits` forwards.
    assert!(
        crate::sync::tombstones::is_tombstoned(&store, &pure_id),
        "destroyed subject must be tombstoned"
    );
    assert!(
        crate::sync::tombstones::destroy_envelope(&store, &pure_id).is_some(),
        "tombstone must resolve to the signed destroy envelope"
    );
}

/// A deleted resource must not leave its Loro snapshot orphaned in
/// `Tree::LoroSnapshots`, and the subject must be tombstoned so bulk sync
/// does not resurrect it.
#[tokio::test]
#[timeout(120000)]
async fn remove_resource_deletes_loro_snapshot() {
    let store = Db::init_temp("orphan_snapshot").await.unwrap();
    let drive = store.create_drive("test-drive").await.unwrap();
    let did = store
        .create_resource(
            "https://atomicdata.dev/classes/Property",
            &drive,
            "age",
            None,
        )
        .await
        .unwrap();
    let subject = Subject::from_raw(&did, store.get_base_domain().as_deref());
    let pure_id = subject.pure_id();

    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_some(),
        "a Loro snapshot should be persisted for a freshly created resource"
    );

    store.remove_resource(&subject).await.unwrap();

    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_none(),
        "Loro snapshot was orphaned after remove_resource"
    );
    assert!(
        crate::sync::tombstones::is_tombstoned(&store, &pure_id),
        "removed subject should be tombstoned to prevent sync resurrection"
    );
}

/// Deleting via a subject that carries a `?drive=` hint must still remove the
/// snapshot — it is keyed by `pure_id()`. Regression test for the mis-keyed
/// `apply_destroy` snapshot removal.
#[tokio::test]
#[timeout(120000)]
async fn remove_resource_with_drive_hint_subject_deletes_snapshot() {
    let store = Db::init_temp("orphan_snapshot_hint").await.unwrap();
    let drive = store.create_drive("test-drive").await.unwrap();
    let did = store
        .create_resource(
            "https://atomicdata.dev/classes/Property",
            &drive,
            "age",
            None,
        )
        .await
        .unwrap();
    let subject = Subject::from_raw(&did, store.get_base_domain().as_deref());
    let pure_id = subject.pure_id();
    assert!(store
        .kv
        .get(Tree::LoroSnapshots, pure_id.as_bytes())
        .unwrap()
        .is_some());

    // Delete via a subject carrying a `?drive=` hint. The snapshot is keyed by
    // pure_id(); the old raw-subject key would miss it.
    let hinted = subject.clone().set_drive_hint(drive.clone());
    assert_ne!(
        hinted.to_string(),
        pure_id,
        "drive hint should make to_string() differ from pure_id()"
    );
    store.remove_resource(&hinted).await.unwrap();

    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_none(),
        "snapshot orphaned when deleting via a drive-hinted subject"
    );
}

/// `add_resource_opts` persists a Loro
/// snapshot for every CRDT resource — including when the resource already
/// carries a `loroUpdate` propval — and the `Tree::Resources` blob is a pure
/// projection with no `loroUpdate`.
#[tokio::test]
#[timeout(120000)]
async fn add_resource_opts_always_writes_loro_snapshot() {
    let store = Db::init_temp("add_resource_snapshot").await.unwrap();

    let mut resource = crate::Resource::new("did:ad:phase2b-test".into());
    resource
        .set_unsafe(urls::NAME.into(), Value::String("Test".into()))
        .unwrap();
    store
        .add_resource_opts(&resource, false, true, true)
        .await
        .unwrap();
    let pure_id = resource.get_subject().pure_id();
    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_some(),
        "add_resource_opts must persist a Loro snapshot"
    );

    // 2c: the persisted blob is a pure projection — no `loroUpdate` in it.
    let blob = store
        .kv
        .get(Tree::Resources, pure_id.as_bytes())
        .unwrap()
        .unwrap();
    assert!(
        !decode_propvals(&blob)
            .unwrap()
            .contains_key(urls::LORO_UPDATE),
        "Tree::Resources blob must not carry a loroUpdate propval"
    );

    // get_resource overlays the snapshot, so the fetched resource carries a
    // `loroUpdate` propval in memory (apply_state_doc re-inserts it).
    let fetched = store.get_resource(resource.get_subject()).await.unwrap();
    assert!(
        fetched.get_propvals().contains_key(urls::LORO_UPDATE),
        "fetched resource should carry a loroUpdate propval in memory"
    );

    // Drop the snapshot row, then re-add: the snapshot must be rewritten even
    // though the resource already carries `loroUpdate`.
    store
        .kv
        .remove(Tree::LoroSnapshots, pure_id.as_bytes())
        .unwrap();
    store
        .add_resource_opts(&fetched, false, true, true)
        .await
        .unwrap();
    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, pure_id.as_bytes())
            .unwrap()
            .is_some(),
        "snapshot must be rewritten even when propvals already carry loroUpdate"
    );
}

/// Signing in on a device that doesn't have the drive yet is the normal case for
/// a second device: it must be told it needs a sync, and asking the question
/// must not drag the drive here.
///
/// The predicate is the point. `load_agent_from_secret` used to ask with
/// `get_resource`, which falls back to *fetching* the subject — resolving a
/// `did:ad:` drive that lives on another phone hung for ~25s on-device while
/// everything waiting on the store queued behind it, including the webview
/// re-authenticating its WebSocket. `has_stored_resource` answers the question
/// that was actually being asked.
///
/// Note this test would pass against the old code too: with no DID resolver
/// reachable, the fetch fails fast instead of hanging. It pins the predicate,
/// not the latency — the hang only reproduces where resolution can stall.
///
/// Timeout is 120s (was 10s, then 30s): see the file-level note on
/// `#[timeout(120000)]`. The predicate itself is instant.
#[tokio::test]
#[timeout(120000)]
async fn load_agent_from_secret_reports_a_missing_drive_without_materialising_it() {
    let db_a = Db::init_temp("agent_secret_local_drive_a").await.unwrap();
    let (agent_a, drive) = db_a.setup("Alice").await.unwrap();
    let secret = agent_a.build_secret().unwrap();

    // A fresh device: same agent, none of the data.
    let db_b = Db::init_temp("agent_secret_local_drive_b").await.unwrap();
    let result = db_b.load_agent_from_secret(&secret).await.unwrap();

    assert!(
        result.drive_needs_sync,
        "a device without the drive must be told it needs a sync"
    );

    let drive_subject = Subject::from_raw(&drive, None);
    assert!(
        !db_b.has_stored_resource(&drive_subject),
        "asking whether the drive is here must not bring it here"
    );
    assert!(
        db_a.has_stored_resource(&drive_subject),
        "the device that made the drive still has it"
    );
}

/// `handle_commit` — the hook `atomic-server` uses to tell subscribed clients
/// that something moved — only runs for applied commits. Writes that arrive as
/// raw CRDT state (a peer's `SYNC_PUSH` import) have no commit, so a listener
/// has to recognise them and fan them out itself. `from_commit` is that
/// discriminator; if it ever lies, a device holds new data and renders the old.
#[tokio::test]
#[timeout(120000)]
async fn db_events_say_whether_a_commit_produced_the_change() {
    use crate::DbEvent;

    let store = Db::init_temp("db_event_from_commit").await.unwrap();
    let (agent, _drive) = store.setup("Alice").await.unwrap();
    store.set_default_agent(agent);

    let mut events = store.subscribe_events();

    // A commit: the hook fires, so listeners must NOT fan this out again.
    let mut committed = Resource::new_instance(urls::CLASS, &store).await.unwrap();
    committed
        .set(
            urls::SHORTNAME.into(),
            Value::Slug("committed".into()),
            &store,
        )
        .await
        .unwrap();
    committed
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("via a commit".into()),
            &store,
        )
        .await
        .unwrap();
    committed.save_locally(&store).await.unwrap();

    let from_commit = loop {
        match events.recv().await.unwrap() {
            DbEvent::Changed { from_commit, .. } => break from_commit,
            _ => continue,
        }
    };
    assert!(from_commit, "an applied commit must say so");

    // A raw write, as a peer import performs: no commit, no hook, and nothing
    // would reach the UI unless a listener notices.
    let mut imported = Resource::new_instance(urls::CLASS, &store).await.unwrap();
    imported
        .set(
            urls::SHORTNAME.into(),
            Value::Slug("imported".into()),
            &store,
        )
        .await
        .unwrap();
    imported
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("straight into the store".into()),
            &store,
        )
        .await
        .unwrap();
    store.add_resource(&imported).await.unwrap();

    let from_commit = loop {
        match events.recv().await.unwrap() {
            DbEvent::Changed { from_commit, .. } => break from_commit,
            _ => continue,
        }
    };
    assert!(
        !from_commit,
        "a write with no commit must be recognisable, or nothing announces it"
    );
}

/// A cascade-deleted child must say which drive it belonged to.
///
/// Destroying a folder removes its contents server-side, and the only way an
/// open client hears about that is the removal event. Clients subscribe per
/// drive — the per-resource subscribe is a no-op in the v2 protocol — so an
/// event with no drive on it is routed to nobody: every other tab keeps
/// rendering children that no longer exist, and the tab that issued the
/// destroy keeps them in its local database, where a reload brings them back.
///
/// The drive has to be read here, while the resource still exists. A listener
/// reacting to the event cannot look it up: by then the resource is gone.
#[tokio::test]
#[timeout(120000)]
async fn a_cascade_deleted_child_names_its_drive() {
    use crate::DbEvent;

    let store = Db::init_temp("cascade_child_names_its_drive")
        .await
        .unwrap();
    store.populate().await.unwrap();
    let drive = crate::test_utils::create_test_drive(&store).await.unwrap();
    let agent = store.get_default_agent().unwrap();

    // Genesis commits with rights validation on, because that is the path that
    // stamps `drive` onto a resource — and the drive is what this is about.
    // A plain `save` skips the stamp, so the fanout would look broken here for
    // a reason the app never hits.
    let create_under = |parent: Subject| {
        let store = &store;
        let agent = agent.clone();
        async move {
            let mut resource = crate::Resource::new("did:ad:placeholder".into());
            resource
                .set(urls::PARENT.into(), Value::AtomicUrl(parent), store)
                .await
                .unwrap();

            let mut commit_builder = resource.get_commit_builder().clone();
            commit_builder.is_genesis = true;
            let commit = commit_builder.sign(&agent, store, &resource).await.unwrap();
            let signature = commit.signature.clone().unwrap();
            let mut genesis_commit = commit;
            genesis_commit.subject = Subject::from_raw(&format!("did:ad:{signature}"), None);

            let opts = crate::commit::CommitOpts {
                validate_schema: true,
                validate_constraints: true,
                validate_signature: true,
                validate_timestamp: false,
                validate_rights: true,
                validate_loro_causality: false,
                validate_for_agent: Some(agent.subject.to_string()),
                update_index: true,
                source_id: None,
            };

            store
                .apply_commit(genesis_commit, &opts)
                .await
                .unwrap()
                .resource_new
                .unwrap()
                .get_subject()
                .clone()
        }
    };

    let parent_subject = create_under(drive.clone()).await;
    let child_subject = create_under(parent_subject.clone()).await.without_params();

    let mut events = store.subscribe_events();

    let mut doomed = store.get_resource(&parent_subject).await.unwrap();
    doomed.destroy(&store).await.unwrap();

    let child_drive = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match events.recv().await.unwrap() {
                DbEvent::Destroyed { subject, drive, .. } if subject == child_subject => {
                    break drive;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("the cascade never announced the child at all");

    assert_eq!(
        child_drive.map(|d| d.to_string()),
        Some(drive.to_string()),
        "a removal with no drive on it reaches no subscriber"
    );
}

/// `DbEvent::Destroyed` is sent only once the removal has been applied.
///
/// `recursive_remove` used to announce each cascade-deleted child while it
/// was still queueing operations into a transaction the caller had yet to
/// apply. A listener — the WS fan-out in `atomic-server`'s `CommitMonitor`, a
/// peer transport — heard of a deletion that could still fail or roll back,
/// and heard of the children before the parent whose removal caused it. Now
/// the caller announces every removed subject, the parent included, after the
/// transaction has landed.
///
/// The listener runs on its own worker thread and checks the store the moment
/// each event arrives. With the old ordering there is a wide window in which
/// that read still finds the resource: the children have yet to be queried,
/// unindexed and applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[timeout(120000)]
async fn destroyed_events_follow_the_applied_removal() {
    use crate::DbEvent;

    let store = Db::init_temp("destroyed_after_apply").await.unwrap();
    let drive = store.create_drive("destroyed-after-apply").await.unwrap();
    let parent = store
        .create_resource(urls::FOLDER, &drive, "parent", None)
        .await
        .unwrap();
    let mut expected: Vec<String> = vec![parent.clone()];
    for name in ["child-1", "child-2"] {
        let child = store
            .create_resource(urls::FOLDER, &parent, name, None)
            .await
            .unwrap();
        expected.push(child);
    }
    let base = store.get_base_domain();
    let to_subject = |s: &str| Subject::from_raw(s, base.as_deref()).without_params();
    expected.sort();

    // Subscribe before the removal, and observe concurrently: what matters is
    // the state of the store at the moment each event can be seen.
    let mut events = store.subscribe_events();
    let observer_store = store.clone();
    let observer = tokio::spawn(async move {
        let mut seen: Vec<(Subject, bool)> = Vec::new();
        while seen.len() < 3 {
            match events.recv().await.unwrap() {
                DbEvent::Destroyed { subject, .. } => {
                    let still_present = observer_store.get_resource(&subject).await.is_ok();
                    seen.push((subject, still_present));
                }
                _ => continue,
            }
        }
        (seen, events)
    });

    store.remove_resource(&to_subject(&parent)).await.unwrap();

    let (seen, mut events) = tokio::time::timeout(std::time::Duration::from_secs(30), observer)
        .await
        .expect("the removal never announced parent and both children")
        .unwrap();

    let mut announced: Vec<String> = seen.iter().map(|(s, _)| s.pure_id()).collect();
    announced.sort();
    assert_eq!(
        announced, expected,
        "parent and both children must each be announced exactly once"
    );
    for (subject, still_present) in &seen {
        assert!(
            !still_present,
            "{subject} was announced as destroyed while the store still held it"
        );
        assert!(
            store.get_resource(subject).await.is_err(),
            "{subject} must be gone once its removal is announced"
        );
    }

    // `remove_resource` has returned, so anything it sent is already in the
    // channel: there must be no fourth removal — the parent is not announced
    // twice.
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, DbEvent::Destroyed { .. }),
            "unexpected extra removal event: {event:?}"
        );
    }
}

/// A resource created under a drive must be findable by that drive.
///
/// `drive` is stamped onto the resource by the server (`commit.rs`, from the
/// parent) rather than carried as an atom of the commit, so indexing only the
/// commit's atoms left it out of the prop/val index. That is invisible until
/// something filters on it: the query planner sizes each constraint by its
/// index, picks the near-empty `drive` one as the cheapest candidate source,
/// finds nothing, and caches the empty result for that filter.
///
/// This is the shape `@tomic/create-template` uses to locate a template in a
/// specific drive — template localIds repeat across drives, so the drive
/// constraint is the only thing disambiguating them.
#[tokio::test]
#[timeout(120000)]
async fn find_resource_scoped_to_its_drive() {
    let store = Db::init_temp("drive_scoped_query").await.unwrap();
    store.populate().await.unwrap();

    let drive = crate::test_utils::create_test_drive(&store).await.unwrap();

    // Created the way an import does it: a parent, no explicit `drive`, and
    // applied with rights validation on — which is what makes the server
    // stamp the drive (`commit.rs`), so `save_as_genesis` (rights off) would
    // not reproduce this at all.
    let agent = store.get_default_agent().unwrap();
    let mut imported = crate::Resource::new("did:ad:placeholder".into());
    imported
        .set(urls::PARENT.into(), Value::AtomicUrl(drive.clone()), &store)
        .await
        .unwrap();
    imported
        .set(
            urls::LOCAL_ID.into(),
            Value::String("website".into()),
            &store,
        )
        .await
        .unwrap();

    let mut commit_builder = imported.get_commit_builder().clone();
    commit_builder.is_genesis = true;
    let commit = commit_builder
        .sign(&agent, &store, &imported)
        .await
        .unwrap();
    let signature = commit.signature.clone().unwrap();
    let mut genesis_commit = commit;
    genesis_commit.subject = Subject::from_raw(&format!("did:ad:{signature}"), None);

    let opts = crate::commit::CommitOpts {
        validate_schema: true,
        validate_constraints: true,
        validate_signature: true,
        validate_timestamp: false,
        validate_rights: true,
        validate_loro_causality: false,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        source_id: None,
    };
    let subject = store
        .apply_commit(genesis_commit, &opts)
        .await
        .unwrap()
        .resource_new
        .unwrap()
        .get_subject()
        .clone();

    let stored = store.get_resource(&subject).await.unwrap();
    assert_eq!(
        stored.get(urls::DRIVE_PROP).unwrap().to_string(),
        drive.to_string(),
        "sanity: the server stamps the drive onto a resource created under it"
    );

    let by_drive = store
        .query(&crate::storelike::Query::new_prop_val(
            urls::DRIVE_PROP,
            drive.as_str(),
        ))
        .await
        .unwrap();
    assert!(
        by_drive.subjects.contains(&subject),
        "the stamped drive must be indexed, not just stored. Found: {:?}",
        by_drive.subjects
    );

    // The shape that actually broke: localId AND drive.
    let mut scoped = crate::storelike::Query::new_prop_val(urls::LOCAL_ID, "website");
    scoped.drive = Some(drive.clone());
    scoped.filters = vec![crate::storelike::PropVal {
        property: Some(urls::DRIVE_PROP.into()),
        value: Some(Value::AtomicUrl(drive.clone())),
        operator: crate::storelike::FilterOperator::Equal,
    }];
    let result = store.query(&scoped).await.unwrap();
    assert_eq!(
        result.subjects,
        vec![subject],
        "a localId lookup constrained to one drive must resolve the resource"
    );
}

/// A watched query's index is built once, when it is both empty and unwatched
/// (`query_complex`). After that nothing reconciles it against reality — so any
/// member the incremental path fails to add is missing for good, and the guard
/// that would have caught it (`total_count == 0`) never fires again because 5
/// is not 0.
///
/// This is the shape behind a table showing 5 of 22 rows on one node and 22 on
/// another: same resources, same query, an index that had stopped keeping up.
#[tokio::test]
#[timeout(120000)]
async fn sorted_query_index_keeps_up_with_later_children() {
    let store = Db::init_temp("query_index_drift").await.unwrap();

    let parent_subject = "https://localhost/drift-parent";
    let mut parent = crate::Resource::new(parent_subject.into());
    parent
        .set_unsafe(urls::NAME.into(), Value::String("Parent".into()))
        .unwrap();
    store
        .add_resource_opts(&parent, false, true, true)
        .await
        .unwrap();

    let add_child = |name: String, sorted: bool| {
        let subj = format!("https://localhost/drift/{name}");
        let mut r = crate::Resource::new(subj);
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_subject.into()))
            .unwrap();
        // Half the rows carry no value for the sort property, exactly like a
        // table row whose sorted column was never filled in.
        if sorted {
            r.set_unsafe(urls::NAME.into(), Value::String(name.clone()))
                .unwrap();
        }
        r
    };

    for i in 0..5 {
        let r = add_child(format!("early{i}"), true);
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, parent_subject);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some("https://localhost".into());
    query.limit = Some(100);

    // Builds and watches the index.
    let first = store.query(&query).await.unwrap();
    assert_eq!(first.count, 5, "expected the 5 existing children");

    // Now the rows that arrive after the filter is already watched.
    for i in 0..17 {
        let r = add_child(format!("later{i}"), i % 2 == 0);
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let second = store.query(&query).await.unwrap();
    assert_eq!(
        second.count, 22,
        "children added after the query was watched must still be listed; \
         got {} of 22. Subjects: {:?}",
        second.count, second.subjects
    );
}

/// Same drift check, with DID subjects — the shape real drives actually use.
/// DID atoms take a different branch in the indexer (they cannot be
/// prefix-matched to a drive, so they consult every drive's property buckets),
/// and the drive-scoped query they are read back through is keyed by drive.
#[tokio::test]
#[timeout(120000)]
async fn sorted_query_index_keeps_up_with_later_did_children() {
    let store = Db::init_temp("query_index_drift_did").await.unwrap();

    let drive =
        "did:ad:driveDRIFTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let parent_subject =
        "did:ad:parentDRIFTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut parent = crate::Resource::new(parent_subject.into());
    parent
        .set_unsafe(urls::NAME.into(), Value::String("Parent".into()))
        .unwrap();
    parent
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    store
        .add_resource_opts(&parent, false, true, true)
        .await
        .unwrap();

    let mk = |i: usize, sorted: bool| {
        let subj = format!("did:ad:row{:0>70}==", format!("{i}"));
        let mut r = crate::Resource::new(subj);
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(parent_subject.into()))
            .unwrap();
        if sorted {
            r.set_unsafe(urls::NAME.into(), Value::String(format!("row{i}")))
                .unwrap();
        }
        r
    };

    for i in 0..5 {
        let r = mk(i, true);
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, parent_subject);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    query.limit = Some(100);

    let first = store.query(&query).await.unwrap();
    assert_eq!(first.count, 5, "expected the 5 existing children");

    for i in 5..22 {
        let r = mk(i, i % 2 == 0);
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let second = store.query(&query).await.unwrap();
    assert_eq!(
        second.count, 22,
        "DID children added after the query was watched must still be listed; \
         got {} of 22",
        second.count
    );
}

/// The real-world shape: TWO constraints (parent AND isA) plus a sort, on DID
/// subjects, drive-scoped. This is what a table view issues — children of the
/// table, narrowed to the table's classtype so the table's own View resources
/// stay out of the row list.
#[tokio::test]
#[timeout(120000)]
async fn sorted_query_index_keeps_up_with_two_constraints() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_index_drift_two").await.unwrap();

    let drive =
        "did:ad:driveTWOaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "did:ad:tableTWOaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let row_class =
        "did:ad:classTWOaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut t = crate::Resource::new(table.into());
    t.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    store
        .add_resource_opts(&t, false, true, true)
        .await
        .unwrap();

    let mk = |i: usize, sorted: bool| {
        let subj = format!("did:ad:two{:0>70}==", format!("{i}"));
        let mut r = crate::Resource::new(subj);
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        r.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![crate::values::SubResource::Subject(row_class.into())]),
        )
        .unwrap();
        if sorted {
            r.set_unsafe(urls::NAME.into(), Value::String(format!("row{i}")))
                .unwrap();
        }
        r
    };

    for i in 0..5 {
        let r = mk(i, true);
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let mut query = Query::new_prop_val(urls::PARENT, table);
    query.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(row_class.into())),
        ..Default::default()
    }];
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    query.limit = Some(100);

    let first = store.query(&query).await.unwrap();
    assert_eq!(
        first.count, 5,
        "expected the 5 existing rows, got {}",
        first.count
    );

    for i in 5..22 {
        let r = mk(i, i % 2 == 0);
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let second = store.query(&query).await.unwrap();
    assert_eq!(
        second.count, 22,
        "rows added after the two-constraint query was watched must still be \
         listed; got {} of 22",
        second.count
    );
}

/// Which encodings of `isA` does a two-constraint query actually find?
///
/// Rows created by a local commit carry `isA` as a `ResourceArray`. Rows
/// rebuilt from a Loro doc (`apply_state_doc`, which every sync import goes
/// through) recover their `Value` variant by inference — that is what the
/// sibling `datatypes` map exists to pin down. If an encoding that reads back
/// as the same subject fails the constraint, the row is silently absent from
/// the index, and therefore from the table, while being present in the store
/// and in every unfiltered query.
///
/// This reproduced two silent failures at once. The `String` row was in the
/// index and was read, and then hidden: the built-in collection class
/// extender did `is_a.to_subjects()?` on it, and `resolve_query_member` took
/// any extender error as a reason to drop the row from the page and the
/// count. The JSON-array `String` row was never a candidate: its `isA` was
/// indexed under the literal `["…"]` string, so the class constraint could
/// not find it and the matcher did not accept it either.
#[tokio::test]
#[timeout(120000)]
async fn is_a_encodings_all_match_the_class_constraint() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_index_isa_encodings").await.unwrap();

    let drive =
        "did:ad:driveENCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "did:ad:tableENCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let cls =
        "did:ad:classENCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut t = crate::Resource::new(table.into());
    t.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    store
        .add_resource_opts(&t, false, true, true)
        .await
        .unwrap();

    let encodings: Vec<(&str, Value)> = vec![
        (
            "ResourceArray",
            Value::ResourceArray(vec![crate::values::SubResource::Subject(cls.into())]),
        ),
        ("String", Value::String(cls.into())),
        ("AtomicUrl", Value::AtomicUrl(cls.into())),
        (
            "String-holding-json-array",
            Value::String(format!("[\"{cls}\"]")),
        ),
    ];

    for (i, (label, val)) in encodings.iter().enumerate() {
        let subj = format!("did:ad:enc{:0>70}==", format!("{i}"));
        let mut r = crate::Resource::new(subj);
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        r.set_unsafe(urls::IS_A.into(), val.clone()).unwrap();
        r.set_unsafe(urls::NAME.into(), Value::String((*label).into()))
            .unwrap();
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    let mut query = Query::new_prop_val(urls::PARENT, table);
    query.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(cls.into())),
        ..Default::default()
    }];
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    query.limit = Some(100);

    let res = store.query(&query).await.unwrap();
    assert_eq!(
        res.count,
        encodings.len(),
        "every isA encoding that names the same class must satisfy the class \
         constraint; got {} of {}. Found: {:?}",
        res.count,
        encodings.len(),
        res.subjects
    );
    assert_eq!(res.subjects.len(), encodings.len());
    assert_eq!(res.resources.len(), encodings.len());

    let report = store.check_query_index(&query).unwrap();
    assert!(
        report.is_consistent(),
        "index and store disagree after the read: {report:?}"
    );
    assert_eq!(report.expected, encodings.len());
}

/// A row built the way sync builds it — a fresh `Resource` given a Loro doc
/// through `apply_state_doc`, persisted by `persist_replicated_resource` —
/// must land in a watched, drive-scoped, sorted, class-filtered index, and
/// the sorted read must then agree with the unsorted and the unscoped
/// shapes of the same question.
///
/// This is the shape from planning/silent-failures.md: a table rendered 5
/// rows through `query_complex` while 22 existed and every other query shape
/// returned 22. The first 5 rows are written before the query is watched
/// (so the build files them), the other 17 arrive as replicas afterwards (so
/// only commit-time maintenance can file them).
#[tokio::test]
#[timeout(120000)]
async fn replicated_rows_reach_a_watched_scoped_sorted_query() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_index_replicated_rows").await.unwrap();

    let drive =
        "did:ad:driveREPLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "did:ad:tableREPLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let cls =
        "did:ad:classREPLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut t = crate::Resource::new(table.into());
    t.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    t.set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    store
        .add_resource_opts(&t, false, true, true)
        .await
        .unwrap();

    // What a peer's SYNC_PUSH entry becomes here: propvals materialized from
    // the Loro doc, not the ones a local caller set.
    let replicate = |i: usize| {
        let subj = format!("did:ad:repl{:0>69}==", format!("{i}"));
        let mut authored = crate::Resource::new(subj.clone());
        authored
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        authored
            .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
        authored
            .set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![crate::values::SubResource::Subject(cls.into())]),
            )
            .unwrap();
        authored
            .set_unsafe(urls::NAME.into(), Value::String(format!("row {i:02}")))
            .unwrap();
        let doc = authored.build_state_doc().unwrap();
        let mut replica = crate::Resource::new(subj);
        replica.apply_state_doc(doc).unwrap();
        replica
    };

    for i in 0..5 {
        store
            .persist_replicated_resource(&replicate(i))
            .await
            .unwrap();
    }

    let table_query = |sort: bool, scope: &str| {
        let mut q = Query::new_prop_val(urls::PARENT, table);
        q.filters = vec![crate::storelike::PropVal {
            property: Some(urls::IS_A.to_string()),
            value: Some(Value::AtomicUrl(cls.into())),
            ..Default::default()
        }];
        q.sort_by = sort.then(|| urls::NAME.to_string());
        q.drive = Some(scope.into());
        q.limit = Some(100);
        q
    };
    let scoped_sorted = table_query(true, drive);

    assert_eq!(store.query(&scoped_sorted).await.unwrap().count, 5);
    assert!(
        crate::db::query_index::QueryFilter::try_from_query(&scoped_sorted)
            .unwrap()
            .is_watched(&store)
    );

    for i in 5..22 {
        store
            .persist_replicated_resource(&replicate(i))
            .await
            .unwrap();
    }

    let unsorted = table_query(false, drive);
    let other_scope = table_query(true, table);

    let sorted_res = store.query(&scoped_sorted).await.unwrap();
    assert_eq!(
        sorted_res.count, 22,
        "the watched sorted index lists {} of 22 replicated rows",
        sorted_res.count
    );
    assert_eq!(store.query(&unsorted).await.unwrap().count, 22);
    assert_eq!(store.query(&other_scope).await.unwrap().count, 22);

    for q in [&scoped_sorted, &unsorted, &other_scope] {
        let report = store.check_query_index(q).unwrap();
        assert!(report.is_consistent(), "{report:?}");
        assert_eq!(report.indexed, 22);
    }
}

/// The planner scans one constraint's index and trusts it to hold every
/// member. When it does not — here one row's `isA` entry is simply gone —
/// the first build must notice through the other constraint, say so, and
/// file the row anyway, instead of watching a partial list for good.
#[tokio::test]
#[timeout(120000)]
async fn first_build_cross_checks_the_unscanned_constraint() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_index_cross_check").await.unwrap();
    let drive =
        "did:ad:driveXCHKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "did:ad:tableXCHKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let cls =
        "did:ad:classXCHKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    // More rows in the table than in the class, so the planner scans `isA`.
    for i in 0..6 {
        let subj = format!("did:ad:xchk{:0>69}==", format!("{i}"));
        let mut r = crate::Resource::new(subj);
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        if i < 4 {
            r.set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![crate::values::SubResource::Subject(cls.into())]),
            )
            .unwrap();
        }
        r.set_unsafe(urls::NAME.into(), Value::String(format!("row{i}")))
            .unwrap();
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
    }

    // Knock one row out of the class index only. Its row still names the
    // class, and its `parent` entry is intact.
    let gone = "did:ad:xchk000000000000000000000000000000000000000000000000000000000000000000002==";
    let mut transaction = crate::db::trees::Transaction::new();
    transaction.push(
        crate::db::trees::Operation::remove_atom_from_prop_val_sub_index(
            &crate::atoms::IndexAtom {
                subject: Subject::from(gone),
                property: urls::IS_A.to_string(),
                ref_value: cls.to_string(),
                sort_value: cls.to_string(),
            },
        ),
    );
    store.apply_transaction(&mut transaction).unwrap();

    let mut query = Query::new_prop_val(urls::PARENT, table);
    query.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(cls.into())),
        ..Default::default()
    }];
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    query.limit = Some(100);

    let res = store.query(&query).await.unwrap();
    assert_eq!(res.count, 4, "got {:?}", res.subjects);
    assert!(res
        .subjects
        .iter()
        .any(|s| s.pure_id() == Subject::from(gone).pure_id()));
    let report = store.check_query_index(&query).unwrap();
    assert!(report.is_consistent(), "{report:?}");
}

/// The consistency check names what is wrong, in both directions.
#[tokio::test]
#[timeout(120000)]
async fn check_query_index_names_missing_and_stale_members() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_index_report").await.unwrap();
    let drive =
        "atomic:driveRPRTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "atomic:tableRPRTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut subjects = vec![];
    for i in 0..3 {
        let subj = format!("atomic:rprt{:0>69}==", format!("{i}"));
        let mut r = crate::Resource::new(subj.clone());
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        r.set_unsafe(urls::NAME.into(), Value::String(format!("row{i}")))
            .unwrap();
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
        subjects.push(subj);
    }

    let mut query = Query::new_prop_val(urls::PARENT, table);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    assert_eq!(store.query(&query).await.unwrap().count, 3);

    let report = store.check_query_index(&query).unwrap();
    assert!(report.is_consistent(), "{report:?}");
    assert!(report.watched);
    assert_eq!((report.indexed, report.expected), (3, 3));

    // Drop one member from the index, and file one that is not a row.
    let q_filter = crate::db::query_index::QueryFilter::try_from_query(&query).unwrap();
    let ghost =
        "atomic:rprtGHOSTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let mut transaction = crate::db::trees::Transaction::new();
    let dropped = store
        .get_resource_shallow(&Subject::from(subjects[1].clone()))
        .unwrap();
    let sort_key = crate::db::query_index::sort_key_for(&dropped, urls::NAME);
    crate::db::query_index::update_indexed_member(
        &q_filter,
        &subjects[1],
        &sort_key,
        true,
        &mut transaction,
    )
    .unwrap();
    crate::db::query_index::update_indexed_member(
        &q_filter,
        ghost,
        &crate::db::query_index::encode_sort_value(Some(&Value::String("zzz".into()))),
        false,
        &mut transaction,
    )
    .unwrap();
    store.apply_transaction(&mut transaction).unwrap();

    let report = store.check_query_index(&query).unwrap();
    assert!(!report.is_consistent());
    assert_eq!(report.missing, vec![subjects[1].clone()]);
    assert_eq!(report.stale, vec![ghost.to_string()]);
    assert_eq!((report.indexed, report.expected), (3, 3));
}

/// A DID row cannot be routed to a drive by its subject, so every drive's
/// watched filters see it on commit. Its `drive` stamp is what keeps it out
/// of the drives it does not belong to — compared against the *root* the
/// filter's `drive` resolves to, since for a `did:` query that field is the
/// queried subject (a table), not the drive itself. Security audit C17.
#[tokio::test]
#[timeout(120000)]
async fn did_rows_stamped_into_another_drive_stay_out_of_a_watched_query() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_index_drive_stamp").await.unwrap();
    let drive_a =
        "did:ad:driveSTMPAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let drive_b =
        "did:ad:driveSTMPBaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table_a =
        "did:ad:tableSTMPAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let cls =
        "did:ad:classSTMPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    for drive in [drive_a, drive_b] {
        let mut d = crate::Resource::new(drive.into());
        d.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![crate::values::SubResource::Subject(
                urls::DRIVE.into(),
            )]),
        )
        .unwrap();
        store
            .add_resource_opts(&d, false, true, true)
            .await
            .unwrap();
    }
    let mut t = crate::Resource::new(table_a.into());
    t.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive_a.into()))
        .unwrap();
    t.set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive_a.into()))
        .unwrap();
    store
        .add_resource_opts(&t, false, true, true)
        .await
        .unwrap();

    let row = |name: &str, drive: Option<&str>| {
        let subj = format!("did:ad:stmp{name}{}==", "a".repeat(69 - name.len()));
        let mut r = crate::Resource::new(subj.clone());
        r.set_unsafe(
            urls::IS_A.into(),
            Value::ResourceArray(vec![crate::values::SubResource::Subject(cls.into())]),
        )
        .unwrap();
        r.set_unsafe(urls::NAME.into(), Value::String(name.into()))
            .unwrap();
        if let Some(drive) = drive {
            r.set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
                .unwrap();
        }
        (subj, r)
    };

    // Written before the query exists: the build path.
    let (in_a, r) = row("inA", Some(drive_a));
    store
        .add_resource_opts(&r, false, true, true)
        .await
        .unwrap();
    let (in_b, r) = row("inB", Some(drive_b));
    store
        .add_resource_opts(&r, false, true, true)
        .await
        .unwrap();
    let (unstamped, r) = row("noStamp", None);
    store
        .add_resource_opts(&r, false, true, true)
        .await
        .unwrap();

    // Every instance of the class, as seen from table A.
    let mut query = Query::new_class(cls);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(table_a.into());
    query.limit = Some(100);

    let found: Vec<String> = store
        .query(&query)
        .await
        .unwrap()
        .subjects
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    assert!(
        found.contains(&Subject::from(in_a.as_str()).pure_id()),
        "{found:?}"
    );
    assert!(
        !found.contains(&Subject::from(in_b.as_str()).pure_id()),
        "a row stamped into drive B is listed by drive A's query: {found:?}"
    );
    // No stamp is no evidence; read rights decide at query time.
    assert!(
        found.contains(&Subject::from(unstamped.as_str()).pure_id()),
        "{found:?}"
    );

    // Written while the query is watched: the commit path.
    let (in_a2, r) = row("inA2", Some(drive_a));
    store
        .add_resource_opts(&r, false, true, true)
        .await
        .unwrap();
    let (in_b2, r) = row("inB2", Some(drive_b));
    store
        .add_resource_opts(&r, false, true, true)
        .await
        .unwrap();

    let found: Vec<String> = store
        .query(&query)
        .await
        .unwrap()
        .subjects
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    assert!(
        found.contains(&Subject::from(in_a2.as_str()).pure_id()),
        "{found:?}"
    );
    assert!(
        !found.contains(&Subject::from(in_b2.as_str()).pure_id()),
        "a row committed into drive B reached drive A's watched query: {found:?}"
    );
    assert_eq!(found.len(), 3, "{found:?}");

    let report = store.check_query_index(&query).unwrap();
    assert!(report.is_consistent(), "{report:?}");
}

/// Narrows the previous failure: is the row rejected by the MATCHER
/// (`resource_matches_filter`, which decides membership) or never offered as a
/// CANDIDATE (`plan_candidate_iterator`, which decides what gets considered)?
/// The fix differs — one is a comparison bug, the other an index-atom bug.
#[tokio::test]
#[timeout(120000)]
async fn is_a_string_encoding_matcher_vs_candidates() {
    let cls = "atomic:classPROBEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut r = crate::Resource::new(
        "atomic:probe0000000000000000000000000000000000000000000000000000000000000000==".into(),
    );
    r.set_unsafe(urls::IS_A.into(), Value::String(cls.into()))
        .unwrap();

    let filter = crate::db::query_index::QueryFilter {
        filters: vec![crate::storelike::PropVal {
            property: Some(urls::IS_A.to_string()),
            value: Some(Value::AtomicUrl(cls.into())),
            ..Default::default()
        }],
        sort_by: None,
        drive:
            "atomic:drivePROBEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=="
                .into(),
    };

    assert!(
        crate::db::query_index::resource_matches_filter(&r, &filter),
        "a String-encoded isA naming the class should satisfy the constraint \
         (contains_value compares by string) — if this fails, the matcher is at fault"
    );

    // If the matcher accepts it, the row must also be OFFERED as a candidate,
    // i.e. its isA must produce an index atom the planner can find it by.
    let atoms: Vec<_> = crate::Atom::new(
        r.get_subject().clone(),
        urls::IS_A.into(),
        Value::String(cls.into()),
    )
    .to_indexable_atoms();
    assert!(
        atoms.iter().any(|a| a.ref_value == cls),
        "a String-encoded isA must yield an index atom keyed by the class \
         subject, else the planner can never surface the row. Got: {:?}",
        atoms
            .iter()
            .map(|a| a.ref_value.clone())
            .collect::<Vec<_>>()
    );
}

/// A query whose index holds *some* members is trusted, forever.
///
/// `query_complex` reconciles an index against reality exactly once, and only
/// when it comes back EMPTY (`total_count == 0 && !is_watched`). A partial
/// index is non-zero, so the rebuild never fires and the query keeps returning
/// a number that is wrong but entirely plausible. An unwatched filter's index
/// is by definition unmaintained — nothing has been keeping it current — so
/// however many entries it happens to hold, it is not evidence of anything.
#[tokio::test]
#[timeout(120000)]
async fn partial_index_for_an_unwatched_filter_is_rebuilt() {
    use crate::storelike::Query;

    let store = Db::init_temp("query_partial_rebuild").await.unwrap();
    let drive =
        "did:ad:drivePARTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "did:ad:tablePARTaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut t = crate::Resource::new(table.into());
    t.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    store
        .add_resource_opts(&t, false, true, true)
        .await
        .unwrap();

    let mut subjects = vec![];
    for i in 0..6 {
        let subj = format!("did:ad:part{:0>69}==", format!("{i}"));
        let mut r = crate::Resource::new(subj.clone());
        r.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        r.set_unsafe(urls::NAME.into(), Value::String(format!("row{i}")))
            .unwrap();
        store
            .add_resource_opts(&r, false, true, true)
            .await
            .unwrap();
        subjects.push(subj);
    }

    let mut query = Query::new_prop_val(urls::PARENT, table);
    query.sort_by = Some(urls::NAME.to_string());
    query.drive = Some(drive.into());
    query.limit = Some(100);
    query.for_agent = crate::agents::ForAgent::Sudo;

    let q_filter = crate::db::query_index::QueryFilter::try_from_query(&query).unwrap();

    // Seed a PARTIAL index for this filter without watching it: two of the six
    // members, as a build that stopped short would leave behind.
    let mut transaction = crate::db::trees::Transaction::new();
    for subj in subjects.iter().take(2) {
        let resource = store
            .get_resource_shallow(&crate::Subject::from(subj.clone()))
            .unwrap();
        let sort_key = crate::db::query_index::sort_key_for(&resource, urls::NAME);
        crate::db::query_index::update_indexed_member(
            &q_filter,
            subj,
            &sort_key,
            false,
            &mut transaction,
        )
        .unwrap();
    }
    store.apply_transaction(&mut transaction).unwrap();
    assert!(
        !q_filter.is_watched(&store),
        "precondition: the filter must be unwatched, so its index is unmaintained"
    );

    let res = store.query(&query).await.unwrap();
    assert_eq!(
        res.count, 6,
        "an unwatched filter's index is unmaintained; a partial one must be \
         rebuilt rather than believed. Got {} of 6",
        res.count
    );
}

#[tokio::test]
#[timeout(120000)]
async fn content_commits_are_not_stored() {
    let store = Db::init_temp("content_commits_are_not_stored")
        .await
        .unwrap();

    let mut resource = crate::Resource::new("did:ad:placeholder".into());
    resource
        .set(urls::NAME.into(), Value::String("first".into()), &store)
        .await
        .unwrap();
    let genesis = resource.save_as_genesis(&store).await.unwrap();
    let genesis_commit = genesis.commit_resource.get_subject().clone();
    let subject = genesis.resource_new.unwrap().get_subject().clone();

    assert!(
        store.get_resource(&genesis_commit).await.is_ok(),
        "genesis commits are always retained"
    );

    let mut resource = store.get_resource(&subject).await.unwrap();
    resource
        .set(urls::NAME.into(), Value::String("second".into()), &store)
        .await
        .unwrap();
    let content = resource.save_locally(&store).await.unwrap();
    let content_commit = content.commit_resource.get_subject().clone();
    assert_eq!(
        store
            .get_resource(&subject)
            .await
            .unwrap()
            .get(urls::NAME)
            .unwrap()
            .to_string(),
        "second",
        "dropping the commit row must not drop the resource state"
    );
    assert!(
        store.get_resource(&content_commit).await.is_err(),
        "ordinary content commits are not stored as resources"
    );

    let mut resource = store.get_resource(&subject).await.unwrap();
    let writer = store.get_default_agent().unwrap().subject.to_string();
    resource
        .set(urls::WRITE.into(), vec![writer].into(), &store)
        .await
        .unwrap();
    let acl = resource.save_locally(&store).await.unwrap();
    let acl_commit = acl.commit_resource.get_subject().clone();
    assert!(
        store.get_resource(&acl_commit).await.is_ok(),
        "rights-changing commits stay on the must-retain floor"
    );

    let mut resource = store.get_resource(&subject).await.unwrap();
    let destroy = resource.destroy(&store).await.unwrap();
    let destroy_commit = destroy.commit_resource.get_subject().clone();
    assert!(
        store.get_resource(&destroy_commit).await.is_ok(),
        "destroy commits stay on the must-retain floor"
    );

    // A creation that never set `isGenesis` (Rust `save_locally` on a fresh
    // subject, an agent's first commit, an HTTP-subject creation) is still
    // the commit that brought the resource into being, and is retained.
    let mut unflagged = crate::Resource::new("internal:/unflagged-creation".into());
    unflagged
        .set(urls::NAME.into(), Value::String("born".into()), &store)
        .await
        .unwrap();
    let created = unflagged.save_locally(&store).await.unwrap();
    assert_eq!(created.commit.is_genesis, None, "test premise: no flag");
    assert!(
        store
            .get_resource(created.commit_resource.get_subject())
            .await
            .is_ok(),
        "an unflagged creation commit is retained like a genesis"
    );
}

/// Cached external rows must keep their read grants in both query shapes.
#[tokio::test]
async fn cached_external_resources_keep_read_permissions() {
    let store = Db::init_temp("external_cache_permissions").await.unwrap();
    let (agent, drive) = store.setup("Cache owner").await.unwrap();
    let subject = Subject::from("https://private.example/cached-resource");
    let mut resource = Resource::new(subject.to_string());
    resource
        .set(
            urls::PARENT.into(),
            Value::AtomicUrl(drive.clone().into()),
            &store,
        )
        .await
        .unwrap();
    resource
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("private cached content".into()),
            &store,
        )
        .await
        .unwrap();
    // Same persistence entry point used for a fetched external resource.
    store
        .add_resource_opts(&resource, true, true, true)
        .await
        .unwrap();
    for include_nested in [false, true] {
        let mut query = Query {
            property: Some(urls::DESCRIPTION.into()),
            value: Some(Value::Markdown("private cached content".into())),
            include_external: true,
            include_nested,
            for_agent: ForAgent::Public,
            ..Query::default()
        };
        let public = store.query(&query).await.unwrap();
        assert!(public.subjects.is_empty());
        assert!(public.resources.is_empty());
        query.for_agent = ForAgent::AgentSubject(agent.subject.clone());
        let authorized = store.query(&query).await.unwrap();
        assert_eq!(authorized.subjects, vec![subject.clone()]);
        assert_eq!(authorized.resources.len(), usize::from(include_nested));
    }
    assert!(store
        .get_resource_extended(&subject, true, &ForAgent::Public)
        .await
        .is_err());
    assert!(store
        .get_resource_extended(&subject, true, &ForAgent::AgentSubject(agent.subject))
        .await
        .is_ok());
}

/// `Db::init_redb_file` must make writes durable on its own: the Flutter
/// binding opens a file store this way and never calls `flush`, and before
/// the library owned the tick every edit since the last drive switch was
/// rolled back on an app kill. Write, wait longer than the interval without
/// flushing, drop, reopen.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn file_store_writes_survive_reopen_without_an_explicit_flush() {
    let dir = std::env::temp_dir().join(format!(
        "atomic-durable-flush-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let uploads = dir.join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();

    let db = Db::init_redb_file(&dir, Some("https://localhost".into()), &uploads)
        .await
        .unwrap();
    db.kv
        .insert(trees::Tree::PluginMeta, b"survives", b"yes")
        .unwrap();
    tokio::time::sleep(DURABLE_FLUSH_INTERVAL * 4).await;
    drop(db);

    let db = Db::init_redb_file(&dir, Some("https://localhost".into()), &uploads)
        .await
        .unwrap();
    assert_eq!(
        db.kv.get(trees::Tree::PluginMeta, b"survives").unwrap(),
        Some(b"yes".to_vec())
    );
    drop(db);
    std::fs::remove_dir_all(&dir).ok();
}

/// A store filled before the rename holds `did:ad:X` rows. Opening it moves
/// them to `atomic:X`; after that, either spelling a caller passes names the
/// same row: writes do not fork, parent queries match either spelling, and
/// destroy replay sees a legacy commit id.
#[tokio::test]
#[timeout(120000)]
async fn canonical_scheme_store_boundary() {
    let store = Db::init_temp("canonical-scheme-boundary").await.unwrap();
    let legacy_drive = "did:ad:legacyDriveKey";
    let canon_drive = crate::identifiers::canonicalize_scheme(legacy_drive);
    assert_eq!(canon_drive, "atomic:legacyDriveKey");

    let mut pv = crate::resources::PropVals::new();
    pv.insert(urls::PARENT.into(), Value::AtomicUrl(legacy_drive.into()));
    pv.insert(urls::NAME.into(), Value::String("legacy child".into()));
    store
        .kv
        .insert(
            Tree::Resources,
            legacy_drive.as_bytes(),
            &encode_propvals(&pv).unwrap(),
        )
        .unwrap();
    // A commit a pre-rename store saved as `did:ad:commit:`.
    let sig = "legacyDestroySig";
    let legacy_commit = format!("did:ad:commit:{sig}");
    let canon_commit = crate::identifiers::commit_subject(sig);
    store
        .kv
        .insert(
            Tree::Resources,
            legacy_commit.as_bytes(),
            &encode_propvals(&crate::resources::PropVals::new()).unwrap(),
        )
        .unwrap();

    // Reopen as a pre-rename store: the rewrite runs on every open until its
    // marker is set.
    store
        .kv
        .remove(
            Tree::PluginMeta,
            super::canonical_scheme::SCHEME_REWRITE_KEY,
        )
        .unwrap();
    store.migrate_canonical_scheme_if_needed().unwrap();

    // Query-style parent match: either spelling of the drive finds the child.
    let kids_canon = store.get_children(&canon_drive, None).await.unwrap();
    let kids_legacy = store.get_children(legacy_drive, None).await.unwrap();
    assert_eq!(
        kids_canon.len(),
        1,
        "canonical parent must see the migrated child"
    );
    assert_eq!(kids_legacy.len(), 1, "legacy parent must see the child");

    // An edit under the canonical subject updates the one row, no fork.
    let mut resource = store
        .get_resource(&canon_drive.as_str().into())
        .await
        .unwrap();
    resource
        .set_string(urls::NAME.into(), "renamed", &store)
        .await
        .unwrap();
    store
        .add_resource_opts(&resource, false, true, true)
        .await
        .unwrap();

    assert!(
        store.has_resource_locally(&canon_drive),
        "canonical key present after write"
    );
    assert!(
        store.has_resource_locally(legacy_drive),
        "legacy spelling is normalized on lookup"
    );
    assert!(
        store
            .kv
            .get(Tree::Resources, canon_drive.as_bytes())
            .unwrap()
            .is_some(),
        "stored under atomic:"
    );
    assert!(
        store
            .kv
            .get(Tree::Resources, legacy_drive.as_bytes())
            .unwrap()
            .is_none(),
        "no did:ad: row after open"
    );

    // Destroy replay: the migrated commit is present under either spelling.
    assert!(store.has_resource_locally(&canon_commit));
    assert!(store.has_resource_locally(&legacy_commit));
}

#[tokio::test]
#[timeout(120000)]
async fn canonical_scheme_open_rewrites_legacy_keys() {
    let store = Db::init_temp("canonical-scheme-migrate").await.unwrap();
    let legacy = "did:ad:migrateMe";
    let canon = crate::identifiers::canonicalize_scheme(legacy);
    let mut pv = crate::resources::PropVals::new();
    pv.insert(
        urls::PARENT.into(),
        Value::AtomicUrl("did:ad:migrateParent".into()),
    );
    store
        .kv
        .insert(
            Tree::Resources,
            legacy.as_bytes(),
            &encode_propvals(&pv).unwrap(),
        )
        .unwrap();
    store
        .kv
        .remove(
            Tree::PluginMeta,
            super::canonical_scheme::SCHEME_REWRITE_KEY,
        )
        .unwrap();

    store.migrate_canonical_scheme_if_needed().unwrap();

    assert!(store
        .kv
        .get(Tree::Resources, canon.as_bytes())
        .unwrap()
        .is_some());
    assert!(store
        .kv
        .get(Tree::Resources, legacy.as_bytes())
        .unwrap()
        .is_none());
    let (_, rewritten) = store.get_propvals_canonical(&canon).unwrap();
    assert_eq!(
        rewritten.get(urls::PARENT).unwrap().to_string(),
        "atomic:migrateParent"
    );
}

/// Every tree that is looked up by canonical subject after the rename is
/// rewritten on open, not only the three a resource is read from.
#[tokio::test]
async fn canonical_scheme_open_rewrites_every_subject_keyed_tree() {
    let store = Db::init_temp("canonical-scheme-migrate-all").await.unwrap();
    let legacy = "did:ad:migrateAll";
    let canon = crate::identifiers::canonicalize_scheme(legacy);
    let legacy_agent = "did:ad:agent:migrateAgent";
    let canon_agent = crate::identifiers::canonicalize_scheme(legacy_agent);

    // Loro snapshot, keyed by subject; the bytes are opaque.
    store
        .kv
        .insert(Tree::LoroSnapshots, legacy.as_bytes(), b"snapshot")
        .unwrap();
    // DID mapping: a legacy key AND a legacy routing-hint value.
    store
        .kv
        .insert(Tree::DidMapping, legacy.as_bytes(), b"did:ad:migrateDrive")
        .unwrap();
    // Envelope: `{subject}\0{created_at be}\0{signature}`; signed JSON value.
    let mut envelope_key = legacy.as_bytes().to_vec();
    envelope_key.push(0);
    envelope_key.extend_from_slice(&42u64.to_be_bytes());
    envelope_key.push(0);
    envelope_key.extend_from_slice(b"sig");
    store
        .kv
        .insert(Tree::Envelopes, &envelope_key, b"{}")
        .unwrap();
    // Tombstone marker on the plugin-meta tree.
    let tombstone_key = format!("tombstone:{legacy}");
    store
        .kv
        .insert(Tree::PluginMeta, tombstone_key.as_bytes(), &[1])
        .unwrap();
    // An unrelated plugin-meta row must be left alone.
    store
        .kv
        .insert(Tree::PluginMeta, b"unrelated:did:ad:x", b"keep")
        .unwrap();
    // Outbox: `{agent}\0{subject}`, both halves legacy.
    let mut outbox_key = legacy_agent.as_bytes().to_vec();
    outbox_key.push(0);
    outbox_key.extend_from_slice(legacy.as_bytes());
    store
        .kv
        .insert(Tree::Outbox, &outbox_key, b"{\"subject\":\"x\"}")
        .unwrap();

    store
        .kv
        .remove(
            Tree::PluginMeta,
            super::canonical_scheme::SCHEME_REWRITE_KEY,
        )
        .unwrap();
    store.migrate_canonical_scheme_if_needed().unwrap();

    let get = |tree, key: &[u8]| store.kv.get(tree, key).unwrap();

    assert_eq!(
        get(Tree::LoroSnapshots, canon.as_bytes()),
        Some(b"snapshot".to_vec())
    );
    assert!(get(Tree::LoroSnapshots, legacy.as_bytes()).is_none());

    assert_eq!(
        get(Tree::DidMapping, canon.as_bytes()),
        Some(b"atomic:migrateDrive".to_vec()),
        "the routing hint value is canonical too"
    );
    assert!(get(Tree::DidMapping, legacy.as_bytes()).is_none());

    let mut canon_envelope_key = canon.as_bytes().to_vec();
    canon_envelope_key.extend_from_slice(&envelope_key[legacy.len()..]);
    assert_eq!(
        get(Tree::Envelopes, &canon_envelope_key),
        Some(b"{}".to_vec())
    );
    assert!(get(Tree::Envelopes, &envelope_key).is_none());

    let canon_tombstone = format!("tombstone:{canon}");
    assert_eq!(
        get(Tree::PluginMeta, canon_tombstone.as_bytes()),
        Some(vec![1])
    );
    assert!(get(Tree::PluginMeta, tombstone_key.as_bytes()).is_none());
    assert_eq!(
        get(Tree::PluginMeta, b"unrelated:did:ad:x"),
        Some(b"keep".to_vec())
    );

    let mut canon_outbox_key = canon_agent.as_bytes().to_vec();
    canon_outbox_key.push(0);
    canon_outbox_key.extend_from_slice(canon.as_bytes());
    assert!(get(Tree::Outbox, &canon_outbox_key).is_some());
    assert!(get(Tree::Outbox, &outbox_key).is_none());

    // Idempotent: a second open finds the flag and touches nothing.
    store.migrate_canonical_scheme_if_needed().unwrap();
    assert!(get(Tree::Outbox, &canon_outbox_key).is_some());
}

#[tokio::test]
async fn canonical_scheme_resumes_index_rebuild_after_rows_moved() {
    let store = Db::init_temp("canonical-scheme-resume-index")
        .await
        .unwrap();
    let mut pv = crate::resources::PropVals::new();
    pv.insert(
        urls::NAME.into(),
        Value::String("migrationresumeneedle".into()),
    );
    store
        .kv
        .insert(
            Tree::Resources,
            b"atomic:migrated",
            &encode_propvals(&pv).unwrap(),
        )
        .unwrap();
    // Simulate a stop after canonical rows were written and indexes cleared,
    // but before the completion marker was committed.
    store
        .kv
        .insert(
            Tree::PluginMeta,
            super::canonical_scheme::INDEX_REBUILD_PENDING_KEY,
            b"1",
        )
        .unwrap();
    store.clear_index().unwrap();
    store
        .kv
        .remove(
            Tree::PluginMeta,
            super::canonical_scheme::SCHEME_REWRITE_KEY,
        )
        .unwrap();
    store.migrate_canonical_scheme_if_needed().unwrap();
    let hits = store
        .search_hits("migrationresumeneedle", &Default::default())
        .unwrap();
    assert!(
        !hits.is_empty(),
        "restart must rebuild even when no rows remain to rename"
    );
}

/// A replica written with the snapshot the caller holds stores that snapshot
/// byte for byte, beside the row and its index entries. Rebuilding it from
/// the propvals instead would give the doc a fresh peer id, and the next
/// merge with the caller's real history would duplicate every value.
#[tokio::test]
#[timeout(120000)]
async fn replica_keeps_the_callers_snapshot() {
    let store = Db::init_temp("replica_keeps_snapshot").await.unwrap();
    let subject =
        "did:ad:snapKEEPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let mut authored = crate::Resource::new(subject.into());
    authored
        .set_unsafe(urls::NAME.into(), Value::String("kept".into()))
        .unwrap();
    let snapshot = authored.build_state_doc().unwrap().export_snapshot();
    let mut replica = crate::Resource::new(subject.into());
    replica
        .apply_state_doc(crate::loro::AtomicLoroDoc::from_snapshot(&snapshot).unwrap())
        .unwrap();

    store
        .persist_replicated_resource_with_snapshot(&replica, snapshot.clone())
        .await
        .unwrap();

    assert_eq!(
        store.get_loro_snapshot_bytes(subject),
        Some(snapshot),
        "the stored snapshot must be the caller's, not a re-seeded one"
    );
    let read = store.get_resource(&subject.into()).await.unwrap();
    assert_eq!(read.get(urls::NAME).unwrap().to_string(), "kept");
}

/// Persisting many replicas in one write stores each row and snapshot as
/// writing them one at a time would, and a subject named twice keeps its last
/// entry.
#[tokio::test]
#[timeout(120000)]
async fn replicas_written_in_a_batch_match_single_writes() {
    let store = Db::init_temp("replica_batch").await.unwrap();
    let make = |n: usize, name: &str| {
        let subject = format!("did:ad:batch{n:02}{}==", "a".repeat(70));
        let mut authored = crate::Resource::new(subject.clone());
        authored
            .set_unsafe(urls::NAME.into(), Value::String(name.into()))
            .unwrap();
        let snapshot = authored.build_state_doc().unwrap().export_snapshot();
        let mut replica = crate::Resource::new(subject.clone());
        replica
            .apply_state_doc(crate::loro::AtomicLoroDoc::from_snapshot(&snapshot).unwrap())
            .unwrap();
        (subject, replica, snapshot)
    };
    let (s0, r0, snap0) = make(0, "zero");
    let (s1, r1, snap1) = make(1, "one");
    let (s1b, r1b, snap1b) = make(1, "one again");
    assert_eq!(s1, s1b);

    store
        .persist_replicated_resources(vec![
            (r0, Some(snap0.clone())),
            (r1, Some(snap1)),
            (r1b, Some(snap1b.clone())),
        ])
        .await
        .unwrap();

    assert_eq!(store.get_loro_snapshot_bytes(&s0), Some(snap0));
    assert_eq!(store.get_loro_snapshot_bytes(&s1), Some(snap1b));
    let read0 = store.get_resource(&s0.as_str().into()).await.unwrap();
    let read1 = store.get_resource(&s1.as_str().into()).await.unwrap();
    assert_eq!(read0.get(urls::NAME).unwrap().to_string(), "zero");
    assert_eq!(read1.get(urls::NAME).unwrap().to_string(), "one again");
}

/// A replica that is written again with a changed value only re-indexes that
/// value, and the watched queries still follow it: a renamed row moves in a
/// sorted view, a row whose class changes leaves a class-filtered view, and a
/// re-put with nothing new leaves the index as it was.
#[tokio::test]
#[timeout(120000)]
async fn replica_edits_keep_watched_queries_current() {
    use crate::storelike::Query;

    let store = Db::init_temp("replica_edits_index").await.unwrap();
    let drive =
        "did:ad:driveEDITaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let table =
        "did:ad:tableEDITaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let cls =
        "did:ad:classEDITaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let other_cls =
        "did:ad:otherEDITaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut t = crate::Resource::new(table.into());
    t.set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    t.set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    store
        .add_resource_opts(&t, false, true, true)
        .await
        .unwrap();

    let replica = |i: usize, name: &str, class: &str| {
        let subj = format!("did:ad:edit{:0>69}==", format!("{i}"));
        let mut authored = crate::Resource::new(subj.clone());
        authored
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(table.into()))
            .unwrap();
        authored
            .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
        authored
            .set_unsafe(
                urls::IS_A.into(),
                Value::ResourceArray(vec![crate::values::SubResource::Subject(class.into())]),
            )
            .unwrap();
        authored
            .set_unsafe(urls::NAME.into(), Value::String(name.into()))
            .unwrap();
        let mut replica = crate::Resource::new(subj);
        replica
            .apply_state_doc(authored.build_state_doc().unwrap())
            .unwrap();
        replica
    };

    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        store
            .persist_replicated_resource(&replica(i, name, cls))
            .await
            .unwrap();
    }

    let mut sorted = Query::new_prop_val(urls::PARENT, table);
    sorted.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(cls.into())),
        ..Default::default()
    }];
    sorted.sort_by = Some(urls::NAME.to_string());
    sorted.drive = Some(drive.into());
    sorted.limit = Some(100);
    async fn names(store: &Db, q: &Query) -> Vec<String> {
        let res = store.query(q).await.unwrap();
        let mut out = Vec::new();
        for subject in &res.subjects {
            let r = store.get_resource(&subject.as_str().into()).await.unwrap();
            out.push(r.get(urls::NAME).unwrap().to_string());
        }
        out
    }
    assert_eq!(names(&store, &sorted).await, ["a", "b", "c"]);

    // Rename "a" to "z": it moves to the end of the sorted view.
    store
        .persist_replicated_resource(&replica(0, "z", cls))
        .await
        .unwrap();
    assert_eq!(names(&store, &sorted).await, ["b", "c", "z"]);

    // Change "b"'s class: it leaves the class-filtered view.
    store
        .persist_replicated_resource(&replica(1, "b", other_cls))
        .await
        .unwrap();
    assert_eq!(names(&store, &sorted).await, ["c", "z"]);

    // The same state again changes nothing.
    store
        .persist_replicated_resource(&replica(2, "c", cls))
        .await
        .unwrap();
    assert_eq!(names(&store, &sorted).await, ["c", "z"]);
}

/// A replica row written from JSON-AD keeps the properties this store has no
/// definition for, and empty arrays, when the caller hands over the snapshot.
/// The parser skips a property it cannot type, and the row
/// `getResourceWithSnapshot` serves must still say what the document says.
#[tokio::test]
#[timeout(60000)]
async fn replica_row_keeps_unresolvable_props_from_snapshot() {
    let store = Db::init_temp("replica_row_unresolvable").await.unwrap();
    let subject =
        "did:ad:rowUNKNOWNaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    // A schema term of some drive this store has never seen.
    let unknown =
        "did:ad:propUNKNOWNaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    // Emptied after having had a member.
    let emptied =
        "did:ad:propEMPTIEDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut authored = crate::Resource::new(subject.into());
    authored
        .set_unsafe(urls::NAME.into(), Value::String("automation".into()))
        .unwrap();
    authored
        .set_unsafe(urls::REQUIRES.into(), Value::ResourceArray(vec![]))
        .unwrap();
    authored
        .set_unsafe(unknown.into(), Value::ResourceArray(vec![]))
        .unwrap();
    let doc = authored.build_state_doc().unwrap();
    doc.push_to_loro_list(emptied, &serde_json::json!("https://example.com/member"))
        .unwrap();
    doc.commit();
    doc.clear_loro_list(emptied).unwrap();
    doc.commit();
    let snapshot = doc.export_snapshot();
    let json_ad = serde_json::json!({
        "@id": subject,
        urls::NAME: "automation",
        urls::REQUIRES: [],
        unknown: [],
        emptied: [],
    })
    .to_string();

    let mut parsed = crate::parse::parse_json_ad_resource(
        &json_ad,
        &store,
        &crate::parse::ParseOpts {
            skip_unknown_props: true,
            save: crate::parse::SaveOpts::DontSave,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // The premise: the parser drops what it cannot type.
    assert!(parsed.get(unknown).is_err());

    let keys: Vec<String> = [urls::NAME, urls::REQUIRES, unknown, emptied]
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(parsed.restore_props_from_snapshot(&keys, &snapshot), 2);
    store
        .persist_replicated_resource_with_snapshot(&parsed, snapshot)
        .await
        .unwrap();

    let row = store.get_resource_shallow(&subject.into()).unwrap();
    assert_eq!(row.get(urls::NAME).unwrap().to_string(), "automation");
    for prop in [urls::REQUIRES, unknown, emptied] {
        match row.get(prop) {
            Ok(Value::ResourceArray(items)) => assert!(items.is_empty(), "{prop}"),
            other => panic!("{prop} should be an empty array, got {other:?}"),
        }
    }
}

/// A critical commit's `Tree::Resources` row is self-contained: its blob
/// keeps the signed `loroUpdate` (a CRDT resource's blob drops it in favour
/// of `Tree::LoroSnapshots`). A creation's commit is not in the atom indexes;
/// it is found by its id. See `envelopes::tests::
/// stored_genesis_commit_keeps_its_signed_payload_after_a_later_edit` for
/// why the payload cannot be borrowed from the envelope.
#[tokio::test]
#[timeout(120000)]
async fn commit_resource_blob_keeps_loro_update_and_is_not_indexed() {
    let store = Db::init_temp("commit_row_self_contained").await.unwrap();
    let (_alice, drive) = store.setup("Alice").await.unwrap();
    let subject = store
        .create_resource(urls::CLASS, &drive, "Doc", None)
        .await
        .unwrap();
    let subject = Subject::from_raw(&subject, None);
    let genesis_id = crate::envelopes::latest_envelope(&store, subject.as_str())
        .unwrap()
        .commit_id();

    let commit_blob = store
        .kv
        .get(Tree::Resources, genesis_id.as_bytes())
        .unwrap()
        .expect("a genesis commit keeps its Tree::Resources row");
    assert!(
        matches!(
            decode_propvals(&commit_blob).unwrap().get(urls::LORO_UPDATE),
            Some(Value::LoroDoc(bytes)) if !bytes.is_empty()
        ),
        "the commit row keeps its signed loroUpdate"
    );
    assert!(
        store
            .kv
            .get(Tree::LoroSnapshots, genesis_id.as_bytes())
            .unwrap()
            .is_none(),
        "a commit has no CRDT snapshot of its own"
    );

    let resource_blob = store
        .kv
        .get(Tree::Resources, subject.pure_id().as_bytes())
        .unwrap()
        .unwrap();
    assert!(
        !decode_propvals(&resource_blob)
            .unwrap()
            .contains_key(urls::LORO_UPDATE),
        "an ordinary row is a projection without loroUpdate"
    );

    let found = store
        .query(&Query::new_prop_val(urls::SUBJECT, subject.as_str()))
        .await
        .unwrap();
    assert!(
        !found
            .subjects
            .iter()
            .any(|s| s.as_str() == genesis_id.as_str()),
        "a creation's commit is found by its id, not by the subject index: {:?}",
        found.subjects
    );
}

/// A pulled batch is merged and stored in one write, and a state that does not
/// decode is skipped without failing the rest.
#[tokio::test]
#[timeout(120000)]
async fn apply_state_updates_stores_a_batch_and_skips_garbage() {
    let store = Db::init_temp("apply_state_updates_batch").await.unwrap();
    let drive =
        "did:ad:driveBATCHaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let state = |i: usize| {
        let subj = format!("did:ad:batch{:0>67}==", format!("{i}"));
        let mut authored = crate::Resource::new(subj.clone());
        authored
            .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
        authored
            .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
            .unwrap();
        authored
            .set_unsafe(urls::NAME.into(), Value::String(format!("row {i}")))
            .unwrap();
        (subj, authored.build_state_doc().unwrap().export_snapshot())
    };

    let mut items: Vec<(String, Vec<u8>)> = (0..3).map(state).collect();
    items.push(("did:ad:garbage".to_string(), vec![1, 2, 3, 4, 5]));

    let applied = crate::sync::ws_apply::apply_state_updates(&store, &items, false)
        .await
        .unwrap();

    assert_eq!(applied, 3);

    for (i, (subj, _)) in items.iter().take(3).enumerate() {
        let stored = store
            .get_resource(&crate::Subject::from_raw(subj, None))
            .await
            .unwrap();
        assert_eq!(
            stored.get(urls::NAME).unwrap().to_string(),
            format!("row {i}")
        );
    }
}

/// Bulk-pulled resources can be stored without search entries and indexed
/// later, after which search finds them.
#[tokio::test]
#[timeout(120000)]
async fn deferred_search_entries_are_added_by_index_pending() {
    let store = Db::init_temp("deferred_search").await.unwrap();
    let drive =
        "did:ad:driveDEFERaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";
    let subj = "did:ad:defer00000000000000000000000000000000000000000000000000000000000000000==";
    let mut authored = crate::Resource::new(subj.to_string());
    authored
        .set_unsafe(urls::PARENT.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    authored
        .set_unsafe(urls::DRIVE_PROP.into(), Value::AtomicUrl(drive.into()))
        .unwrap();
    authored
        .set_unsafe(
            urls::NAME.into(),
            Value::String("zebrafish handbook".into()),
        )
        .unwrap();
    let state = authored.build_state_doc().unwrap().export_snapshot();
    let items = vec![(subj.to_string(), state)];

    crate::sync::ws_apply::apply_state_updates(&store, &items, true)
        .await
        .unwrap();

    let opts = crate::client::search::SearchOpts::default();
    assert!(store.search_hits("zebrafish", &opts).unwrap().is_empty());

    assert_eq!(crate::search::index_pending(&store, 10).await.unwrap(), 1);
    assert_eq!(crate::search::index_pending(&store, 10).await.unwrap(), 0);
    assert_eq!(store.search_hits("zebrafish", &opts).unwrap().len(), 1);
}

#[tokio::test]
async fn removing_an_atom_also_removes_rows_an_older_store_wrote() {
    use crate::db::trees::{Method, Operation, Transaction, Tree};
    let store = Db::init_temp("legacy_atom_rows").await.unwrap();
    let atom = crate::atoms::IndexAtom {
        subject: Subject::from("did:ad:legacy-subject"),
        // Not a core property: its key part is the same in old and new stores, so
        // the reader finds the old row. A core property's old row has the full URL
        // in its key and is rebuilt by `migrate_index_keys` instead.
        property: "https://example.com/properties/legacy".to_string(),
        ref_value: "Legacy Title".to_string(),
        sort_value: "Legacy Title".to_string(),
    };
    let legacy_pvs = crate::db::prop_val_sub_index::propvalsub_legacy_key(&atom);
    let legacy_vps = crate::db::val_prop_sub_index::valpropsub_legacy_key(&atom);
    let mut tx = Transaction::new();
    for (tree, key) in [
        (Tree::PropValSub, &legacy_pvs),
        (Tree::ValPropSub, &legacy_vps),
    ] {
        tx.push(Operation {
            tree,
            method: Method::Insert,
            key: key.clone(),
            val: Some(Vec::new()),
        });
    }
    store.apply_transaction(&mut tx).unwrap();
    // An old row is still read back as the same atom.
    let found: Vec<_> = crate::db::prop_val_sub_index::find_in_prop_val_sub_index(
        &store,
        "https://example.com/properties/legacy",
        Some(&Value::String("Legacy Title".into())),
    )
    .map(|a| a.unwrap())
    .collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].sort_value, "Legacy Title");

    let mut tx = Transaction::new();
    for op in Operation::remove_atom_from_legacy_indexes(&atom) {
        tx.push(op);
    }
    store.apply_transaction(&mut tx).unwrap();
    assert!(store
        .kv
        .get(Tree::PropValSub, &legacy_pvs)
        .unwrap()
        .is_none());
    assert!(store
        .kv
        .get(Tree::ValPropSub, &legacy_vps)
        .unwrap()
        .is_none());
}

/// An `after_commit` extender runs after the commit is persisted, so its
/// failure must not turn into a failed commit: the client would retry or show
/// an error for a change that was saved. The error is logged instead, and the
/// extenders registered after the failing one still run. (#1848)
#[tokio::test]
#[timeout(120000)]
async fn failing_after_commit_does_not_fail_a_saved_commit() {
    use crate::class_extender::ClassExtender;
    use crate::commit::{CommitBuilder, CommitOpts};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const CLASS: &str = "did:ad:afterCommitFailureTestClass";

    let store = Db::init_temp("after_commit_failure").await.unwrap();
    let agent = store.create_agent(Some("test-agent")).await.unwrap();
    store.set_default_agent(agent.clone());

    store
        .add_class_extender(
            ClassExtender::builder()
                .id("failing")
                .class(CLASS)
                .after_commit_fn(|_ctx| Box::pin(async { Err("after_commit exploded".into()) }))
                .build(),
        )
        .unwrap();

    let later_ran = Arc::new(AtomicBool::new(false));
    let flag = later_ran.clone();
    store
        .add_class_extender(
            ClassExtender::builder()
                .id("later")
                .class(CLASS)
                .after_commit_fn(move |_ctx| {
                    let flag = flag.clone();
                    Box::pin(async move {
                        flag.store(true, Ordering::SeqCst);
                        Ok(())
                    })
                })
                .build(),
        )
        .unwrap();

    let mut builder = CommitBuilder::new("placeholder".into());
    builder.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![Subject::from(CLASS).into()]),
    );
    builder.set(urls::NAME.into(), Value::String("saved anyway".into()));
    let commit = crate::commit::Commit::create_did(builder, &agent, &store)
        .await
        .unwrap();
    let subject = commit.subject.clone();

    let result = store
        .apply_commit(commit, &CommitOpts::no_validations_no_index())
        .await;
    assert!(
        result.is_ok(),
        "a failing after_commit must not fail a persisted commit: {:?}",
        result.err()
    );

    let stored = store.get_resource(&subject).await.unwrap();
    assert_eq!(stored.get(urls::NAME).unwrap().to_string(), "saved anyway");
    assert!(
        later_ran.load(Ordering::SeqCst),
        "the extender after the failing one should still run"
    );
}

/// A table row is indexed by `createdAt` while it has no `sortOrder`, and is
/// given one by a later commit (Shift+Enter inserts a row between two others).
/// The old `createdAt` entry must go: left behind, the row is listed at its
/// creation time instead of where its `sortOrder` puts it.
#[tokio::test]
#[timeout(120000)]
async fn sort_order_added_by_a_later_commit_replaces_the_created_at_entry() {
    use crate::commit::{Commit, CommitBuilder, CommitOpts};

    let store = Db::init_temp("sort_order_later_commit").await.unwrap();
    let agent = store.create_agent(Some("test-agent")).await.unwrap();
    store.set_default_agent(agent.clone());
    let drive_did = store.create_drive("Test Drive").await.unwrap();
    let row_class = "https://atomicdata.dev/classes/Test";

    let opts = CommitOpts {
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    // A table row is a draft first (parent and class only) and gets its
    // content, with its sortOrder, in a later commit.
    let mut rows: Vec<(Subject, String)> = Vec::new();
    for _ in 0..3 {
        let mut b = CommitBuilder::new("placeholder".into());
        b.set(
            urls::PARENT.into(),
            Value::AtomicUrl(drive_did.clone().into()),
        );
        b.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![row_class.into()]),
        );
        let commit = Commit::create_did(b, &agent, &store).await.unwrap();
        let subject = commit.subject.clone();
        let result = store.apply_commit(commit, &opts).await.unwrap();
        rows.push((subject, result.commit_resource.get_subject().to_string()));
        // createdAt has millisecond resolution.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    let mut query = crate::storelike::Query::new_prop_val(urls::PARENT, &drive_did);
    query.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(row_class.into())),
        ..Default::default()
    }];
    query.sort_by = Some(urls::SORT_ORDER.to_string());
    query.drive = Some(drive_did.clone().into());
    query.limit = Some(100);

    // Builds and watches the index: creation order.
    let before = store.query(&query).await.unwrap();
    assert_eq!(before.subjects.len(), 3, "got {:?}", before.subjects);

    // Give the first row a sortOrder far above every createdAt: it must go
    // last.
    let (subject, previous) = rows[0].clone();
    let stored = store.get_resource(&subject).await.unwrap();
    let mut b = CommitBuilder::new(subject.clone());
    b.set(urls::NAME.into(), Value::String("first".into()));
    b.set(urls::SORT_ORDER.into(), Value::Float(1.0e18));
    b.set_previous_commit(previous);
    let commit = b.sign(&agent, &store, &stored).await.unwrap();
    store.apply_commit(commit, &opts).await.unwrap();

    let after = store.query(&query).await.unwrap();
    let order: Vec<String> = after.subjects.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        order.last().map(String::as_str),
        Some(subject.as_str()),
        "the row with the big sortOrder must list last, got {order:?}"
    );
    assert_eq!(order.len(), 3, "no duplicate entries, got {order:?}");
}

/// Shift+Enter in a table: the third row is created after the first query
/// built the index and carries a `sortOrder` between the other two, so it must
/// list between them.
#[tokio::test]
#[timeout(120000)]
async fn row_inserted_between_two_others_after_the_index_was_built_lists_between_them() {
    use crate::commit::{Commit, CommitBuilder, CommitOpts};
    let store = Db::init_temp("zz_insert").await.unwrap();
    let agent = store.create_agent(Some("test-agent")).await.unwrap();
    store.set_default_agent(agent.clone());
    let drive_did = store.create_drive("Test Drive").await.unwrap();
    let row_class = "https://atomicdata.dev/classes/Test";
    let opts = CommitOpts {
        update_index: true,
        ..CommitOpts::no_validations_no_index()
    };
    let now = 1_791_033_284_445.0_f64;
    let mut subjects = Vec::new();
    for (i, v) in [now, now + 265.0, now + 130.0].into_iter().enumerate() {
        if i == 2 {
            let mut q = crate::storelike::Query::new_prop_val(urls::PARENT, &drive_did);
            q.filters = vec![crate::storelike::PropVal {
                property: Some(urls::IS_A.to_string()),
                value: Some(Value::AtomicUrl(row_class.into())),
                ..Default::default()
            }];
            q.sort_by = Some(urls::SORT_ORDER.to_string());
            q.drive = Some(drive_did.clone().into());
            q.limit = Some(100);
            // Builds and watches the index with the first two rows in it.
            let first = store.query(&q).await.unwrap();
            assert_eq!(first.subjects.len(), 2);
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let doc = loro::LoroDoc::new();
        let props = doc.get_map("properties");
        props.insert(urls::PARENT, drive_did.as_str()).unwrap();
        props.insert(urls::SORT_ORDER, v).unwrap();
        let list = props
            .insert_container(urls::IS_A, loro::LoroList::new())
            .unwrap();
        list.push(row_class).unwrap();
        doc.commit();
        let mut b = CommitBuilder::new("placeholder".into());
        b.set_loro_update(doc.export(loro::ExportMode::Snapshot).unwrap());
        let commit = Commit::create_did(b, &agent, &store).await.unwrap();
        subjects.push(commit.subject.clone());
        store.apply_commit(commit, &opts).await.unwrap();
    }
    let mut q = crate::storelike::Query::new_prop_val(urls::PARENT, &drive_did);
    q.filters = vec![crate::storelike::PropVal {
        property: Some(urls::IS_A.to_string()),
        value: Some(Value::AtomicUrl(row_class.into())),
        ..Default::default()
    }];
    q.sort_by = Some(urls::SORT_ORDER.to_string());
    q.drive = Some(drive_did.clone().into());
    q.limit = Some(100);
    let res = store.query(&q).await.unwrap();
    let order: Vec<String> = res.subjects.iter().map(|s| s.to_string()).collect();
    let expect: Vec<String> = [0, 2, 1].iter().map(|i| subjects[*i].to_string()).collect();
    assert_eq!(order, expect);
}

/// Prints where the bytes of a 50-message chat go, per tree, with the
/// compressed trees counted as stored. Run with `--ignored --nocapture`.
#[tokio::test]
#[ignore = "measurement, not a check"]
async fn measure_chat_message_bytes() {
    let store = Db::init_temp("measure_chat").await.unwrap();
    let mut chat = Resource::new("did:ad:placeholder".into());
    chat.set(urls::NAME.into(), Value::String("Chat".into()), &store)
        .await
        .unwrap();
    chat.set(
        urls::IS_A.into(),
        Value::ResourceArray(vec![urls::CHATROOM.into()]),
        &store,
    )
    .await
    .unwrap();
    let chat = chat
        .save_as_genesis(&store)
        .await
        .unwrap()
        .resource_new
        .unwrap();
    let parent = chat.get_subject().clone();
    let trees = [
        Tree::Resources,
        Tree::LoroSnapshots,
        Tree::Envelopes,
        Tree::PropValSub,
        Tree::ValPropSub,
        Tree::QueryMembers,
        Tree::WatchedQueries,
        Tree::SearchPostings,
        Tree::SearchDocs,
        Tree::SearchTrigrams,
        Tree::DidMapping,
        Tree::DriveMapping,
        Tree::Outbox,
    ];
    let stored = super::compressed_kv::CompressedKv::new(store.kv.clone());
    let tally = |store: &Db| {
        trees
            .iter()
            .map(|t| {
                let (mut n, mut k, mut v) = (0usize, 0usize, 0usize);
                for kv in store.kv.iter_tree(*t) {
                    let (key, val) = kv.unwrap();
                    n += 1;
                    k += key.len();
                    v += if super::compressed_kv::is_compressed_tree(*t) {
                        stored.encoded(*t, &key, &val, &[]).len()
                    } else {
                        val.len()
                    };
                }
                (*t, n, k, v)
            })
            .collect::<Vec<_>>()
    };
    let before = tally(&store);
    const N: usize = 50;
    let mut last = None;
    for i in 0..N {
        let mut msg = Resource::new("did:ad:placeholder".into());
        msg.set(
            urls::PARENT.into(),
            Value::AtomicUrl(parent.clone()),
            &store,
        )
        .await
        .unwrap();
        msg.set(
            urls::IS_A.into(),
            Value::ResourceArray(vec![urls::MESSAGE.into()]),
            &store,
        )
        .await
        .unwrap();
        msg.set(
            urls::DESCRIPTION.into(),
            Value::Markdown(format!("Hallo dit is bericht nummer {i}, een gewone zin.")),
            &store,
        )
        .await
        .unwrap();
        let r = msg.save_as_genesis(&store).await.unwrap();
        last = r.resource_new;
    }
    let after = tally(&store);
    println!(
        "{:<16}{:>6}{:>10}{:>10}{:>10}",
        "tree", "rows", "key B", "val B", "B/msg"
    );
    let mut total = 0;
    for (b, a) in before.iter().zip(after.iter()) {
        let rows = a.1 - b.1;
        let kb = a.2 - b.2;
        let vb = a.3 - b.3;
        total += kb + vb;
        println!(
            "{:<16}{:>6}{:>10}{:>10}{:>10}",
            format!("{:?}", a.0),
            rows,
            kb,
            vb,
            (kb + vb) / N
        );
    }
    println!("TOTAL per message: {}", total / N);
    let _ = last;
}

/// A drive with a chat in it, and the agent that owns both.
async fn chat_log_world(id: &str) -> (Db, crate::agents::Agent, String) {
    let store = Db::init_temp(id).await.unwrap();
    let (agent, drive) = store.setup("Alice").await.unwrap();
    let chat = store
        .create_resource(urls::CHATROOM, &drive, "Chat", None)
        .await
        .unwrap();
    (store, agent, chat)
}

fn chat_log_opts(agent: &crate::agents::Agent) -> crate::commit::CommitOpts {
    crate::commit::CommitOpts {
        validate_signature: true,
        validate_rights: true,
        validate_for_agent: Some(agent.subject.to_string()),
        update_index: true,
        ..crate::commit::CommitOpts::no_validations_no_index()
    }
}

/// A `ChatLog` page under `chat`, created through the real commit path.
async fn create_chat_log_page(store: &Db, agent: &crate::agents::Agent, chat: &str) -> Subject {
    let doc = crate::loro::AtomicLoroDoc::new();
    let parent = Value::AtomicUrl(chat.into());
    doc.set_property(
        urls::IS_A,
        &Value::ResourceArray(vec![urls::CHAT_LOG.into()]),
    )
    .unwrap();
    doc.set_property(urls::PARENT, &parent).unwrap();
    let mut builder = crate::commit::CommitBuilder::new("placeholder".into());
    builder.set(urls::PARENT.into(), parent);
    builder.set_loro_update(doc.export_snapshot());
    let commit = crate::Commit::create_did(builder, agent, store)
        .await
        .unwrap();
    let subject = commit.subject.clone();
    store
        .apply_commit(commit, &chat_log_opts(agent))
        .await
        .unwrap();
    subject
}

/// Appends one entry to `page` as one signed commit, through the real path.
/// `doc` is the client's copy of the page; keep it between calls for a stable
/// Loro peer, like a real client has.
async fn append_chat_log_entry(
    store: &Db,
    agent: &crate::agents::Agent,
    page: &Subject,
    doc: &crate::loro::AtomicLoroDoc,
    text: &str,
) {
    let resource = store.get_resource(page).await.unwrap();
    let vv = doc.oplog_vv();
    doc.add_entry(&crate::chat_log::Entry::new(
        agent.subject.to_string(),
        text,
        crate::utils::now(),
    ))
    .unwrap();
    doc.commit();
    let mut builder = crate::commit::CommitBuilder::new(page.clone());
    builder.set_loro_update(doc.export_updates_since(&vv));
    let commit = builder.sign(agent, store, &resource).await.unwrap();
    store
        .apply_commit(commit, &chat_log_opts(agent))
        .await
        .unwrap();
}

/// Chat log entries live only in the page's Loro document: no propval, no
/// index row, no search posting.
#[tokio::test]
async fn chat_log_entries_are_not_materialized_indexed_or_searched() {
    let (store, agent, chat) = chat_log_world("chat_log_not_indexed").await;
    let page = create_chat_log_page(&store, &agent, &chat).await;
    let needle = "zyxwvuttsrqpon";
    let doc = store
        .get_resource(&page)
        .await
        .unwrap()
        .build_state_doc()
        .unwrap();
    append_chat_log_entry(
        &store,
        &agent,
        &page,
        &doc,
        &format!("hello {needle} world"),
    )
    .await;

    let resource = store.get_resource(&page).await.unwrap();
    assert_eq!(resource.build_state_doc().unwrap().list_entries().len(), 1);
    for (prop, val) in resource.get_propvals() {
        if prop == urls::LORO_UPDATE {
            continue;
        }
        assert!(!prop.contains("entries"), "{prop}");
        assert!(!val.to_string().contains(needle), "{prop} holds the text");
    }

    // The text sits in the snapshot (compressed) and nowhere else.
    for tree in [
        Tree::PropValSub,
        Tree::ValPropSub,
        Tree::QueryMembers,
        Tree::WatchedQueries,
        Tree::SearchPostings,
        Tree::SearchDocs,
        Tree::SearchTrigrams,
    ] {
        for kv in store.kv.iter_tree(tree) {
            let (key, val) = kv.unwrap();
            let holds = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle.as_bytes());
            assert!(
                !holds(&key) && !holds(&val),
                "{tree:?} holds the entry text"
            );
        }
    }
}

/// Prints where the bytes of a chat go per tree when every message is one
/// entry of a `ChatLog` page of 256, one signed commit per message, through
/// the real commit path. Compare with `measure_chat_message_bytes`. Run with
/// `--ignored --nocapture`.
#[tokio::test]
#[ignore = "measurement, not a check"]
async fn measure_chat_log_entry_bytes() {
    const N: usize = 500;
    const PAGE: usize = 256;
    let (store, agent, chat) = chat_log_world("measure_chat_log").await;
    let trees = [
        Tree::Resources,
        Tree::LoroSnapshots,
        Tree::Envelopes,
        Tree::PropValSub,
        Tree::ValPropSub,
        Tree::QueryMembers,
        Tree::WatchedQueries,
        Tree::SearchPostings,
        Tree::SearchDocs,
        Tree::SearchTrigrams,
        Tree::DidMapping,
        Tree::DriveMapping,
        Tree::Outbox,
    ];
    let stored = super::compressed_kv::CompressedKv::new(store.kv.clone());
    let tally = |store: &Db| {
        trees
            .iter()
            .map(|t| {
                let (mut n, mut k, mut v) = (0usize, 0usize, 0usize);
                for kv in store.kv.iter_tree(*t) {
                    let (key, val) = kv.unwrap();
                    n += 1;
                    k += key.len();
                    v += if super::compressed_kv::is_compressed_tree(*t) {
                        stored.encoded(*t, &key, &val, &[]).len()
                    } else {
                        val.len()
                    };
                }
                (*t, n, k, v)
            })
            .collect::<Vec<_>>()
    };
    let before = tally(&store);
    let mut page = create_chat_log_page(&store, &agent, &chat).await;
    let mut doc = store
        .get_resource(&page)
        .await
        .unwrap()
        .build_state_doc()
        .unwrap();
    for i in 0..N {
        if i > 0 && i % PAGE == 0 {
            page = create_chat_log_page(&store, &agent, &chat).await;
            doc = store
                .get_resource(&page)
                .await
                .unwrap()
                .build_state_doc()
                .unwrap();
        }
        append_chat_log_entry(
            &store,
            &agent,
            &page,
            &doc,
            &format!("Hallo dit is bericht nummer {i}, een gewone zin."),
        )
        .await;
    }
    let after = tally(&store);
    // What the page's document weighs raw, and how much of it is the server's
    // own bookkeeping (`lastCommit` is restamped on every commit).
    let first = store
        .get_resource(&page)
        .await
        .unwrap()
        .build_state_doc()
        .unwrap();
    println!(
        "last page: {} entries, raw snapshot {} B, {} B/entry; properties: {:?}",
        first.entries().len(),
        first.export_snapshot().len(),
        first.export_snapshot().len() / first.entries().len().max(1),
        first.get_all_properties().keys().collect::<Vec<_>>()
    );
    println!(
        "{:<16}{:>6}{:>10}{:>10}{:>10}",
        "tree", "rows", "key B", "val B", "B/msg"
    );
    let mut total = 0;
    for (b, a) in before.iter().zip(after.iter()) {
        let rows = a.1 as i64 - b.1 as i64;
        let kb = a.2 as i64 - b.2 as i64;
        let vb = a.3 as i64 - b.3 as i64;
        total += kb + vb;
        println!(
            "{:<16}{:>6}{:>10}{:>10}{:>10}",
            format!("{:?}", a.0),
            rows,
            kb,
            vb,
            (kb + vb) / N as i64
        );
    }
    println!(
        "TOTAL per message ({N} messages, pages of {PAGE}): {}",
        total / N as i64
    );
}

/// A snapshot is stored as the changes after the genesis commit, and read
/// back as the same document, also after later edits.
#[tokio::test]
#[timeout(120000)]
async fn snapshot_is_stored_as_a_delta_on_the_genesis_commit() {
    let store = Db::init_temp("snapshot_delta").await.unwrap();
    let mut resource = Resource::new("did:ad:placeholder".into());
    resource
        .set(urls::NAME.into(), Value::String("hallo".into()), &store)
        .await
        .unwrap();
    resource
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("een gewone zin".into()),
            &store,
        )
        .await
        .unwrap();
    let response = resource.save_as_genesis(&store).await.unwrap();
    let subject = response.resource_new.unwrap().get_subject().clone();
    let key = subject.pure_id();

    let snapshot = store
        .kv
        .get(Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    let stored = super::compressed_kv::CompressedKv::new(store.kv.clone());
    let packed = stored.encoded(Tree::LoroSnapshots, key.as_bytes(), &snapshot, &[]);
    assert_eq!(
        &packed[..2],
        &[0, 2],
        "a fresh resource's snapshot is a delta"
    );
    assert!(
        packed.len() * 2 < snapshot.len(),
        "{} vs {}",
        packed.len(),
        snapshot.len()
    );

    let read = store.get_resource(&subject).await.unwrap();
    assert_eq!(read.get(urls::NAME).unwrap().to_string(), "hallo");

    // Edits sit on top of the genesis and survive a read.
    let mut edit = store.get_resource(&subject).await.unwrap();
    edit.set(urls::NAME.into(), Value::String("edited".into()), &store)
        .await
        .unwrap();
    edit.save_locally(&store).await.unwrap();
    let read = store.get_resource(&subject).await.unwrap();
    assert_eq!(read.get(urls::NAME).unwrap().to_string(), "edited");
    assert_eq!(
        read.get(urls::DESCRIPTION).unwrap().to_string(),
        "een gewone zin"
    );

    // Without the genesis commit there is nothing to be a delta on, so the
    // whole snapshot is kept.
    let snapshot = store
        .kv
        .get(Tree::LoroSnapshots, key.as_bytes())
        .unwrap()
        .unwrap();
    let orphan = stored.encoded(
        Tree::LoroSnapshots,
        b"atomic:no-such-genesis",
        &snapshot,
        &[],
    );
    assert_ne!(orphan.get(1), Some(&2), "no base, no delta");
    assert_eq!(
        stored
            .get(Tree::LoroSnapshots, key.as_bytes())
            .unwrap()
            .unwrap(),
        snapshot
    );
}

// --- Lenses: derived values at materialization ---

mod lenses {
    use super::*;
    use crate::commit::{Commit, CommitBuilder, CommitOpts};
    use crate::datatype::DataType;
    use crate::lens::lens_id;
    use crate::property_identity::property_id;
    use crate::Resource;

    const PARENT: &str = "atomic:ontologylens0";

    fn opts() -> CommitOpts {
        CommitOpts {
            update_index: true,
            ..CommitOpts::no_validations_no_index()
        }
    }

    async fn make_property(
        db: &Db,
        agent: &crate::agents::Agent,
        parent: &str,
        shortname: &str,
    ) -> String {
        let id = property_id(parent, shortname, urls::STRING).unwrap();
        let mut b = CommitBuilder::new(id.as_str().into());
        b.is_genesis = true;
        b.set(urls::PARENT.into(), Value::AtomicUrl(parent.into()));
        b.set(urls::SHORTNAME.into(), Value::Slug(shortname.into()));
        b.set(
            urls::DATATYPE_PROP.into(),
            Value::AtomicUrl(urls::STRING.into()),
        );
        b.set(urls::DESCRIPTION.into(), Value::Markdown(shortname.into()));
        let commit = b.sign(agent, db, &Resource::new(id.clone())).await.unwrap();
        db.apply_commit(commit, &opts()).await.unwrap();
        id
    }

    async fn lens_commit(
        db: &Db,
        agent: &crate::agents::Agent,
        parent: &str,
        from: &str,
        to: &str,
    ) -> AtomicResult<crate::commit::CommitResponse> {
        let transform = serde_json::json!({"op": "rename"});
        let id = lens_id(from, to, &transform).unwrap();
        let mut b = CommitBuilder::new(id.as_str().into());
        b.is_genesis = true;
        b.set(urls::IS_A.into(), Value::from(vec![urls::LENS.to_string()]));
        b.set(urls::PARENT.into(), Value::AtomicUrl(parent.into()));
        b.set(urls::LENS_FROM.into(), Value::AtomicUrl(from.into()));
        b.set(urls::LENS_TO.into(), Value::AtomicUrl(to.into()));
        b.set(urls::LENS_TRANSFORM.into(), Value::Json(transform));
        let commit = b.sign(agent, db, &Resource::new(id.clone())).await?;
        db.apply_commit(commit, &opts()).await
    }

    async fn indexed(db: &Db, prop: &str, value: &str) -> Vec<String> {
        crate::db::prop_val_sub_index::find_in_prop_val_sub_index(
            db,
            prop,
            Some(&Value::String(value.into())),
        )
        .flatten()
        .map(|a| a.subject.to_string())
        .collect()
    }

    #[tokio::test]
    #[timeout(120000)]
    async fn lens_derives_values_on_read_and_in_the_index() {
        let db = Db::init_temp("lens_derives").await.unwrap();
        let agent = db.get_default_agent().unwrap();
        let title = make_property(&db, &agent, PARENT, "title").await;
        let name = make_property(&db, &agent, PARENT, "name").await;

        // A resource written before the lens exists.
        let mut b = CommitBuilder::new("placeholder".into());
        b.set(title.clone(), Value::String("Hello".into()));
        let created = db
            .apply_commit(Commit::create_did(b, &agent, &db).await.unwrap(), &opts())
            .await
            .unwrap();
        let subject = created.resource_new.unwrap().get_subject().clone();
        assert!(db.get_resource(&subject).await.unwrap().get(&name).is_err());
        assert!(indexed(&db, &name, "Hello").await.is_empty());

        // The lens arrives: reads and the index follow, without a new commit.
        lens_commit(&db, &agent, PARENT, &title, &name)
            .await
            .unwrap();
        assert_eq!(db.lenses().len(), 1);
        let read = db.get_resource(&subject).await.unwrap();
        assert_eq!(read.get(&name).unwrap().to_string(), "Hello");
        assert_eq!(
            indexed(&db, &name, "Hello").await,
            vec![subject.to_string()]
        );

        // An edit of the old property moves the derived value and its index row.
        let mut edit = db.get_resource(&subject).await.unwrap();
        edit.set(title.clone(), Value::String("Hi".into()), &db)
            .await
            .unwrap();
        edit.save_locally(&db).await.unwrap();
        let read = db.get_resource(&subject).await.unwrap();
        assert_eq!(read.get(&name).unwrap().to_string(), "Hi");
        assert!(indexed(&db, &name, "Hello").await.is_empty());
        assert_eq!(indexed(&db, &name, "Hi").await, vec![subject.to_string()]);

        // A real value of the new property wins and stays when the old changes.
        let mut edit = db.get_resource(&subject).await.unwrap();
        edit.set(name.clone(), Value::String("Real".into()), &db)
            .await
            .unwrap();
        edit.save_locally(&db).await.unwrap();
        let mut edit = db.get_resource(&subject).await.unwrap();
        edit.set(title.clone(), Value::String("Again".into()), &db)
            .await
            .unwrap();
        edit.save_locally(&db).await.unwrap();
        let read = db.get_resource(&subject).await.unwrap();
        assert_eq!(read.get(&name).unwrap().to_string(), "Real");
        assert_eq!(read.get(&title).unwrap().to_string(), "Again");
        assert!(indexed(&db, &name, "Hi").await.is_empty());
        assert_eq!(indexed(&db, &name, "Real").await, vec![subject.to_string()]);

        // The signed doc never held a derived value.
        let doc = read.build_state_doc().unwrap();
        assert!(doc.get_all_properties().contains_key(&title));

        // The index is rebuilt from the stored Lens resources.
        db.update_lenses(|index| *index = Default::default());
        assert!(db.lenses().is_empty());
        db.load_lenses().await;
        assert_eq!(db.lenses().len(), 1);
    }

    /// A resource that arrives by sync is materialized from its doc without
    /// derived values; persisting it files the derived ones like real ones.
    #[tokio::test]
    #[timeout(120000)]
    async fn lens_values_are_indexed_for_synced_resources() {
        let db = Db::init_temp("lens_sync").await.unwrap();
        let agent = db.get_default_agent().unwrap();
        let title = make_property(&db, &agent, PARENT, "title").await;
        let name = make_property(&db, &agent, PARENT, "name").await;
        lens_commit(&db, &agent, PARENT, &title, &name)
            .await
            .unwrap();
        assert_eq!(db.lenses().len(), 1);

        let doc = crate::loro::AtomicLoroDoc::new();
        doc.set_property(&title, &Value::String("Synced".into()))
            .unwrap();
        let mut replica = Resource::new("atomic:syncedresource0".into());
        replica.apply_state_doc(doc).unwrap();
        assert!(replica.get(&name).is_err(), "no lens on a bare apply");

        db.persist_replicated_resource(&replica).await.unwrap();
        assert_eq!(
            indexed(&db, &name, "Synced").await,
            vec!["atomic:syncedresource0".to_string()]
        );
        let read = db
            .get_resource(&replica.get_subject().clone())
            .await
            .unwrap();
        assert_eq!(read.get(&name).unwrap().to_string(), "Synced");
    }

    #[tokio::test]
    #[timeout(120000)]
    async fn lens_only_applies_within_the_ontology_that_owns_its_target() {
        let db = Db::init_temp("lens_authority").await.unwrap();
        let agent = db.get_default_agent().unwrap();
        let title = make_property(&db, &agent, PARENT, "title").await;
        let name = make_property(&db, &agent, PARENT, "name").await;

        // Claims another ontology owns `name`: stored, never applied.
        lens_commit(&db, &agent, "atomic:someoneelse", &title, &name)
            .await
            .unwrap();
        assert!(db.lenses().is_empty());
        assert_eq!(db.pending_lenses.read().unwrap().len(), 1);
    }

    #[tokio::test]
    #[timeout(120000)]
    async fn lens_identity_is_checked_and_immutable() {
        let db = Db::init_temp("lens_identity").await.unwrap();
        let agent = db.get_default_agent().unwrap();
        let title = make_property(&db, &agent, PARENT, "title").await;
        let name = make_property(&db, &agent, PARENT, "name").await;

        // A subject that is not the hash of its fields.
        let wrong = lens_id(&name, &title, &serde_json::json!({"op": "rename"})).unwrap();
        let mut b = CommitBuilder::new(wrong.as_str().into());
        b.is_genesis = true;
        b.set(urls::PARENT.into(), Value::AtomicUrl(PARENT.into()));
        b.set(
            urls::LENS_FROM.into(),
            Value::AtomicUrl(title.as_str().into()),
        );
        b.set(urls::LENS_TO.into(), Value::AtomicUrl(name.as_str().into()));
        b.set(
            urls::LENS_TRANSFORM.into(),
            Value::Json(serde_json::json!({"op": "rename"})),
        );
        let commit = b
            .sign(&agent, &db, &Resource::new(wrong.clone()))
            .await
            .unwrap();
        let err = db.apply_commit(commit, &opts()).await.unwrap_err();
        assert!(err.to_string().contains("Lens ID mismatch"), "{err}");

        // A real lens cannot be pointed somewhere else later.
        lens_commit(&db, &agent, PARENT, &title, &name)
            .await
            .unwrap();
        let id = lens_id(&title, &name, &serde_json::json!({"op": "rename"})).unwrap();
        let mut edit = db.get_resource(&id.as_str().into()).await.unwrap();
        let err = match edit
            .set(
                urls::LENS_TO.into(),
                Value::AtomicUrl(title.as_str().into()),
                &db,
            )
            .await
        {
            Err(e) => e,
            Ok(_) => edit.save_locally(&db).await.unwrap_err(),
        };
        assert!(
            err.to_string().contains("Cannot change the lensTo"),
            "{err}"
        );
        let _ = DataType::String;
    }
}

#[tokio::test]
#[timeout(120000)]
async fn index_keys_migration_rebuilds_old_rows_in_slices() {
    use super::prop_val_sub_index::{propvalsub_key, propvalsub_legacy_key};

    let store = Db::init_temp("index-keys-migration").await.unwrap();
    let mut resource = Resource::new_instance(urls::PARAGRAPH, &store)
        .await
        .unwrap();
    resource
        .set(
            urls::PARENT.into(),
            Value::AtomicUrl("https://localhost/p".into()),
            &store,
        )
        .await
        .unwrap();
    resource
        .set(
            urls::DESCRIPTION.into(),
            Value::Markdown("hallo".into()),
            &store,
        )
        .await
        .unwrap();
    resource.save_locally(&store).await.unwrap();
    let atom = crate::atoms::IndexAtom {
        property: urls::PARENT.into(),
        ref_value: "https://localhost/p".into(),
        sort_value: "https://localhost/p".into(),
        subject: resource.get_subject().to_string().into(),
    };

    // An index as an older store left it: the full property URL in the key,
    // no marker.
    store.clear_index().unwrap();
    let old_key = propvalsub_legacy_key(&atom);
    store.kv.insert(Tree::PropValSub, &old_key, b"").unwrap();
    store
        .kv
        .remove(Tree::PluginMeta, super::index_keys::DONE_KEY)
        .unwrap();
    assert!(store.index_migration_pending().unwrap());

    let mut seen = Vec::new();
    loop {
        let step = store.migrate_index_keys_step(1).unwrap();
        seen.push(step.done);
        if step.finished {
            assert_eq!(step.done, step.total);
            break;
        }
        assert!(step.total > 0 && step.done <= step.total);
    }
    assert!(seen.windows(2).all(|w| w[0] <= w[1]));
    assert!(
        seen.len() > 2,
        "a slice of one resource means several steps"
    );

    assert!(!store.index_migration_pending().unwrap());
    assert!(store.kv.get(Tree::PropValSub, &old_key).unwrap().is_none());
    assert!(store
        .kv
        .get(Tree::PropValSub, &propvalsub_key(&atom))
        .unwrap()
        .is_some());
    assert!(propvalsub_key(&atom).len() < old_key.len());
}
