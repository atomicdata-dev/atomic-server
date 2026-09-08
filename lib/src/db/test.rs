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
    fn json_ad_without_loro(r: &crate::Resource) -> String {
        let mut json: serde_json::Value =
            serde_json::from_str(&r.to_json_ad(None).unwrap()).unwrap();
        if let Some(obj) = json.as_object_mut() {
            obj.remove(crate::urls::LORO_UPDATE);
        }
        serde_json::to_string(&json).unwrap()
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
    let demo_reference = Value::AtomicUrl(urls::PARAGRAPH.into());

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

    q.property = None;
    q.value = Some(demo_val);
    let res = store.query(&q).await.unwrap();
    assert_eq!(res.count, count, "literal value, no property filter");

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
#[tokio::test]
#[timeout(120000)]
#[ignore = "reproduces an OPEN bug: query_sorted_indexed returns 2 of 3 members \
            that are written, parseable, local and matching — the read stops \
            after the second. Run with `--ignored` while working on it."]
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
}

/// Narrows the previous failure: is the row rejected by the MATCHER
/// (`resource_matches_filter`, which decides membership) or never offered as a
/// CANDIDATE (`plan_candidate_iterator`, which decides what gets considered)?
/// The fix differs — one is a comparison bug, the other an index-atom bug.
#[tokio::test]
#[timeout(120000)]
async fn is_a_string_encoding_matcher_vs_candidates() {
    let cls = "did:ad:classPROBEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==";

    let mut r = crate::Resource::new(
        "did:ad:probe0000000000000000000000000000000000000000000000000000000000000000==".into(),
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
            "did:ad:drivePROBEaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=="
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
