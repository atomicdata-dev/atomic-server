use crate::urls;

use super::*;
use ntest::timeout;

/// Share the Db instance between tests. Otherwise, all tests try to init the same location on disk and throw errors.
/// Note that not all behavior can be properly tested with a shared database.
/// If you need a clean one, juts call init("someId").
use lazy_static::lazy_static; // 1.4.0
use std::sync::Mutex;
lazy_static! {
    pub static ref DB: Mutex<Db> = Mutex::new(Db::init_temp("shared").unwrap());
}

#[test]
#[timeout(30000)]
fn basic() {
    let store = DB.lock().unwrap().clone();
    // We can create a new Resource, linked to the store.
    // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
    // Let's make a new Property instance!
    let mut new_resource =
        crate::Resource::new_instance("https://atomicdata.dev/classes/Property", &store).unwrap();
    // And add a description for that Property
    new_resource
        .set_propval_shortname("description", "the age of a person", &store)
        .unwrap();
    new_resource
        .set_propval_shortname("shortname", "age", &store)
        .unwrap();
    new_resource
        .set_propval_shortname("datatype", crate::urls::INTEGER, &store)
        .unwrap();
    // Changes are only applied to the store after saving them explicitly.
    new_resource.save_locally(&store).unwrap();
    // The modified resource is saved to the store after this

    // A subject URL has been created automatically.
    let subject = new_resource.get_subject();
    let fetched_new_resource = store.get_resource(subject).unwrap();
    let description_val = fetched_new_resource
        .get_shortname("description", &store)
        .unwrap()
        .to_string();
    assert!(description_val == "the age of a person");

    // Try removing something
    store.get_resource(crate::urls::CLASS).unwrap();
    store.remove_resource(crate::urls::CLASS).unwrap();
    // Should throw an error, because can't remove non-existent resource
    store.remove_resource(crate::urls::CLASS).unwrap_err();
    // Should throw an error, because resource is deleted
    store.get_propvals(crate::urls::CLASS).unwrap_err();

    assert!(store.all_resources(false).len() < store.all_resources(true).len());
}

#[test]
fn populate_collections() {
    let store = Db::init_temp("populate_collections").unwrap();
    let subjects: Vec<String> = store
        .all_resources(false)
        .into_iter()
        .map(|r| r.get_subject().into())
        .collect();
    println!("{:?}", subjects);
    let collections_collection_url = format!("{}/collections", store.get_server_url());
    let collections_resource = store
        .get_resource_extended(&collections_collection_url, false, None)
        .unwrap();
    let member_count = collections_resource
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert!(member_count > 11);
    let nested = collections_resource
        .get(crate::urls::COLLECTION_INCLUDE_NESTED)
        .unwrap()
        .to_bool()
        .unwrap();
    assert!(nested);
    // Make sure it can be run multiple times
    store.populate().unwrap();
}

#[test]
/// Check if the cache is working
fn add_atom_to_index() {
    let store = Db::init_temp("add_atom_to_index").unwrap();
    let subject = urls::CLASS.into();
    let property: String = urls::PARENT.into();
    let value = Value::AtomicUrl(urls::AGENT.into());
    // This atom should normally not exist - Agent is not the parent of Class.
    let atom = Atom::new(subject, property.clone(), value.clone());
    store
        .add_atom_to_index(&atom, &Resource::new("ds".into()))
        .unwrap();
    let found_no_external = store
        .tpf(None, Some(&property), Some(&value), false)
        .unwrap();
    // Don't find the atom if no_external is true.
    assert_eq!(
        found_no_external.len(),
        0,
        "found items - should ignore external items"
    );
    let found_external = store
        .tpf(None, Some(&property), Some(&value), true)
        .unwrap();
    // If we see the atom, it's in the index.
    assert_eq!(found_external.len(), 1);
}

#[test]
/// Check if a resource is properly removed from the DB after a delete command.
/// Also counts commits.
fn destroy_resource_and_check_collection_and_commits() {
    let store = Db::init_temp("counter").unwrap();
    let agents_url = format!("{}/agents", store.get_server_url());
    let agents_collection_1 = store
        .get_resource_extended(&agents_url, false, None)
        .unwrap();
    let agents_collection_count_1 = agents_collection_1
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(
        agents_collection_count_1, 1,
        "The Agents collection is not one (we assume there is one agent already present from init)"
    );

    // We will count the commits, and check if they've incremented later on.
    let commits_url = format!("{}/commits", store.get_server_url());
    let commits_collection_1 = store
        .get_resource_extended(&commits_url, false, None)
        .unwrap();
    let commits_collection_count_1 = commits_collection_1
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    println!("Commits collection count 1: {}", commits_collection_count_1);

    // Create a new agent, check if it is added to the new Agents collection as a Member.
    let mut resource = crate::agents::Agent::new(None, &store)
        .unwrap()
        .to_resource(&store)
        .unwrap();
    let _res = resource.save_locally(&store).unwrap();
    let agents_collection_2 = store
        .get_resource_extended(&agents_url, false, None)
        .unwrap();
    let agents_collection_count_2 = agents_collection_2
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(
        agents_collection_count_2, 2,
        "The new Agent resource did not increase the collection member count from 1 to 2."
    );

    let commits_collection_2 = store
        .get_resource_extended(&commits_url, false, None)
        .unwrap();
    let commits_collection_count_2 = commits_collection_2
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    println!("Commits collection count 2: {}", commits_collection_count_2);
    assert_eq!(
        commits_collection_count_2,
        commits_collection_count_1 + 1,
        "The commits collection did not increase after saving the resource."
    );

    _res.resource_new.unwrap().destroy(&store).unwrap();
    let agents_collection_3 = store
        .get_resource_extended(&agents_url, false, None)
        .unwrap();
    let agents_collection_count_3 = agents_collection_3
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(
        agents_collection_count_3, 1,
        "The collection count did not decrease after destroying the resource."
    );

    let commits_collection_3 = store
        .get_resource_extended(&commits_url, false, None)
        .unwrap();
    let commits_collection_count_3 = commits_collection_3
        .get(crate::urls::COLLECTION_MEMBER_COUNT)
        .unwrap()
        .to_int()
        .unwrap();
    println!("Commits collection count 3: {}", commits_collection_count_3);
    assert_eq!(
        commits_collection_count_3,
        commits_collection_count_2 + 1,
        "The commits collection did not increase after destroying the resource."
    );
}

#[test]
fn get_extended_resource_pagination() {
    let store = Db::init_temp("get_extended_resource_pagination").unwrap();
    let subject = format!("{}/commits?current_page=2", store.get_server_url());
    // Should throw, because page 2 is out of bounds for default page size
    let _wrong_resource = store
        .get_resource_extended(&subject, false, None)
        .unwrap_err();
    // let subject = "https://atomicdata.dev/classes?current_page=2&page_size=1";
    let subject_with_page_size = format!("{}&page_size=1", subject);
    let resource = store
        .get_resource_extended(&subject_with_page_size, false, None)
        .unwrap();
    let cur_page = resource
        .get(urls::COLLECTION_CURRENT_PAGE)
        .unwrap()
        .to_int()
        .unwrap();
    assert_eq!(cur_page, 2);
    assert_eq!(resource.get_subject(), &subject_with_page_size);
}

/// Generate a bunch of resources, query them.
/// Checks if cache is properly invalidated on modifying or deleting resources.
#[test]
fn queries() {
    // Re-using the same instance can cause issues with testing concurrently.
    // let store = &DB.lock().unwrap().clone();
    let store = &Db::init_temp("queries").unwrap();

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

    for _x in 0..count {
        let mut demo_resource = Resource::new_generate_subject(store);
        // We make one resource public
        if _x == 1 {
            demo_resource
                .set_propval(urls::READ.into(), vec![urls::PUBLIC_AGENT].into(), store)
                .unwrap();
        }
        demo_resource
            .set_propval(urls::DESTINATION.into(), demo_reference.clone(), store)
            .unwrap();
        demo_resource
            .set_propval(urls::SHORTNAME.into(), demo_val.clone(), store)
            .unwrap();
        demo_resource
            .set_propval(
                sort_by.into(),
                Value::Markdown(crate::utils::random_string(10)),
                store,
            )
            .unwrap();
        demo_resource.save(store).unwrap();
    }

    let mut q = Query {
        property: Some(prop_filter.into()),
        value: Some(demo_reference.clone()),
        limit: Some(limit),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        for_agent: None,
    };
    let res = store.query(&q).unwrap();
    assert_eq!(
        res.count, count,
        "number of references without property filter"
    );
    assert_eq!(limit, res.subjects.len(), "limit");

    q.property = None;
    q.value = Some(demo_val);
    let res = store.query(&q).unwrap();
    assert_eq!(res.count, count, "literal value");

    q.offset = 9;
    let res = store.query(&q).unwrap();
    assert_eq!(res.subjects.len(), count - q.offset, "offset");
    assert_eq!(res.resources.len(), 0, "no nested resources");

    q.offset = 0;
    q.include_nested = true;
    let res = store.query(&q).unwrap();
    assert_eq!(res.resources.len(), limit, "nested resources");

    q.sort_by = Some(sort_by.into());
    let mut res = store.query(&q).unwrap();
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
            r.set_propval(sort_by.into(), Value::Markdown("!first".into()), store)
                .unwrap();
            let resp = r.save(store).unwrap();
            resource_changed_order_opt = resp.resource_new.clone();
        }
        prev_resource = r.clone();
    }

    let mut resource_changed_order = resource_changed_order_opt.unwrap();

    assert_eq!(res.count, count, "count changed after updating one value");

    q.sort_by = Some(sort_by.into());
    let res = store.query(&q).unwrap();
    assert_eq!(
        res.resources[0].get_subject(),
        resource_changed_order.get_subject(),
        "order did not change after updating resource"
    );

    resource_changed_order.destroy(store).unwrap();
    let res = store.query(&q).unwrap();
    assert!(
        res.resources[0].get_subject() != resource_changed_order.get_subject(),
        "deleted resource still in results"
    );

    q.sort_desc = true;
    let res = store.query(&q).unwrap();
    let first = res.resources[0].get(sort_by).unwrap().to_string();
    let later = res.resources[limit - 1].get(sort_by).unwrap().to_string();
    assert!(first > later, "sort by desc");

    q.for_agent = Some(urls::PUBLIC_AGENT.into());
    let res = store.query(&q).unwrap();
    assert_eq!(res.subjects.len(), 1, "authorized subjects");
    assert_eq!(res.resources.len(), 1, "authorized resources");
    // TODO: Ideally, the count is authorized too. But doing that could be hard. (or expensive)
    // https://github.com/joepio/atomic-data-rust/issues/286
    // assert_eq!(res.count, 1, "authorized count");

    println!("Filter by value, property and also Sort");
    q.property = Some(prop_filter.into());
    q.value = Some(demo_reference);
    q.sort_by = Some(sort_by.into());
    q.for_agent = None;
    let res = store.query(&q).unwrap();
    println!("res {:?}", res.subjects);
    let first = res.resources[0].get(sort_by).unwrap().to_string();
    let later = res.resources[limit - 1].get(sort_by).unwrap().to_string();
    assert!(first > later, "sort by desc");

    println!("Set a start value");
    let middle_val = res.resources[limit / 2].get(sort_by).unwrap().to_string();
    q.start_val = Some(Value::String(middle_val.clone()));
    let res = store.query(&q).unwrap();
    println!("res {:?}", res.subjects);

    let first = res.resources[0].get(sort_by).unwrap().to_string();
    assert!(
        first > middle_val,
        "start value not respected, found value larger than middle value of earlier query"
    );
}

/// Check if `include_external` is respected.
#[test]
fn query_include_external() {
    let store = &Db::init_temp("query_include_external").unwrap();

    let mut q = Query {
        property: None,
        value: None,
        limit: None,
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: None,
        sort_desc: false,
        include_external: true,
        include_nested: false,
        for_agent: None,
    };
    let res_include = store.query(&q).unwrap();
    q.include_external = false;
    let res_no_include = store.query(&q).unwrap();
    println!("{:?}", res_include.subjects.len());
    println!("{:?}", res_no_include.subjects.len());
    assert!(
        res_include.subjects.len() > res_no_include.subjects.len(),
        "Amount of results should be higher for include_external"
    );
}

// check if all_resources include_external working
#[test]
fn test_db_resources_all() {
    let store = &DB.lock().unwrap().clone();
    let res_no_include = store.all_resources(false).len();
    let res_include = store.all_resources(true).len();
    assert!(
        res_include > res_no_include,
        "Amount of results should be higher for include_external"
    );
}

#[test]
fn test_db_resources_all() {
    let store = &Db::init_temp("resources_all").unwrap();
    let res_no_include = store.all_resources(false).len();
    let res_include = store.all_resources(true).len();
    assert!(
        res_include > res_no_include,
        "Amount of results should be higher for include_external"
    );
}

#[test]
/// Changing these values actually correctly updates the index.
fn index_invalidate_cache() {
    let store = &Db::init_temp("invalidate_cache").unwrap();

    // Make sure to use Properties that are not in the default store

    // Do strings work?
    test_collection_update_value(
        store,
        urls::FILENAME,
        Value::String("old_val".into()),
        Value::String("1".into()),
    );
    // Do booleans work?
    test_collection_update_value(
        store,
        urls::IS_LOCKED,
        Value::Boolean(true),
        Value::Boolean(false),
    );
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
    );
}

/// Generates a bunch of resources, changes the value for one of them, checks if the order has changed correctly.
/// new_val should be lexicograhically _smaller_ than old_val.
fn test_collection_update_value(store: &Db, property_url: &str, old_val: Value, new_val: Value) {
    println!("cache_invalidation test for {}", property_url);
    let count = 10;
    let limit = 5;
    assert!(
        count > limit,
        "the following tests might not make sense if count is less than limit"
    );

    for _x in 0..count {
        let mut demo_resource = Resource::new_generate_subject(store);
        demo_resource
            .set_propval(property_url.into(), old_val.clone(), store)
            .unwrap();
        demo_resource.save(store).unwrap();
    }

    let q = Query {
        property: Some(property_url.into()),
        value: None,
        limit: Some(limit),
        start_val: None,
        end_val: None,
        offset: 0,
        sort_by: Some(property_url.into()),
        sort_desc: false,
        include_external: true,
        include_nested: true,
        for_agent: None,
    };
    let mut res = store.query(&q).unwrap();
    assert_eq!(
        res.count, count,
        "Not the right amount of members in this collection"
    );

    // For one resource, we will change the order by changing its value
    let mut resource_changed_order_opt = None;
    for (i, r) in res.resources.iter_mut().enumerate() {
        // We change the order!
        if i == 4 {
            r.set_propval(property_url.into(), new_val.clone(), store)
                .unwrap();
            r.save(store).unwrap();
            resource_changed_order_opt = Some(r.clone());
        }
    }

    let resource_changed_order =
        resource_changed_order_opt.expect("not enough resources in collection");

    let res = store.query(&q).expect("No first result ");
    assert_eq!(res.count, count, "count changed after updating one value");

    assert_eq!(
        res.subjects.first().unwrap(),
        resource_changed_order.get_subject(),
        "Updated resource is not the first Result of the new query"
    );
}
