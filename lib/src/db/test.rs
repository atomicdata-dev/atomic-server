use crate::urls;

use super::*;
use ntest::timeout;

/// Creates new temporary database, populates it, removes previous one.
/// Can only be run one thread at a time, because it requires a lock on the DB file.
fn init(id: &str) -> Db {
    let tmp_dir_path = format!("tmp/db/{}", id);
    let _try_remove_existing = std::fs::remove_dir_all(&tmp_dir_path);
    let store = Db::init(
        std::path::Path::new(&tmp_dir_path),
        "https://localhost".into(),
    )
    .unwrap();
    let agent = store.create_agent(None).unwrap();
    store.set_default_agent(agent);
    store.populate().unwrap();
    store
}

/// Share the Db instance between tests. Otherwise, all tests try to init the same location on disk and throw errors.
/// Note that not all behavior can be properly tested with a shared database.
/// If you need a clean one, juts call init("someId").
use lazy_static::lazy_static; // 1.4.0
use std::sync::Mutex;
lazy_static! {
    pub static ref DB: Mutex<Db> = Mutex::new(init("shared"));
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
    let store = DB.lock().unwrap().clone();
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
}

#[test]
/// Check if the cache is working
fn add_atom_to_index() {
    let store = DB.lock().unwrap().clone();
    let subject = urls::CLASS.into();
    let property: String = urls::PARENT.into();
    let val_string = urls::AGENT;
    let value = Value::new(val_string, &crate::datatype::DataType::AtomicUrl).unwrap();
    // This atom should normally not exist - Agent is not the parent of Class.
    let atom = Atom::new(subject, property.clone(), value);
    store.add_atom_to_index(&atom).unwrap();
    let found_no_external = store
        .tpf(None, Some(&property), Some(val_string), false)
        .unwrap();
    // Don't find the atom if no_external is true.
    assert_eq!(
        found_no_external.len(),
        0,
        "found items - should ignore external items"
    );
    let found_external = store
        .tpf(None, Some(&property), Some(val_string), true)
        .unwrap();
    // If we see the atom, it's in the index.
    assert_eq!(found_external.len(), 1);
}

#[test]
/// Check if a resource is properly removed from the DB after a delete command.
/// Also counts commits.
fn destroy_resource_and_check_collection_and_commits() {
    let store = init("counter");
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

    let mut resource = crate::agents::Agent::new(None, &store)
        .unwrap()
        .to_resource(&store)
        .unwrap();
    resource.save_locally(&store).unwrap();
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
        "The Resource was not found in the collection."
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

    resource.destroy(&store).unwrap();
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
    let store = DB.lock().unwrap().clone();
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
