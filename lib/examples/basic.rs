// Should be the same as code in `lib.rs`

fn main() {
    // Import the `Storelike` trait to get access to most functions
    use atomic_lib::Storelike;
    // Start with initializing the in-memory store
    let store = atomic_lib::Store::init().unwrap();
    // Pre-load the default Atomic Data Atoms (from atomicdata.dev),
    // this is not necessary, but will probably make your project a bit faster
    store.populate().unwrap();
    // We can create a new Resource, linked to the store.
    // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
    // Let's make a new Property instance! Let's create "age".
    let mut new_property =
        atomic_lib::Resource::new_instance("https://atomicdata.dev/classes/Property", &store)
            .unwrap();
    // And add a description for that Property
    new_property
        .set_propval_shortname("description", "the age of a person", &store)
        .unwrap();
    // A subject URL for the new resource has been created automatically.
    let subject = new_property.get_subject().clone();
    // Now we need to make sure these changes are also applied to the store.
    // In order to change things in the store, we should use Commits,
    // which are signed pieces of data that contain state changes.
    // Because these are signed, we need an Agent, which has a private key to sign Commits.
    let agent = store.create_agent(Some("my_agent")).unwrap();
    store.set_default_agent(agent);
    let _fails = new_property.save_locally(&store);
    // But.. when we commit, we get an error!
    // Because we haven't set all the properties required for the Property class.
    // We still need to set `shortname` and `datatype`.
    new_property
        .set_propval_shortname("shortname", "age", &store)
        .unwrap();
    new_property
        .set_propval_shortname("datatype", atomic_lib::urls::INTEGER, &store)
        .unwrap();
    new_property.save_locally(&store).unwrap();
    // Now the changes to the resource applied to the store, and we can fetch the newly created resource!
    let fetched_new_resource = store.get_resource(&subject).unwrap();
    assert!(
        fetched_new_resource
            .get_shortname("description", &store)
            .unwrap()
            .to_string()
            == "the age of a person"
    );
}
