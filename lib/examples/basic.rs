// Should be the same as code in `lib.rs`

fn main() {
    // Import the `Storelike` trait to get access to most functions
    use atomic_lib::Storelike;
    // Start with initializing the in-memory store
    let store = atomic_lib::Store::init();
    // Pre-load the default Atomic Data Atoms (from atomicdata.dev),
    // this is not necessary, but will probably make your project a bit faster
    store.populate().unwrap();
    // Let's parse this AD3 string.
    let ad3 = r#"["https://localhost/test","https://atomicdata.dev/properties/description","Test"]"#;
    // The parser returns a Vector of Atoms
    let atoms = atomic_lib::parse::parse_ad3(&ad3).unwrap();
    // Add the Atoms to the Store
    store.add_atoms(atoms).unwrap();
    // Get our resource...
    let my_resource = store.get_resource("https://localhost/test").unwrap();
    // Get our value by filtering on our property...
    let my_value = my_resource
        .get("https://atomicdata.dev/properties/description")
        .unwrap();
    assert!(my_value.to_string() == "Test");
    // We can also use the shortname of description
    let my_value_from_shortname = my_resource.get_shortname("description").unwrap();
    assert!(my_value_from_shortname.to_string() == "Test");
    // We can find any Atoms matching some value using Triple Pattern Fragments:
    let found_atoms = store.tpf(None, None, Some("Test")).unwrap();
    assert!(found_atoms.len() == 1);

    // We can also create a new Resource, linked to the store.
    // Note that since this store only exists in memory, it's data cannot be accessed from the internet.
    // Let's make a new Property instance!
    let mut new_property = atomic_lib::Resource::new_instance("https://atomicdata.dev/classes/Property", &store).unwrap();
    // And add a description for that Property
    new_property.set_propval_by_shortname("description", "the age of a person").unwrap();
    // A subject URL has been created automatically.
    let subject = new_property.get_subject().clone();
    // Now we need to make sure these changes are also applied to the store.
    // In order to change things in the store, we should use Commits,
    // which are signed pieces of data that contain state changes.
    // Because these are signed, we need an Agent, which has a private key to sign Commits.
    let agent = store.create_agent("my_agent").unwrap();
    store.set_default_agent(agent);
    store.commit_resource_changes(&mut new_property).unwrap();
    // Now the changes to the resource applied to the store, and we can fetch the newly created resource!
    let fetched_new_resource = store.get_resource(&subject).unwrap();
    assert!(fetched_new_resource.get_shortname("description").unwrap().to_string() == "the age of a person");
}
