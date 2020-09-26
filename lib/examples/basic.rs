// Should be the same as code in `lib.rs`

fn main() {
    // Import the `Storelike` trait to get access to most functions
    use atomic_lib::Storelike;
    // Start with initializing our store
    let store = atomic_lib::Store::init();
    // Load the default Atomic Data Atoms
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
    // Let's make a new Property instance!
    let new_property = atomic_lib::Resource::new_instance("https://atomicdata.dev/classes/Property", &store).unwrap();
    new_property.
}
