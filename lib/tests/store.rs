extern crate atomic_lib;

#[test]
fn full_circle() {
  let string = String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"Test\"]");
  let mut store = atomic_lib::store::Store::init();
  store.parse_ad3(&string).unwrap();
  let my_resource = store.get(&"_:test".to_string()).unwrap();
  let my_value = my_resource.get("https://atomicdata.dev/properties/shortname").unwrap();
  assert!(my_value == "Test")
}
