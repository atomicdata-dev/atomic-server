extern crate atomic_lib;

#[test]
fn main() {
  // Let's parse this AD3 string
  let string = String::from("[\"_:test\",\"https://atomicdata.dev/properties/shortname\",\"Test\"]");
  // Start with initializing our store
  let mut store = atomic_lib::store::init();
  // Run parse...
  atomic_lib::store::parse_ad3(&mut store, &string).unwrap();
  // Get our resource...
  let my_resource = store.get("_:test").unwrap();
  // Get our value by filtering on our property...
  let my_value = my_resource.get("https://atomicdata.dev/properties/shortname").unwrap();
  println!("My value: {}", my_value);
  assert!(my_value == "Test")
}
